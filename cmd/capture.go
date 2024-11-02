package cmd

import (
	"context"
	"fmt"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/capturer"
	"github.com/mozillazg/ptcpdump/internal/consumer"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/mozillazg/ptcpdump/internal/utils"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func capture(ctx context.Context, stopFunc context.CancelFunc, opts *Options) error {
	log.Info("start get all devices")
	devices, err := opts.GetDevices()
	if err != nil {
		return err
	}

	log.Info("start process and container cache")
	pcache := metadata.NewProcessCache()
	cc, _ := applyContainerFilter(ctx, opts)
	if cc != nil {
		pcache.WithContainerCache(cc)
	}
	pcache.Start(ctx)

	log.Info("start init writers")
	writers, fcloser, err := getWriters(opts, pcache)
	if err != nil {
		return err
	}
	defer func() {
		if fcloser != nil {
			fcloser()
		}
	}()

	log.Info("start init gotls event consumer")
	gcr, err := getGoKeyLogEventConsumer(opts, writers)
	if err != nil {
		return err
	}
	execConsumer := consumer.NewExecEventConsumer(pcache, int(opts.execEventsWorkerNumber))
	exitConsumer := consumer.NewExitEventConsumer(pcache, 10)
	packetConsumer := consumer.NewPacketEventConsumer(writers, opts.deviceCache).
		WithDelay(opts.delayBeforeHandlePacketEvents)

	log.Info("start get current connections")
	conns := getCurrentConnects(ctx, pcache, opts)
	log.Infof("got %d connections", len(conns))

	copts := opts.ToCapturerOptions()
	copts.Connections = conns
	copts.ProcessCache = pcache
	copts.DeviceCache = opts.deviceCache
	copts.NetNSCache = opts.netNSCache
	copts.ExecConsumer = execConsumer
	copts.ExitConsumer = exitConsumer
	copts.PacketConsumer = packetConsumer
	copts.Gcr = gcr
	copts.Writers = writers
	caper := capturer.NewCapturer(copts)
	defer caper.Stop()

	if err := caper.StartSubProcessLoader(ctx, os.Args[0], opts.subProgArgs); err != nil {
		return err
	}

	log.Info("start prepare capturer")
	if err := caper.Prepare(); err != nil {
		return err
	}

	log.Info("start attach hooks")
	if err := caper.AttachTracingHooks(); err != nil {
		return err
	}
	if err := attachGoTLSHooks(opts, caper.BPF()); err != nil {
		return err
	}
	log.Info("start to attach tc hooks when startup")
	if err := caper.AttachTcHooksToDevs(devices.Devs()); err != nil {
		return err
	}
	log.Info("start events monitor")
	if err := caper.Start(ctx, stopFunc); err != nil {
		return err
	}

	headerTips(opts)
	log.Info("capturing...")

	go printCaptureCountBySignal(ctx, caper.BPF(), packetConsumer)

	caper.Wait()

	if !caper.StopByInternal() && ctx.Err() != nil {
		utils.OutStderr("%s", "\n")
	}
	counts := getCaptureCounts(caper.BPF(), packetConsumer)
	utils.OutStderr("%s\n", strings.Join(counts, "\n"))

	stopFunc()

	return nil
}

func headerTips(opts *Options) {
	interfaces := "any"
	if len(opts.ifaces) > 0 {
		interfaces = fmt.Sprintf("[%s]", strings.Join(opts.ifaces, ", "))
	}

	msg := fmt.Sprintf("capturing on %s, link-type EN10MB (Ethernet), snapshot length %d bytes",
		interfaces, opts.snapshotLength)

	if opts.verbose < 1 {
		log.Warn("ptcpdump: verbose output suppressed, use -v[v]... for verbose output")
		log.Warn(msg)
	} else {
		log.Warnf("ptcpdump: %s", msg)
	}
}

func printCaptureCountBySignal(ctx context.Context, bf *bpf.BPF, c *consumer.PacketEventConsumer) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			counts := getCaptureCounts(bf, c)
			utils.OutStderr("ptcpdump: %s\n", strings.Join(counts, ", "))
		}
	}
}

func getCaptureCounts(bf *bpf.BPF, c *consumer.PacketEventConsumer) []string {
	var ret []string
	report := bf.CountReport()
	report.Captured = c.ProcessedCount()

	ret = append(ret, fmt.Sprintf("%d packets captured", report.Captured))
	ret = append(ret, fmt.Sprintf("%d packets received by filter", report.Received))
	ret = append(ret, fmt.Sprintf("%d packets dropped by kernel", report.Dropped))

	return ret
}

func getCurrentConnects(ctx context.Context, pcache *metadata.ProcessCache, opts *Options) []metadata.Connection {
	var pids []int
	var filterPid bool

	if len(opts.subProgArgs) > 0 {
		return nil
	}

	if len(opts.pids) > 0 {
		filterPid = true
		for _, pid := range opts.pids {
			pids = append(pids, int(pid))
		}
	}
	if opts.comm != "" {
		filterPid = true
		ps := pcache.GetPidsByComm(opts.comm)
		pids = append(pids, ps...)
	}
	if len(opts.pidnsIds) > 0 {
		filterPid = true
		for _, id := range opts.pidnsIds {
			ps := pcache.GetPidsByPidNsId(int64(id))
			pids = append(pids, ps...)
		}
	}
	if len(opts.mntnsIds) > 0 {
		filterPid = true
		for _, id := range opts.mntnsIds {
			ps := pcache.GetPidsByPidNsId(int64(id))
			pids = append(pids, ps...)
		}
	}
	if len(opts.netnsIds) > 0 {
		filterPid = true
		for _, id := range opts.netnsIds {
			ps := pcache.GetPidsByPidNsId(int64(id))
			pids = append(pids, ps...)
		}
	}
	pids = utils.GetUniqInts(pids)

	if filterPid {
		if len(pids) == 0 {
			return nil
		}
		cs, err := metadata.GetCurrentConnects(ctx, pids, false)
		if err != nil {
			log.Errorf("get current connects failed: %s", err)
		}
		return cs
	}

	cs, err := metadata.GetCurrentConnects(ctx, nil, true)
	if err != nil {
		log.Errorf("get current connects failed: %s", err)
	}
	return cs
}
