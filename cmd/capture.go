package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/btf"
	"github.com/mozillazg/ptcpdump/internal/consumer"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/mozillazg/ptcpdump/internal/utils"
)

func capture(ctx context.Context, stop context.CancelFunc, opts *Options) error {
	devices, err := opts.GetDevices()
	if err != nil {
		return err
	}
	btfSpec, btfPath, err := btf.LoadBTFSpec(opts.btfPath)
	if err != nil {
		return err
	}
	if btfPath != btf.DefaultPath {
		log.Warnf("use BTF specs from %s", btfPath)
	}

	log.Info("start process and container cache")
	pcache := metadata.NewProcessCache()
	cc, _ := applyContainerFilter(ctx, opts)
	if cc != nil {
		pcache.WithContainerCache(cc)
	}

	writers, fcloser, err := getWriters(opts, pcache)
	if err != nil {
		return err
	}
	defer func() {
		for _, w := range writers {
			w.Flush()
		}
		if fcloser != nil {
			fcloser()
		}
	}()
	gcr, err := getGoKeyLogEventConsumer(opts, writers)
	if err != nil {
		return err
	}

	var subProcessFinished <-chan struct{}
	var subProcessLoaderPid int
	if len(opts.subProgArgs) > 0 {
		log.Info("start sub process loader")
		subProcessLoaderPid, subProcessFinished, err = utils.StartSubProcessLoader(ctx, os.Args[0], opts.subProgArgs)
		if err != nil {
			return err
		}
		opts.pids = []uint{uint(subProcessLoaderPid)}
		opts.followForks = true
	}

	pcache.Start(ctx)

	log.Info("start get current connections")
	conns := getCurrentConnects(ctx, pcache, opts)

	log.Info("start attach hooks")
	bf, closers, err := attachHooks(btfSpec, conns, opts)
	if err != nil {
		runClosers(closers)
		return err
	}
	defer runClosers(closers)

	packetEvensCh, err := bf.PullPacketEvents(ctx, int(opts.eventChanSize), int(opts.snapshotLength))
	if err != nil {
		return err
	}
	execEvensCh, err := bf.PullExecEvents(ctx, int(opts.eventChanSize))
	if err != nil {
		return err
	}
	exitEvensCh, err := bf.PullExitEvents(ctx, int(opts.eventChanSize))
	if err != nil {
		return err
	}
	goTlsKeyLogEventsCh, err := bf.PullGoKeyLogEvents(ctx, int(opts.eventChanSize))
	if err != nil {
		return err
	}

	headerTips(opts)
	log.Info("capturing...")

	execConsumer := consumer.NewExecEventConsumer(pcache, int(opts.execEventsWorkerNumber))
	go execConsumer.Start(ctx, execEvensCh)
	exitConsumer := consumer.NewExitEventConsumer(pcache, 10)
	go exitConsumer.Start(ctx, exitEvensCh)
	go gcr.Start(ctx, goTlsKeyLogEventsCh)

	var stopByInternal bool
	packetConsumer := consumer.NewPacketEventConsumer(writers, devices).
		WithDelay(opts.delayBeforeHandlePacketEvents)
	if subProcessLoaderPid > 0 {
		go func() {
			log.Infof("notify loader %d to start sub process", subProcessLoaderPid)
			syscall.Kill(subProcessLoaderPid, syscall.SIGHUP)
			<-subProcessFinished
			log.Info("sub process exited")
			time.Sleep(time.Second * 3)
			stopByInternal = true
			time.Sleep(opts.delayBeforeHandlePacketEvents)
			stop()
		}()
	}

	go printCaptureCountBySignal(ctx, bf, packetConsumer)
	packetConsumer.Start(ctx, packetEvensCh, opts.maxPacketCount)
	defer func() {
		packetConsumer.Stop()
		execConsumer.Stop()
		exitConsumer.Stop()
		gcr.Stop()
	}()

	if !stopByInternal && ctx.Err() != nil {
		fmt.Fprint(os.Stderr, "\n")
	}
	counts := getCaptureCounts(bf, packetConsumer)
	fmt.Fprintf(os.Stderr, "%s\n", strings.Join(counts, "\n"))

	return nil
}

func headerTips(opts *Options) {
	interfaces := opts.ifaces[0]
	if len(opts.ifaces) > 1 {
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
			fmt.Fprintf(os.Stderr, fmt.Sprintf("ptcpdump: %s\n", strings.Join(counts, ", ")))
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
