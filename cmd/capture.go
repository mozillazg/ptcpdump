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
	"github.com/mozillazg/ptcpdump/internal/consumer"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/mozillazg/ptcpdump/internal/utils"
)

func capture(ctx context.Context, stop context.CancelFunc, opts Options) error {
	headerTips(opts)
	log.Info("capturing...")

	log.Debug("start process and container cache")
	pcache := metadata.NewProcessCache()
	cc, _ := applyContainerFilter(ctx, &opts)
	if cc != nil {
		pcache.WithContainerCache(cc)
	}

	var subProcessFinished <-chan struct{}
	var err error
	var subProcessLoaderPid int
	if len(opts.subProgArgs) > 0 {
		log.Debug("start sub process loader")
		subProcessLoaderPid, subProcessFinished, err = utils.StartSubProcessLoader(ctx, os.Args[0], opts.subProgArgs)
		if err != nil {
			return err
		}
		opts.pid = uint(subProcessLoaderPid)
		opts.followForks = true
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
	pcache.Start()

	log.Debug("start get current connections")
	conns := getCurrentConnects(ctx, pcache, opts)

	log.Debug("start attach hooks")
	bf, err := attachHooks(conns, opts)
	if err != nil {
		if bf != nil {
			bf.Close()
		}
		return err
	}
	defer bf.Close()

	packetEvensCh, err := bf.PullPacketEvents(ctx, int(opts.eventChanSize))
	if err != nil {
		return err
	}
	execEvensCh, err := bf.PullExecEvents(ctx, int(opts.eventChanSize))
	if err != nil {
		return err
	}

	execConsumer := consumer.NewExecEventConsumer(pcache, int(opts.execEventsWorkerNumber))
	go execConsumer.Start(ctx, execEvensCh)

	var stopByInternal bool
	packetConsumer := consumer.NewPacketEventConsumer(writers)
	if opts.delayBeforeHandlePacketEvents > 0 {
		time.Sleep(opts.delayBeforeHandlePacketEvents)
	}
	if subProcessLoaderPid > 0 {
		go func() {
			log.Debugf("notify loader %d to start sub process", subProcessLoaderPid)
			syscall.Kill(subProcessLoaderPid, syscall.SIGHUP)
			<-subProcessFinished
			log.Debug("sub process exited")
			time.Sleep(time.Second * 3)
			stopByInternal = true
			stop()
		}()
	}

	go printCaptureCountBySignal(ctx, bf, packetConsumer)
	packetConsumer.Start(ctx, packetEvensCh, opts.maxPacketCount)

	if !stopByInternal && ctx.Err() != nil {
		fmt.Fprint(os.Stderr, "\n")
	}
	counts := getCaptureCounts(bf, packetConsumer)
	fmt.Fprintf(os.Stderr, "%s\n", strings.Join(counts, "\n"))

	return nil
}

func headerTips(opts Options) {
	interfaces := opts.ifaces[0]
	if len(opts.ifaces) > 1 {
		interfaces = fmt.Sprintf("[%s]", strings.Join(opts.ifaces, ", "))
	}
	if opts.verbose < 1 {
		log.Warn("ptcpdump: verbose output suppressed, use -v[v]... for verbose output")
		log.Warnf("capturing on %s, link-type EN10MB (Ethernet)", interfaces)
	} else {
		log.Warnf("tcpdump: capturing on %s, link-type EN10MB (Ethernet)", interfaces)
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

func getCurrentConnects(ctx context.Context, pcache *metadata.ProcessCache, opts Options) []metadata.Connection {
	var pids []int
	var filter_pid bool

	if opts.pid != 0 {
		filter_pid = true
		pids = append(pids, int(opts.pid))
	}
	if opts.comm != "" {
		filter_pid = true
		ps := pcache.GetPidsByComm(opts.comm)
		pids = append(pids, ps...)
	}
	if opts.pidns_id > 0 {
		filter_pid = true
		ps := pcache.GetPidsByPidNsId(int64(opts.pidns_id))
		pids = append(pids, ps...)
	}
	if opts.mntns_id > 0 {
		filter_pid = true
		ps := pcache.GetPidsByPidNsId(int64(opts.mntns_id))
		pids = append(pids, ps...)
	}
	if opts.netns_id > 0 {
		filter_pid = true
		ps := pcache.GetPidsByPidNsId(int64(opts.netns_id))
		pids = append(pids, ps...)
	}

	if filter_pid {
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
