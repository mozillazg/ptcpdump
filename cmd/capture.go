package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/consumer"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/mozillazg/ptcpdump/internal/utils"
)

func capture(ctx context.Context, stop context.CancelFunc, opts Options) error {
	pcache := metadata.NewProcessCache()
	cc, _ := applyContainerFilter(ctx, &opts)
	if cc != nil {
		pcache.WithContainerCache(cc)
	}

	var subProcessFinished <-chan struct{}
	var err error
	var subProcessLoaderPid int
	if len(opts.subProgArgs) > 0 {
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
	conns := getCurrentConnects(ctx, pcache, opts)

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

	log.Println("capturing...")

	var stopByInternal bool
	packetConsumer := consumer.NewPacketEventConsumer(writers)
	if opts.delayBeforeHandlePacketEvents > 0 {
		time.Sleep(opts.delayBeforeHandlePacketEvents)
	}
	if subProcessLoaderPid > 0 {
		go func() {
			syscall.Kill(subProcessLoaderPid, syscall.SIGHUP)
			<-subProcessFinished
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
			log.Printf("get current connects failed: %s", err)
		}
		return cs
	}

	cs, err := metadata.GetCurrentConnects(ctx, nil, true)
	if err != nil {
		log.Printf("get current connects failed: %s", err)
	}
	return cs
}
