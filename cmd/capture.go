package cmd

import (
	"context"
	"log"
	"os"
	"syscall"
	"time"

	"github.com/mozillazg/ptcpdump/internal/consumer"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/mozillazg/ptcpdump/internal/utils"
)

func capture(ctx context.Context, stop context.CancelFunc, opts Options) error {
	pcache := metadata.NewProcessCache()

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

	writers, err := getWriters(opts, pcache)
	if err != nil {
		return err
	}
	defer func() {
		for _, w := range writers {
			w.Flush()
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

	packetConsumer := consumer.NewPacketEventConsumer(writers)
	if opts.delayBeforeHandlePacketEvents > 0 {
		time.Sleep(opts.delayBeforeHandlePacketEvents)
	}
	if subProcessLoaderPid > 0 {
		go func() {
			syscall.Kill(subProcessLoaderPid, syscall.SIGHUP)
			<-subProcessFinished
			time.Sleep(time.Second * 5)
			stop()
		}()
	}

	packetConsumer.Start(ctx, packetEvensCh, opts.maxPacketCount)

	return nil
}

func getCurrentConnects(ctx context.Context, pcache *metadata.ProcessCache, opts Options) []metadata.Connection {
	if opts.pid != 0 {
		cs, err := metadata.GetCurrentConnects(ctx, []int{int(opts.pid)}, false)
		if err != nil {
			log.Printf("get current connects failed: %s", err)
		}
		return cs
	}
	if opts.comm != "" {
		pids := pcache.GetPidsByComm(opts.comm)
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
