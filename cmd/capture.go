package cmd

import (
	"context"
	"log"
	"time"

	"github.com/mozillazg/ptcpdump/internal/consumer"
	"github.com/mozillazg/ptcpdump/internal/metadata"
)

func capture(ctx context.Context, opts Options) error {
	pcache := metadata.NewProcessCache()
	writers, err := getWriters(opts, pcache)
	if err != nil {
		return err
	}
	defer func() {
		for _, w := range writers {
			w.Flush()
		}
	}()
	go pcache.Start()

	bf, err := attachHooks(opts)
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
	packetConsumer.Start(ctx, packetEvensCh, opts.maxPacketCount)

	return nil
}
