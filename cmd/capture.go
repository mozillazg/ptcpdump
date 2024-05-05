package cmd

import (
	"context"
	"github.com/mozillazg/ptcpdump/internal/consumer"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"log"
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

	packetEvensCh, err := bf.PullPacketEvents(ctx)
	if err != nil {
		return err
	}
	execEvensCh, err := bf.PullExecEvents(ctx)
	if err != nil {
		return err
	}

	execConsumer := consumer.NewExecEventConsumer(pcache)
	go execConsumer.Start(ctx, execEvensCh)

	log.Println("capturing...")

	packetConsumer := consumer.NewPacketEventConsumer(writers)
	packetConsumer.Start(ctx, packetEvensCh, opts.maxPacketCount)

	return nil
}
