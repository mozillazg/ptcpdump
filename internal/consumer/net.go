package consumer

import (
	"context"
	"errors"
	"github.com/cilium/ebpf/perf"
	"github.com/mozillazg/ptcpdump/internal/dev"
	"github.com/mozillazg/ptcpdump/internal/event"
	"github.com/mozillazg/ptcpdump/internal/writer"
	"log"
)

type PacketEventConsumer struct {
	writers []writer.PacketWriter
	devices map[int]dev.Device
}

func NewPacketEventConsumer(writers []writer.PacketWriter, devices map[int]dev.Device) *PacketEventConsumer {
	return &PacketEventConsumer{
		writers: writers,
		devices: devices,
	}
}

func (c *PacketEventConsumer) Start(ctx context.Context, reader *perf.Reader) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("[PacketEventConsumer] Received signal, exiting...")
				return
			}
			log.Printf("[PacketEventConsumer] read event failed: %s", err)
			continue
		}
		if record.LostSamples > 0 {
			log.Printf("[PacketEventConsumer] lost samples: %d", record.LostSamples)
		}
		c.parsePacketEvent(record.RawSample)
	}
}

func (c *PacketEventConsumer) parsePacketEvent(rawSample []byte) {
	pevent, err := event.ParsePacketEvent(c.devices, rawSample)
	if err != nil {
		log.Printf("[PacketEventConsumer] parse event failed: %s", err)
		return
	}

	for _, w := range c.writers {
		if err := w.Write(pevent); err != nil {
			log.Printf("[PacketEventConsumer] write packet failed: %s", err)
		}
	}
}

func (c *PacketEventConsumer) Stop() {

}
