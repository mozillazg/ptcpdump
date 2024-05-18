package consumer

import (
	"context"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/dev"
	"github.com/mozillazg/ptcpdump/internal/event"
	"github.com/mozillazg/ptcpdump/internal/writer"
	"log"
)

type PacketEventConsumer struct {
	writers        []writer.PacketWriter
	devices        map[int]dev.Device
	processedCount int
}

func NewPacketEventConsumer(writers []writer.PacketWriter) *PacketEventConsumer {
	devices, _ := dev.GetDevices([]string{})
	return &PacketEventConsumer{
		writers: writers,
		devices: devices,
	}
}

func (c *PacketEventConsumer) Start(ctx context.Context, ch <-chan bpf.BpfPacketEventT, maxPacketCount uint) {
	for {
		select {
		case <-ctx.Done():
			return
		case pt := <-ch:
			c.handlePacketEvent(pt)
			c.processedCount++
			if maxPacketCount > 0 && c.processedCount == int(maxPacketCount) {
				return
			}
		}
	}
}

func (c *PacketEventConsumer) handlePacketEvent(pt bpf.BpfPacketEventT) {
	pevent, err := event.ParsePacketEvent(c.devices, pt)
	if err != nil {
		log.Printf("[PacketEventConsumer] parse event failed: %s", err)
		return
	}

	for _, w := range c.writers {
		if err := w.Write(pevent); err != nil {
			log.Printf("[PacketEventConsumer] write packet failed: %s, device: %#v", err, pevent.Device)
		}
		w.Flush()
	}
}

func (c *PacketEventConsumer) Stop() {

}

func (c *PacketEventConsumer) ProcessedCount() int {
	return c.processedCount
}
