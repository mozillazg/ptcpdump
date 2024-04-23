package writer

import "github.com/mozillazg/ptcpdump/internal/event"

type PacketWriter interface {
	Write(e *event.Packet) error
	Flush() error
	Close() error
}
