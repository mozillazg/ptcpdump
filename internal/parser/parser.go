package parser

import "github.com/mozillazg/ptcpdump/internal/event"

type Parser interface {
	Parse() (*event.Packet, error)
}
