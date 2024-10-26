package parser

import (
	"github.com/mozillazg/ptcpdump/internal/types"
	"io"

	"github.com/gopacket/gopacket/pcapgo"
	"github.com/mozillazg/ptcpdump/internal/event"
	"github.com/mozillazg/ptcpdump/internal/metadata"
)

type PcapNGParser struct {
	pcache *metadata.ProcessCache
	r      *pcapgo.NgReader
}

func NewPcapNGParser(reader io.Reader, pcache *metadata.ProcessCache) (*PcapNGParser, error) {
	r, err := pcapgo.NewNgReader(reader, pcapgo.NgReaderOptions{})
	if err != nil {
		return nil, err
	}
	return &PcapNGParser{
		r:      r,
		pcache: pcache,
	}, nil
}

func (p *PcapNGParser) Parse() (*event.Packet, error) {
	data, ci, opts, err := p.r.ZeroCopyReadPacketDataWithOptions()
	if err != nil {
		return nil, err
	}

	e, err := event.FromPacket(ci, data)
	if err != nil {
		return nil, err
	}

	interf, err := p.r.Interface(ci.InterfaceIndex)
	if err == nil {
		e.Device = types.Device{
			Name:    interf.Name,
			Ifindex: 0,
			NetNs:   nil,
		}
	}
	if opts.Flags != nil {
		switch {
		case opts.Flags.Direction == pcapgo.NgEpbFlagDirectionInbound:
			e.MarkIngress()
		case opts.Flags.Direction == pcapgo.NgEpbFlagDirectionOutbound:
			e.MarkEgress()
		}
	}

	exec, ctx := event.FromPacketOptions(opts)
	e.Pid = exec.Pid
	p.pcache.AddItemWithContext(exec, ctx)

	return e, nil
}
