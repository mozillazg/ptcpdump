package parser

import (
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
	exec := event.FromPacketOptions(opts)
	e.Pid = exec.Pid
	p.pcache.AddItem(exec)
	return e, nil
}
