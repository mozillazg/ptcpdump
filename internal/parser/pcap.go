package parser

import (
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/mozillazg/ptcpdump/internal/event"
)

type PcapParser struct {
	h *pcap.Handle
}

func NewPcapParser(file *os.File) (*PcapParser, error) {
	h, err := pcap.OpenOfflineFile(file)
	if err != nil {
		return nil, err
	}
	return &PcapParser{
		h: h,
	}, nil
}

func (p *PcapParser) Decoder() gopacket.Decoder {
	return p.h.LinkType()
}

func (p *PcapParser) Parse() (*event.Packet, error) {
	data, ci, err := p.h.ZeroCopyReadPacketData()
	if err != nil {
		return nil, err
	}
	e, err := event.FromPacket(ci, data)
	if err != nil {
		return nil, err
	}
	return e, nil
}
