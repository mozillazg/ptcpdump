package writer

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/mozillazg/ptcpdump/internal/event"
	"log"
)

type StdoutWriter struct {
}

func NewStdoutWriter() *StdoutWriter {
	return &StdoutWriter{}
}

func (w *StdoutWriter) Write(p *event.Packet) error {
	packetType := "=>·  "
	if p.Egress() {
		packetType = "  ·=>"
	}

	// Decode a packet
	packet := gopacket.NewPacket(p.Data, layers.LayerTypeEthernet, gopacket.Default)
	var ipv4 *layers.IPv4
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4, _ = ipv4Layer.(*layers.IPv4)
	}
	if ipv4 == nil {
		return nil
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		log.Printf("%s %s-%d %s:%d => %s:%d",
			packetType, p.Comm, p.Pid,
			ipv4.SrcIP.String(), tcp.SrcPort,
			ipv4.DstIP.String(), tcp.DstPort)
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		log.Printf("%s %s-%d %s:%d => %s:%d",
			packetType, p.Comm, p.Pid,
			ipv4.SrcIP.String(), udp.SrcPort,
			ipv4.DstIP.String(), udp.DstPort)
	}

	return nil
}
