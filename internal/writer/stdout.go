package writer

import (
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/mozillazg/ptcpdump/internal/event"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"log"
)

type StdoutWriter struct {
	pcache *metadata.ProcessCache
}

func NewStdoutWriter(pcache *metadata.ProcessCache) *StdoutWriter {
	return &StdoutWriter{
		pcache: pcache,
	}
}

func (w *StdoutWriter) Write(e *event.Packet) error {
	packetType := "=>·  "
	if e.Egress() {
		packetType = "  ·=>"
	}
	p := w.pcache.Get(e.Pid)
	pidInfo := fmt.Sprintf("PID: %d Command: %s Args: %s",
		e.Pid, p.FilenameStr(), p.ArgsStr())

	// Decode a packet
	packet := gopacket.NewPacket(e.Data, layers.LayerTypeEthernet, gopacket.Default)
	var ipv4 *layers.IPv4
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4, _ = ipv4Layer.(*layers.IPv4)
	}
	if ipv4 == nil {
		return nil
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		log.Printf("[TCP] %s %s-%d %s:%d => %s:%d, %s",
			packetType, e.Comm, e.Pid,
			ipv4.SrcIP.String(), tcp.SrcPort,
			ipv4.DstIP.String(), tcp.DstPort, pidInfo)
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		log.Printf("[UDP] %s %s-%d %s:%d => %s:%d, %s",
			packetType, e.Comm, e.Pid,
			ipv4.SrcIP.String(), udp.SrcPort,
			ipv4.DstIP.String(), udp.DstPort, pidInfo)
	}

	return nil
}
