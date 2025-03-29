package writer

import (
	"encoding/json"
	"github.com/gopacket/gopacket/layers"
	"github.com/mozillazg/ptcpdump/internal/types"
	"io"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/mozillazg/ptcpdump/internal/event"
	"github.com/mozillazg/ptcpdump/internal/metadata"
)

type JSONWriter struct {
	pcache  *metadata.ProcessCache
	w       io.Writer
	Decoder gopacket.Decoder
}

func NewJSONWriter(writer io.Writer, pcache *metadata.ProcessCache) *JSONWriter {
	return &JSONWriter{
		w:       writer,
		Decoder: layers.LayerTypeEthernet,
		pcache:  pcache,
	}
}

func (w *JSONWriter) Write(e *event.Packet) error {
	p := w.pcache.Get(e.Pid, e.MntNs, e.NetNs, e.CgroupName)
	p.Tid = e.Tid
	p.TName = e.TName
	if p.UserId == 0 && e.Uid != 0 {
		p.UserId = e.Uid
	}

	// Decode a packet
	packet := gopacket.NewPacket(e.Data, w.Decoder, gopacket.NoCopy)
	output := NewJSONOutput(packet)

	if e.Egress() {
		output.Direction = 2
	}
	output.TimestampNs = e.Time.UTC().UnixNano()
	output.DateTime = e.Time.UTC().Format(time.RFC3339)
	output.Interface = &DevInterface{
		Name:    e.Device.Name,
		Index:   e.Device.Ifindex,
		NetNsId: int64(e.Device.NetNs.Inode()),
	}

	if p.Pid > 0 {
		output.Process = &Process{
			Name:             p.Comm(),
			ProcessBase:      p.ProcessBase,
			ProcessNamespace: p.ProcessNamespace,
		}
	}
	if p.Parent.Pid > 0 {
		output.ParentProcess = &Process{
			Name:        p.Parent.Comm(),
			ProcessBase: p.Parent,
		}
	}
	if p.Container.Id != "" {
		output.Container = &p.Container
	}
	if p.Pod.Name != "" {
		output.Pod = &p.Pod
	}

	return json.NewEncoder(w.w).Encode(output)
}

func (w *JSONWriter) Flush() error {
	return nil
}

func (w *JSONWriter) Close() error {
	return nil
}

type JSONOutput struct {
	TimestampNs int64         `json:"timestampNs"`
	DateTime    string        `json:"dateTime"`
	Interface   *DevInterface `json:"interface"`
	Direction   int           `json:"direction"` // 1: inbound, 2: outbound

	Ethernet *EthernetInfo `json:"ethernet,omitempty"`
	ARP      *ARPInfo      `json:"arp,omitempty"`
	IP       *IPInfo       `json:"ip,omitempty"`
	TCP      *TCPInfo      `json:"tcp,omitempty"`
	UDP      *UDPInfo      `json:"udp,omitempty"`
	ICMP     *ICMPInfo     `json:"icmp,omitempty"`

	Process       *Process         `json:"process,omitempty"`
	ParentProcess *Process         `json:"parentProcess,omitempty"`
	Container     *types.Container `json:"container,omitempty"`
	Pod           *types.Pod       `json:"pod,omitempty"`
}

func NewJSONOutput(packet gopacket.Packet) JSONOutput {
	var nextLayerType gopacket.LayerType
	var length int
	j := JSONOutput{
		Direction: 1,
	}

	if layer := packet.LinkLayer(); layer != nil {
		switch layer := layer.(type) {
		case *layers.Ethernet:
			j.Ethernet = &EthernetInfo{
				SrcMAC: layer.SrcMAC.String(),
				DstMAC: layer.DstMAC.String(),
				Type:   int(layer.EthernetType),
				Len:    len(layer.LayerPayload()),
			}
			switch layer.NextLayerType() {
			case layers.LayerTypeARP:
				if ly := packet.Layer(layers.LayerTypeARP); ly != nil {
					arp, _ := ly.(*layers.ARP)
					j.ARP = &ARPInfo{
						Operation: int(arp.Operation),
						SrcMAC:    net.HardwareAddr(arp.SourceHwAddress).String(),
						SrcIP:     net.IP(arp.SourceProtAddress).String(),
						DstIP:     net.IP(arp.DstProtAddress).String(),
					}
				}
			}
		}
	}

	if layer := packet.NetworkLayer(); layer != nil {
		switch netLayer := layer.(type) {
		case *layers.IPv4:
			j.IP = &IPInfo{
				Version:  int(netLayer.Version),
				SrcAddr:  netLayer.SrcIP.String(),
				DstAddr:  netLayer.DstIP.String(),
				Protocol: int(netLayer.Protocol),
				Len:      int(netLayer.Length) - int(netLayer.IHL)*4,
			}
			length = j.IP.Len
			nextLayerType = netLayer.NextLayerType()
		case *layers.IPv6:
			j.IP = &IPInfo{
				Version:  int(netLayer.Version),
				SrcAddr:  netLayer.SrcIP.String(),
				DstAddr:  netLayer.DstIP.String(),
				Protocol: int(netLayer.NextHeader),
				Len:      int(netLayer.Length),
			}
			length = j.IP.Len
			nextLayerType = netLayer.NextLayerType()
		}
	}

	switch nextLayerType {
	case layers.LayerTypeUDP:
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			j.UDP = &UDPInfo{
				SrcPort: int(udp.SrcPort),
				DstPort: int(udp.DstPort),
				Len:     int(udp.Length) - 8,
			}
		}
	case layers.LayerTypeTCP:
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			j.TCP = &TCPInfo{
				SrcPort: int(tcp.SrcPort),
				DstPort: int(tcp.DstPort),
				Len:     length - int(tcp.DataOffset)*4,
			}
		}
	case layers.LayerTypeICMPv6:
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv6)
			j.ICMP = &ICMPInfo{
				Type: int(icmp.TypeCode.Type()),
				Code: int(icmp.TypeCode.Code()),
				Len:  length,
			}
		}
	case layers.LayerTypeICMPv4:
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			j.ICMP = &ICMPInfo{
				Type: int(icmp.TypeCode.Type()),
				Code: int(icmp.TypeCode.Code()),
				Len:  length,
			}
		}
	}

	return j
}

type DevInterface struct {
	Name    string `json:"name"`
	Index   int    `json:"index"`
	NetNsId int64  `json:"netNSId"`
}

type EthernetInfo struct {
	SrcMAC string `json:"srcMAC"`
	DstMAC string `json:"dstMAC"`
	Type   int    `json:"type"`
	Len    int    `json:"len"`
}

type ARPInfo struct {
	Operation int    `json:"operation"`
	SrcMAC    string `json:"srcMAC"`
	SrcIP     string `json:"srcIP"`
	DstIP     string `json:"dstIP"`
}

type ICMPInfo struct {
	Type int `json:"type"`
	Code int `json:"code"`
	Len  int `json:"len"`
}

type IPInfo struct {
	Version  int    `json:"version"`
	SrcAddr  string `json:"srcAddr"`
	DstAddr  string `json:"dstAddr"`
	Protocol int    `json:"protocol"`
	Len      int    `json:"len"`
}

type TCPInfo struct {
	SrcPort int `json:"srcPort"`
	DstPort int `json:"dstPort"`
	Len     int `json:"len"`
}

type UDPInfo struct {
	SrcPort int `json:"srcPort"`
	DstPort int `json:"dstPort"`
	Len     int `json:"len"`
}

type Process struct {
	Name string `json:"name"`
	types.ProcessBase
	types.ProcessNamespace
}
