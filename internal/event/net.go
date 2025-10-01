package event

import (
	"encoding/binary"
	"github.com/gopacket/gopacket/layers"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/mozillazg/ptcpdump/internal/types"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/host"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/utils"
)

type packetType int
type firstLayerType int

const (
	packetTypeIngress packetType = 1
	packetTypeEgress  packetType = 2

	FirstLayerL2 firstLayerType = 2
	FirstLayerL3 firstLayerType = 3
)

type Packet struct {
	Time      time.Time
	Type      packetType
	Device    types.Device
	Pid       int
	Tid       int
	Uid       int
	TName     string
	MntNs     int
	NetNs     int
	Truncated bool
	Len       int

	Data []byte

	CgroupName string
	FirstLayer firstLayerType
	L3Protocol uint16
}

func ParsePacketEvent(deviceCache *metadata.DeviceCache, event bpf.BpfPacketEventWithPayloadT) (*Packet, error) {
	var p Packet
	if t, err := convertBpfKTimeNs(event.Meta.Timestamp); err != nil {
		log.Errorf("convert bpf time failed: %s", err)
		p.Time = time.Now().UTC()
	} else {
		p.Time = t.UTC()
	}
	p.Pid = int(event.Meta.Process.Pid)
	p.Tid = int(event.Meta.Process.Tid)
	p.Uid = int(event.Meta.Process.Uid)
	p.TName = utils.GoString(event.Meta.Process.Tname[:])
	p.MntNs = int(event.Meta.Process.MntnsId)
	p.NetNs = int(event.Meta.Process.NetnsId)
	p.CgroupName = utils.GoString(event.Meta.Process.CgroupName[:])

	if p.NetNs == 0 {
		p.NetNs = int(event.Meta.NetnsId)
	}
	ifindex := event.Meta.Ifindex
	ifName := utils.GoStringUint(event.Meta.Ifname[:])
	isFromSkb := len(ifName) > 0
	var ok bool
	p.Device, ok = deviceCache.GetByKnownIfindex(int(ifindex))
	if !ok {
		p.Device, _ = deviceCache.GetByIfindex(int(ifindex), uint32(p.NetNs))
	}
	if p.Device.IsDummy() {
		netns := event.Meta.NetnsId
		if len(ifName) > 0 {
			deviceCache.Add(netns, ifindex, ifName)
			p.Device, _ = deviceCache.GetByIfindex(int(ifindex), netns)
		}
	}

	p.L3Protocol = event.Meta.L3Protocol
	p.FirstLayer = firstLayerType(event.Meta.FirstLayer)
	p.Type = packetType(event.Meta.PacketType)
	if event.Meta.PacketSize > event.Meta.PayloadLen {
		p.Truncated = true
	}
	p.Len = int(event.Meta.PacketSize)

	log.Infof("new packet event, %d.%s firstLayer: %d thread: %s.%d, pid: %d, uid: %d, mntns: %d, netns: %d, cgroupName: %s",
		ifindex, p.Device.Name, p.FirstLayer, p.TName, p.Tid, p.Pid, p.Uid, p.MntNs, p.NetNs, p.CgroupName)

	var fakeEthernet []byte
	var fakeEthernetLen int
	if p.FirstLayer == FirstLayerL3 || (isFromSkb && noL2Data(event.Payload[:event.Meta.PayloadLen])) {
		if v := getL3Protocol(event.Payload[:event.Meta.PayloadLen]); v > 0 {
			p.L3Protocol = v
		}
		fakeEthernet = newFakeEthernet(p.L3Protocol)
		fakeEthernetLen = len(fakeEthernet)
		log.Infof("add fake ethernet header, l3protocol: 0x%x", p.L3Protocol)
	}

	p.Data = make([]byte, event.Meta.PayloadLen+uint64(fakeEthernetLen))
	if fakeEthernetLen > 0 {
		copy(p.Data[:fakeEthernetLen], fakeEthernet)
		p.Len += fakeEthernetLen
	}
	copy(p.Data[fakeEthernetLen:], event.Payload[:event.Meta.PayloadLen])

	log.Infof("%d, %+v", p.L3Protocol, p.Data)

	return &p, nil
}

func noL2Data(payload []byte) bool {
	if len(payload) < 14 {
		return true
	}
	packet := gopacket.NewPacket(payload, layers.LayerTypeEthernet, gopacket.NoCopy)
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		if eth, ok := ethLayer.(*layers.Ethernet); ok {
			log.Debugf("%+v", payload)
			log.Debugf("%+v", eth)
			if len(eth.Payload) > 0 &&
				eth.EthernetType != layers.EthernetTypeLLC &&
				eth.EthernetType.String() != "UnknownEthernetType" {
				return false
			}
		}
	}
	return true
}

func getL3Protocol(payload []byte) uint16 {
	packet := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.NoCopy)
	if ethLayer := packet.Layer(layers.LayerTypeIPv4); ethLayer != nil {
		if _, ok := ethLayer.(*layers.IPv4); ok {
			return 0x0800
		}
	}
	packet = gopacket.NewPacket(payload, layers.LayerTypeIPv6, gopacket.NoCopy)
	if ethLayer := packet.Layer(layers.LayerTypeIPv6); ethLayer != nil {
		if _, ok := ethLayer.(*layers.IPv6); ok {
			return 0x86DD
		}
	}
	return 0
}

func newFakeEthernet(l3Protocol uint16) []byte {
	ethernetHeader := make([]byte, 14)
	copy(ethernetHeader[0:6], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02})
	copy(ethernetHeader[6:12], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
	binary.BigEndian.PutUint16(ethernetHeader[12:14], l3Protocol)

	return ethernetHeader
}

func FromPacket(ci gopacket.CaptureInfo, data []byte) (*Packet, error) {
	p := Packet{
		Time:      ci.Timestamp,
		Type:      -1,
		Device:    types.Device{},
		Pid:       0,
		Truncated: false,
		Len:       ci.Length,
		Data:      data,
	}
	return &p, nil
}

func (p *Packet) Ingress() bool {
	return p.Type == packetTypeIngress
}

func (p *Packet) Egress() bool {
	return p.Type == packetTypeEgress
}

func (p *Packet) MarkIngress() {
	p.Type = packetTypeIngress
}

func (p *Packet) MarkEgress() {
	p.Type = packetTypeEgress
}

func strComm(comm [16]int8) string {
	b := make([]byte, len(comm))
	for i, c := range comm {
		b[i] = byte(c)
	}
	return string(b)
}

func convertBpfKTimeNs(t uint64) (time.Time, error) {
	b, err := host.GetBootTimeNs()
	if err != nil {
		return time.Time{}, err
	}

	return time.Now().Add(-time.Duration(b - int64(t))), nil
}
