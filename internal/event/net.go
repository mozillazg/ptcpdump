package event

import (
	"encoding/binary"
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
	Gid       int
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
	p.Gid = int(event.Meta.Process.Gid)
	p.TName = utils.GoString(event.Meta.Process.Tname[:])
	p.MntNs = int(event.Meta.Process.MntnsId)
	p.NetNs = int(event.Meta.Process.NetnsId)
	p.CgroupName = utils.GoString(event.Meta.Process.CgroupName[:])
	p.Device, _ = deviceCache.GetByIfindex(int(event.Meta.Ifindex), event.Meta.Process.NetnsId)

	log.Infof("new packet event, thread: %s.%d, pid: %d, uid: %d, gid: %d, mntns: %d, netns: %d, cgroupName: %s",
		p.TName, p.Tid, p.Pid, p.Uid, p.Gid, p.MntNs, p.NetNs, p.CgroupName)

	p.L3Protocol = event.Meta.L3Protocol
	p.FirstLayer = firstLayerType(event.Meta.FirstLayer)
	p.Type = packetType(event.Meta.PacketType)
	if event.Meta.PacketSize > event.Meta.PayloadLen {
		p.Truncated = true
	}
	p.Len = int(event.Meta.PacketSize)

	var fakeEthernet []byte
	var fakeEthernetLen int
	if p.FirstLayer == FirstLayerL3 {
		fakeEthernet = newFakeEthernet(p.L3Protocol)
		fakeEthernetLen = len(fakeEthernet)
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
