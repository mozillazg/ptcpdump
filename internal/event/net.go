package event

import (
	"time"

	"github.com/gopacket/gopacket"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/dev"
	"github.com/mozillazg/ptcpdump/internal/host"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/utils"
)

type packetType int

const (
	packetTypeIngress packetType = 0
	packetTypeEgress  packetType = 1
)

type Packet struct {
	Time      time.Time
	Type      packetType
	Device    dev.Device
	Pid       int
	MntNs     int
	NetNs     int
	Truncated bool
	Len       int

	Data []byte

	CgroupName string
}

func ParsePacketEvent(devices *dev.Interfaces, event bpf.BpfPacketEventWithPayloadT) (*Packet, error) {
	var p Packet
	if t, err := convertBpfKTimeNs(event.Meta.Timestamp); err != nil {
		log.Errorf("convert bpf time failed: %s", err)
		p.Time = time.Now().UTC()
	} else {
		p.Time = t.UTC()
	}
	p.Pid = int(event.Meta.Process.Pid)
	p.MntNs = int(event.Meta.Process.MntnsId)
	p.NetNs = int(event.Meta.Process.NetnsId)
	p.CgroupName = utils.GoString(event.Meta.Process.CgroupName[:])
	p.Device = devices.GetByIfindex(int(event.Meta.Ifindex))

	log.Infof("new packet event, pid: %d mntns: %d, netns: %d, cgroupName: %s",
		p.Pid, p.MntNs, p.NetNs, p.CgroupName)

	if event.Meta.PacketType == 1 {
		p.Type = packetTypeEgress
	}
	if event.Meta.PacketSize > event.Meta.PayloadLen {
		p.Truncated = true
	}
	p.Len = int(event.Meta.PacketSize)
	p.Data = make([]byte, event.Meta.PayloadLen)
	copy(p.Data[:], event.Payload[:event.Meta.PayloadLen])

	return &p, nil
}

func FromPacket(ci gopacket.CaptureInfo, data []byte) (*Packet, error) {
	p := Packet{
		Time:      ci.Timestamp,
		Type:      -1,
		Device:    dev.Device{},
		Pid:       0,
		Truncated: false,
		Len:       ci.Length,
		Data:      data,
	}
	return &p, nil
}

func (p Packet) Ingress() bool {
	return p.Type == packetTypeIngress
}

func (p Packet) Egress() bool {
	return p.Type == packetTypeEgress
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
