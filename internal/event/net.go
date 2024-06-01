package event

import (
	"fmt"
	"log"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/dev"
	"golang.org/x/sys/unix"
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
}

func ParsePacketEvent(devices map[int]dev.Device, event bpf.BpfPacketEventT) (*Packet, error) {
	var p Packet
	if t, err := convertBpfKTimeNs(event.Meta.Timestamp); err != nil {
		log.Printf("convert bpf time failed: %+v", err)
		p.Time = time.Now().UTC()
	} else {
		p.Time = t.UTC()
	}
	p.Pid = int(event.Meta.Pid)
	p.MntNs = int(event.Meta.MntnsId)
	p.NetNs = int(event.Meta.NetnsId)
	log.Printf("mntns: %d, netns: %d", p.MntNs, p.NetNs)
	p.Device = devices[int(event.Meta.Ifindex)]

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
	b, err := getBootTimeNs()
	if err != nil {
		return time.Time{}, err
	}

	return time.Now().Add(-time.Duration(b - int64(t))), nil
}

func getBootTimeNs() (int64, error) {
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	if err != nil {
		return 0, fmt.Errorf("could not get time: %s", err)
	}

	return unix.TimespecToNsec(ts), nil
}
