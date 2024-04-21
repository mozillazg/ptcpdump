package event

import (
	"bytes"
	"encoding/binary"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/dev"
	"golang.org/x/xerrors"
	"unsafe"
)

type packetType int

const (
	packetTypeIngress packetType = 0
	packetTypeEgress  packetType = 1
)

type Packet struct {
	Type   packetType
	Device dev.Device
	Pid    int
	Comm   string

	Data []byte
}

func ParsePacketEvent(devices map[int]dev.Device, rawSample []byte) (*Packet, error) {
	var p Packet
	event := bpf.BpfPacketEventT{}
	if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event.Meta); err != nil {
		return nil, xerrors.Errorf("parse meta: %w", err)
	}
	copy(event.Payload[:], rawSample[unsafe.Offsetof(event.Payload):])

	p.Pid = int(event.Meta.Pid)
	p.Comm = strComm(event.Meta.Comm)
	if event.Meta.PacketType == 1 {
		p.Type = packetTypeEgress
	}
	p.Device = devices[int(event.Meta.Ifindex)]
	p.Data = make([]byte, event.Meta.PayloadLen)
	copy(p.Data[:], event.Payload[:event.Meta.PayloadLen])

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
