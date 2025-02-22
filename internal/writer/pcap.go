package writer

import (
	"fmt"
	"io"
	"sync"
	"unsafe"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/mozillazg/ptcpdump/internal/event"
)

type PcapWriter struct {
	rr   Rotator
	pw   *pcapgo.Writer
	lock sync.Mutex

	newWriter func(io.Writer) (*pcapgo.Writer, error)
}

func NewPcapWriter(rr Rotator, newWriter func(io.Writer) (*pcapgo.Writer, error)) (*PcapWriter, error) {
	pw, err := newWriter(rr)
	if err != nil {
		return nil, err
	}

	return &PcapWriter{
		rr:        rr,
		pw:        pw,
		lock:      sync.Mutex{},
		newWriter: newWriter,
	}, nil
}

func (w *PcapWriter) Write(e *event.Packet) error {
	payloadLen := len(e.Data)
	info := gopacket.CaptureInfo{
		Timestamp:      e.Time.Local(),
		CaptureLength:  payloadLen,
		Length:         e.Len,
		InterfaceIndex: e.Device.Ifindex,
	}
	w.lock.Lock()
	defer w.lock.Unlock()

	if w.rr.ShouldRotate(int(unsafe.Sizeof(info)) + len(e.Data)) {
		if err := w.rr.Rotate(); err != nil {
			return fmt.Errorf("rotating file: %w", err)
		}
		pw, err := w.newWriter(w.rr)
		if err != nil {
			return fmt.Errorf("creating new pcap writer: %w", err)
		}
		w.pw = pw
	}

	if err := w.pw.WritePacket(info, e.Data); err != nil {
		return fmt.Errorf("writing packet: %w", err)
	}

	return nil
}

func (w *PcapWriter) Flush() error {
	return nil
}

func (w *PcapWriter) Close() error {
	return nil
}
