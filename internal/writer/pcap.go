package writer

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/mozillazg/ptcpdump/internal/event"
	"golang.org/x/xerrors"
)

type PcapWriter struct {
	pw *pcapgo.Writer
}

func NewPcapWriter(pw *pcapgo.Writer) *PcapWriter {
	return &PcapWriter{pw: pw}
}

func (w *PcapWriter) Write(e *event.Packet) error {
	payloadLen := len(e.Data)
	info := gopacket.CaptureInfo{
		Timestamp:      e.Time.Local(),
		CaptureLength:  payloadLen,
		Length:         e.Len,
		InterfaceIndex: e.Device.Ifindex,
	}
	if err := w.pw.WritePacket(info, e.Data); err != nil {
		return xerrors.Errorf("writing packet: %w", err)
	}

	return nil
}

func (w *PcapWriter) Flush() error {
	return nil
}

func (w *PcapWriter) Close() error {
	return nil
}
