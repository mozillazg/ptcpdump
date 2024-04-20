package writer

import (
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/mozillazg/ptcpdump/internal/event"
	"golang.org/x/xerrors"
	"time"
)

type PcapNGWriter struct {
	pw *pcapgo.NgWriter
}

func NewPcapNGWriter(pw *pcapgo.NgWriter) *PcapNGWriter {
	return &PcapNGWriter{pw: pw}
}

func (w *PcapNGWriter) Write(p *event.Packet) error {
	payloadLen := len(p.Data)
	info := gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		CaptureLength:  payloadLen,
		Length:         payloadLen,
		InterfaceIndex: 0,
	}
	opts := pcapgo.NgPacketOptions{
		Comment: fmt.Sprintf("PID: %d\nCOMMAND: %s", p.Pid, p.Comm),
	}

	if err := w.pw.WritePacketWithOptions(info, p.Data, opts); err != nil {
		return xerrors.Errorf("writing packet: %w", err)
	}

	return nil
}

func (w *PcapNGWriter) Flush() error {
	return w.pw.Flush()
}
