package writer

import (
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/mozillazg/ptcpdump/internal/event"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"golang.org/x/xerrors"
	"log"
	"time"
)

type PcapNGWriter struct {
	pw     *pcapgo.NgWriter
	pcache *metadata.ProcessCache
}

func NewPcapNGWriter(pw *pcapgo.NgWriter, pcache *metadata.ProcessCache) *PcapNGWriter {
	return &PcapNGWriter{pw: pw, pcache: pcache}
}

func (w *PcapNGWriter) Write(e *event.Packet) error {
	payloadLen := len(e.Data)
	info := gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		CaptureLength:  payloadLen,
		Length:         payloadLen,
		InterfaceIndex: 0,
	}
	p := w.pcache.Get(e.Pid)
	if p.Pid == 0 {
		log.Printf("not found pid from cache: %d", e.Pid)
	}
	opts := pcapgo.NgPacketOptions{
		Comment: fmt.Sprintf("PID: %d\nCOMMAND: %s", e.Pid, string(p.Args)),
	}

	if err := w.pw.WritePacketWithOptions(info, e.Data, opts); err != nil {
		return xerrors.Errorf("writing packet: %w", err)
	}

	return nil
}

func (w *PcapNGWriter) Flush() error {
	return w.pw.Flush()
}
