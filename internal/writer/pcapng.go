package writer

import (
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/mozillazg/ptcpdump/internal/event"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"golang.org/x/xerrors"
)

type PcapNGWriter struct {
	pw     *pcapgo.NgWriter
	pcache *metadata.ProcessCache

	noBuffer bool
}

func NewPcapNGWriter(pw *pcapgo.NgWriter, pcache *metadata.ProcessCache) *PcapNGWriter {
	return &PcapNGWriter{pw: pw, pcache: pcache}
}

func (w *PcapNGWriter) Write(e *event.Packet) error {
	payloadLen := len(e.Data)
	info := gopacket.CaptureInfo{
		Timestamp:      e.Time.Local(),
		CaptureLength:  payloadLen,
		Length:         e.Len,
		InterfaceIndex: e.Device.Ifindex,
	}
	p := w.pcache.Get(e.Pid, e.MntNs)

	opts := pcapgo.NgPacketOptions{}
	if p.Pid != 0 {
		// log.Printf("not found pid from cache: %d", e.Pid)
		opts.Comments = append(opts.Comments,
			fmt.Sprintf("PID: %d\nCommand: %s\nArgs: %s",
				e.Pid, p.Cmd, p.FormatArgs()),
		)
	}
	if p.Container.Id != "" {
		opts.Comments = append(opts.Comments,
			fmt.Sprintf("ContainerName: %s\nContainerId: %s\nContainerImage: %s\nContainerLabels: %s",
				p.Container.TidyName(), p.Container.Id, p.Container.Image, p.Container.FormatLabels()),
		)
	}

	if err := w.pw.WritePacketWithOptions(info, e.Data, opts); err != nil {
		return xerrors.Errorf("writing packet: %w", err)
	}
	if w.noBuffer {
		w.pw.Flush()
	}

	return nil
}

func (w *PcapNGWriter) Flush() error {
	return w.pw.Flush()
}

func (w *PcapNGWriter) Close() error {
	return nil
}

func (w *PcapNGWriter) WithNoBuffer() *PcapNGWriter {
	w.noBuffer = true
	return w
}
