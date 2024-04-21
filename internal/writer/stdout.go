package writer

import (
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/mozillazg/ptcpdump/internal/event"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/x-way/pktdump"
	"io"
	"time"
)

type StdoutWriter struct {
	pcache *metadata.ProcessCache
	w      io.Writer
}

func NewStdoutWriter(writer io.Writer, pcache *metadata.ProcessCache) *StdoutWriter {
	return &StdoutWriter{
		w:      writer,
		pcache: pcache,
	}
}

func (w *StdoutWriter) Write(e *event.Packet) error {
	packetType := "In"
	if e.Egress() {
		packetType = "Out"
	}
	p := w.pcache.Get(e.Pid)
	pidInfo := fmt.Sprintf("Process [pid %d, cmd %s, args %s]",
		e.Pid, p.FilenameStr(), p.ArgsStr())

	// Decode a packet
	packet := gopacket.NewPacket(e.Data, layers.LayerTypeEthernet, gopacket.NoCopy)
	formated := pktdump.Format(packet)

	msg := fmt.Sprintf("%s %s %s, %s\n",
		//packet.Metadata().CaptureInfo.Timestamp.Format("15:04:05.000000"),
		time.Now().Local().Format("15:04:05.000000"),
		packetType, formated, pidInfo)

	w.w.Write([]byte(msg))

	return nil
}

func (w *StdoutWriter) Close() error {
	return nil
}
