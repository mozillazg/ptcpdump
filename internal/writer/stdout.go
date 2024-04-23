package writer

import (
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/mozillazg/ptcpdump/internal/event"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/x-way/pktdump"
	"io"
	"log"
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
	ifName := e.Device.Name
	packetType := "In"
	if e.Egress() {
		packetType = "Out"
	}
	p := w.pcache.Get(e.Pid)
	pidInfo := fmt.Sprintf("Process (pid %d, cmd %s, args %s)",
		e.Pid, p.FilenameStr(), p.ArgsStr())

	// Decode a packet
	packet := gopacket.NewPacket(e.Data, layers.LayerTypeEthernet, gopacket.NoCopy)
	formated := pktdump.Format(packet)

	msg := fmt.Sprintf("%s %s %s %s\n    %s\n",
		e.Time.Local().Format("15:04:05.000000"), ifName,
		packetType, formated, pidInfo)

	if _, err := w.w.Write([]byte(msg)); err != nil {
		log.Printf("write packet failed: %+v", err)
	}

	return nil
}

func (w *StdoutWriter) Flush() error {
	return nil
}

func (w *StdoutWriter) Close() error {
	return nil
}
