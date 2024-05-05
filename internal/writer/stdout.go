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
	"strings"
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
	packetType := ""
	if e.Egress() {
		packetType = "Out"
	} else if e.Ingress() {
		packetType = "In"
	}
	p := w.pcache.Get(e.Pid)
	pidInfo := fmt.Sprintf("Process (pid %d, cmd %s, args %s)",
		e.Pid, p.FilenameStr(), p.ArgsStr())

	// Decode a packet
	packet := gopacket.NewPacket(e.Data, layers.LayerTypeEthernet, gopacket.NoCopy)
	formated := pktdump.Format(packet)

	builder := strings.Builder{}
	builder.WriteString(fmt.Sprintf("%s", e.Time.Local().Format("15:04:05.000000")))
	if ifName != "" {
		builder.WriteString(fmt.Sprintf(" %s", ifName))
	}
	if packetType != "" {
		builder.WriteString(fmt.Sprintf(" %s", packetType))
	}
	builder.WriteString(fmt.Sprintf(" %s\n", formated))
	if p.Pid > 0 {
		builder.WriteString(fmt.Sprintf("    %s\n", pidInfo))
	}
	msg := builder.String()

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
