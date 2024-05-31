package writer

import (
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/mozillazg/ptcpdump/internal/event"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/x-way/pktdump"
)

type StdoutWriter struct {
	pcache      *metadata.ProcessCache
	w           io.Writer
	Decoder     gopacket.Decoder
	OneLine     bool
	PrintNumber bool
	n           int64
}

func NewStdoutWriter(writer io.Writer, pcache *metadata.ProcessCache) *StdoutWriter {
	return &StdoutWriter{
		w:       writer,
		pcache:  pcache,
		Decoder: layers.LayerTypeEthernet,
		n:       1,
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
	packet := gopacket.NewPacket(e.Data, w.Decoder, gopacket.NoCopy)
	formated := pktdump.Format(packet)

	builder := strings.Builder{}

	if w.PrintNumber {
		builder.WriteString(fmt.Sprintf("%5d  ", w.n))
	}

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

	if w.OneLine {
		var newLines []string
		lines := strings.Split(msg, "\n")
		for _, s := range lines {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			newLines = append(newLines, s)
		}
		msg = strings.Join(newLines, ": ") + "\n"
	}

	if _, err := w.w.Write([]byte(msg)); err != nil {
		log.Printf("write packet failed: %+v", err)
	} else {
		w.n++
	}

	return nil
}

func (w *StdoutWriter) Flush() error {
	return nil
}

func (w *StdoutWriter) Close() error {
	return nil
}
