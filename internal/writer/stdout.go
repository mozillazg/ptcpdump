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
	NoTimestamp bool
	DoNothing   bool
	FormatStyle pktdump.FormatStyle

	n int64
}

func NewStdoutWriter(writer io.Writer, pcache *metadata.ProcessCache) *StdoutWriter {
	return &StdoutWriter{
		w:           writer,
		pcache:      pcache,
		Decoder:     layers.LayerTypeEthernet,
		n:           1,
		FormatStyle: pktdump.FormatStyleNormal,
	}
}

func (w *StdoutWriter) Write(e *event.Packet) error {
	if w.DoNothing {
		return nil
	}

	ifName := e.Device.Name
	packetType := ""
	if e.Egress() {
		packetType = "Out"
	} else if e.Ingress() {
		packetType = "In"
	}
	p := w.pcache.Get(e.Pid, e.MntNs, e.NetNs, e.CgroupName)

	pidInfo := ""
	containerInfo := ""
	PodInfo := ""

	switch {
	case w.FormatStyle >= pktdump.FormatStyleVerbose:
		pidInfo = fmt.Sprintf("Process (pid %d, cmd %s, args %s)",
			e.Pid, p.Cmd, p.FormatArgs())
		containerInfo = fmt.Sprintf("Container (name %s, id %s, image %s, labels %s)",
			p.Container.TidyName(), p.Container.Id, p.Container.Image, p.Container.FormatLabels())
		PodInfo = fmt.Sprintf("Pod (name %s, namespace %s, UID %s, labels %s, annotations %s)",
			p.Pod.Name, p.Pod.Namespace, p.Pod.Uid, p.Pod.FormatLabels(), p.Pod.FormatAnnotations())
		break
	default:
		pidInfo = fmt.Sprintf("Process [%s.%d]", p.Cmd, e.Pid)
		containerInfo = fmt.Sprintf("Container [%s]", p.Container.TidyName())
		PodInfo = fmt.Sprintf("Pod [%s.%s]", p.Pod.Name, p.Pod.Namespace)
	}

	// Decode a packet
	packet := gopacket.NewPacket(e.Data, w.Decoder, gopacket.NoCopy)
	formated := pktdump.FormatWithStyle(packet, w.FormatStyle)

	builder := strings.Builder{}

	if w.PrintNumber {
		builder.WriteString(fmt.Sprintf("%5d  ", w.n))
	}

	if !w.NoTimestamp {
		builder.WriteString(fmt.Sprintf("%s ", e.Time.Local().Format("15:04:05.000000")))
	}

	if ifName != "" {
		builder.WriteString(fmt.Sprintf("%s ", ifName))
	}
	if packetType != "" {
		builder.WriteString(fmt.Sprintf("%s ", packetType))
	}

	switch {
	case w.FormatStyle >= pktdump.FormatStyleVerbose:
		builder.WriteString(fmt.Sprintf("%s\n", formated))
		if p.Pid > 0 {
			builder.WriteString(fmt.Sprintf("    %s\n", pidInfo))
		}
		if p.Container.Id != "" {
			builder.WriteString(fmt.Sprintf("    %s\n", containerInfo))
		}
		if p.Pod.Name != "" {
			builder.WriteString(fmt.Sprintf("    %s\n", PodInfo))
		}
		break
	default:
		builder.WriteString(formated)
		if p.Pid > 0 {
			builder.WriteString(fmt.Sprintf(", %s", pidInfo))
		}
		if p.Container.Id != "" {
			builder.WriteString(fmt.Sprintf(", %s", containerInfo))
		}
		if p.Pod.Name != "" {
			builder.WriteString(fmt.Sprintf(", %s", PodInfo))
		}
		builder.WriteString("\n")
	}
	msg := builder.String()

	if w.OneLine || w.FormatStyle < pktdump.FormatStyleVerbose {
		var newLines []string
		lines := strings.Split(msg, "\n")
		for _, s := range lines {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			newLines = append(newLines, s)
		}
		msg = strings.Join(newLines, ", ") + "\n"
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
