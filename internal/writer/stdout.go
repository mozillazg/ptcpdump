package writer

import (
	"fmt"
	"github.com/gopacket/gopacket/layers"
	"github.com/mozillazg/ptcpdump/internal/types"
	"io"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/mozillazg/ptcpdump/internal/event"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/x-way/pktdump"
)

type StdoutWriter struct {
	pcache        *metadata.ProcessCache
	w             io.Writer
	Decoder       gopacket.Decoder
	OneLine       bool
	PrintNumber   bool
	NoTimestamp   bool
	TimestampNano bool
	DoNothing     bool
	Quiet         bool
	FormatStyle   pktdump.FormatStyle
	DataStyle     pktdump.ContentStyle

	enhancedContext types.EnhancedContext
	n               int64
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

func (w *StdoutWriter) WithEnhancedContext(c types.EnhancedContext) *StdoutWriter {
	w.enhancedContext = c
	return w
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
	p.Tid = e.Tid
	p.TName = e.TName

	processInfo := ""
	threadInfo := ""
	parentProcInfo := ""
	containerInfo := ""
	PodInfo := ""

	switch {
	case w.FormatStyle >= pktdump.FormatStyleVerbose:
		if w.enhancedContext.ProcessContext() && e.Pid > 0 {
			processInfo = fmt.Sprintf("Process (pid %d, cmd %s, args %s)",
				e.Pid, p.Cmd, p.FormatArgs())
		}
		if w.enhancedContext.ProcessContext() && p.Tid > 0 {
			threadInfo = fmt.Sprintf("Thread (tid %d, name %s)", p.Tid, p.TName)
		}
		if w.enhancedContext.ParentProcContext() && p.Parent.Pid > 0 {
			parentProcInfo = fmt.Sprintf("ParentProc (pid %d, cmd %s, args %s)",
				p.Parent.Pid, p.Parent.Cmd, p.Parent.FormatArgs())
		}
		if w.enhancedContext.ContainerContext() && p.Container.Id != "" {
			containerInfo = fmt.Sprintf("Container (name %s, id %s, image %s, labels %s)",
				p.Container.TidyName(), p.Container.Id, p.Container.Image, p.Container.FormatLabels())
		}
		if w.enhancedContext.PodContext() && p.Pod.Name != "" {
			PodInfo = fmt.Sprintf("Pod (name %s, namespace %s, UID %s, labels %s, annotations %s)",
				p.Pod.Name, p.Pod.Namespace, p.Pod.Uid, p.Pod.FormatLabels(), p.Pod.FormatAnnotations())
		}
		break
	default:
		if w.enhancedContext.ProcessContext() && e.Pid > 0 {
			processInfo = fmt.Sprintf("%s.%d", p.Comm(), e.Pid)
		}
		if w.enhancedContext.ThreadContext() && p.Tid > 0 {
			threadInfo = fmt.Sprintf("Thread [%s.%d]", p.TName, p.Tid)
		}
		if w.enhancedContext.ParentProcContext() && p.Parent.Pid > 0 {
			parentProcInfo = fmt.Sprintf("ParentProc [%s.%d]", p.Parent.Comm(), p.Parent.Pid)
		}
		if w.enhancedContext.ContainerContext() && p.Container.Id != "" {
			containerInfo = fmt.Sprintf("Container [%s]", p.Container.TidyName())
		}
		if w.enhancedContext.PodContext() && p.Pod.Name != "" {
			PodInfo = fmt.Sprintf("Pod [%s.%s]", p.Pod.Name, p.Pod.Namespace)
		}
	}

	// Decode a packet
	packet := gopacket.NewPacket(e.Data, w.Decoder, gopacket.NoCopy)
	formatOpts := &pktdump.Options{
		HeaderStyle:   w.FormatStyle,
		ContentStyle:  w.DataStyle,
		ContentIndent: "        ",
		Quiet:         w.Quiet,
	}
	formatedHeader := (&pktdump.Formatter{}).FormatWithOptions(packet, formatOpts)
	formatedData := formatOpts.FormatedContent

	builder := strings.Builder{}

	if w.PrintNumber {
		builder.WriteString(fmt.Sprintf("%5d  ", w.n))
	}

	if !w.NoTimestamp {
		layout := "15:04:05.000000"
		if w.TimestampNano {
			layout = "15:04:05.000000000"
		}
		builder.WriteString(fmt.Sprintf("%s ", e.Time.Local().Format(layout)))
	}

	if ifName != "" {
		builder.WriteString(fmt.Sprintf("%s ", ifName))
	}
	if processInfo != "" && w.FormatStyle <= pktdump.FormatStyleNormal {
		builder.WriteString(fmt.Sprintf("%s ", processInfo))
	}
	if packetType != "" {
		builder.WriteString(fmt.Sprintf("%s ", packetType))
	}

	switch {
	case w.FormatStyle >= pktdump.FormatStyleVerbose:
		builder.WriteString(fmt.Sprintf("%s\n", formatedHeader))
		if processInfo != "" {
			builder.WriteString(fmt.Sprintf("    %s\n", processInfo))
			if threadInfo != "" {
				builder.WriteString(fmt.Sprintf("    %s\n", threadInfo))
			}
			if parentProcInfo != "" {
				builder.WriteString(fmt.Sprintf("    %s\n", parentProcInfo))
			}
		}
		if containerInfo != "" {
			builder.WriteString(fmt.Sprintf("    %s\n", containerInfo))
		}
		if PodInfo != "" {
			builder.WriteString(fmt.Sprintf("    %s\n", PodInfo))
		}
		break
	default:
		builder.WriteString(formatedHeader)
		if threadInfo != "" {
			builder.WriteString(fmt.Sprintf(", %s", threadInfo))
		}
		if parentProcInfo != "" {
			builder.WriteString(fmt.Sprintf(", %s", parentProcInfo))
		}
		if containerInfo != "" {
			builder.WriteString(fmt.Sprintf(", %s", containerInfo))
		}
		if PodInfo != "" {
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
	if len(formatedData) > 0 {
		msg = strings.TrimSuffix(msg, "\n")
		msg += string(formatedData) + "\n"
	}

	if _, err := w.w.Write([]byte(msg)); err != nil {
		log.Errorf("write packet failed: %+v", err)
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
