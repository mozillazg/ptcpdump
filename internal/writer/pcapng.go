package writer

import (
	"bytes"
	"fmt"
	"github.com/mozillazg/ptcpdump/internal/types"
	"io"
	"strings"
	"sync"
	"unsafe"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/mozillazg/ptcpdump/internal/event"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/metadata"
)

type PcapNGWriter struct {
	rr            Rotator
	pw            *pcapgo.NgWriter
	pcache        *metadata.ProcessCache
	interfaceIds  map[string]int
	newInterfaces []pcapgo.NgInterface
	pcapFilter    string

	noBuffer bool
	lock     sync.RWMutex
	keylogs  bytes.Buffer

	enhancedContext types.EnhancedContext
	newWriter       func(io.Writer) (*pcapgo.NgWriter, error)
}

func NewPcapNGWriter(rr Rotator, newWriter func(io.Writer) (*pcapgo.NgWriter, error),
	pcache *metadata.ProcessCache, interfaceIds map[string]int) (*PcapNGWriter, error) {
	pw, err := newWriter(rr)
	if err != nil {
		return nil, err
	}

	return &PcapNGWriter{
		rr:            rr,
		newWriter:     newWriter,
		pw:            pw,
		pcache:        pcache,
		interfaceIds:  interfaceIds,
		newInterfaces: []pcapgo.NgInterface{},
		lock:          sync.RWMutex{},
	}, nil
}

func (w *PcapNGWriter) WithEnhancedContext(c types.EnhancedContext) *PcapNGWriter {
	w.enhancedContext = c
	return w
}

func (w *PcapNGWriter) Write(e *event.Packet) error {
	payloadLen := len(e.Data)
	info := gopacket.CaptureInfo{
		Timestamp:      e.Time.Local(),
		CaptureLength:  payloadLen,
		Length:         e.Len,
		InterfaceIndex: w.getInterfaceIndex(e.Device),
	}
	p := w.pcache.Get(e.Pid, e.MntNs, e.NetNs, e.CgroupName)
	p.Tid = e.Tid
	p.TName = e.TName
	if p.UserId == 0 && e.Uid != 0 {
		p.UserId = e.Uid
	}

	opts := pcapgo.NgPacketOptions{}
	if w.enhancedContext.ProcessContext() && p.Pid > 0 {
		log.Debugf("found pid from cache: %d", e.Pid)
		opts.Comments = append(opts.Comments,
			fmt.Sprintf("PID: %d\nCmd: %s\nArgs: %s",
				e.Pid, p.Cmd, p.FormatArgs()),
		)
		if w.enhancedContext.ThreadContext() && p.Tid > 0 {
			opts.Comments = append(opts.Comments,
				fmt.Sprintf("ThreadId: %d\nThreadName: %s",
					p.Tid, p.TName),
			)
		}
		if w.enhancedContext.UserContext() && p.UserId >= 0 {
			opts.Comments = append(opts.Comments,
				fmt.Sprintf("UserId: %d", p.UserId),
			)
		}
		if w.enhancedContext.ParentProcContext() && p.Parent.Pid > 0 {
			opts.Comments = append(opts.Comments,
				fmt.Sprintf("ParentPID: %d\nParentCmd: %s\nParentArgs: %s",
					p.Parent.Pid, p.Parent.Cmd, p.Parent.FormatArgs()),
			)
		}
	}
	if w.enhancedContext.ContainerContext() && p.Container.Id != "" {
		opts.Comments = append(opts.Comments,
			fmt.Sprintf("ContainerName: %s\nContainerId: %s\nContainerImage: %s\nContainerLabels: %s",
				p.Container.TidyName(), p.Container.Id, p.Container.Image, p.Container.FormatLabels()),
		)
	}
	if w.enhancedContext.PodContext() && p.Pod.Name != "" {
		opts.Comments = append(opts.Comments,
			fmt.Sprintf("PodName: %s\nPodNamespace: %s\nPodUID: %s\nPodLabels: %s\nPodAnnotations: %s",
				p.Pod.Name, p.Pod.Namespace, p.Pod.Uid, p.Pod.FormatLabels(), p.Pod.FormatAnnotations()),
		)
	}
	opts.Flags = &pcapgo.NgEpbFlags{}
	switch {
	case e.Ingress():
		opts.Flags.Direction = pcapgo.NgEpbFlagDirectionInbound
	case e.Egress():
		opts.Flags.Direction = pcapgo.NgEpbFlagDirectionOutbound
	}

	if err := w.writeTLSKeyLogs(); err != nil {
		return err
	}

	if err := w.writePacket(info, e.Data, opts); err != nil {
		return err
	}
	if w.noBuffer {
		w.pw.Flush()
	}

	return nil
}

func (w *PcapNGWriter) writePacket(ci gopacket.CaptureInfo, data []byte, opts pcapgo.NgPacketOptions) error {
	w.lock.Lock()
	defer w.lock.Unlock()

	if w.rr.ShouldRotate(int(unsafe.Sizeof(ci)) + len(data) + int(unsafe.Sizeof(opts))) {
		if err := w.rr.Rotate(); err != nil {
			return fmt.Errorf("rotating file: %w", err)
		}
		pw, err := w.newWriter(w.rr)
		if err != nil {
			return fmt.Errorf("creating new pcapng writer: %w", err)
		}
		for _, intf := range w.newInterfaces {
			if _, err := pw.AddInterface(intf); err != nil {
				log.Errorf("error adding interface %s: %+v", intf.Name, err)
			}
		}
		w.pw = pw
	}

	if err := w.pw.WritePacketWithOptions(ci, data, opts); err != nil {
		return fmt.Errorf("writing packet: %w", err)
	}

	return nil
}

func (w *PcapNGWriter) WriteTLSKeyLog(line string) error {
	w.lock.Lock()
	defer w.lock.Unlock()

	w.keylogs.WriteString(line)

	return nil
}

func (w *PcapNGWriter) writeTLSKeyLogs() error {
	w.lock.Lock()
	defer w.lock.Unlock()

	lines := w.keylogs.Bytes()
	if len(lines) == 0 {
		return nil
	}

	if err := w.pw.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, lines); err != nil {
		return fmt.Errorf("writing tls key log: %w", err)
	}

	w.keylogs.Reset()

	return nil
}

func (w *PcapNGWriter) AddDev(dev types.Device) {
	w.lock.Lock()
	defer w.lock.Unlock()

	log.Infof("new dev: %+v, currLen: %d", dev, len(w.interfaceIds))
	key := dev.Key()
	if w.interfaceIds[key] > 0 {
		return
	}

	index := len(w.interfaceIds) + 1
	intf := metadata.NewNgInterface(dev, w.pcapFilter, index)
	log.Infof("add interface: %+v", intf)

	if _, err := w.pw.AddInterface(intf); err != nil {
		log.Errorf("error adding interface %s: %+v", intf.Name, err)
	}

	w.newInterfaces = append(w.newInterfaces, intf)
	w.interfaceIds[key] = index
}

func (w *PcapNGWriter) getInterfaceIndex(dev types.Device) int {
	w.lock.RLock()
	defer w.lock.RUnlock()

	log.Infof("interfaceIds: %+v, dev: %+v", w.interfaceIds, dev)

	index := w.interfaceIds[dev.Key()]
	if index > 0 {
		return index
	}
	suffix := fmt.Sprintf(".%d", dev.Ifindex)
	for k, index := range w.interfaceIds {
		if strings.HasSuffix(k, suffix) {
			return index
		}
	}
	return 0
}

func (w *PcapNGWriter) WithPcapFilter(filter string) *PcapNGWriter {
	w.pcapFilter = filter
	return w
}

func (w *PcapNGWriter) Flush() error {
	w.lock.Lock()
	defer w.lock.Unlock()

	return w.pw.Flush()
}

func (w *PcapNGWriter) Close() error {
	return nil
}

func (w *PcapNGWriter) WithNoBuffer() *PcapNGWriter {
	w.noBuffer = true
	return w
}
