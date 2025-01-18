package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/mozillazg/ptcpdump/internal/types"
	"github.com/mozillazg/ptcpdump/internal/utils"
	"io"
	"os"
	"unsafe"

	"github.com/cilium/ebpf/perf"

	"github.com/mozillazg/ptcpdump/internal/log"
)

type BpfPacketEventWithPayloadT struct {
	BpfPacketEventT
	Payload []byte
}

var ErrIteratorIsNotSupported = errors.New("iterator is not supported")

func (b *BPF) PullPacketEvents(ctx context.Context, chanSize int, maxPacketSize int) (<-chan BpfPacketEventWithPayloadT, error) {
	pageSize := os.Getpagesize()
	log.Infof("pagesize is %d", pageSize)
	perCPUBuffer := pageSize * 64
	eventSize := int(unsafe.Sizeof(BpfPacketEventT{})) + maxPacketSize
	if eventSize >= perCPUBuffer {
		perCPUBuffer = perCPUBuffer * (1 + (eventSize / perCPUBuffer))
	}
	log.Infof("use %d as perCPUBuffer", perCPUBuffer)

	reader, err := perf.NewReader(b.objs.PacketEvents, perCPUBuffer)
	if err != nil {
		return nil, fmt.Errorf(": %w", err)
	}
	ch := make(chan BpfPacketEventWithPayloadT, chanSize)
	go func() {
		defer close(ch)
		defer reader.Close()
		b.handlePacketEvents(ctx, reader, ch)
	}()

	return ch, nil
}

func (b *BPF) handlePacketEvents(ctx context.Context, reader *perf.Reader, ch chan<- BpfPacketEventWithPayloadT) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				log.Infof("got EOF error: %s", err)
				continue
			}
			log.Errorf("read packet event failed: %s", err)
			continue
		}
		event, err := parsePacketEvent(record.RawSample)
		if err != nil {
			log.Errorf("parse packet event failed: %s", err)
		} else {
			ch <- *event
		}
		if record.LostSamples > 0 {
			b.report.Dropped += int(record.LostSamples)
		}
	}
}

func parsePacketEvent(rawSample []byte) (*BpfPacketEventWithPayloadT, error) {
	event := BpfPacketEventWithPayloadT{}
	if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event.Meta); err != nil {
		return nil, fmt.Errorf("parse meta: %w", err)
	}
	event.Payload = make([]byte, int(event.Meta.PacketSize))
	copy(event.Payload[:], rawSample[unsafe.Sizeof(BpfPacketEventT{}):])
	return &event, nil
}

func (b *BPF) PullExecEvents(ctx context.Context, chanSize int) (<-chan BpfExecEventT, error) {
	pageSize := os.Getpagesize()
	log.Infof("pagesize is %d", pageSize)
	perCPUBuffer := pageSize * 64
	eventSize := int(unsafe.Sizeof(BpfExecEventT{}))
	if eventSize >= perCPUBuffer {
		perCPUBuffer = perCPUBuffer * (1 + (eventSize / perCPUBuffer))
	}
	log.Infof("use %d as perCPUBuffer", perCPUBuffer)

	reader, err := perf.NewReader(b.objs.ExecEvents, perCPUBuffer)
	if err != nil {
		return nil, fmt.Errorf(": %w", err)
	}
	ch := make(chan BpfExecEventT, chanSize)
	go func() {
		defer close(ch)
		defer reader.Close()
		b.handleExecEvents(ctx, reader, ch)
	}()

	return ch, nil
}

func (b *BPF) handleExecEvents(ctx context.Context, reader *perf.Reader, ch chan<- BpfExecEventT) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				log.Infof("got EOF error: %s", err)
				continue
			}
			log.Errorf("read exec event failed: %s", err)
			continue
		}
		event, err := parseExecEvent(record.RawSample)
		if err != nil {
			log.Errorf("parse exec event failed: %s", err)
		} else {
			ch <- *event
		}
		if record.LostSamples > 0 {
			// TODO: XXX
		}
	}
}

func (b *BPF) PullGoKeyLogEvents(ctx context.Context, chanSize int) (<-chan BpfGoKeylogEventT, error) {
	pageSize := os.Getpagesize()
	log.Infof("pagesize is %d", pageSize)
	perCPUBuffer := pageSize * 4
	eventSize := int(unsafe.Sizeof(BpfGoKeylogEventT{}))
	if eventSize >= perCPUBuffer {
		perCPUBuffer = perCPUBuffer * (1 + (eventSize / perCPUBuffer))
	}
	log.Infof("use %d as perCPUBuffer", perCPUBuffer)

	reader, err := perf.NewReader(b.objs.GoKeylogEvents, perCPUBuffer)
	if err != nil {
		return nil, fmt.Errorf(": %w", err)
	}
	ch := make(chan BpfGoKeylogEventT, chanSize)
	go func() {
		defer close(ch)
		defer reader.Close()
		b.handleGoKeyLogEvents(ctx, reader, ch)
	}()

	return ch, nil
}

func (b *BPF) handleGoKeyLogEvents(ctx context.Context, reader *perf.Reader, ch chan<- BpfGoKeylogEventT) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				log.Infof("got EOF error: %s", err)
				continue
			}
			log.Errorf("read go tls keylog event failed: %s", err)
			continue
		}
		event, err := parseGoKeyLogEvent(record.RawSample)
		if err != nil {
			log.Errorf("parse go tls keylog event failed: %s", err)
		} else {
			ch <- *event
		}
		if record.LostSamples > 0 {
			// TODO: XXX
		}
	}
}

func (b *BPF) PullNewNetDeviceEvents(ctx context.Context, chanSize int) (<-chan BpfNewNetdeviceEventT, error) {
	pageSize := os.Getpagesize()
	log.Infof("pagesize is %d", pageSize)
	perCPUBuffer := pageSize * 1
	eventSize := int(unsafe.Sizeof(BpfNewNetdeviceEventT{}))
	if eventSize >= perCPUBuffer {
		perCPUBuffer = perCPUBuffer * (1 + (eventSize / perCPUBuffer))
	}
	log.Infof("use %d as perCPUBuffer", perCPUBuffer)

	reader, err := perf.NewReader(b.objs.NewNetdeviceEvents, perCPUBuffer)
	if err != nil {
		return nil, fmt.Errorf(": %w", err)
	}
	ch := make(chan BpfNewNetdeviceEventT, chanSize)
	go func() {
		defer close(ch)
		defer reader.Close()
		b.handleNewNetDeviceEvents(ctx, reader, ch)
	}()

	return ch, nil
}

func (b *BPF) handleNewNetDeviceEvents(ctx context.Context, reader *perf.Reader, ch chan<- BpfNewNetdeviceEventT) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				log.Infof("got EOF error: %s", err)
				continue
			}
			log.Errorf("read new net device event failed: %s", err)
			continue
		}
		event, err := parseNewNetDeviceEvent(record.RawSample)
		if err != nil {
			log.Errorf("parse new net device event failed: %s", err)
		} else {
			ch <- *event
			dev := event.Dev
			log.Infof("new BpfNewNetdeviceEventT: name %s, ifindex %d, netns, %d",
				utils.GoString(dev.Name[:]), dev.Ifindex, dev.NetnsId)
		}
		if record.LostSamples > 0 {
			// TODO: XXX
		}
	}
}

func parseNewNetDeviceEvent(rawSample []byte) (*BpfNewNetdeviceEventT, error) {
	event := BpfNewNetdeviceEventT{}
	if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("parse event: %w", err)
	}
	return &event, nil
}

func (b *BPF) PullNetDeviceChangeEvents(ctx context.Context, chanSize int) (<-chan BpfNetdeviceChangeEventT, error) {
	pageSize := os.Getpagesize()
	log.Infof("pagesize is %d", pageSize)
	perCPUBuffer := pageSize * 1
	eventSize := int(unsafe.Sizeof(BpfNetdeviceChangeEventT{}))
	if eventSize >= perCPUBuffer {
		perCPUBuffer = perCPUBuffer * (1 + (eventSize / perCPUBuffer))
	}
	log.Infof("use %d as perCPUBuffer", perCPUBuffer)

	reader, err := perf.NewReader(b.objs.NetdeviceChangeEvents, perCPUBuffer)
	if err != nil {
		return nil, fmt.Errorf(": %w", err)
	}
	ch := make(chan BpfNetdeviceChangeEventT, chanSize)
	go func() {
		defer close(ch)
		defer reader.Close()
		b.handleNetDeviceChangeEvents(ctx, reader, ch)
	}()

	return ch, nil
}

func (b *BPF) handleNetDeviceChangeEvents(ctx context.Context, reader *perf.Reader, ch chan<- BpfNetdeviceChangeEventT) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				log.Infof("got EOF error: %s", err)
				continue
			}
			log.Errorf("read net device change event failed: %s", err)
			continue
		}
		event, err := parseNetDeviceChangeEvent(record.RawSample)
		if err != nil {
			log.Errorf("parse net device change event failed: %s", err)
		} else {
			ch <- *event
			oldDev := event.OldDevice
			newDev := event.NewDevice
			log.Infof("new BpfNetdeviceChangeEventT: (name %s, ifindex %d, netns, %d) -> (name %s, ifindex %d, netns, %d)",
				utils.GoString(oldDev.Name[:]), oldDev.Ifindex, oldDev.NetnsId,
				utils.GoString(newDev.Name[:]), newDev.Ifindex, newDev.NetnsId)
		}
		if record.LostSamples > 0 {
			// TODO: XXX
		}
	}
}

func parseNetDeviceChangeEvent(rawSample []byte) (*BpfNetdeviceChangeEventT, error) {
	event := BpfNetdeviceChangeEventT{}
	if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("parse event: %w", err)
	}
	return &event, nil
}

func (b *BPF) PullMountEventEvents(ctx context.Context, chanSize int) (<-chan BpfMountEventT, error) {
	pageSize := os.Getpagesize()
	log.Infof("pagesize is %d", pageSize)
	perCPUBuffer := pageSize * 1
	eventSize := int(unsafe.Sizeof(BpfMountEventT{}))
	if eventSize >= perCPUBuffer {
		perCPUBuffer = perCPUBuffer * (1 + (eventSize / perCPUBuffer))
	}
	log.Infof("use %d as perCPUBuffer", perCPUBuffer)

	reader, err := perf.NewReader(b.objs.MountEvents, perCPUBuffer)
	if err != nil {
		return nil, fmt.Errorf(": %w", err)
	}
	ch := make(chan BpfMountEventT, chanSize)
	go func() {
		defer close(ch)
		defer reader.Close()
		b.handleMountEvents(ctx, reader, ch)
	}()

	return ch, nil
}

func (b *BPF) handleMountEvents(ctx context.Context, reader *perf.Reader, ch chan<- BpfMountEventT) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				log.Infof("got EOF error: %s", err)
				continue
			}
			log.Errorf("read mount event failed: %s", err)
			continue
		}
		event, err := parseMountEvent(record.RawSample)
		if err != nil {
			log.Errorf("parse mount event failed: %s", err)
		} else {
			ch <- *event
			log.Infof("new BpfMountEventT: (source %s, dest %s, fstype, %s)",
				utils.GoString(event.Src[:]), utils.GoString(event.Dest[:]), utils.GoString(event.Fs[:]))
		}
		if record.LostSamples > 0 {
			// TODO: XXX
		}
	}
}

func parseMountEvent(rawSample []byte) (*BpfMountEventT, error) {
	event := BpfMountEventT{}
	if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("parse event: %w", err)
	}
	return &event, nil
}

func parseGoKeyLogEvent(rawSample []byte) (*BpfGoKeylogEventT, error) {
	event := BpfGoKeylogEventT{}
	if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("parse event: %w", err)
	}
	return &event, nil
}

func parseExecEvent(rawSample []byte) (*BpfExecEventT, error) {
	event := BpfExecEventT{}
	if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("parse event: %w", err)
	}
	return &event, nil
}

func (b *BPF) PullExitEvents(ctx context.Context, chanSize int) (<-chan BpfExitEventT, error) {
	pageSize := os.Getpagesize()
	log.Infof("pagesize is %d", pageSize)
	perCPUBuffer := pageSize * 4
	eventSize := int(unsafe.Sizeof(BpfExitEventT{}))
	if eventSize >= perCPUBuffer {
		perCPUBuffer = perCPUBuffer * (1 + (eventSize / perCPUBuffer))
	}
	log.Infof("use %d as perCPUBuffer", perCPUBuffer)

	reader, err := perf.NewReader(b.objs.ExitEvents, perCPUBuffer)
	if err != nil {
		return nil, fmt.Errorf(": %w", err)
	}
	ch := make(chan BpfExitEventT, chanSize)
	go func() {
		defer close(ch)
		defer reader.Close()
		b.handleExitEvents(ctx, reader, ch)
	}()

	return ch, nil
}

func (b *BPF) handleExitEvents(ctx context.Context, reader *perf.Reader, ch chan<- BpfExitEventT) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				log.Infof("got EOF error: %s", err)
				continue
			}
			log.Errorf("read exit event failed: %s", err)
			continue
		}
		event, err := parseExitEvent(record.RawSample)
		if err != nil {
			log.Errorf("parse exit event failed: %s", err)
		} else {
			ch <- *event
		}
		if record.LostSamples > 0 {
			// TODO: XXX
		}
	}
}

func (b *BPF) IterConnections(ctx context.Context) error {
	log.Info("start to iter task files")
	if b.objs.IterTaskFile == nil {
		return ErrIteratorIsNotSupported
	}

	var closers []types.Closer
	iter, err := link.AttachIter(link.IterOptions{
		Program: b.objs.IterTaskFile,
	})
	if err != nil {
		log.Errorf("attach iter task files failed: %s", err)
		return fmt.Errorf(": %w", err)
	}
	defer iter.Close()

	reader, err := iter.Open()
	if err != nil {
		utils.CloseAll(closers)
		log.Errorf("open iter task files failed: %s", err)
		return fmt.Errorf(": %w", err)
	}
	defer reader.Close()

	if _, err := io.ReadAll(reader); err != nil {
		if !errors.Is(err, io.EOF) {
			return fmt.Errorf("read iter task files: %w", err)
		}
	}

	log.Info("iter task files done")
	return nil
}

func parseExitEvent(rawSample []byte) (*BpfExitEventT, error) {
	event := BpfExitEventT{}
	if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("parse event: %w", err)
	}
	return &event, nil
}
