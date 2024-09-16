package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
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
	eventSize := int(unsafe.Sizeof(BpfExecEventT{}))
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

func parseExitEvent(rawSample []byte) (*BpfExitEventT, error) {
	event := BpfExitEventT{}
	if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("parse event: %w", err)
	}
	return &event, nil
}
