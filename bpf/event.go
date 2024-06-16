package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"unsafe"

	"github.com/cilium/ebpf/perf"
	"golang.org/x/xerrors"

	"github.com/mozillazg/ptcpdump/internal/log"
)

func (b *BPF) PullPacketEvents(ctx context.Context, chanSize int) (<-chan BpfPacketEventT, error) {
	reader, err := perf.NewReader(b.objs.PacketEvents, 1500*1000)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	ch := make(chan BpfPacketEventT, chanSize)
	go func() {
		defer close(ch)
		defer reader.Close()
		b.handlePacketEvents(ctx, reader, ch)
	}()

	return ch, nil
}

func (b *BPF) handlePacketEvents(ctx context.Context, reader *perf.Reader, ch chan<- BpfPacketEventT) {
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

func parsePacketEvent(rawSample []byte) (*BpfPacketEventT, error) {
	event := BpfPacketEventT{}
	if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event.Meta); err != nil {
		return nil, xerrors.Errorf("parse meta: %w", err)
	}
	copy(event.Payload[:], rawSample[unsafe.Offsetof(event.Payload):])
	return &event, nil
}

func (b *BPF) PullExecEvents(ctx context.Context, chanSize int) (<-chan BpfExecEventT, error) {
	reader, err := perf.NewReader(b.objs.ExecEvents, 1024*256)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
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

func parseExecEvent(rawSample []byte) (*BpfExecEventT, error) {
	event := BpfExecEventT{}
	if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event); err != nil {
		return nil, xerrors.Errorf("parse event: %w", err)
	}
	return &event, nil
}
