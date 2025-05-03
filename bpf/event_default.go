//go:build !arm

package bpf

import (
	"context"
	"fmt"
	"github.com/cilium/ebpf/perf"
	"github.com/mozillazg/ptcpdump/internal/log"
	"os"
	"unsafe"
)

func (b *BPF) PullNewNetDeviceEvents(ctx context.Context, chanSize int) (<-chan BpfNewNetdeviceEventT, error) {
	pageSize := os.Getpagesize()
	log.Infof("pagesize is %d", pageSize)
	perCPUBuffer := pageSize * 1
	eventSize := int(unsafe.Sizeof(BpfNewNetdeviceEventT{}))
	if eventSize >= perCPUBuffer {
		perCPUBuffer = perCPUBuffer * (1 + (eventSize / perCPUBuffer))
	}
	log.Infof("use %d as perCPUBuffer", perCPUBuffer)

	reader, err := perf.NewReader(b.objs.PtcpdumpNewNetdeviceEvents, perCPUBuffer)
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

func (b *BPF) PullNetDeviceChangeEvents(ctx context.Context, chanSize int) (<-chan BpfNetdeviceChangeEventT, error) {
	pageSize := os.Getpagesize()
	log.Infof("pagesize is %d", pageSize)
	perCPUBuffer := pageSize * 1
	eventSize := int(unsafe.Sizeof(BpfNetdeviceChangeEventT{}))
	if eventSize >= perCPUBuffer {
		perCPUBuffer = perCPUBuffer * (1 + (eventSize / perCPUBuffer))
	}
	log.Infof("use %d as perCPUBuffer", perCPUBuffer)

	reader, err := perf.NewReader(b.objs.PtcpdumpNetdeviceChangeEvents, perCPUBuffer)
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

func (b *BPF) PullMountEventEvents(ctx context.Context, chanSize int) (<-chan BpfMountEventT, error) {
	pageSize := os.Getpagesize()
	log.Infof("pagesize is %d", pageSize)
	perCPUBuffer := pageSize * 1
	eventSize := int(unsafe.Sizeof(BpfMountEventT{}))
	if eventSize >= perCPUBuffer {
		perCPUBuffer = perCPUBuffer * (1 + (eventSize / perCPUBuffer))
	}
	log.Infof("use %d as perCPUBuffer", perCPUBuffer)

	reader, err := perf.NewReader(b.objs.PtcpdumpMountEvents, perCPUBuffer)
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
