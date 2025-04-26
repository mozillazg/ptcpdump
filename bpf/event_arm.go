//go:build arm

package bpf

import "context"

func (b *BPF) PullNewNetDeviceEvents(ctx context.Context, chanSize int) (<-chan BpfNewNetdeviceEventT, error) {
	ch := make(chan BpfNewNetdeviceEventT, 1)
	return ch, nil
}

func (b *BPF) PullNetDeviceChangeEvents(ctx context.Context, chanSize int) (<-chan BpfNetdeviceChangeEventT, error) {
	ch := make(chan BpfNetdeviceChangeEventT, 1)
	return ch, nil
}

func (b *BPF) PullMountEventEvents(ctx context.Context, chanSize int) (<-chan BpfMountEventT, error) {
	ch := make(chan BpfMountEventT, 1)
	return ch, nil
}
