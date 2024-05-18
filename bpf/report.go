package bpf

import (
	"errors"
	"log"

	"github.com/cilium/ebpf"
	"github.com/mozillazg/ptcpdump/internal/types"
)

func (b *BPF) CountReport() types.CountReport {
	zero := uint32(0)
	var value uint32
	if err := b.objs.FilterByKernelCount.Lookup(&zero, &value); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			log.Printf("get value of filter_by_kernel_count failed: %s", err)
		}
	}
	b.report.Received = int(value)
	return *b.report
}
