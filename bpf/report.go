package bpf

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/types"
)

func (b *BPF) CountReport() types.CountReport {
	zero := uint32(0)
	var value uint32
	if err := b.objs.PtcpdumpFilterByKernelCount.Lookup(&zero, &value); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			log.Errorf("get value of filter_by_kernel_count failed: %s", err)
		}
	}
	b.report.Received = int(value)
	return *b.report
}
