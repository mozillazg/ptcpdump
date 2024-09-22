package bpf

import (
	"fmt"
	"github.com/cilium/ebpf/link"
)

func (b *BPF) AttachGoTLSUprobeHooks(exec *link.Executable, symbol string,
	funcAddr uint64, retOffset uint64, pid int) error {
	lk, err := exec.Uprobe(symbol, b.objs.UprobeGoBuiltinTlsWriteKeyLog,
		&link.UprobeOptions{
			PID:     pid,
			Address: funcAddr,
		})
	if err != nil {
		return fmt.Errorf("attach uprobe for %s: %w", symbol, err)
	}
	b.links = append(b.links, lk)

	lk, err = exec.Uprobe(symbol, b.objs.UprobeGoBuiltinTlsWriteKeyLogRet,
		&link.UprobeOptions{
			PID:    pid,
			Offset: retOffset, // if c.KeyLogWriter == nil { return nil }
		})
	if err != nil {
		return fmt.Errorf("attach uprobe for %s: %w", symbol, err)
	}
	b.links = append(b.links, lk)
	return nil
}
