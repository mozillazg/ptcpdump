package bpf

import (
	"fmt"
	"github.com/cilium/ebpf/link"
)

func (b *BPF) AttachUprobeHook(exec *link.Executable, symbol string, offset uint64, pid int) error {
	lk, err := exec.Uprobe(symbol, b.objs.UprobeGoBuiltinTlsWriteKeyLog,
		&link.UprobeOptions{
			PID:    pid,
			Offset: offset,
		})
	if err != nil {
		return fmt.Errorf("attach uprobe for %s: %w", symbol, err)
	}
	b.links = append(b.links, lk)

	lk, err = exec.Uprobe(symbol, b.objs.UprobeGoBuiltinTlsWriteKeyLogRet,
		// TODO: get offset by parse binary
		&link.UprobeOptions{
			PID:    pid,
			Offset: 508, // if c.KeyLogWriter == nil { return nil }
		})
	if err != nil {
		return fmt.Errorf("attach uprobe for %s: %w", symbol, err)
	}
	b.links = append(b.links, lk)
	return nil
}
