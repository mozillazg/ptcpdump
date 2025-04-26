//go:build !arm

package bpf

import (
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/mozillazg/ptcpdump/internal/log"
)

func (b *BPF) attachNetNsHooks() error {
	if !b.opts.hookMount {
		return nil
	}

	log.Info("attaching tracepoint/syscalls/sys_enter_mount")
	lk, err := link.Tracepoint("syscalls", "sys_enter_mount", b.objs.PtcpdumpTracepointSyscallsSysEnterMount, &link.TracepointOptions{})
	if err != nil {
		return fmt.Errorf("attach tracepoint/syscalls/sys_enter_mount: %w", err)
	}
	b.links = append(b.links, lk)
	log.Info("attaching tracepoint/syscalls/sys_exit_mount")
	lk, err = link.Tracepoint("syscalls", "sys_exit_mount", b.objs.PtcpdumpTracepointSyscallsSysExitMount, &link.TracepointOptions{})
	if err != nil {
		return fmt.Errorf("attach tracepoint/syscalls/sys_exit_mount: %w", err)
	}
	b.links = append(b.links, lk)

	return nil
}
