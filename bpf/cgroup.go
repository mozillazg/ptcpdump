package bpf

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func (b *BPF) AttachCgroups(cgroupPath string) error {
	if cgroupPath == "" {
		b.skipAttachCgroup = true
	}
	if b.skipAttachCgroup {
		return nil
	}

	lk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetSockCreate,
		Program: b.objs.CgroupSockCreate,
	})
	if err != nil {
		return fmt.Errorf("attach cgroup/sock_create: %w", err)
	}
	b.links = append(b.links, lk)

	lk, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCgroupInetSockRelease,
		Program: b.objs.CgroupSockRelease,
	})
	if err != nil {
		return fmt.Errorf("attach cgroup/sock_release: %w", err)
	}
	b.links = append(b.links, lk)

	return nil
}
