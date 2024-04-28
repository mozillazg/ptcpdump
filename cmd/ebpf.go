package cmd

import (
	"github.com/cilium/ebpf/rlimit"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/dev"
)

func attachHooks(opts Options) (*bpf.BPF, error) {
	devices, err := dev.GetDevices(opts.ifaces)
	if err != nil {
		return nil, err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}
	bf, err := bpf.NewBPF()
	if err != nil {
		return nil, err
	}
	if err := bf.Load(bpf.NewOptions(opts.pid, opts.comm, opts.followForks, opts.pcapFilter)); err != nil {
		return nil, err
	}

	if err := bf.AttachKprobes(); err != nil {
		return bf, err
	}
	if err := bf.AttachTracepoints(); err != nil {
		return bf, err
	}
	for _, iface := range devices {
		if err := bf.AttachTcHooks(iface.Ifindex, opts.DirectionOut(), opts.DirectionIn()); err != nil {
			return bf, err
		}
	}

	return bf, nil
}
