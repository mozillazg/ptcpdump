package cmd

import (
	"github.com/cilium/ebpf/rlimit"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/dev"
)

func attachHooks(opts Options) (map[int]dev.Device, *bpf.BPF, error) {
	devices, err := dev.GetDevices(opts.iface)
	if err != nil {
		return nil, nil, err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return devices, nil, err
	}
	bf, err := bpf.NewBPF()
	if err != nil {
		return devices, nil, err
	}
	if err := bf.Load(bpf.NewOptions(opts.pid, opts.comm, opts.followForks, opts.pcapFilter)); err != nil {
		return devices, nil, err
	}

	if err := bf.AttachKprobes(); err != nil {
		return devices, bf, err
	}
	if err := bf.AttachTracepoints(); err != nil {
		return devices, bf, err
	}
	for _, iface := range devices {
		if err := bf.AttachTcHooks(iface.Ifindex); err != nil {
			return devices, bf, err
		}
	}

	return devices, bf, nil
}
