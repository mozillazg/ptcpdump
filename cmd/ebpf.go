package cmd

import (
	"encoding/binary"
	"github.com/mozillazg/ptcpdump/internal/utils"
	"log"
	"net/netip"

	"github.com/cilium/ebpf/rlimit"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/dev"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"golang.org/x/xerrors"
)

func attachHooks(currentConns []metadata.Connection, opts Options) (*bpf.BPF, error) {
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

	if len(currentConns) > 0 {
		if err := updateFlowPidMapValues(bf, currentConns); err != nil {
			return nil, err
		}
	}

	cgroupPath, err := utils.GetCgroupV2RootDir()
	if err != nil {
		log.Print(err)
	}
	if cgroupPath != "" {
		if err := bf.AttachCgroups(cgroupPath); err != nil {
			return bf, err
		}
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

func updateFlowPidMapValues(bf *bpf.BPF, conns []metadata.Connection) error {
	data := map[*bpf.BpfFlowPidKeyT]bpf.BpfFlowPidValueT{}
	for _, conn := range conns {
		k := bpf.BpfFlowPidKeyT{
			Saddr: addrTo128(conn.LocalIP),
			Sport: uint16(conn.LocalPort),
		}
		v := bpf.BpfFlowPidValueT{
			Pid: uint32(conn.Pid),
		}
		data[&k] = v
	}
	if err := bf.UpdateFlowPidMapValues(data); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	return nil
}

func addrTo128(addr netip.Addr) [4]uint32 {
	ret := [4]uint32{}
	addr = addr.Unmap()
	switch {
	case addr.Is4():
		ip := addr.As4()
		ret[0] = binary.LittleEndian.Uint32(ip[:])
		break
	default:
		ip := addr.As16()
		ret[0] = binary.LittleEndian.Uint32(ip[:4])
		ret[1] = binary.LittleEndian.Uint32(ip[4:8])
		ret[2] = binary.LittleEndian.Uint32(ip[8:12])
		ret[3] = binary.LittleEndian.Uint32(ip[12:16])
	}
	return ret
}
