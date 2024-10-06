package cmd

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"

	btftype "github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/mozillazg/ptcpdump/internal/utils"
)

func attachHooks(btfSpec *btftype.Spec, currentConns []metadata.Connection, opts *Options) (*bpf.BPF, []func(), error) {
	devices, err := opts.GetDevices()
	if err != nil {
		return nil, nil, err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, err
	}
	bf, err := bpf.NewBPF()
	if err != nil {
		return nil, nil, err
	}
	bpfopts := &bpf.Options{}
	bpfopts = bpfopts.WithPids(opts.pids).
		WithComm(opts.comm).
		WithFollowFork(opts.followForks).
		WithPidNsIds(opts.pidnsIds).
		WithMntNsIds(opts.mntnsIds).
		WithNetNsIds(opts.netnsIds).
		WithMaxPayloadSize(opts.snapshotLength).
		WithPcapFilter(opts.pcapFilter).
		WithKernelTypes(btfSpec)

	if err := bf.Load(*bpfopts); err != nil {
		return nil, nil, err
	}
	var finalCloseFuncs []func()
	finalCloseFuncs = append(finalCloseFuncs, bf.Close)

	if len(currentConns) > 0 {
		if err := updateFlowPidMapValues(bf, currentConns); err != nil {
			return bf, finalCloseFuncs, err
		}
	}

	cgroupPath, err := utils.GetCgroupV2RootDir()
	if err != nil {
		log.Warnf("skip attach cgroup due to get cgroup v2 root dir failed: %s", err)
	}
	if cgroupPath != "" {
		if err := bf.AttachCgroups(cgroupPath); err != nil {
			return bf, finalCloseFuncs, err
		}
	}

	if err := attachGoTLSHooks(opts, bf); err != nil {
		return bf, finalCloseFuncs, err
	}
	if err := bf.AttachKprobes(); err != nil {
		return bf, finalCloseFuncs, err
	}
	if err := bf.AttachTracepoints(); err != nil {
		return bf, finalCloseFuncs, err
	}

	for _, iface := range devices.Devs() {
		var finalErr error
		log.Infof("start to attach tc hook to %s in netns %s", iface.Name, iface.NetNs)
		err := iface.NetNs.Do(func() {
			closeFuncs, err := bf.AttachTcHooks(iface.Ifindex, opts.DirectionOut(), opts.DirectionIn())
			if err != nil {
				runClosers(closeFuncs)
				// TODO: use errors.Is(xxx) or ==
				if strings.Contains(err.Error(), "netlink receive: no such file or directory") ||
					strings.Contains(err.Error(), "netlink receive: no such device") {
					log.Warnf("skip interface %s due to %s", iface.Name, err)
					return
				}
				finalErr = err
			} else {
				finalCloseFuncs = append(finalCloseFuncs, func() {
					iface.NetNs.Do(func() {
						runClosers(closeFuncs)
					})
				})
			}
		})
		if finalErr == nil {
			finalErr = err
		}
		if finalErr != nil {
			return bf, finalCloseFuncs, fmt.Errorf("attach tc hooks for interface %d.%s: %w",
				iface.Ifindex, iface.Name, finalErr)
		}

	}

	return bf, finalCloseFuncs, nil
}

func runClosers(funcs []func()) {
	for i := len(funcs) - 1; i >= 0; i-- {
		f := funcs[i]
		if f != nil {
			f()
		}
	}
}

func updateFlowPidMapValues(bf *bpf.BPF, conns []metadata.Connection) error {
	data := map[*bpf.BpfFlowPidKeyT]bpf.BpfProcessMetaT{}
	for _, conn := range conns {
		if conn.Pid == 0 {
			continue
		}
		k := bpf.BpfFlowPidKeyT{
			Saddr: addrTo128(conn.LocalIP),
			Sport: uint16(conn.LocalPort),
		}
		v := bpf.BpfProcessMetaT{
			Pid:     uint32(conn.Pid),
			MntnsId: uint32(conn.MntNs),
			NetnsId: uint32(conn.NetNs),
		}
		data[&k] = v
	}
	if err := bf.UpdateFlowPidMapValues(data); err != nil {
		return fmt.Errorf(": %w", err)
	}
	return nil
}

func addrTo128(addr netip.Addr) [2]uint64 {
	ret := [2]uint64{}
	addr = addr.Unmap()
	switch {
	case addr.Is4():
		a4 := addr.As4()
		tmp := [4]byte{}
		ip := append([]byte{}, a4[:]...)
		ip = append(ip, tmp[:]...)
		ret[0] = binary.LittleEndian.Uint64(ip[:])
		break
	default:
		ip := addr.As16()
		ret[0] = binary.LittleEndian.Uint64(ip[:8])
		ret[1] = binary.LittleEndian.Uint64(ip[8:16])
	}
	return ret
}
