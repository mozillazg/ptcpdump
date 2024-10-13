package bpf

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/mozillazg/ptcpdump/internal/log"
)

// $TARGET is set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -no-global-types -target $TARGET bpf_legacy ./ptcpdump.c -- -I./headers -I./headers/$TARGET -I. -Wall -DLEGACY_KERNEL

type BpfObjectsForLegacyKernel struct {
	KprobeDevChangeNetNamespace          *ebpf.Program `ebpf:"kprobe__dev_change_net_namespace"`
	KprobeDevChangeNetNamespaceLegacy    *ebpf.Program `ebpf:"kprobe__dev_change_net_namespace_legacy"`
	KprobeNfNatManipPkt                  *ebpf.Program `ebpf:"kprobe__nf_nat_manip_pkt"`
	KprobeNfNatPacket                    *ebpf.Program `ebpf:"kprobe__nf_nat_packet"`
	KprobeRegisterNetdevice              *ebpf.Program `ebpf:"kprobe__register_netdevice"`
	KprobeSecuritySkClassifyFlow         *ebpf.Program `ebpf:"kprobe__security_sk_classify_flow"`
	KprobeTcpSendmsg                     *ebpf.Program `ebpf:"kprobe__tcp_sendmsg"`
	KprobeUdpSendSkb                     *ebpf.Program `ebpf:"kprobe__udp_send_skb"`
	KprobeUdpSendmsg                     *ebpf.Program `ebpf:"kprobe__udp_sendmsg"`
	KretprobeDevChangeNetNamespace       *ebpf.Program `ebpf:"kretprobe__dev_change_net_namespace"`
	KretprobeDevChangeNetNamespaceLegacy *ebpf.Program `ebpf:"kretprobe__dev_change_net_namespace_legacy"`
	KretprobeDevGetByIndex               *ebpf.Program `ebpf:"kretprobe__dev_get_by_index"`
	KretprobeDevGetByIndexLegacy         *ebpf.Program `ebpf:"kretprobe__dev_get_by_index_legacy"`
	KretprobeRegisterNetdevice           *ebpf.Program `ebpf:"kretprobe__register_netdevice"`
	RawTracepointSchedProcessExec        *ebpf.Program `ebpf:"raw_tracepoint__sched_process_exec"`
	RawTracepointSchedProcessExit        *ebpf.Program `ebpf:"raw_tracepoint__sched_process_exit"`
	RawTracepointSchedProcessFork        *ebpf.Program `ebpf:"raw_tracepoint__sched_process_fork"`
	TcEgress                             *ebpf.Program `ebpf:"tc_egress"`
	TcIngress                            *ebpf.Program `ebpf:"tc_ingress"`
	TracepointSyscallsSysEnterMount      *ebpf.Program `ebpf:"tracepoint__syscalls__sys_enter_mount"`
	TracepointSyscallsSysExitMount       *ebpf.Program `ebpf:"tracepoint__syscalls__sys_exit_mount"`
	UprobeGoBuiltinTlsWriteKeyLog        *ebpf.Program `ebpf:"uprobe__go_builtin__tls__write_key_log"`
	UprobeGoBuiltinTlsWriteKeyLogRet     *ebpf.Program `ebpf:"uprobe__go_builtin__tls__write_key_log__ret"`

	BpfMaps
}

func (b *BpfObjects) FromLegacy(o *BpfObjectsForLegacyKernel) {
	b.KprobeTcpSendmsg = o.KprobeTcpSendmsg
	b.KprobeUdpSendmsg = o.KprobeUdpSendmsg
	b.KprobeUdpSendSkb = o.KprobeUdpSendSkb
	b.KprobeNfNatManipPkt = o.KprobeNfNatManipPkt
	b.KprobeNfNatPacket = o.KprobeNfNatPacket
	b.KprobeSecuritySkClassifyFlow = o.KprobeSecuritySkClassifyFlow
	b.RawTracepointSchedProcessExec = o.RawTracepointSchedProcessExec
	b.RawTracepointSchedProcessExit = o.RawTracepointSchedProcessExit
	b.RawTracepointSchedProcessFork = o.RawTracepointSchedProcessFork
	b.KprobeRegisterNetdevice = o.KprobeRegisterNetdevice
	b.KretprobeRegisterNetdevice = o.KretprobeRegisterNetdevice
	b.KprobeDevChangeNetNamespace = o.KprobeDevChangeNetNamespace
	b.KprobeDevChangeNetNamespaceLegacy = o.KprobeDevChangeNetNamespaceLegacy
	b.KretprobeDevChangeNetNamespace = o.KretprobeDevChangeNetNamespace
	b.KretprobeDevChangeNetNamespaceLegacy = o.KretprobeDevChangeNetNamespaceLegacy
	b.KretprobeDevGetByIndex = o.KretprobeDevGetByIndex
	b.KretprobeDevGetByIndexLegacy = o.KretprobeDevGetByIndexLegacy
	b.TracepointSyscallsSysEnterMount = o.TracepointSyscallsSysEnterMount
	b.TracepointSyscallsSysExitMount = o.TracepointSyscallsSysExitMount
	b.TcEgress = o.TcEgress
	b.TcIngress = o.TcIngress
	b.UprobeGoBuiltinTlsWriteKeyLog = o.UprobeGoBuiltinTlsWriteKeyLog
	b.UprobeGoBuiltinTlsWriteKeyLogRet = o.UprobeGoBuiltinTlsWriteKeyLogRet

	b.BpfMaps = o.BpfMaps
}

func supportCgroupSock() bool {
	if err := features.HaveProgramHelper(ebpf.CGroupSock, asm.FnGetSocketCookie); err != nil {
		log.Infof("%+v", err)
		return false
	}
	if err := features.HaveProgramHelper(ebpf.CGroupSock, asm.FnGetCurrentTask); err != nil {
		log.Infof("%+v", err)
		return false
	}

	return true
}

func kernelVersion(a, b, c int) uint32 {
	if c > 255 {
		c = 255
	}

	return uint32((a << 16) + (b << 8) + c)
}

// map .rodata: map create: read- and write-only maps not supported (requires >= 5.2)
func isLegacyKernel() (bool, error) {
	versionCode, err := features.LinuxVersionCode()
	if err != nil {
		return false, fmt.Errorf(": %w", err)
	}
	if versionCode < kernelVersion(5, 2, 0) {
		return true, nil
	}
	return false, nil
}

func loadBpfWithData(b []byte) (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(b)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Bpf: %w", err)
	}

	return spec, err
}
