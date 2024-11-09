package bpf

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/mozillazg/ptcpdump/internal/log"
)

// $TARGET is set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -no-global-types -target $TARGET bpf_no_optimize ./ptcpdump.c -- -I./headers -I./headers/$TARGET -I. -Wall -DNO_OPTIMIZE

type BpfObjectsForNoOptimize struct {
	CgroupSockCreate                     *ebpf.Program `ebpf:"cgroup__sock_create"`
	CgroupSockRelease                    *ebpf.Program `ebpf:"cgroup__sock_release"`
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

func (b *BpfObjects) FromNoOptimize(o *BpfObjectsForNoOptimize) {
	b.CgroupSockCreate = o.CgroupSockCreate
	b.CgroupSockRelease = o.CgroupSockRelease
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

func supportTracing() bool {
	if err := features.HaveProgramType(ebpf.Tracing); err != nil {
		log.Infof("%+v", err)
		return false
	}
	return true
}
