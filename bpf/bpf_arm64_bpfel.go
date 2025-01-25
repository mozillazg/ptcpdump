// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64

package bpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type BpfEnterMountBufT struct {
	Fs   uint64
	Src  uint64
	Dest uint64
}

type BpfExecEventT struct {
	Meta              BpfProcessMetaT
	FilenameTruncated uint8
	ArgsTruncated     uint8
	_                 [2]byte
	ArgsSize          uint32
	Filename          [512]int8
	Args              [4096]int8
}

type BpfExitEventT struct{ Pid uint32 }

type BpfFlowPidKeyT struct {
	Saddr [2]uint64
	Sport uint16
	_     [6]byte
}

type BpfGconfigT struct {
	HaveFilter          uint8
	FilterFollowForks   uint8
	FilterComm          [16]int8
	FilterCommEnable    uint8
	FilterIfindexEnable uint8
	UseRingbufSubmitSkb uint8
	_                   [3]byte
	MaxPayloadSize      uint32
}

type BpfGoKeylogBufT struct {
	LabelPtr     uint64
	LabelLenPtr  uint64
	RandomPtr    uint64
	RandomLenPtr uint64
	SecretPtr    uint64
	SecretLenPtr uint64
}

type BpfGoKeylogEventT struct {
	Label           [32]int8
	ClientRandom    [32]int8
	Secret          [64]int8
	LabelLen        uint8
	ClientRandomLen uint8
	SecretLen       uint8
}

type BpfMountEventT struct {
	Fs   [8]int8
	Src  [4096]int8
	Dest [4096]int8
}

type BpfNatFlowT struct {
	Saddr [2]uint64
	Daddr [2]uint64
	Sport uint16
	Dport uint16
	_     [4]byte
}

type BpfNetdeviceBufT struct {
	Dev uint64
	Net uint64
}

type BpfNetdeviceChangeEventT struct {
	OldDevice BpfNetdeviceT
	NewDevice BpfNetdeviceT
}

type BpfNetdeviceT struct {
	NetnsId uint32
	Ifindex uint32
	Name    [16]int8
}

type BpfNewNetdeviceEventT struct{ Dev BpfNetdeviceT }

type BpfPacketEventMetaT struct {
	Timestamp  uint64
	PacketType uint8
	FirstLayer uint8
	L3Protocol uint16
	Ifindex    uint32
	PayloadLen uint64
	PacketSize uint64
	Process    BpfProcessMetaT
	_          [4]byte
}

type BpfPacketEventT struct{ Meta BpfPacketEventMetaT }

type BpfProcessMetaT struct {
	Ppid       uint32
	Pid        uint32
	PidnsId    uint32
	MntnsId    uint32
	NetnsId    uint32
	Tid        uint32
	Uid        uint32
	Tname      [16]int8
	CgroupName [128]int8
}

// LoadBpf returns the embedded CollectionSpec for Bpf.
func LoadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Bpf: %w", err)
	}

	return spec, err
}

// LoadBpfObjects loads Bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*BpfObjects
//	*BpfPrograms
//	*BpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// BpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfSpecs struct {
	BpfProgramSpecs
	BpfMapSpecs
	BpfVariableSpecs
}

// BpfProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfProgramSpecs struct {
	CgroupSockCreate                     *ebpf.ProgramSpec `ebpf:"cgroup__sock_create"`
	CgroupSockRelease                    *ebpf.ProgramSpec `ebpf:"cgroup__sock_release"`
	CgroupSkbEgress                      *ebpf.ProgramSpec `ebpf:"cgroup_skb__egress"`
	CgroupSkbIngress                     *ebpf.ProgramSpec `ebpf:"cgroup_skb__ingress"`
	FentryNfNatManipPkt                  *ebpf.ProgramSpec `ebpf:"fentry__nf_nat_manip_pkt"`
	FentryNfNatPacket                    *ebpf.ProgramSpec `ebpf:"fentry__nf_nat_packet"`
	FentrySecuritySkClassifyFlow         *ebpf.ProgramSpec `ebpf:"fentry__security_sk_classify_flow"`
	FentryTcpSendmsg                     *ebpf.ProgramSpec `ebpf:"fentry__tcp_sendmsg"`
	FentryUdpSendSkb                     *ebpf.ProgramSpec `ebpf:"fentry__udp_send_skb"`
	FentryUdpSendmsg                     *ebpf.ProgramSpec `ebpf:"fentry__udp_sendmsg"`
	KprobeDevChangeNetNamespace          *ebpf.ProgramSpec `ebpf:"kprobe__dev_change_net_namespace"`
	KprobeDevChangeNetNamespaceLegacy    *ebpf.ProgramSpec `ebpf:"kprobe__dev_change_net_namespace_legacy"`
	KprobeNfNatManipPkt                  *ebpf.ProgramSpec `ebpf:"kprobe__nf_nat_manip_pkt"`
	KprobeNfNatPacket                    *ebpf.ProgramSpec `ebpf:"kprobe__nf_nat_packet"`
	KprobeRegisterNetdevice              *ebpf.ProgramSpec `ebpf:"kprobe__register_netdevice"`
	KprobeSecuritySkClassifyFlow         *ebpf.ProgramSpec `ebpf:"kprobe__security_sk_classify_flow"`
	KprobeTcpSendmsg                     *ebpf.ProgramSpec `ebpf:"kprobe__tcp_sendmsg"`
	KprobeUdpSendSkb                     *ebpf.ProgramSpec `ebpf:"kprobe__udp_send_skb"`
	KprobeUdpSendmsg                     *ebpf.ProgramSpec `ebpf:"kprobe__udp_sendmsg"`
	KretprobeDevChangeNetNamespace       *ebpf.ProgramSpec `ebpf:"kretprobe__dev_change_net_namespace"`
	KretprobeDevChangeNetNamespaceLegacy *ebpf.ProgramSpec `ebpf:"kretprobe__dev_change_net_namespace_legacy"`
	KretprobeDevGetByIndex               *ebpf.ProgramSpec `ebpf:"kretprobe__dev_get_by_index"`
	KretprobeDevGetByIndexLegacy         *ebpf.ProgramSpec `ebpf:"kretprobe__dev_get_by_index_legacy"`
	KretprobeRegisterNetdevice           *ebpf.ProgramSpec `ebpf:"kretprobe__register_netdevice"`
	RawTracepointSchedProcessExec        *ebpf.ProgramSpec `ebpf:"raw_tracepoint__sched_process_exec"`
	RawTracepointSchedProcessExit        *ebpf.ProgramSpec `ebpf:"raw_tracepoint__sched_process_exit"`
	RawTracepointSchedProcessFork        *ebpf.ProgramSpec `ebpf:"raw_tracepoint__sched_process_fork"`
	TcEgress                             *ebpf.ProgramSpec `ebpf:"tc_egress"`
	TcIngress                            *ebpf.ProgramSpec `ebpf:"tc_ingress"`
	TcxEgress                            *ebpf.ProgramSpec `ebpf:"tcx_egress"`
	TcxIngress                           *ebpf.ProgramSpec `ebpf:"tcx_ingress"`
	TpBtfSchedProcessExec                *ebpf.ProgramSpec `ebpf:"tp_btf__sched_process_exec"`
	TpBtfSchedProcessExit                *ebpf.ProgramSpec `ebpf:"tp_btf__sched_process_exit"`
	TpBtfSchedProcessFork                *ebpf.ProgramSpec `ebpf:"tp_btf__sched_process_fork"`
	TracepointSyscallsSysEnterMount      *ebpf.ProgramSpec `ebpf:"tracepoint__syscalls__sys_enter_mount"`
	TracepointSyscallsSysExitMount       *ebpf.ProgramSpec `ebpf:"tracepoint__syscalls__sys_exit_mount"`
	UprobeGoBuiltinTlsWriteKeyLog        *ebpf.ProgramSpec `ebpf:"uprobe__go_builtin__tls__write_key_log"`
	UprobeGoBuiltinTlsWriteKeyLogRet     *ebpf.ProgramSpec `ebpf:"uprobe__go_builtin__tls__write_key_log__ret"`
}

// BpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfMapSpecs struct {
	ConfigMap             *ebpf.MapSpec `ebpf:"config_map"`
	EnterMountBufs        *ebpf.MapSpec `ebpf:"enter_mount_bufs"`
	ExecEventStack        *ebpf.MapSpec `ebpf:"exec_event_stack"`
	ExecEventTmp          *ebpf.MapSpec `ebpf:"exec_event_tmp"`
	ExecEvents            *ebpf.MapSpec `ebpf:"exec_events"`
	ExecEventsRingbuf     *ebpf.MapSpec `ebpf:"exec_events_ringbuf"`
	ExitEvents            *ebpf.MapSpec `ebpf:"exit_events"`
	ExitEventsRingbuf     *ebpf.MapSpec `ebpf:"exit_events_ringbuf"`
	FilterByKernelCount   *ebpf.MapSpec `ebpf:"filter_by_kernel_count"`
	FilterIfindexMap      *ebpf.MapSpec `ebpf:"filter_ifindex_map"`
	FilterMntnsMap        *ebpf.MapSpec `ebpf:"filter_mntns_map"`
	FilterNetnsMap        *ebpf.MapSpec `ebpf:"filter_netns_map"`
	FilterPidMap          *ebpf.MapSpec `ebpf:"filter_pid_map"`
	FilterPidnsMap        *ebpf.MapSpec `ebpf:"filter_pidns_map"`
	FilterUidMap          *ebpf.MapSpec `ebpf:"filter_uid_map"`
	FlowPidMap            *ebpf.MapSpec `ebpf:"flow_pid_map"`
	GoKeylogBufStorage    *ebpf.MapSpec `ebpf:"go_keylog_buf_storage"`
	GoKeylogEventTmp      *ebpf.MapSpec `ebpf:"go_keylog_event_tmp"`
	GoKeylogEvents        *ebpf.MapSpec `ebpf:"go_keylog_events"`
	GoKeylogEventsRingbuf *ebpf.MapSpec `ebpf:"go_keylog_events_ringbuf"`
	MountEventStack       *ebpf.MapSpec `ebpf:"mount_event_stack"`
	MountEvents           *ebpf.MapSpec `ebpf:"mount_events"`
	NatFlowMap            *ebpf.MapSpec `ebpf:"nat_flow_map"`
	NetdeviceBufs         *ebpf.MapSpec `ebpf:"netdevice_bufs"`
	NetdeviceChangeEvents *ebpf.MapSpec `ebpf:"netdevice_change_events"`
	NewNetdeviceEvents    *ebpf.MapSpec `ebpf:"new_netdevice_events"`
	PacketEventStack      *ebpf.MapSpec `ebpf:"packet_event_stack"`
	PacketEvents          *ebpf.MapSpec `ebpf:"packet_events"`
	PacketEventsRingbuf   *ebpf.MapSpec `ebpf:"packet_events_ringbuf"`
	SockCookiePidMap      *ebpf.MapSpec `ebpf:"sock_cookie_pid_map"`
	TidNetdeviceMap       *ebpf.MapSpec `ebpf:"tid_netdevice_map"`
}

// BpfVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfVariableSpecs struct {
	G        *ebpf.VariableSpec `ebpf:"g"`
	Unused1  *ebpf.VariableSpec `ebpf:"unused1"`
	Unused10 *ebpf.VariableSpec `ebpf:"unused10"`
	Unused11 *ebpf.VariableSpec `ebpf:"unused11"`
	Unused2  *ebpf.VariableSpec `ebpf:"unused2"`
	Unused3  *ebpf.VariableSpec `ebpf:"unused3"`
	Unused4  *ebpf.VariableSpec `ebpf:"unused4"`
	Unused5  *ebpf.VariableSpec `ebpf:"unused5"`
	Unused6  *ebpf.VariableSpec `ebpf:"unused6"`
	Unused7  *ebpf.VariableSpec `ebpf:"unused7"`
}

// BpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfObjects struct {
	BpfPrograms
	BpfMaps
	BpfVariables
}

func (o *BpfObjects) Close() error {
	return _BpfClose(
		&o.BpfPrograms,
		&o.BpfMaps,
	)
}

// BpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfMaps struct {
	ConfigMap             *ebpf.Map `ebpf:"config_map"`
	EnterMountBufs        *ebpf.Map `ebpf:"enter_mount_bufs"`
	ExecEventStack        *ebpf.Map `ebpf:"exec_event_stack"`
	ExecEventTmp          *ebpf.Map `ebpf:"exec_event_tmp"`
	ExecEvents            *ebpf.Map `ebpf:"exec_events"`
	ExecEventsRingbuf     *ebpf.Map `ebpf:"exec_events_ringbuf"`
	ExitEvents            *ebpf.Map `ebpf:"exit_events"`
	ExitEventsRingbuf     *ebpf.Map `ebpf:"exit_events_ringbuf"`
	FilterByKernelCount   *ebpf.Map `ebpf:"filter_by_kernel_count"`
	FilterIfindexMap      *ebpf.Map `ebpf:"filter_ifindex_map"`
	FilterMntnsMap        *ebpf.Map `ebpf:"filter_mntns_map"`
	FilterNetnsMap        *ebpf.Map `ebpf:"filter_netns_map"`
	FilterPidMap          *ebpf.Map `ebpf:"filter_pid_map"`
	FilterPidnsMap        *ebpf.Map `ebpf:"filter_pidns_map"`
	FilterUidMap          *ebpf.Map `ebpf:"filter_uid_map"`
	FlowPidMap            *ebpf.Map `ebpf:"flow_pid_map"`
	GoKeylogBufStorage    *ebpf.Map `ebpf:"go_keylog_buf_storage"`
	GoKeylogEventTmp      *ebpf.Map `ebpf:"go_keylog_event_tmp"`
	GoKeylogEvents        *ebpf.Map `ebpf:"go_keylog_events"`
	GoKeylogEventsRingbuf *ebpf.Map `ebpf:"go_keylog_events_ringbuf"`
	MountEventStack       *ebpf.Map `ebpf:"mount_event_stack"`
	MountEvents           *ebpf.Map `ebpf:"mount_events"`
	NatFlowMap            *ebpf.Map `ebpf:"nat_flow_map"`
	NetdeviceBufs         *ebpf.Map `ebpf:"netdevice_bufs"`
	NetdeviceChangeEvents *ebpf.Map `ebpf:"netdevice_change_events"`
	NewNetdeviceEvents    *ebpf.Map `ebpf:"new_netdevice_events"`
	PacketEventStack      *ebpf.Map `ebpf:"packet_event_stack"`
	PacketEvents          *ebpf.Map `ebpf:"packet_events"`
	PacketEventsRingbuf   *ebpf.Map `ebpf:"packet_events_ringbuf"`
	SockCookiePidMap      *ebpf.Map `ebpf:"sock_cookie_pid_map"`
	TidNetdeviceMap       *ebpf.Map `ebpf:"tid_netdevice_map"`
}

func (m *BpfMaps) Close() error {
	return _BpfClose(
		m.ConfigMap,
		m.EnterMountBufs,
		m.ExecEventStack,
		m.ExecEventTmp,
		m.ExecEvents,
		m.ExecEventsRingbuf,
		m.ExitEvents,
		m.ExitEventsRingbuf,
		m.FilterByKernelCount,
		m.FilterIfindexMap,
		m.FilterMntnsMap,
		m.FilterNetnsMap,
		m.FilterPidMap,
		m.FilterPidnsMap,
		m.FilterUidMap,
		m.FlowPidMap,
		m.GoKeylogBufStorage,
		m.GoKeylogEventTmp,
		m.GoKeylogEvents,
		m.GoKeylogEventsRingbuf,
		m.MountEventStack,
		m.MountEvents,
		m.NatFlowMap,
		m.NetdeviceBufs,
		m.NetdeviceChangeEvents,
		m.NewNetdeviceEvents,
		m.PacketEventStack,
		m.PacketEvents,
		m.PacketEventsRingbuf,
		m.SockCookiePidMap,
		m.TidNetdeviceMap,
	)
}

// BpfVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfVariables struct {
	G        *ebpf.Variable `ebpf:"g"`
	Unused1  *ebpf.Variable `ebpf:"unused1"`
	Unused10 *ebpf.Variable `ebpf:"unused10"`
	Unused11 *ebpf.Variable `ebpf:"unused11"`
	Unused2  *ebpf.Variable `ebpf:"unused2"`
	Unused3  *ebpf.Variable `ebpf:"unused3"`
	Unused4  *ebpf.Variable `ebpf:"unused4"`
	Unused5  *ebpf.Variable `ebpf:"unused5"`
	Unused6  *ebpf.Variable `ebpf:"unused6"`
	Unused7  *ebpf.Variable `ebpf:"unused7"`
}

// BpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfPrograms struct {
	CgroupSockCreate                     *ebpf.Program `ebpf:"cgroup__sock_create"`
	CgroupSockRelease                    *ebpf.Program `ebpf:"cgroup__sock_release"`
	CgroupSkbEgress                      *ebpf.Program `ebpf:"cgroup_skb__egress"`
	CgroupSkbIngress                     *ebpf.Program `ebpf:"cgroup_skb__ingress"`
	FentryNfNatManipPkt                  *ebpf.Program `ebpf:"fentry__nf_nat_manip_pkt"`
	FentryNfNatPacket                    *ebpf.Program `ebpf:"fentry__nf_nat_packet"`
	FentrySecuritySkClassifyFlow         *ebpf.Program `ebpf:"fentry__security_sk_classify_flow"`
	FentryTcpSendmsg                     *ebpf.Program `ebpf:"fentry__tcp_sendmsg"`
	FentryUdpSendSkb                     *ebpf.Program `ebpf:"fentry__udp_send_skb"`
	FentryUdpSendmsg                     *ebpf.Program `ebpf:"fentry__udp_sendmsg"`
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
	TcxEgress                            *ebpf.Program `ebpf:"tcx_egress"`
	TcxIngress                           *ebpf.Program `ebpf:"tcx_ingress"`
	TpBtfSchedProcessExec                *ebpf.Program `ebpf:"tp_btf__sched_process_exec"`
	TpBtfSchedProcessExit                *ebpf.Program `ebpf:"tp_btf__sched_process_exit"`
	TpBtfSchedProcessFork                *ebpf.Program `ebpf:"tp_btf__sched_process_fork"`
	TracepointSyscallsSysEnterMount      *ebpf.Program `ebpf:"tracepoint__syscalls__sys_enter_mount"`
	TracepointSyscallsSysExitMount       *ebpf.Program `ebpf:"tracepoint__syscalls__sys_exit_mount"`
	UprobeGoBuiltinTlsWriteKeyLog        *ebpf.Program `ebpf:"uprobe__go_builtin__tls__write_key_log"`
	UprobeGoBuiltinTlsWriteKeyLogRet     *ebpf.Program `ebpf:"uprobe__go_builtin__tls__write_key_log__ret"`
}

func (p *BpfPrograms) Close() error {
	return _BpfClose(
		p.CgroupSockCreate,
		p.CgroupSockRelease,
		p.CgroupSkbEgress,
		p.CgroupSkbIngress,
		p.FentryNfNatManipPkt,
		p.FentryNfNatPacket,
		p.FentrySecuritySkClassifyFlow,
		p.FentryTcpSendmsg,
		p.FentryUdpSendSkb,
		p.FentryUdpSendmsg,
		p.KprobeDevChangeNetNamespace,
		p.KprobeDevChangeNetNamespaceLegacy,
		p.KprobeNfNatManipPkt,
		p.KprobeNfNatPacket,
		p.KprobeRegisterNetdevice,
		p.KprobeSecuritySkClassifyFlow,
		p.KprobeTcpSendmsg,
		p.KprobeUdpSendSkb,
		p.KprobeUdpSendmsg,
		p.KretprobeDevChangeNetNamespace,
		p.KretprobeDevChangeNetNamespaceLegacy,
		p.KretprobeDevGetByIndex,
		p.KretprobeDevGetByIndexLegacy,
		p.KretprobeRegisterNetdevice,
		p.RawTracepointSchedProcessExec,
		p.RawTracepointSchedProcessExit,
		p.RawTracepointSchedProcessFork,
		p.TcEgress,
		p.TcIngress,
		p.TcxEgress,
		p.TcxIngress,
		p.TpBtfSchedProcessExec,
		p.TpBtfSchedProcessExit,
		p.TpBtfSchedProcessFork,
		p.TracepointSyscallsSysEnterMount,
		p.TracepointSyscallsSysExitMount,
		p.UprobeGoBuiltinTlsWriteKeyLog,
		p.UprobeGoBuiltinTlsWriteKeyLogRet,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_arm64_bpfel.o
var _BpfBytes []byte
