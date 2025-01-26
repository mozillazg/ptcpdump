// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package bpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadBpf_no_tracing returns the embedded CollectionSpec for bpf_no_tracing.
func loadBpf_no_tracing() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Bpf_no_tracingBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf_no_tracing: %w", err)
	}

	return spec, err
}

// loadBpf_no_tracingObjects loads bpf_no_tracing and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpf_no_tracingObjects
//	*bpf_no_tracingPrograms
//	*bpf_no_tracingMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpf_no_tracingObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf_no_tracing()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpf_no_tracingSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpf_no_tracingSpecs struct {
	bpf_no_tracingProgramSpecs
	bpf_no_tracingMapSpecs
	bpf_no_tracingVariableSpecs
}

// bpf_no_tracingProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpf_no_tracingProgramSpecs struct {
	CgroupSockCreate                     *ebpf.ProgramSpec `ebpf:"cgroup__sock_create"`
	CgroupSockRelease                    *ebpf.ProgramSpec `ebpf:"cgroup__sock_release"`
	CgroupSkbEgress                      *ebpf.ProgramSpec `ebpf:"cgroup_skb__egress"`
	CgroupSkbIngress                     *ebpf.ProgramSpec `ebpf:"cgroup_skb__ingress"`
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
	TracepointSyscallsSysEnterMount      *ebpf.ProgramSpec `ebpf:"tracepoint__syscalls__sys_enter_mount"`
	TracepointSyscallsSysExitMount       *ebpf.ProgramSpec `ebpf:"tracepoint__syscalls__sys_exit_mount"`
	UprobeGoBuiltinTlsWriteKeyLog        *ebpf.ProgramSpec `ebpf:"uprobe__go_builtin__tls__write_key_log"`
	UprobeGoBuiltinTlsWriteKeyLogRet     *ebpf.ProgramSpec `ebpf:"uprobe__go_builtin__tls__write_key_log__ret"`
}

// bpf_no_tracingMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpf_no_tracingMapSpecs struct {
	ConfigMap             *ebpf.MapSpec `ebpf:"config_map"`
	EnterMountBufs        *ebpf.MapSpec `ebpf:"enter_mount_bufs"`
	ExecEventStack        *ebpf.MapSpec `ebpf:"exec_event_stack"`
	ExecEvents            *ebpf.MapSpec `ebpf:"exec_events"`
	ExecEventsRingbuf     *ebpf.MapSpec `ebpf:"exec_events_ringbuf"`
	ExitEventTmp          *ebpf.MapSpec `ebpf:"exit_event_tmp"`
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

// bpf_no_tracingVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpf_no_tracingVariableSpecs struct {
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

// bpf_no_tracingObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpf_no_tracingObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpf_no_tracingObjects struct {
	bpf_no_tracingPrograms
	bpf_no_tracingMaps
	bpf_no_tracingVariables
}

func (o *bpf_no_tracingObjects) Close() error {
	return _Bpf_no_tracingClose(
		&o.bpf_no_tracingPrograms,
		&o.bpf_no_tracingMaps,
	)
}

// bpf_no_tracingMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpf_no_tracingObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpf_no_tracingMaps struct {
	ConfigMap             *ebpf.Map `ebpf:"config_map"`
	EnterMountBufs        *ebpf.Map `ebpf:"enter_mount_bufs"`
	ExecEventStack        *ebpf.Map `ebpf:"exec_event_stack"`
	ExecEvents            *ebpf.Map `ebpf:"exec_events"`
	ExecEventsRingbuf     *ebpf.Map `ebpf:"exec_events_ringbuf"`
	ExitEventTmp          *ebpf.Map `ebpf:"exit_event_tmp"`
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

func (m *bpf_no_tracingMaps) Close() error {
	return _Bpf_no_tracingClose(
		m.ConfigMap,
		m.EnterMountBufs,
		m.ExecEventStack,
		m.ExecEvents,
		m.ExecEventsRingbuf,
		m.ExitEventTmp,
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

// bpf_no_tracingVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadBpf_no_tracingObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpf_no_tracingVariables struct {
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

// bpf_no_tracingPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpf_no_tracingObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpf_no_tracingPrograms struct {
	CgroupSockCreate                     *ebpf.Program `ebpf:"cgroup__sock_create"`
	CgroupSockRelease                    *ebpf.Program `ebpf:"cgroup__sock_release"`
	CgroupSkbEgress                      *ebpf.Program `ebpf:"cgroup_skb__egress"`
	CgroupSkbIngress                     *ebpf.Program `ebpf:"cgroup_skb__ingress"`
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
}

func (p *bpf_no_tracingPrograms) Close() error {
	return _Bpf_no_tracingClose(
		p.CgroupSockCreate,
		p.CgroupSockRelease,
		p.CgroupSkbEgress,
		p.CgroupSkbIngress,
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
		p.TracepointSyscallsSysEnterMount,
		p.TracepointSyscallsSysExitMount,
		p.UprobeGoBuiltinTlsWriteKeyLog,
		p.UprobeGoBuiltinTlsWriteKeyLogRet,
	)
}

func _Bpf_no_tracingClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_no_tracing_x86_bpfel.o
var _Bpf_no_tracingBytes []byte
