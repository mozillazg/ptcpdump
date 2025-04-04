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
	PtcpdumpCgroupSockCreate                     *ebpf.ProgramSpec `ebpf:"ptcpdump_cgroup__sock_create"`
	PtcpdumpCgroupSockRelease                    *ebpf.ProgramSpec `ebpf:"ptcpdump_cgroup__sock_release"`
	PtcpdumpCgroupSkbEgress                      *ebpf.ProgramSpec `ebpf:"ptcpdump_cgroup_skb__egress"`
	PtcpdumpCgroupSkbIngress                     *ebpf.ProgramSpec `ebpf:"ptcpdump_cgroup_skb__ingress"`
	PtcpdumpKprobeDevChangeNetNamespace          *ebpf.ProgramSpec `ebpf:"ptcpdump_kprobe__dev_change_net_namespace"`
	PtcpdumpKprobeDevChangeNetNamespaceLegacy    *ebpf.ProgramSpec `ebpf:"ptcpdump_kprobe__dev_change_net_namespace_legacy"`
	PtcpdumpKprobeNfNatManipPkt                  *ebpf.ProgramSpec `ebpf:"ptcpdump_kprobe__nf_nat_manip_pkt"`
	PtcpdumpKprobeNfNatPacket                    *ebpf.ProgramSpec `ebpf:"ptcpdump_kprobe__nf_nat_packet"`
	PtcpdumpKprobeRegisterNetdevice              *ebpf.ProgramSpec `ebpf:"ptcpdump_kprobe__register_netdevice"`
	PtcpdumpKprobeSecuritySkClassifyFlow         *ebpf.ProgramSpec `ebpf:"ptcpdump_kprobe__security_sk_classify_flow"`
	PtcpdumpKprobeTcpSendmsg                     *ebpf.ProgramSpec `ebpf:"ptcpdump_kprobe__tcp_sendmsg"`
	PtcpdumpKprobeUdpSendSkb                     *ebpf.ProgramSpec `ebpf:"ptcpdump_kprobe__udp_send_skb"`
	PtcpdumpKprobeUdpSendmsg                     *ebpf.ProgramSpec `ebpf:"ptcpdump_kprobe__udp_sendmsg"`
	PtcpdumpKretprobeDevChangeNetNamespace       *ebpf.ProgramSpec `ebpf:"ptcpdump_kretprobe__dev_change_net_namespace"`
	PtcpdumpKretprobeDevChangeNetNamespaceLegacy *ebpf.ProgramSpec `ebpf:"ptcpdump_kretprobe__dev_change_net_namespace_legacy"`
	PtcpdumpKretprobeDevGetByIndex               *ebpf.ProgramSpec `ebpf:"ptcpdump_kretprobe__dev_get_by_index"`
	PtcpdumpKretprobeDevGetByIndexLegacy         *ebpf.ProgramSpec `ebpf:"ptcpdump_kretprobe__dev_get_by_index_legacy"`
	PtcpdumpKretprobeRegisterNetdevice           *ebpf.ProgramSpec `ebpf:"ptcpdump_kretprobe__register_netdevice"`
	PtcpdumpRawTracepointSchedProcessExec        *ebpf.ProgramSpec `ebpf:"ptcpdump_raw_tracepoint__sched_process_exec"`
	PtcpdumpRawTracepointSchedProcessExit        *ebpf.ProgramSpec `ebpf:"ptcpdump_raw_tracepoint__sched_process_exit"`
	PtcpdumpRawTracepointSchedProcessFork        *ebpf.ProgramSpec `ebpf:"ptcpdump_raw_tracepoint__sched_process_fork"`
	PtcpdumpTcEgress                             *ebpf.ProgramSpec `ebpf:"ptcpdump_tc_egress"`
	PtcpdumpTcIngress                            *ebpf.ProgramSpec `ebpf:"ptcpdump_tc_ingress"`
	PtcpdumpTracepointSyscallsSysEnterMount      *ebpf.ProgramSpec `ebpf:"ptcpdump_tracepoint__syscalls__sys_enter_mount"`
	PtcpdumpTracepointSyscallsSysExitMount       *ebpf.ProgramSpec `ebpf:"ptcpdump_tracepoint__syscalls__sys_exit_mount"`
	PtcpdumpUprobeGoBuiltinTlsWriteKeyLog        *ebpf.ProgramSpec `ebpf:"ptcpdump_uprobe__go_builtin__tls__write_key_log"`
	PtcpdumpUprobeGoBuiltinTlsWriteKeyLogRet     *ebpf.ProgramSpec `ebpf:"ptcpdump_uprobe__go_builtin__tls__write_key_log__ret"`
}

// bpf_no_tracingMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpf_no_tracingMapSpecs struct {
	PtcpdumpConfigMap                 *ebpf.MapSpec `ebpf:"ptcpdump_config_map"`
	PtcpdumpEnterMountBufs            *ebpf.MapSpec `ebpf:"ptcpdump_enter_mount_bufs"`
	PtcpdumpExecEventStack            *ebpf.MapSpec `ebpf:"ptcpdump_exec_event_stack"`
	PtcpdumpExecEvents                *ebpf.MapSpec `ebpf:"ptcpdump_exec_events"`
	PtcpdumpExitEventTmp              *ebpf.MapSpec `ebpf:"ptcpdump_exit_event_tmp"`
	PtcpdumpExitEvents                *ebpf.MapSpec `ebpf:"ptcpdump_exit_events"`
	PtcpdumpExitEventsRingbuf         *ebpf.MapSpec `ebpf:"ptcpdump_exit_events_ringbuf"`
	PtcpdumpFilterByKernelCount       *ebpf.MapSpec `ebpf:"ptcpdump_filter_by_kernel_count"`
	PtcpdumpFilterIfindexMap          *ebpf.MapSpec `ebpf:"ptcpdump_filter_ifindex_map"`
	PtcpdumpFilterMntnsMap            *ebpf.MapSpec `ebpf:"ptcpdump_filter_mntns_map"`
	PtcpdumpFilterNetnsMap            *ebpf.MapSpec `ebpf:"ptcpdump_filter_netns_map"`
	PtcpdumpFilterPidMap              *ebpf.MapSpec `ebpf:"ptcpdump_filter_pid_map"`
	PtcpdumpFilterPidnsMap            *ebpf.MapSpec `ebpf:"ptcpdump_filter_pidns_map"`
	PtcpdumpFilterUidMap              *ebpf.MapSpec `ebpf:"ptcpdump_filter_uid_map"`
	PtcpdumpFlowPidMap                *ebpf.MapSpec `ebpf:"ptcpdump_flow_pid_map"`
	PtcpdumpGoKeylogBufStorage        *ebpf.MapSpec `ebpf:"ptcpdump_go_keylog_buf_storage"`
	PtcpdumpGoKeylogEventTmp          *ebpf.MapSpec `ebpf:"ptcpdump_go_keylog_event_tmp"`
	PtcpdumpGoKeylogEvents            *ebpf.MapSpec `ebpf:"ptcpdump_go_keylog_events"`
	PtcpdumpGoKeylogEventsRingbuf     *ebpf.MapSpec `ebpf:"ptcpdump_go_keylog_events_ringbuf"`
	PtcpdumpMountEventStack           *ebpf.MapSpec `ebpf:"ptcpdump_mount_event_stack"`
	PtcpdumpMountEvents               *ebpf.MapSpec `ebpf:"ptcpdump_mount_events"`
	PtcpdumpNatFlowMap                *ebpf.MapSpec `ebpf:"ptcpdump_nat_flow_map"`
	PtcpdumpNetdeviceBufs             *ebpf.MapSpec `ebpf:"ptcpdump_netdevice_bufs"`
	PtcpdumpNetdeviceChangeEvents     *ebpf.MapSpec `ebpf:"ptcpdump_netdevice_change_events"`
	PtcpdumpNewNetdeviceEvents        *ebpf.MapSpec `ebpf:"ptcpdump_new_netdevice_events"`
	PtcpdumpPacketEventStack          *ebpf.MapSpec `ebpf:"ptcpdump_packet_event_stack"`
	PtcpdumpPacketEvents              *ebpf.MapSpec `ebpf:"ptcpdump_packet_events"`
	PtcpdumpPacketEventsRingbuf       *ebpf.MapSpec `ebpf:"ptcpdump_packet_events_ringbuf"`
	PtcpdumpPtcpdumpExecEventsRingbuf *ebpf.MapSpec `ebpf:"ptcpdump_ptcpdump_exec_events_ringbuf"`
	PtcpdumpSockCookiePidMap          *ebpf.MapSpec `ebpf:"ptcpdump_sock_cookie_pid_map"`
	PtcpdumpTidNetdeviceMap           *ebpf.MapSpec `ebpf:"ptcpdump_tid_netdevice_map"`
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
	PtcpdumpConfigMap                 *ebpf.Map `ebpf:"ptcpdump_config_map"`
	PtcpdumpEnterMountBufs            *ebpf.Map `ebpf:"ptcpdump_enter_mount_bufs"`
	PtcpdumpExecEventStack            *ebpf.Map `ebpf:"ptcpdump_exec_event_stack"`
	PtcpdumpExecEvents                *ebpf.Map `ebpf:"ptcpdump_exec_events"`
	PtcpdumpExitEventTmp              *ebpf.Map `ebpf:"ptcpdump_exit_event_tmp"`
	PtcpdumpExitEvents                *ebpf.Map `ebpf:"ptcpdump_exit_events"`
	PtcpdumpExitEventsRingbuf         *ebpf.Map `ebpf:"ptcpdump_exit_events_ringbuf"`
	PtcpdumpFilterByKernelCount       *ebpf.Map `ebpf:"ptcpdump_filter_by_kernel_count"`
	PtcpdumpFilterIfindexMap          *ebpf.Map `ebpf:"ptcpdump_filter_ifindex_map"`
	PtcpdumpFilterMntnsMap            *ebpf.Map `ebpf:"ptcpdump_filter_mntns_map"`
	PtcpdumpFilterNetnsMap            *ebpf.Map `ebpf:"ptcpdump_filter_netns_map"`
	PtcpdumpFilterPidMap              *ebpf.Map `ebpf:"ptcpdump_filter_pid_map"`
	PtcpdumpFilterPidnsMap            *ebpf.Map `ebpf:"ptcpdump_filter_pidns_map"`
	PtcpdumpFilterUidMap              *ebpf.Map `ebpf:"ptcpdump_filter_uid_map"`
	PtcpdumpFlowPidMap                *ebpf.Map `ebpf:"ptcpdump_flow_pid_map"`
	PtcpdumpGoKeylogBufStorage        *ebpf.Map `ebpf:"ptcpdump_go_keylog_buf_storage"`
	PtcpdumpGoKeylogEventTmp          *ebpf.Map `ebpf:"ptcpdump_go_keylog_event_tmp"`
	PtcpdumpGoKeylogEvents            *ebpf.Map `ebpf:"ptcpdump_go_keylog_events"`
	PtcpdumpGoKeylogEventsRingbuf     *ebpf.Map `ebpf:"ptcpdump_go_keylog_events_ringbuf"`
	PtcpdumpMountEventStack           *ebpf.Map `ebpf:"ptcpdump_mount_event_stack"`
	PtcpdumpMountEvents               *ebpf.Map `ebpf:"ptcpdump_mount_events"`
	PtcpdumpNatFlowMap                *ebpf.Map `ebpf:"ptcpdump_nat_flow_map"`
	PtcpdumpNetdeviceBufs             *ebpf.Map `ebpf:"ptcpdump_netdevice_bufs"`
	PtcpdumpNetdeviceChangeEvents     *ebpf.Map `ebpf:"ptcpdump_netdevice_change_events"`
	PtcpdumpNewNetdeviceEvents        *ebpf.Map `ebpf:"ptcpdump_new_netdevice_events"`
	PtcpdumpPacketEventStack          *ebpf.Map `ebpf:"ptcpdump_packet_event_stack"`
	PtcpdumpPacketEvents              *ebpf.Map `ebpf:"ptcpdump_packet_events"`
	PtcpdumpPacketEventsRingbuf       *ebpf.Map `ebpf:"ptcpdump_packet_events_ringbuf"`
	PtcpdumpPtcpdumpExecEventsRingbuf *ebpf.Map `ebpf:"ptcpdump_ptcpdump_exec_events_ringbuf"`
	PtcpdumpSockCookiePidMap          *ebpf.Map `ebpf:"ptcpdump_sock_cookie_pid_map"`
	PtcpdumpTidNetdeviceMap           *ebpf.Map `ebpf:"ptcpdump_tid_netdevice_map"`
}

func (m *bpf_no_tracingMaps) Close() error {
	return _Bpf_no_tracingClose(
		m.PtcpdumpConfigMap,
		m.PtcpdumpEnterMountBufs,
		m.PtcpdumpExecEventStack,
		m.PtcpdumpExecEvents,
		m.PtcpdumpExitEventTmp,
		m.PtcpdumpExitEvents,
		m.PtcpdumpExitEventsRingbuf,
		m.PtcpdumpFilterByKernelCount,
		m.PtcpdumpFilterIfindexMap,
		m.PtcpdumpFilterMntnsMap,
		m.PtcpdumpFilterNetnsMap,
		m.PtcpdumpFilterPidMap,
		m.PtcpdumpFilterPidnsMap,
		m.PtcpdumpFilterUidMap,
		m.PtcpdumpFlowPidMap,
		m.PtcpdumpGoKeylogBufStorage,
		m.PtcpdumpGoKeylogEventTmp,
		m.PtcpdumpGoKeylogEvents,
		m.PtcpdumpGoKeylogEventsRingbuf,
		m.PtcpdumpMountEventStack,
		m.PtcpdumpMountEvents,
		m.PtcpdumpNatFlowMap,
		m.PtcpdumpNetdeviceBufs,
		m.PtcpdumpNetdeviceChangeEvents,
		m.PtcpdumpNewNetdeviceEvents,
		m.PtcpdumpPacketEventStack,
		m.PtcpdumpPacketEvents,
		m.PtcpdumpPacketEventsRingbuf,
		m.PtcpdumpPtcpdumpExecEventsRingbuf,
		m.PtcpdumpSockCookiePidMap,
		m.PtcpdumpTidNetdeviceMap,
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
	PtcpdumpCgroupSockCreate                     *ebpf.Program `ebpf:"ptcpdump_cgroup__sock_create"`
	PtcpdumpCgroupSockRelease                    *ebpf.Program `ebpf:"ptcpdump_cgroup__sock_release"`
	PtcpdumpCgroupSkbEgress                      *ebpf.Program `ebpf:"ptcpdump_cgroup_skb__egress"`
	PtcpdumpCgroupSkbIngress                     *ebpf.Program `ebpf:"ptcpdump_cgroup_skb__ingress"`
	PtcpdumpKprobeDevChangeNetNamespace          *ebpf.Program `ebpf:"ptcpdump_kprobe__dev_change_net_namespace"`
	PtcpdumpKprobeDevChangeNetNamespaceLegacy    *ebpf.Program `ebpf:"ptcpdump_kprobe__dev_change_net_namespace_legacy"`
	PtcpdumpKprobeNfNatManipPkt                  *ebpf.Program `ebpf:"ptcpdump_kprobe__nf_nat_manip_pkt"`
	PtcpdumpKprobeNfNatPacket                    *ebpf.Program `ebpf:"ptcpdump_kprobe__nf_nat_packet"`
	PtcpdumpKprobeRegisterNetdevice              *ebpf.Program `ebpf:"ptcpdump_kprobe__register_netdevice"`
	PtcpdumpKprobeSecuritySkClassifyFlow         *ebpf.Program `ebpf:"ptcpdump_kprobe__security_sk_classify_flow"`
	PtcpdumpKprobeTcpSendmsg                     *ebpf.Program `ebpf:"ptcpdump_kprobe__tcp_sendmsg"`
	PtcpdumpKprobeUdpSendSkb                     *ebpf.Program `ebpf:"ptcpdump_kprobe__udp_send_skb"`
	PtcpdumpKprobeUdpSendmsg                     *ebpf.Program `ebpf:"ptcpdump_kprobe__udp_sendmsg"`
	PtcpdumpKretprobeDevChangeNetNamespace       *ebpf.Program `ebpf:"ptcpdump_kretprobe__dev_change_net_namespace"`
	PtcpdumpKretprobeDevChangeNetNamespaceLegacy *ebpf.Program `ebpf:"ptcpdump_kretprobe__dev_change_net_namespace_legacy"`
	PtcpdumpKretprobeDevGetByIndex               *ebpf.Program `ebpf:"ptcpdump_kretprobe__dev_get_by_index"`
	PtcpdumpKretprobeDevGetByIndexLegacy         *ebpf.Program `ebpf:"ptcpdump_kretprobe__dev_get_by_index_legacy"`
	PtcpdumpKretprobeRegisterNetdevice           *ebpf.Program `ebpf:"ptcpdump_kretprobe__register_netdevice"`
	PtcpdumpRawTracepointSchedProcessExec        *ebpf.Program `ebpf:"ptcpdump_raw_tracepoint__sched_process_exec"`
	PtcpdumpRawTracepointSchedProcessExit        *ebpf.Program `ebpf:"ptcpdump_raw_tracepoint__sched_process_exit"`
	PtcpdumpRawTracepointSchedProcessFork        *ebpf.Program `ebpf:"ptcpdump_raw_tracepoint__sched_process_fork"`
	PtcpdumpTcEgress                             *ebpf.Program `ebpf:"ptcpdump_tc_egress"`
	PtcpdumpTcIngress                            *ebpf.Program `ebpf:"ptcpdump_tc_ingress"`
	PtcpdumpTracepointSyscallsSysEnterMount      *ebpf.Program `ebpf:"ptcpdump_tracepoint__syscalls__sys_enter_mount"`
	PtcpdumpTracepointSyscallsSysExitMount       *ebpf.Program `ebpf:"ptcpdump_tracepoint__syscalls__sys_exit_mount"`
	PtcpdumpUprobeGoBuiltinTlsWriteKeyLog        *ebpf.Program `ebpf:"ptcpdump_uprobe__go_builtin__tls__write_key_log"`
	PtcpdumpUprobeGoBuiltinTlsWriteKeyLogRet     *ebpf.Program `ebpf:"ptcpdump_uprobe__go_builtin__tls__write_key_log__ret"`
}

func (p *bpf_no_tracingPrograms) Close() error {
	return _Bpf_no_tracingClose(
		p.PtcpdumpCgroupSockCreate,
		p.PtcpdumpCgroupSockRelease,
		p.PtcpdumpCgroupSkbEgress,
		p.PtcpdumpCgroupSkbIngress,
		p.PtcpdumpKprobeDevChangeNetNamespace,
		p.PtcpdumpKprobeDevChangeNetNamespaceLegacy,
		p.PtcpdumpKprobeNfNatManipPkt,
		p.PtcpdumpKprobeNfNatPacket,
		p.PtcpdumpKprobeRegisterNetdevice,
		p.PtcpdumpKprobeSecuritySkClassifyFlow,
		p.PtcpdumpKprobeTcpSendmsg,
		p.PtcpdumpKprobeUdpSendSkb,
		p.PtcpdumpKprobeUdpSendmsg,
		p.PtcpdumpKretprobeDevChangeNetNamespace,
		p.PtcpdumpKretprobeDevChangeNetNamespaceLegacy,
		p.PtcpdumpKretprobeDevGetByIndex,
		p.PtcpdumpKretprobeDevGetByIndexLegacy,
		p.PtcpdumpKretprobeRegisterNetdevice,
		p.PtcpdumpRawTracepointSchedProcessExec,
		p.PtcpdumpRawTracepointSchedProcessExit,
		p.PtcpdumpRawTracepointSchedProcessFork,
		p.PtcpdumpTcEgress,
		p.PtcpdumpTcIngress,
		p.PtcpdumpTracepointSyscallsSysEnterMount,
		p.PtcpdumpTracepointSyscallsSysExitMount,
		p.PtcpdumpUprobeGoBuiltinTlsWriteKeyLog,
		p.PtcpdumpUprobeGoBuiltinTlsWriteKeyLogRet,
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
//go:embed bpf_no_tracing_arm64_bpfel.o
var _Bpf_no_tracingBytes []byte
