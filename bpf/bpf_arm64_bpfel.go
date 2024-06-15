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

type BpfExecEventT struct {
	Meta              BpfProcessMetaT
	FilenameTruncated uint8
	ArgsTruncated     uint8
	_                 [2]byte
	ArgsSize          uint32
	Filename          [512]int8
	Args              [4096]int8
}

type BpfFlowPidKeyT struct {
	Saddr [2]uint64
	Sport uint16
	_     [6]byte
}

type BpfNatFlowT struct {
	Saddr [2]uint64
	Daddr [2]uint64
	Sport uint16
	Dport uint16
	_     [4]byte
}

type BpfPacketEventMetaT struct {
	Timestamp  uint64
	PacketType uint8
	_          [3]byte
	Ifindex    uint32
	PayloadLen uint64
	PacketSize uint64
	Process    BpfProcessMetaT
	_          [4]byte
}

type BpfPacketEventT struct {
	Meta    BpfPacketEventMetaT
	Payload [1500]uint8
	_       [4]byte
}

type BpfProcessMetaT struct {
	Pid        uint32
	MntnsId    uint32
	NetnsId    uint32
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
}

// BpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfProgramSpecs struct {
	CgroupSockCreate              *ebpf.ProgramSpec `ebpf:"cgroup__sock_create"`
	CgroupSockRelease             *ebpf.ProgramSpec `ebpf:"cgroup__sock_release"`
	KprobeNfNatManipPkt           *ebpf.ProgramSpec `ebpf:"kprobe__nf_nat_manip_pkt"`
	KprobeNfNatPacket             *ebpf.ProgramSpec `ebpf:"kprobe__nf_nat_packet"`
	KprobeSecuritySkClassifyFlow  *ebpf.ProgramSpec `ebpf:"kprobe__security_sk_classify_flow"`
	KprobeTcpSendmsg              *ebpf.ProgramSpec `ebpf:"kprobe__tcp_sendmsg"`
	KprobeUdpSendSkb              *ebpf.ProgramSpec `ebpf:"kprobe__udp_send_skb"`
	KprobeUdpSendmsg              *ebpf.ProgramSpec `ebpf:"kprobe__udp_sendmsg"`
	RawTracepointSchedProcessExec *ebpf.ProgramSpec `ebpf:"raw_tracepoint__sched_process_exec"`
	RawTracepointSchedProcessExit *ebpf.ProgramSpec `ebpf:"raw_tracepoint__sched_process_exit"`
	RawTracepointSchedProcessFork *ebpf.ProgramSpec `ebpf:"raw_tracepoint__sched_process_fork"`
	TcEgress                      *ebpf.ProgramSpec `ebpf:"tc_egress"`
	TcIngress                     *ebpf.ProgramSpec `ebpf:"tc_ingress"`
}

// BpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfMapSpecs struct {
	ExecEventStack      *ebpf.MapSpec `ebpf:"exec_event_stack"`
	ExecEvents          *ebpf.MapSpec `ebpf:"exec_events"`
	FilterByKernelCount *ebpf.MapSpec `ebpf:"filter_by_kernel_count"`
	FilterPidMap        *ebpf.MapSpec `ebpf:"filter_pid_map"`
	FlowPidMap          *ebpf.MapSpec `ebpf:"flow_pid_map"`
	NatFlowMap          *ebpf.MapSpec `ebpf:"nat_flow_map"`
	PacketEventStack    *ebpf.MapSpec `ebpf:"packet_event_stack"`
	PacketEvents        *ebpf.MapSpec `ebpf:"packet_events"`
	SockCookiePidMap    *ebpf.MapSpec `ebpf:"sock_cookie_pid_map"`
}

// BpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfObjects struct {
	BpfPrograms
	BpfMaps
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
	ExecEventStack      *ebpf.Map `ebpf:"exec_event_stack"`
	ExecEvents          *ebpf.Map `ebpf:"exec_events"`
	FilterByKernelCount *ebpf.Map `ebpf:"filter_by_kernel_count"`
	FilterPidMap        *ebpf.Map `ebpf:"filter_pid_map"`
	FlowPidMap          *ebpf.Map `ebpf:"flow_pid_map"`
	NatFlowMap          *ebpf.Map `ebpf:"nat_flow_map"`
	PacketEventStack    *ebpf.Map `ebpf:"packet_event_stack"`
	PacketEvents        *ebpf.Map `ebpf:"packet_events"`
	SockCookiePidMap    *ebpf.Map `ebpf:"sock_cookie_pid_map"`
}

func (m *BpfMaps) Close() error {
	return _BpfClose(
		m.ExecEventStack,
		m.ExecEvents,
		m.FilterByKernelCount,
		m.FilterPidMap,
		m.FlowPidMap,
		m.NatFlowMap,
		m.PacketEventStack,
		m.PacketEvents,
		m.SockCookiePidMap,
	)
}

// BpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfPrograms struct {
	CgroupSockCreate              *ebpf.Program `ebpf:"cgroup__sock_create"`
	CgroupSockRelease             *ebpf.Program `ebpf:"cgroup__sock_release"`
	KprobeNfNatManipPkt           *ebpf.Program `ebpf:"kprobe__nf_nat_manip_pkt"`
	KprobeNfNatPacket             *ebpf.Program `ebpf:"kprobe__nf_nat_packet"`
	KprobeSecuritySkClassifyFlow  *ebpf.Program `ebpf:"kprobe__security_sk_classify_flow"`
	KprobeTcpSendmsg              *ebpf.Program `ebpf:"kprobe__tcp_sendmsg"`
	KprobeUdpSendSkb              *ebpf.Program `ebpf:"kprobe__udp_send_skb"`
	KprobeUdpSendmsg              *ebpf.Program `ebpf:"kprobe__udp_sendmsg"`
	RawTracepointSchedProcessExec *ebpf.Program `ebpf:"raw_tracepoint__sched_process_exec"`
	RawTracepointSchedProcessExit *ebpf.Program `ebpf:"raw_tracepoint__sched_process_exit"`
	RawTracepointSchedProcessFork *ebpf.Program `ebpf:"raw_tracepoint__sched_process_fork"`
	TcEgress                      *ebpf.Program `ebpf:"tc_egress"`
	TcIngress                     *ebpf.Program `ebpf:"tc_ingress"`
}

func (p *BpfPrograms) Close() error {
	return _BpfClose(
		p.CgroupSockCreate,
		p.CgroupSockRelease,
		p.KprobeNfNatManipPkt,
		p.KprobeNfNatPacket,
		p.KprobeSecuritySkClassifyFlow,
		p.KprobeTcpSendmsg,
		p.KprobeUdpSendSkb,
		p.KprobeUdpSendmsg,
		p.RawTracepointSchedProcessExec,
		p.RawTracepointSchedProcessExit,
		p.RawTracepointSchedProcessFork,
		p.TcEgress,
		p.TcIngress,
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
