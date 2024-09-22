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
	KprobeTcpSendmsg                 *ebpf.Program `ebpf:"kprobe__tcp_sendmsg"`
	KprobeUdpSendmsg                 *ebpf.Program `ebpf:"kprobe__udp_sendmsg"`
	KprobeUdpSendSkb                 *ebpf.Program `ebpf:"kprobe__udp_send_skb"`
	KprobeNfNatManipPkt              *ebpf.Program `ebpf:"kprobe__nf_nat_manip_pkt"`
	KprobeNfNatPacket                *ebpf.Program `ebpf:"kprobe__nf_nat_packet"`
	KprobeSecuritySkClassifyFlow     *ebpf.Program `ebpf:"kprobe__security_sk_classify_flow"`
	RawTracepointSchedProcessExec    *ebpf.Program `ebpf:"raw_tracepoint__sched_process_exec"`
	RawTracepointSchedProcessExit    *ebpf.Program `ebpf:"raw_tracepoint__sched_process_exit"`
	RawTracepointSchedProcessFork    *ebpf.Program `ebpf:"raw_tracepoint__sched_process_fork"`
	TcEgress                         *ebpf.Program `ebpf:"tc_egress"`
	TcIngress                        *ebpf.Program `ebpf:"tc_ingress"`
	UprobeGoBuiltinTlsWriteKeyLog    *ebpf.Program `ebpf:"uprobe__go_builtin__tls__write_key_log"`
	UprobeGoBuiltinTlsWriteKeyLogRet *ebpf.Program `ebpf:"uprobe__go_builtin__tls__write_key_log__ret"`

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
