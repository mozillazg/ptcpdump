package bpf

import (
	"encoding/binary"
	"log"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/jschwinger233/elibpcap"
	"github.com/mozillazg/ptcpdump/internal/types"
	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

// $TARGET is set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target $TARGET -type packet_event_t -type exec_event_t -type flow_pid_key_t -type process_meta_t -type packet_event_meta_t Bpf ./ptcpdump.c -- -I./headers -I./headers/$TARGET -I. -Wall

const tcFilterName = "ptcpdump"

type BpfObjectsWithoutCgroup struct {
	KprobeTcpSendmsg              *ebpf.Program `ebpf:"kprobe__tcp_sendmsg"`
	KprobeUdpSendmsg              *ebpf.Program `ebpf:"kprobe__udp_sendmsg"`
	KprobeUdpSendSkb              *ebpf.Program `ebpf:"kprobe__udp_send_skb"`
	KprobeNfNatManipPkt           *ebpf.Program `ebpf:"kprobe__nf_nat_manip_pkt"`
	KprobeNfNatPacket             *ebpf.Program `ebpf:"kprobe__nf_nat_packet"`
	KprobeSecuritySkClassifyFlow  *ebpf.Program `ebpf:"kprobe__security_sk_classify_flow"`
	RawTracepointSchedProcessExec *ebpf.Program `ebpf:"raw_tracepoint__sched_process_exec"`
	RawTracepointSchedProcessExit *ebpf.Program `ebpf:"raw_tracepoint__sched_process_exit"`
	RawTracepointSchedProcessFork *ebpf.Program `ebpf:"raw_tracepoint__sched_process_fork"`
	TcEgress                      *ebpf.Program `ebpf:"tc_egress"`
	TcIngress                     *ebpf.Program `ebpf:"tc_ingress"`

	BpfMaps
}

type BPF struct {
	spec       *ebpf.CollectionSpec
	objs       *BpfObjects
	links      []link.Link
	opts       Options
	closeFuncs []func()

	skipAttachCgroup bool
	report           *types.CountReport
}

type Options struct {
	Pid         uint32
	Comm        [16]int8
	filterComm  uint8
	FollowForks uint8
	PcapFilter  string
	mntns_id    uint32
	pidns_id    uint32
	netns_id    uint32
}

func NewBPF() (*BPF, error) {
	spec, err := LoadBpf()
	if err != nil {
		return nil, err
	}
	return &BPF{
		spec:   spec,
		objs:   &BpfObjects{},
		report: &types.CountReport{},
	}, nil
}

func NewOptions(pid uint, comm string, followForks bool, pcapFilter string,
	mntns_id uint32, pidns_id uint32, netns_id uint32) Options {
	opts := Options{
		Pid:      uint32(pid),
		mntns_id: mntns_id,
		pidns_id: pidns_id,
		netns_id: netns_id,
	}
	opts.Comm = [16]int8{}
	if len(comm) > 0 {
		for i, s := range comm {
			if i == 15 {
				break
			}
			opts.Comm[i] = int8(s)
		}
		opts.Comm[15] = '\x00'
		opts.filterComm = 1
	}
	opts.FollowForks = 0
	if followForks {
		opts.FollowForks = 1
	}
	opts.PcapFilter = strings.TrimSpace(pcapFilter)

	return opts
}

func (b *BPF) Load(opts Options) error {
	// log.Printf("%#v", opts)
	err := b.spec.RewriteConstants(map[string]interface{}{
		"filter_pid":          opts.Pid,
		"filter_comm":         opts.Comm,
		"filter_comm_enable":  opts.filterComm,
		"filter_follow_forks": opts.FollowForks,
		"filter_mntns_id":     opts.mntns_id,
		"filter_netns_id":     opts.netns_id,
		"filter_pidns_id":     opts.pidns_id,
	})
	if err != nil {
		return xerrors.Errorf("rewrite constants: %w", err)
	}

	if opts.PcapFilter != "" {
		for _, progName := range []string{"tc_ingress", "tc_egress"} {
			prog, ok := b.spec.Programs[progName]
			if !ok {
				return xerrors.Errorf("program %s not found", progName)
			}
			prog.Instructions, err = elibpcap.Inject(
				opts.PcapFilter,
				prog.Instructions,
				elibpcap.Options{
					AtBpf2Bpf:  "pcap_filter",
					DirectRead: true,
					L2Skb:      true,
				},
			)
			if err != nil {
				return xerrors.Errorf("inject pcap filter: %w", err)
			}
		}
	}

	err = b.spec.LoadAndAssign(b.objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  ebpf.DefaultVerifierLogSize * 32,
		},
	})
	if err != nil {
		if strings.Contains(err.Error(), "unknown func bpf_get_socket_cookie") {
			log.Printf("will skip attach cgroup due to %s", err)

			b.skipAttachCgroup = true
			objs := BpfObjectsWithoutCgroup{}
			if err = b.spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
				Programs: ebpf.ProgramOptions{
					LogLevel: ebpf.LogLevelInstruction,
					LogSize:  ebpf.DefaultVerifierLogSize * 32,
				},
			}); err != nil {
				return err
			}
			b.objs.KprobeTcpSendmsg = objs.KprobeTcpSendmsg
			b.objs.KprobeUdpSendmsg = objs.KprobeUdpSendmsg
			b.objs.KprobeUdpSendSkb = objs.KprobeUdpSendSkb
			b.objs.KprobeNfNatManipPkt = objs.KprobeNfNatManipPkt
			b.objs.KprobeNfNatPacket = objs.KprobeNfNatPacket
			b.objs.KprobeSecuritySkClassifyFlow = objs.KprobeSecuritySkClassifyFlow
			b.objs.RawTracepointSchedProcessExec = objs.RawTracepointSchedProcessExec
			b.objs.RawTracepointSchedProcessExit = objs.RawTracepointSchedProcessExit
			b.objs.RawTracepointSchedProcessFork = objs.RawTracepointSchedProcessFork
			b.objs.TcEgress = objs.TcEgress
			b.objs.TcIngress = objs.TcIngress
			b.objs.BpfMaps = objs.BpfMaps
		} else {
			return err
		}
	}
	b.opts = opts

	return nil
}

func (b *BPF) Close() {
	for _, lk := range b.links {
		if err := lk.Close(); err != nil {
			log.Printf("[bpf] close link %v failed: %+v", lk, err)
		}
	}
	for i := len(b.closeFuncs) - 1; i >= 0; i-- {
		f := b.closeFuncs[i]
		f()
	}
	if err := b.objs.Close(); err != nil {
		log.Printf("[bpf] close objects failed: %+v", err)
	}
}

func (b *BPF) UpdateFlowPidMapValues(data map[*BpfFlowPidKeyT]BpfProcessMetaT) error {
	for k, v := range data {
		err := b.objs.FlowPidMap.Update(*k, v, ebpf.UpdateNoExist)
		if err != nil {
			if err == ebpf.ErrKeyExist || strings.Contains(err.Error(), "key already exists") {
				continue
			}
			return xerrors.Errorf(": %w", err)
		}
	}
	return nil
}

func (b *BPF) AttachCgroups(cgroupPath string) error {
	if b.skipAttachCgroup {
		return nil
	}

	lk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetSockCreate,
		Program: b.objs.CgroupSockCreate,
	})
	if err != nil {
		return xerrors.Errorf("attach cgroup/sock_create: %w", err)
	}
	b.links = append(b.links, lk)

	lk, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCgroupInetSockRelease,
		Program: b.objs.CgroupSockRelease,
	})
	if err != nil {
		return xerrors.Errorf("attach cgroup/sock_release: %w", err)
	}
	b.links = append(b.links, lk)

	return nil
}

func (b *BPF) AttachKprobes() error {
	lk, err := link.Kprobe("security_sk_classify_flow",
		b.objs.KprobeSecuritySkClassifyFlow, &link.KprobeOptions{})
	if err != nil {
		return xerrors.Errorf("attach kprobe/security_sk_classify_flow: %w", err)
	}
	b.links = append(b.links, lk)

	lk, err = link.Kprobe("tcp_sendmsg",
		b.objs.KprobeTcpSendmsg, &link.KprobeOptions{})
	if err != nil {
		return xerrors.Errorf("attach kprobe/tcp_sendmsg: %w", err)
	}
	b.links = append(b.links, lk)

	lk, err = link.Kprobe("udp_send_skb", b.objs.KprobeUdpSendSkb, &link.KprobeOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "no such file or directory") {
			lk, err = link.Kprobe("udp_sendmsg", b.objs.KprobeUdpSendmsg, &link.KprobeOptions{})
			if err != nil {
				return xerrors.Errorf("attach kprobe/udp_sendmsg: %w", err)
			}
		} else {
			return xerrors.Errorf("attach kprobe/udp_send_skb: %w", err)
		}
	}
	b.links = append(b.links, lk)

	lk, err = link.Kprobe("nf_nat_packet",
		b.objs.KprobeNfNatPacket, &link.KprobeOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "nf_nat_packet: not found: no such file or directory") {
			log.Println("current system doest not enable netfilter based NAT feature, skip attach kprobe/nf_nat_packet")
		} else {
			return xerrors.Errorf("attach kprobe/nf_nat_packet: %w", err)
		}
	}
	if lk != nil {
		b.links = append(b.links, lk)
	}

	lk, err = link.Kprobe("nf_nat_manip_pkt",
		b.objs.KprobeNfNatManipPkt, &link.KprobeOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "nf_nat_manip_pkt: not found: no such file or directory") {
			log.Println("current system doest not enable netfilter based NAT feature, skip attach kprobe/nf_nat_manip_pkt")
		} else {
			return xerrors.Errorf("attach kprobe/nf_nat_manip_pkt: %w", err)
		}
	}
	if lk != nil {
		b.links = append(b.links, lk)
	}

	return nil
}

func (b *BPF) AttachTracepoints() error {
	lk, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exec",
		Program: b.objs.RawTracepointSchedProcessExec,
	})
	if err != nil {
		return xerrors.Errorf("attach raw_tracepoint/sched_process_exec: %w", err)
	}
	b.links = append(b.links, lk)

	lk, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exit",
		Program: b.objs.RawTracepointSchedProcessExit,
	})
	if err != nil {
		return xerrors.Errorf("attach raw_tracepoint/sched_process_exit: %w", err)
	}
	b.links = append(b.links, lk)

	if b.opts.attachForks() {
		lk, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    "sched_process_fork",
			Program: b.objs.RawTracepointSchedProcessFork,
		})
		if err != nil {
			return xerrors.Errorf("attach raw_tracepoint/sched_process_fork: %w", err)
		}
		b.links = append(b.links, lk)
	}

	return nil
}

func (b *BPF) AttachTcHooks(ifindex int, egress, ingress bool) error {
	closeFunc, err := ensureTcQdisc(ifindex)
	if err != nil {
		if closeFunc != nil {
			closeFunc()
		}
		return xerrors.Errorf("attach tc hooks: %w", err)
	}

	if egress {
		c1, err := attachTcHook(ifindex, b.objs.TcEgress, false)
		if err != nil {
			if c1 != nil {
				c1()
			}
			closeFunc()
			return xerrors.Errorf("attach tc hooks: %w", err)
		}
		b.closeFuncs = append(b.closeFuncs, c1)
	}

	if ingress {
		c2, err := attachTcHook(ifindex, b.objs.TcIngress, true)
		if err != nil {
			if c2 != nil {
				c2()
			}
			closeFunc()
			return xerrors.Errorf("attach tc hooks: %w", err)
		}
		b.closeFuncs = append(b.closeFuncs, c2)
	}

	return nil
}

func (o Options) attachForks() bool {
	return o.FollowForks == 1
}

func attachTcHook(ifindex int, prog *ebpf.Program, ingress bool) (func(), error) {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return nil, err
	}
	closeFunc := func() {
		if err := tcnl.Close(); err != nil {
			log.Printf("tcnl.Close() failed: %+v", err)
		}
	}

	fd := uint32(prog.FD())
	name := tcFilterName
	parent := tc.HandleMinEgress
	if ingress {
		parent = tc.HandleMinIngress
	}

	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(ifindex),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, parent),
			Info:    1<<16 | uint32(htons(unix.ETH_P_ALL)),
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:   &fd,
				Name: &name,
			},
		},
	}
	if err := tcnl.Filter().Add(&filter); err != nil {
		return closeFunc, xerrors.Errorf("add filter: %w", err)
	}

	newCloseFunc := func() {
		if err := tcnl.Filter().Delete(&filter); err != nil {
			log.Printf("delete tcnl filter failed: %+v", err)
		}
		closeFunc()
	}
	return newCloseFunc, nil
}

func ensureTcQdisc(ifindex int) (func(), error) {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return nil, err
	}
	closeFunc := func() {
		if err := tcnl.Close(); err != nil {
			log.Printf("tcnl.Close() failed: %+v", err)
		}
	}

	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(ifindex),
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}

	if err := tcnl.Qdisc().Replace(&qdisc); err != nil {
		return closeFunc, err
	}

	newCloseFunc := func() {
		if err := tcnl.Qdisc().Delete(&qdisc); err != nil {
			log.Printf("delete tcnl qdisc failed: %+v", err)
		}
		closeFunc()
	}

	return newCloseFunc, nil
}

func htons(n uint16) uint16 {
	b := *(*[2]byte)(unsafe.Pointer(&n))
	return binary.BigEndian.Uint16(b[:])
}
