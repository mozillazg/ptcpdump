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
	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type ptcpdump_config_t -type packet_event_t -type exec_event_t Bpf ./ptcpdump.c -- -I./headers -I. -Wall

const tcFilterName = "ptcpdump"

type BPF struct {
	spec       *ebpf.CollectionSpec
	objs       *BpfObjects
	links      []link.Link
	opts       Options
	closeFuncs []func()
}

type Options struct {
	Pid         uint32
	Comm        [16]int8
	filterComm  uint8
	FollowForks uint8
	PcapFilter  string
}

func NewBPF() (*BPF, error) {
	spec, err := LoadBpf()
	if err != nil {
		return nil, err
	}
	return &BPF{
		spec: spec,
		objs: &BpfObjects{},
	}, nil
}

func NewOptions(pid uint, comm string, followForks bool, pcapFilter string) Options {
	opts := Options{
		Pid: uint32(pid),
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
	var err error
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
			LogSize:  ebpf.DefaultVerifierLogSize * 8,
		},
	})
	if err != nil {
		return err
	}
	b.opts = opts

	err = b.objs.PtcpdumpConfig.Update(uint32(0), BpfPtcpdumpConfigT{
		FilterPid:         opts.Pid,
		FilterFollowForks: opts.FollowForks,
		FilterCommEnable:  opts.filterComm,
		FilterComm:        opts.Comm,
	}, ebpf.UpdateAny)
	if err != nil {
		return err
	}

	return nil
}

func (b *BPF) Close() {
	for _, lk := range b.links {
		if err := lk.Close(); err != nil {
			log.Printf("[bpf] close link %v failed: %+v", lk, err)
		}
	}
	for i := len(b.closeFuncs) - 1; i > 0; i-- {
		f := b.closeFuncs[i]
		f()
	}
	if err := b.objs.Close(); err != nil {
		log.Printf("[bpf] close objects failed: %+v", err)
	}
}

func (b *BPF) AttachKprobes() error {
	lk, err := link.Kprobe("security_sk_classify_flow",
		b.objs.KprobeSecuritySkClassifyFlow, &link.KprobeOptions{})
	if err != nil {
		return xerrors.Errorf("attach kprobe/security_sk_classify_flow: %w", err)
	}
	b.links = append(b.links, lk)
	return nil
}

func (b *BPF) AttachTracepoints() error {
		lk, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			"sched_process_exec",
			b.objs.RawTracepointSchedProcessExec,
		})
	if err != nil {
		return xerrors.Errorf("attach raw_tracepoint/sched_process_exec: %w", err)
	}
	b.links = append(b.links, lk)

	if b.opts.attachForks() {
		lk, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			"sched_process_fork",
			b.objs.RawTracepointSchedProcessFork,
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
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(ifindex),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, parent),
			Info:    1<<16 | uint32(htons(unix.ETH_P_ALL)),
		},
		tc.Attribute{
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
