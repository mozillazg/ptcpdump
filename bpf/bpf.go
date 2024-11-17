package bpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/jschwinger233/elibpcap"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/types"
	"golang.org/x/sys/unix"
)

// $TARGET is set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target $TARGET -type gconfig_t -type packet_event_t -type exec_event_t -type exit_event_t -type flow_pid_key_t -type process_meta_t -type packet_event_meta_t -type go_keylog_event_t -type new_netdevice_event_t -type netdevice_change_event_t -type mount_event_t Bpf ./ptcpdump.c -- -I./headers -I./headers/$TARGET -I. -Wall

const tcFilterName = "ptcpdump"
const logSzie = ebpf.DefaultVerifierLogSize * 64

type BPF struct {
	spec       *ebpf.CollectionSpec
	objs       *BpfObjects
	links      []link.Link
	opts       Options
	closeFuncs []func()

	skipAttachCgroup bool
	isLegacyKernel   bool
	report           *types.CountReport
}

type Options struct {
	haveFilter     uint8
	pids           []uint32
	comm           [16]int8
	filterComm     uint8
	followForks    uint8
	pcapFilter     string
	mntnsIds       []uint32
	pidnsIds       []uint32
	netnsIds       []uint32
	maxPayloadSize uint32
	hookMount      bool
	hookNetDev     bool
	kernelTypes    *btf.Spec
}

func NewBPF() (*BPF, error) {
	var legacyKernel bool
	var skipAttachCgroup bool
	if ok, err := isLegacyKernel(); err != nil {
		log.Warnf("%s", err)
	} else {
		legacyKernel = ok
	}
	if !supportCgroupSock() {
		skipAttachCgroup = true
		legacyKernel = true
	}

	b := _BpfBytes
	if legacyKernel {
		b = _Bpf_legacyBytes
		skipAttachCgroup = true
	} else {
		if !supportTracing() {
			b = _Bpf_no_tracingBytes
		}
	}

	spec, err := loadBpfWithData(b)
	if err != nil {
		return nil, err
	}

	bf := &BPF{
		spec:             spec,
		objs:             &BpfObjects{},
		report:           &types.CountReport{},
		isLegacyKernel:   legacyKernel,
		skipAttachCgroup: skipAttachCgroup,
	}

	return bf, nil
}

func (b *BPF) Load(opts Options) error {
	log.Infof("load with opts: %#v", opts)
	var err error

	config := BpfGconfigT{
		HaveFilter:        opts.haveFilter,
		FilterFollowForks: opts.followForks,
		FilterComm:        opts.comm,
		FilterCommEnable:  opts.filterComm,
		MaxPayloadSize:    opts.maxPayloadSize,
	}
	if !b.isLegacyKernel {
		log.Infof("rewrite constants with %+v", config)
		err = b.spec.RewriteConstants(map[string]interface{}{
			"g": config,
		})
		if err != nil {
			return fmt.Errorf("rewrite constants: %w", err)
		}
	}

	if opts.pcapFilter != "" {
		for _, progName := range []string{"tc_ingress", "tc_egress"} {
			prog, ok := b.spec.Programs[progName]
			if !ok {
				return fmt.Errorf("program %s not found", progName)
			}
			prog.Instructions, err = elibpcap.Inject(
				opts.pcapFilter,
				prog.Instructions,
				elibpcap.Options{
					AtBpf2Bpf:  "pcap_filter",
					DirectRead: true,
					L2Skb:      true,
				},
			)
			if err != nil {
				return fmt.Errorf("inject pcap filter: %w", err)
			}
		}
	}

	err = b.spec.LoadAndAssign(b.objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes: opts.kernelTypes,
			LogLevel:    ebpf.LogLevelInstruction,
			LogSize:     logSzie,
		},
		IgnoreUnknownProgram:      true,
		IgnoreNotSupportedProgram: true,
	})
	if err != nil {
		return fmt.Errorf("bpf load and assign: %w", err)
	}

	b.opts = opts

	if b.isLegacyKernel {
		log.Infof("update config map with %+v", config)
		key := uint32(0)
		if err := b.objs.BpfMaps.ConfigMap.Update(key, config, ebpf.UpdateAny); err != nil {
			return fmt.Errorf(": %w", err)
		}
	}
	if err := b.applyFilters(); err != nil {
		return fmt.Errorf(": %w", err)
	}

	return nil
}

func (b *BPF) Close() {
	for _, lk := range b.links {
		if err := lk.Close(); err != nil {
			log.Warnf("[bpf] close link %v failed: %+v", lk, err)
		}
	}
	for i := len(b.closeFuncs) - 1; i >= 0; i-- {
		f := b.closeFuncs[i]
		f()
	}
	if err := b.objs.Close(); err != nil {
		log.Warnf("[bpf] close objects failed: %+v", err)
	}
}

func (b *BPF) UpdateFlowPidMapValues(data map[*BpfFlowPidKeyT]BpfProcessMetaT) error {
	for k, v := range data {
		err := b.objs.BpfMaps.FlowPidMap.Update(*k, v, ebpf.UpdateNoExist)
		if err != nil {
			if err == ebpf.ErrKeyExist || strings.Contains(err.Error(), "key already exists") {
				continue
			}
			return fmt.Errorf(": %w", err)
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
		return fmt.Errorf("attach cgroup/sock_create: %w", err)
	}
	b.links = append(b.links, lk)

	lk, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCgroupInetSockRelease,
		Program: b.objs.CgroupSockRelease,
	})
	if err != nil {
		return fmt.Errorf("attach cgroup/sock_release: %w", err)
	}
	b.links = append(b.links, lk)

	return nil
}

func (b *BPF) AttachKprobes() error {
	err := b.attachFentryOrKprobe("security_sk_classify_flow",
		b.objs.FentrySecuritySkClassifyFlow, b.objs.KprobeSecuritySkClassifyFlow)
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	err = b.attachFentryOrKprobe("tcp_sendmsg",
		b.objs.FentryTcpSendmsg, b.objs.KprobeTcpSendmsg)
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	err = b.attachFentryOrKprobe("udp_send_skb", b.objs.FentryUdpSendSkb, b.objs.KprobeUdpSendSkb)
	if err != nil {
		log.Infof("%+v", err)
		if strings.Contains(err.Error(), "no such file or directory") {
			err = b.attachFentryOrKprobe("udp_sendmsg", b.objs.FentryUdpSendmsg, b.objs.KprobeUdpSendmsg)
			if err != nil {
				return fmt.Errorf(": %w", err)
			}
		} else {
			return fmt.Errorf(": %w", err)
		}
	}

	err = b.attachFentryOrKprobe("nf_nat_packet",
		b.objs.FentryNfNatPacket, b.objs.KprobeNfNatPacket)
	if err != nil {
		log.Infof("%+v", err)
		if strings.Contains(err.Error(), "no such file or directory") {
			log.Info("the kernel does not support netfilter based NAT feature, skip attach kprobe/nf_nat_packet")
		} else {
			return fmt.Errorf(": %w", err)
		}
	}

	err = b.attachFentryOrKprobe("nf_nat_manip_pkt",
		b.objs.FentryNfNatManipPkt, b.objs.KprobeNfNatManipPkt)
	if err != nil {
		log.Infof("%+v", err)
		if strings.Contains(err.Error(), "no such file or directory") {
			log.Info("the kernel does not support netfilter based NAT feature, skip attach kprobe/nf_nat_manip_pkt")
		} else {
			return fmt.Errorf(": %w", err)
		}
	}

	return b.attachNetDevHooks()
}

func (b *BPF) attachNetDevHooks() error {
	if !b.opts.hookNetDev {
		return nil
	}

	err := b.attachFexitOrKprobe("register_netdevice",
		nil, b.objs.KprobeRegisterNetdevice, b.objs.KretprobeRegisterNetdevice)
	if err != nil {
		return err
	}

	// TODO: refine
	err = b.attachFexitOrKprobe("__dev_get_by_index",
		nil, nil, b.objs.KretprobeDevGetByIndex)
	if err != nil {
		log.Infof("%+v", err)
		if strings.Contains(err.Error(), "no such file or directory") {
			err = b.attachFexitOrKprobe("dev_get_by_index",
				nil, nil, b.objs.KretprobeDevGetByIndexLegacy)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	err = b.attachFentryOrKprobe("__dev_change_net_namespace",
		nil, b.objs.KprobeDevChangeNetNamespace)
	if err != nil {
		log.Infof("%+v", err)
		if strings.Contains(err.Error(), "no such file or directory") {
			err = b.attachFentryOrKprobe("dev_change_net_namespace",
				nil, b.objs.KprobeDevChangeNetNamespaceLegacy)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	err = b.attachFexitOrKprobe("__dev_change_net_namespace",
		nil, nil, b.objs.KretprobeDevChangeNetNamespace)
	if err != nil {
		log.Infof("%+v", err)
		if strings.Contains(err.Error(), "no such file or directory") {
			err = b.attachFexitOrKprobe("dev_change_net_namespace",
				nil, nil, b.objs.KretprobeDevChangeNetNamespaceLegacy)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	return nil
}

func (b *BPF) AttachTracepoints() error {
	err := b.attachBTFTracepointOrRawTP("sched_process_exec",
		b.objs.TpBtfSchedProcessExec, b.objs.RawTracepointSchedProcessExec,
	)
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	err = b.attachBTFTracepointOrRawTP("sched_process_exit",
		b.objs.TpBtfSchedProcessExit, b.objs.RawTracepointSchedProcessExit,
	)
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	if b.opts.attachForks() {
		err := b.attachBTFTracepointOrRawTP("sched_process_fork",
			b.objs.TpBtfSchedProcessFork, b.objs.RawTracepointSchedProcessFork,
		)
		if err != nil {
			return fmt.Errorf(": %w", err)
		}
	}

	if b.opts.hookMount {
		log.Info("attaching tracepoint/syscalls/sys_enter_mount")
		lk, err := link.Tracepoint("syscalls", "sys_enter_mount", b.objs.TracepointSyscallsSysEnterMount, &link.TracepointOptions{})
		if err != nil {
			return fmt.Errorf("attach tracepoint/syscalls/sys_enter_mount: %w", err)
		}
		b.links = append(b.links, lk)
		log.Info("attaching tracepoint/syscalls/sys_exit_mount")
		lk, err = link.Tracepoint("syscalls", "sys_exit_mount", b.objs.TracepointSyscallsSysExitMount, &link.TracepointOptions{})
		if err != nil {
			return fmt.Errorf("attach tracepoint/syscalls/sys_exit_mount: %w", err)
		}
		b.links = append(b.links, lk)
	}

	return nil
}

func (b *BPF) AttachTcHooks(ifindex int, egress, ingress bool) ([]func(), error) {
	var closeFuncs []func()
	closeFunc, err := ensureTcQdisc(ifindex)
	if err != nil {
		closeFuncs = append(closeFuncs, closeFunc)
		return closeFuncs, fmt.Errorf("attach tc hooks: %w", err)
	}

	if egress {
		c1, err := attachTcHook(ifindex, b.objs.TcEgress, false)
		if err != nil {
			closeFuncs = append(closeFuncs, c1)
			return closeFuncs, fmt.Errorf("attach tc hooks: %w", err)
		}
		closeFuncs = append(closeFuncs, c1)
	}

	if ingress {
		c2, err := attachTcHook(ifindex, b.objs.TcIngress, true)
		if err != nil {
			closeFuncs = append(closeFuncs, c2)
			return closeFuncs, fmt.Errorf("attach tc hooks: %w", err)
		}
		closeFuncs = append(closeFuncs, c2)
	}

	return closeFuncs, nil
}

func (opts Options) attachForks() bool {
	return opts.followForks == 1
}

func attachTcHook(ifindex int, prog *ebpf.Program, ingress bool) (func(), error) {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return nil, err
	}
	closeFunc := func() {
		if err := tcnl.Close(); err != nil {
			if !strings.Contains(err.Error(), "no such device") {
				log.Warnf("tcnl.Close() failed: %+v", err)
			}
		}
	}

	var filter *tc.Object
	fd := uint32(prog.FD())
	name := tcFilterName
	parent := tc.HandleMinEgress
	if ingress {
		parent = tc.HandleMinIngress
	}
	flags := uint32(tc.BpfActDirect)

	// don't overwrite other filters
	for hid := uint32(1); hid < 128; hid++ {
		filter = &tc.Object{
			Msg: tc.Msg{
				Family:  unix.AF_UNSPEC,
				Ifindex: uint32(ifindex),
				Handle:  hid,
				Parent:  core.BuildHandle(tc.HandleRoot, parent),
				Info:    1<<16 | uint32(htons(unix.ETH_P_ALL)), // priority (1) << 16 | proto (htons(ETH_P_ALL))
			},
			Attribute: tc.Attribute{
				Kind: "bpf",
				BPF: &tc.Bpf{
					FD:    &fd,
					Name:  &name,
					Flags: &flags,
				},
			},
		}
		log.Infof("try to add tc filter with handle %d to %d", hid, ifindex)
		if err = tcnl.Filter().Add(filter); err != nil {
			log.Infof("add tc filter: %+v", err)
			if !errors.Is(err, unix.EEXIST) {
				return closeFunc, fmt.Errorf("add tc filter: %w", err)
			} else {
				// TODO: check and remove dead filter?
			}
		} else {
			break
		}
	}

	if err != nil {
		return closeFunc, fmt.Errorf("add tc filter: %w", err)
	}

	newCloseFunc := func() {
		if err := tcnl.Filter().Delete(filter); err != nil {
			// TODO: change to use errors.Is
			if !(strings.Contains(err.Error(), "no such device") ||
				strings.Contains(err.Error(), "no such file or directory")) {
				log.Warnf("delete tcnl filter failed: %+v", err)
			}
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
			// TODO: change to use errors.Is
			if !strings.Contains(err.Error(), "no such device") {
				log.Warnf("tcnl.Close() failed: %+v", err)
			}
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

	if err := tcnl.Qdisc().Add(&qdisc); err != nil {
		log.Infof("%s", err)
		if !errors.Is(err, unix.EEXIST) {
			return closeFunc, fmt.Errorf("add clsact qdisc to ifindex %d: %w", ifindex, err)
		}
	}

	return closeFunc, nil
}

func htons(n uint16) uint16 {
	b := *(*[2]byte)(unsafe.Pointer(&n))
	return binary.BigEndian.Uint16(b[:])
}

func (b *BPF) applyFilters() error {
	value := uint8(0)
	opts := b.opts

	log.Infof("start to update FilterPidMap with %+v", opts.pids)
	for _, pid := range opts.pids {
		pid := pid
		if err := b.objs.BpfMaps.FilterPidMap.Update(pid, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update FilterPidMap: %w", err)
		}
	}

	log.Infof("start to update FilterPidnsMap with %+v", opts.pidnsIds)
	for _, id := range opts.pidnsIds {
		id := id
		if err := b.objs.BpfMaps.FilterPidnsMap.Update(id, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update FilterPidnsMap: %w", err)
		}
	}

	log.Infof("start to update FilterMntnsMap with %+v", opts.mntnsIds)
	for _, id := range opts.mntnsIds {
		id := id
		if err := b.objs.BpfMaps.FilterMntnsMap.Update(id, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update FilterMntnsMap: %w", err)
		}
	}

	log.Infof("start to update FilterNetnsMap with %+v", opts.netnsIds)
	for _, id := range opts.netnsIds {
		id := id
		if err := b.objs.BpfMaps.FilterNetnsMap.Update(id, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update FilterNetnsMap: %w", err)
		}
	}

	return nil
}

func (opts *Options) WithPids(pids []uint) *Options {
	for _, id := range pids {
		if id == 0 {
			continue
		}
		opts.pids = append(opts.pids, uint32(id))
	}
	if len(opts.pids) > 0 {
		opts.haveFilter = 1
	}
	return opts
}

func (opts *Options) WithComm(comm string) *Options {
	opts.comm = [16]int8{}
	if len(comm) > 0 {
		opts.haveFilter = 1
		for i, s := range comm {
			if i == 15 {
				break
			}
			opts.comm[i] = int8(s)
		}
		opts.comm[15] = '\x00'
		opts.filterComm = 1
	}
	return opts
}

func (opts *Options) WithFollowFork(v bool) *Options {
	if v {
		opts.followForks = 1
	} else {
		opts.followForks = 0
	}
	return opts
}

func (opts *Options) WithPidNsIds(ids []uint32) *Options {
	for _, id := range ids {
		if id == 0 {
			continue
		}
		opts.pidnsIds = append(opts.pidnsIds, id)
	}
	if len(opts.pidnsIds) > 0 {
		opts.haveFilter = 1
	}
	return opts
}
func (opts *Options) WithMntNsIds(ids []uint32) *Options {
	for _, id := range ids {
		if id == 0 {
			continue
		}
		opts.mntnsIds = append(opts.mntnsIds, id)
	}
	if len(opts.mntnsIds) > 0 {
		opts.haveFilter = 1
	}
	return opts
}
func (opts *Options) WithNetNsIds(ids []uint32) *Options {
	for _, id := range ids {
		if id == 0 {
			continue
		}
		opts.netnsIds = append(opts.netnsIds, id)
	}
	if len(opts.netnsIds) > 0 {
		opts.haveFilter = 1
	}
	return opts
}
func (opts *Options) WithPcapFilter(pcapFilter string) *Options {
	opts.pcapFilter = strings.TrimSpace(pcapFilter)
	return opts
}

func (opts *Options) WithMaxPayloadSize(n uint32) *Options {
	opts.maxPayloadSize = n
	return opts
}

func (opts *Options) WithHookMount(v bool) *Options {
	opts.hookMount = v
	return opts
}

func (opts *Options) WithHookNetDev(v bool) *Options {
	opts.hookNetDev = v
	return opts
}

func (opts *Options) WithKernelTypes(spec *btf.Spec) *Options {
	opts.kernelTypes = spec
	return opts
}
