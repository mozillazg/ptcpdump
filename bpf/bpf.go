package bpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/mdlayher/netlink"
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
	"github.com/mozillazg/ptcpdump/internal/utils"
	"golang.org/x/sys/unix"
)

// $TARGET is set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target $TARGET -type gconfig_t -type packet_event_t -type exec_event_t -type exit_event_t -type flow_pid_key_t -type process_meta_t -type packet_event_meta_t -type go_keylog_event_t -type new_netdevice_event_t -type netdevice_change_event_t -type mount_event_t Bpf ./ptcpdump.c -- -I./headers -I./headers/$TARGET -I. -Wall

const tcFilterName = "ptcpdump"
const logSzie = 64 * 1024 * 64

type BPF struct {
	spec       *ebpf.CollectionSpec
	objs       *BpfObjects
	links      []link.Link
	opts       Options
	closeFuncs []func()

	skipAttachCgroup    bool
	skipTcx             bool
	isLegacyKernel      bool
	supportRingBuf      bool
	useRingBufSubmitSkb bool
	report              *types.CountReport
}

type Options struct {
	haveFilter     uint8
	pids           []uint32
	uids           []uint32
	comm           [16]int8
	filterComm     uint8
	followForks    uint8
	pcapFilter     string
	mntnsIds       []uint32
	pidnsIds       []uint32
	netnsIds       []uint32
	ifindexes      []uint32
	maxPayloadSize uint32
	hookMount      bool
	hookNetDev     bool
	kernelTypes    *btf.Spec
	backend        types.NetHookBackend
}

func NewBPF() (*BPF, error) {
	var skipAttachCgroup bool
	legacyKernel := isLegacyKernel()
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
		spec:                spec,
		objs:                &BpfObjects{},
		report:              &types.CountReport{},
		isLegacyKernel:      legacyKernel,
		skipAttachCgroup:    skipAttachCgroup,
		skipTcx:             !supportTcx(),
		supportRingBuf:      !legacyKernel && supportRingBuf(),
		useRingBufSubmitSkb: canUseRingBufSubmitSkb(),
	}

	return bf, nil
}

func (b *BPF) Load(opts Options) error {
	log.Infof("load with opts: %#v", opts)
	var err error

	b.opts = opts
	config := BpfGconfigT{
		HaveFilter:        opts.haveFilter,
		FilterFollowForks: opts.followForks,
		FilterComm:        opts.comm,
		FilterCommEnable:  opts.filterComm,
		MaxPayloadSize:    opts.maxPayloadSize,
	}
	if len(opts.ifindexes) > 0 {
		config.FilterIfindexEnable = 1
	}
	if b.useRingBufSubmitSkb {
		config.UseRingbufSubmitSkb = 1
	}
	if opts.backend != types.NetHookBackendCgroupSkb {
		b.disableCgroupSkb()
	}
	if !b.isLegacyKernel {
		log.Infof("rewrite constants with %+v", config)
		err = b.spec.Variables["g"].Set(config)
		if err != nil {
			return fmt.Errorf("rewrite constants: %w", err)
		}
	}

	if opts.pcapFilter != "" {
		log.Infof("pcap filter: %s", opts.pcapFilter)
		if err := b.injectPcapFilter(); err != nil {
			return fmt.Errorf(": %w", err)
		}
	}

	loadCount := 0
load:
	loadCount++
	err = b.spec.LoadAndAssign(b.objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes:  opts.kernelTypes,
			LogLevel:     ebpf.LogLevelInstruction,
			LogSizeStart: logSzie,
		},
		IgnoreUnknownProgram:      true,
		IgnoreNotSupportedProgram: true,
		IgnoreUnknownVariable:     true,
		IgnoreInvalidMap:          true,
	})
	if err != nil {
		log.Infof("load and assign failed: %+v", err)
		if isTracingNotSupportErr(err) && loadCount < 2 {
			b.disableTracing()
			goto load
		}
		return fmt.Errorf("bpf load and assign: %w", err)
	}

	if b.isLegacyKernel {
		log.Infof("update config map with %+v", config)
		key := uint32(0)
		if err := b.objs.BpfMaps.PtcpdumpConfigMap.Update(key, config, ebpf.UpdateAny); err != nil {
			return fmt.Errorf(": %w", err)
		}
	}
	if err := b.applyFilters(); err != nil {
		return fmt.Errorf(": %w", err)
	}

	return nil
}

func (b *BPF) injectPcapFilter() error {
	var err error
	for _, progName := range []string{"ptcpdump_tc_ingress", "ptcpdump_tc_egress",
		"ptcpdump_tcx_ingress", "ptcpdump_tcx_egress",
		"ptcpdump_cgroup_skb__ingress", "ptcpdump_cgroup_skb__egress"} {
		prog, ok := b.spec.Programs[progName]
		if !ok {
			log.Infof("program %s not found", progName)
			continue
		}
		if prog == nil {
			log.Infof("program %s is nil", progName)
			continue
		}
		l2skb := true
		if strings.Contains(progName, "cgroup_skb") {
			l2skb = false
			if b.opts.backend != types.NetHookBackendCgroupSkb {
				continue
			}
		}
		log.Infof("inject pcap filter to %s", progName)
		prog.Instructions, err = elibpcap.Inject(
			b.opts.pcapFilter,
			prog.Instructions,
			elibpcap.Options{
				AtBpf2Bpf:  "pcap_filter",
				DirectRead: true,
				L2Skb:      l2skb,
			},
		)
		if err != nil {
			return fmt.Errorf("inject pcap filter to %s: %w", progName, err)
		}
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
		err := b.objs.BpfMaps.PtcpdumpFlowPidMap.Update(*k, v, ebpf.UpdateNoExist)
		if err != nil {
			if err == ebpf.ErrKeyExist || strings.Contains(err.Error(), "key already exists") {
				continue
			}
			return fmt.Errorf(": %w", err)
		}
	}
	return nil
}

func (b *BPF) AttachKprobes() error {
	if err := b.attachFentryOrKprobe("security_sk_classify_flow",
		b.objs.PtcpdumpFentrySecuritySkClassifyFlow,
		b.objs.PtcpdumpKprobeSecuritySkClassifyFlow); err != nil {
		log.Infof("%+v", err)
	}

	if err := b.attachFentryOrKprobe("tcp_sendmsg", b.objs.PtcpdumpFentryTcpSendmsg,
		b.objs.PtcpdumpKprobeTcpSendmsg); err != nil {
		return fmt.Errorf(": %w", err)
	}
	if err := b.attachFentryOrKprobe("udp_send_skb", b.objs.PtcpdumpFentryUdpSendSkb,
		b.objs.PtcpdumpKprobeUdpSendSkb); err != nil {
		log.Infof("%+v", err)
		if isProbeNotSupportErr(err) {
			err = b.attachFentryOrKprobe("udp_sendmsg", b.objs.PtcpdumpFentryUdpSendmsg,
				b.objs.PtcpdumpKprobeUdpSendmsg)
		}
		if err != nil {
			return fmt.Errorf(": %w", err)
		}
	}
	if err := b.attachFentryOrKprobe("__kfree_skb", b.objs.PtcpdumpFentryKfreeSkb,
		b.objs.PtcpdumpKprobeKfreeSkb); err != nil {
		log.Infof("%+v", err)
	}

	if err := b.attachNatHooks(); err != nil {
		return fmt.Errorf(": %w", err)
	}

	return b.attachNetDevHooks()
}

func (b *BPF) AttachTracepoints() error {
	if err := b.attachProcessHooks(); err != nil {
		return fmt.Errorf(": %w", err)
	}

	if err := b.attachNetNsHooks(); err != nil {
		return fmt.Errorf(": %w", err)
	}

	return nil
}

func (b *BPF) AttachTcHooks(ifindex int, egress, ingress bool) ([]func(), error) {
	closers, err := b.attachTcxHooks(ifindex, egress, ingress)
	if err != nil {
		log.Infof("attach tcx failed, fallback to tc: %+v", err)
		utils.RunClosers(closers)
		closers, err = b.attachTcHooks(ifindex, egress, ingress)
	}
	return closers, err
}

func (b *BPF) attachTcxHooks(ifindex int, egress, ingress bool) ([]func(), error) {
	var closeFuncs []func()

	if b.skipTcx || b.objs.PtcpdumpTcxEgress == nil || b.objs.PtcpdumpTcxIngress == nil {
		return closeFuncs, errors.New("tcx programs not found")
	}

	if egress {
		log.Infof("attach tcx/egress hooks to ifindex %d", ifindex)
		lk, err := link.AttachTCX(link.TCXOptions{
			Interface: ifindex,
			Program:   b.objs.PtcpdumpTcxEgress,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			return closeFuncs, fmt.Errorf("attach tcx/egress hooks: %w", err)
		}
		closeFuncs = append(closeFuncs, func() {
			lk.Close()
		})
	}

	if ingress {
		log.Infof("attach tcx/ingress hooks to ifindex %d", ifindex)
		lk, err := link.AttachTCX(link.TCXOptions{
			Interface: ifindex,
			Program:   b.objs.PtcpdumpTcxIngress,
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			return closeFuncs, fmt.Errorf("attach tcx/ingress hooks: %w", err)
		}
		closeFuncs = append(closeFuncs, func() {
			lk.Close()
		})
	}

	return closeFuncs, nil
}

func (b *BPF) attachTcHooks(ifindex int, egress, ingress bool) ([]func(), error) {
	var closeFuncs []func()
	closeFunc, err := ensureTcQdisc(ifindex)
	if err != nil {
		closeFuncs = append(closeFuncs, closeFunc)
		return closeFuncs, fmt.Errorf("attach tc hooks: %w", err)
	}

	if egress {
		c1, err := attachTcHook(ifindex, b.objs.PtcpdumpTcEgress, false)
		if err != nil {
			closeFuncs = append(closeFuncs, c1)
			return closeFuncs, fmt.Errorf("attach tc hooks: %w", err)
		}
		closeFuncs = append(closeFuncs, c1)
	}

	if ingress {
		c2, err := attachTcHook(ifindex, b.objs.PtcpdumpTcIngress, true)
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
	err = tcnl.SetOption(netlink.ExtendedAcknowledge, true)
	if err != nil {
		return closeFunc, fmt.Errorf("tc: set option ExtendedAcknowledge: %w", err)
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
	err = tcnl.SetOption(netlink.ExtendedAcknowledge, true)
	if err != nil {
		return closeFunc, fmt.Errorf("tc: set option ExtendedAcknowledge: %w", err)
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
		if err := b.objs.BpfMaps.PtcpdumpFilterPidMap.Update(pid, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update FilterPidMap: %w", err)
		}
	}

	log.Infof("start to update FilterUidMap with %+v", opts.pids)
	for _, uid := range opts.uids {
		uid := uid
		if err := b.objs.BpfMaps.PtcpdumpFilterUidMap.Update(uid, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update FilterUidMap: %w", err)
		}
	}

	log.Infof("start to update FilterPidnsMap with %+v", opts.pidnsIds)
	for _, id := range opts.pidnsIds {
		id := id
		if err := b.objs.BpfMaps.PtcpdumpFilterPidnsMap.Update(id, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update FilterPidnsMap: %w", err)
		}
	}

	log.Infof("start to update FilterMntnsMap with %+v", opts.mntnsIds)
	for _, id := range opts.mntnsIds {
		id := id
		if err := b.objs.BpfMaps.PtcpdumpFilterMntnsMap.Update(id, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update FilterMntnsMap: %w", err)
		}
	}

	log.Infof("start to update FilterNetnsMap with %+v", opts.netnsIds)
	for _, id := range opts.netnsIds {
		id := id
		if err := b.objs.BpfMaps.PtcpdumpFilterNetnsMap.Update(id, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update FilterNetnsMap: %w", err)
		}
	}

	log.Infof("start to update FilterIfindexMap with %+v", opts.ifindexes)
	for _, id := range opts.ifindexes {
		id := id
		if err := b.objs.BpfMaps.PtcpdumpFilterIfindexMap.Update(id, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update FilterIfindexMap: %w", err)
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

func (opts *Options) WithUids(uids []uint) *Options {
	for _, id := range uids {
		opts.uids = append(opts.uids, uint32(id))
	}
	if len(opts.uids) > 0 {
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

func (opts *Options) WithBackend(backend types.NetHookBackend) *Options {
	opts.backend = backend
	return opts
}

func (opts *Options) WithIfindexes(ifindexes []uint32) *Options {
	for _, id := range ifindexes {
		if id == 0 {
			continue
		}
		opts.ifindexes = append(opts.ifindexes, id)
	}
	return opts
}
