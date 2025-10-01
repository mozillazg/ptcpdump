package bpf

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/jschwinger233/elibpcap"
	"github.com/mozillazg/ptcpdump/internal/log"
)

type pcapFilterCase struct {
	enabled bool
	opts    elibpcap.Options
}

func (b *BPF) programSpec(progName string) (*ebpf.ProgramSpec, bool) {
	prog, ok := b.spec.Programs[progName]
	if !ok {
		log.Infof("program %s not found", progName)
		return nil, false
	}
	if prog == nil {
		log.Infof("program %s is nil", progName)
		return nil, false
	}
	return prog, true
}

func (b *BPF) injectProgramFilters(progName string, prog *ebpf.ProgramSpec, cases ...pcapFilterCase) error {
	for _, c := range cases {
		if !c.enabled {
			continue
		}
		if err := injectWithFallback(prog, b.opts.pcapFilter, c.opts); err != nil {
			return fmt.Errorf("inject pcap filter to %s: %w", progName, err)
		}
	}
	return nil
}

func injectWithFallback(prog *ebpf.ProgramSpec, filter string, opts elibpcap.Options) error {
	original := prog.Instructions
	ins, err := elibpcap.Inject(filter, original, opts)
	if err != nil {
		if !isRejectAllPacketsErr(err) {
			return err
		}
		ins, err = elibpcap.Inject(elibpcap.RejectAllExpr, original, opts)
		if err != nil {
			return err
		}
	}
	prog.Instructions = ins
	return nil
}

func isRejectAllPacketsErr(err error) bool {
	return strings.Contains(fmt.Sprintf("%+v", err), "expression rejects all packets")
}

func (b *BPF) injectPcapFilterToTcs() error {
	for _, progName := range []string{
		"ptcpdump_tc_ingress_l2", "ptcpdump_tc_ingress_l3",
		"ptcpdump_tc_egress_l2", "ptcpdump_tc_egress_l3",
		"ptcpdump_tcx_ingress_l2", "ptcpdump_tcx_ingress_l3",
		"ptcpdump_tcx_egress_l2", "ptcpdump_tcx_egress_l3",
	} {
		prog, ok := b.programSpec(progName)
		if !ok {
			continue
		}

		log.Infof("inject pcap filter to %s", progName)
		if err := b.injectProgramFilters(
			progName,
			prog,
			pcapFilterCase{
				enabled: strings.HasSuffix(progName, "l2"),
				opts: elibpcap.Options{
					AtBpf2Bpf:        "pcap_filter",
					PacketAccessMode: elibpcap.Direct,
					L2Skb:            true,
				},
			},
			pcapFilterCase{
				enabled: strings.HasSuffix(progName, "l3"),
				opts: elibpcap.Options{
					AtBpf2Bpf:        "pcap_filter_l3",
					PacketAccessMode: elibpcap.Direct,
					L2Skb:            false,
				},
			},
		); err != nil {
			return err
		}
	}
	return nil
}

func (b *BPF) injectPcapFilterToCgroupSkbs() error {
	for _, progName := range []string{
		"ptcpdump_cgroup_skb__ingress",
		"ptcpdump_cgroup_skb__egress",
	} {
		prog, ok := b.programSpec(progName)
		if !ok {
			continue
		}
		log.Infof("inject pcap filter to %s", progName)
		if err := b.injectProgramFilters(
			progName,
			prog,
			pcapFilterCase{
				enabled: true,
				opts: elibpcap.Options{
					AtBpf2Bpf:        "pcap_filter_l3",
					PacketAccessMode: elibpcap.Direct,
					L2Skb:            false,
				},
			},
		); err != nil {
			return err
		}
	}
	return nil
}

func (b *BPF) injectPcapFilterToTpBtfs() error {
	for _, progName := range []string{
		"ptcpdump_tp_btf__net_dev_queue",
		"ptcpdump_tp_btf__netif_receive_skb",
	} {
		prog, ok := b.programSpec(progName)
		if !ok {
			continue
		}

		log.Infof("inject pcap filter to %s", progName)
		if err := b.injectProgramFilters(
			progName,
			prog,
			pcapFilterCase{
				enabled: true,
				opts: elibpcap.Options{
					AtBpf2Bpf:        "pcap_filter",
					PacketAccessMode: elibpcap.BpfProbeReadKernel,
					L2Skb:            true,
				},
			},
			pcapFilterCase{
				enabled: true,
				opts: elibpcap.Options{
					AtBpf2Bpf:        "pcap_filter_l3",
					PacketAccessMode: elibpcap.BpfProbeReadKernel,
					L2Skb:            false,
				},
			},
		); err != nil {
			return err
		}
	}
	return nil
}

func (b *BPF) injectPcapFilterToSocketFilters() error {
	for _, progName := range []string{
		"ptcpdump_socket_filter__ingress_l2", "ptcpdump_socket_filter__ingress_l3",
		"ptcpdump_socket_filter__egress_l2", "ptcpdump_socket_filter__egress_l3",
	} {
		prog, ok := b.programSpec(progName)
		if !ok {
			continue
		}

		log.Infof("inject pcap filter to %s", progName)
		if err := b.injectProgramFilters(
			progName,
			prog,
			pcapFilterCase{
				enabled: strings.HasSuffix(progName, "l2"),
				opts: elibpcap.Options{
					AtBpf2Bpf:        "pcap_filter",
					PacketAccessMode: elibpcap.BpfSkbLoadBytes,
					L2Skb:            true,
				},
			},
			pcapFilterCase{
				enabled: strings.HasSuffix(progName, "l3"),
				opts: elibpcap.Options{
					AtBpf2Bpf:        "pcap_filter_l3",
					PacketAccessMode: elibpcap.BpfSkbLoadBytes,
					L2Skb:            false,
				},
			},
		); err != nil {
			return err
		}
	}

	return nil
}
