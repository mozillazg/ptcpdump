package bpf

import (
	"fmt"
	"github.com/jschwinger233/elibpcap"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/types"
	"strings"
)

func (b *BPF) injectPcapFilterToTcs() error {
	var err error
	for _, progName := range []string{
		"ptcpdump_tc_ingress_l2", "ptcpdump_tc_ingress_l3",
		"ptcpdump_tc_egress_l2", "ptcpdump_tc_egress_l3",
		"ptcpdump_tcx_ingress_l2", "ptcpdump_tcx_ingress_l3",
		"ptcpdump_tcx_egress_l2", "ptcpdump_tcx_egress_l3",
		"ptcpdump_cgroup_skb__ingress",
		"ptcpdump_cgroup_skb__egress",
	} {
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
		} else if b.opts.backend != types.NetHookBackendTc {
			continue
		}

		log.Infof("inject pcap filter to %s", progName)
		if strings.HasSuffix(progName, "l2") || l2skb {
			prog.Instructions, err = elibpcap.Inject(
				b.opts.pcapFilter,
				prog.Instructions,
				elibpcap.Options{
					AtBpf2Bpf:        "pcap_filter",
					PacketAccessMode: elibpcap.Direct,
					L2Skb:            true,
				},
			)
			if err != nil {
				if strings.Contains(fmt.Sprintf("%+v", err), "expression rejects all packets") {
					prog.Instructions, err = elibpcap.Inject(
						elibpcap.RejectAllExpr,
						prog.Instructions,
						elibpcap.Options{
							AtBpf2Bpf:        "pcap_filter",
							PacketAccessMode: elibpcap.Direct,
							L2Skb:            true,
						},
					)
				}
			}
			if err != nil {
				return fmt.Errorf("inject pcap filter to %s: %w", progName, err)
			}
		}

		if strings.HasSuffix(progName, "l3") || !l2skb {
			prog.Instructions, err = elibpcap.Inject(
				b.opts.pcapFilter,
				prog.Instructions,
				elibpcap.Options{
					AtBpf2Bpf:        "pcap_filter_l3",
					PacketAccessMode: elibpcap.Direct,
					L2Skb:            false,
				},
			)
			if err != nil {
				if strings.Contains(fmt.Sprintf("%+v", err), "expression rejects all packets") {
					prog.Instructions, err = elibpcap.Inject(
						elibpcap.RejectAllExpr,
						prog.Instructions,
						elibpcap.Options{
							AtBpf2Bpf:        "pcap_filter_l3",
							PacketAccessMode: elibpcap.Direct,
							L2Skb:            false,
						},
					)
				}
			}
			if err != nil {
				return fmt.Errorf("inject pcap filter to %s: %w", progName, err)
			}
		}
	}
	return err
}

func (b *BPF) injectPcapFilterToTpBtfs() error {
	var err error
	for _, progName := range []string{
		"ptcpdump_tp_btf__net_dev_queue",
		"ptcpdump_tp_btf__netif_receive_skb",
	} {
		prog, ok := b.spec.Programs[progName]
		if !ok {
			log.Infof("program %s not found", progName)
			continue
		}
		if prog == nil {
			log.Infof("program %s is nil", progName)
			continue
		}

		log.Infof("inject pcap filter to %s", progName)
		prog.Instructions, err = elibpcap.Inject(
			b.opts.pcapFilter,
			prog.Instructions,
			elibpcap.Options{
				AtBpf2Bpf:        "pcap_filter",
				PacketAccessMode: elibpcap.BpfProbeReadKernel,
				L2Skb:            true,
			},
		)
		if err != nil {
			if strings.Contains(fmt.Sprintf("%+v", err), "expression rejects all packets") {
				prog.Instructions, err = elibpcap.Inject(
					elibpcap.RejectAllExpr,
					prog.Instructions,
					elibpcap.Options{
						AtBpf2Bpf:        "pcap_filter",
						PacketAccessMode: elibpcap.BpfProbeReadKernel,
						L2Skb:            true,
					},
				)
			}
		}
		if err != nil {
			return fmt.Errorf("inject pcap filter to %s: %w", progName, err)
		}

		prog.Instructions, err = elibpcap.Inject(
			b.opts.pcapFilter,
			prog.Instructions,
			elibpcap.Options{
				AtBpf2Bpf:        "pcap_filter_l3",
				PacketAccessMode: elibpcap.BpfProbeReadKernel,
				L2Skb:            false,
			},
		)
		if err != nil {
			if strings.Contains(fmt.Sprintf("%+v", err), "expression rejects all packets") {
				prog.Instructions, err = elibpcap.Inject(
					elibpcap.RejectAllExpr,
					prog.Instructions,
					elibpcap.Options{
						AtBpf2Bpf:        "pcap_filter_l3",
						PacketAccessMode: elibpcap.BpfProbeReadKernel,
						L2Skb:            false,
					},
				)
			}
		}
		if err != nil {
			return fmt.Errorf("inject pcap filter to %s: %w", progName, err)
		}
	}
	return err
}

func (b *BPF) injectPcapFilterToSocketFilters() error {
	var err error

	for _, progName := range []string{
		"ptcpdump_socket_filter__ingress_l2", "ptcpdump_socket_filter__ingress_l3",
		"ptcpdump_socket_filter__egress_l2", "ptcpdump_socket_filter__egress_l3",
	} {
		prog, ok := b.spec.Programs[progName]
		if !ok {
			log.Infof("program %s not found", progName)
			continue
		}
		if prog == nil {
			log.Infof("program %s is nil", progName)
			continue
		}

		log.Infof("inject pcap filter to %s", progName)
		if strings.HasSuffix(progName, "l2") {
			prog.Instructions, err = elibpcap.Inject(
				b.opts.pcapFilter,
				prog.Instructions,
				elibpcap.Options{
					AtBpf2Bpf:        "pcap_filter",
					PacketAccessMode: elibpcap.BpfSkbLoadBytes,
					L2Skb:            true,
				},
			)
			if err != nil {
				if strings.Contains(fmt.Sprintf("%+v", err), "expression rejects all packets") {
					prog.Instructions, err = elibpcap.Inject(
						elibpcap.RejectAllExpr,
						prog.Instructions,
						elibpcap.Options{
							AtBpf2Bpf:        "pcap_filter",
							PacketAccessMode: elibpcap.BpfSkbLoadBytes,
							L2Skb:            true,
						},
					)
				}
			}
			if err != nil {
				return fmt.Errorf("inject pcap filter to %s: %w", progName, err)
			}
		}

		if strings.HasSuffix(progName, "l3") {
			prog.Instructions, err = elibpcap.Inject(
				b.opts.pcapFilter,
				prog.Instructions,
				elibpcap.Options{
					AtBpf2Bpf:        "pcap_filter_l3",
					PacketAccessMode: elibpcap.BpfSkbLoadBytes,
					L2Skb:            false,
				},
			)
			if err != nil {
				if strings.Contains(fmt.Sprintf("%+v", err), "expression rejects all packets") {
					prog.Instructions, err = elibpcap.Inject(
						elibpcap.RejectAllExpr,
						prog.Instructions,
						elibpcap.Options{
							AtBpf2Bpf:        "pcap_filter_l3",
							PacketAccessMode: elibpcap.BpfSkbLoadBytes,
							L2Skb:            false,
						},
					)
				}
			}
			if err != nil {
				return fmt.Errorf("inject pcap filter to %s: %w", progName, err)
			}
		}
	}

	return nil
}
