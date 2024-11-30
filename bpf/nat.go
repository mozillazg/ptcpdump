package bpf

import (
	"fmt"
	"github.com/mozillazg/ptcpdump/internal/log"
	"strings"
)

func (b *BPF) attachNatHooks() error {
	err := b.attachFentryOrKprobe("nf_nat_packet",
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

	return nil
}
