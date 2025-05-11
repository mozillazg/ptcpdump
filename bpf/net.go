package bpf

import (
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/mozillazg/ptcpdump/internal/log"
)

func (b *BPF) AttachTpBtfCaptureHooks(egress, ingress bool) error {
	if b.objs.PtcpdumpTpBtfNetDevQueue == nil ||
		b.objs.PtcpdumpTpBtfNetifReceiveSkb == nil {
		return errors.New("the system doesn't support the `tp-btf` backend")
	}

	if egress {
		log.Info("attaching tp_btf/net_dev_queue")
		lk, err := link.AttachTracing(link.TracingOptions{
			Program:    b.objs.PtcpdumpTpBtfNetDevQueue,
			AttachType: ebpf.AttachTraceRawTp,
		})
		if err != nil {
			return fmt.Errorf("attach tp_btf/net_dev_queue failed: %w", err)
		}
		b.links = append(b.links, lk)
	}
	if ingress {
		log.Info("attaching tp_btf/netif_receive_skb")
		lk, err := link.AttachTracing(link.TracingOptions{
			Program:    b.objs.PtcpdumpTpBtfNetifReceiveSkb,
			AttachType: ebpf.AttachTraceRawTp,
		})
		if err != nil {
			return fmt.Errorf("attach tp_btf/netif_receive_skb failed: %w", err)
		}
		b.links = append(b.links, lk)
	}

	return nil
}

func supportTracingGetSocket() bool {
	if err := features.HaveProgramHelper(ebpf.Tracing, asm.FnGetSocketCookie); err != nil {
		log.Infof("%+v", err)
		return false
	}

	return true
}
