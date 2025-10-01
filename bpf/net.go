package bpf

import (
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/types"
	"os"
	"syscall"
)

func (b *BPF) AttachTpBtfCaptureHooks(egress, ingress bool) error {
	if b.objs.PtcpdumpTpBtfNetDevQueue == nil ||
		b.objs.PtcpdumpTpBtfNetifReceiveSkb == nil {
		return errors.New("the system doesn't support the `tp-btf` backend")
	}

	if egress {
		log.Infof("attaching tp_btf/net_dev_queue %q", b.objs.PtcpdumpTpBtfNetDevQueue.String())
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
		log.Infof("attaching tp_btf/netif_receive_skb %q", b.objs.PtcpdumpTpBtfNetifReceiveSkb.String())
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

func (b *BPF) AttachSocketFilterHooks(iface types.Device, egress, ingress bool) ([]func(), error) {
	var closeFuncs []func()
	ifindex := iface.Ifindex

	if egress {
		prog := trueOr(iface.L2(), b.objs.PtcpdumpSocketFilterEgressL2, b.objs.PtcpdumpSocketFilterEgressL3)
		log.Infof("attaching socket/egress %q to %s", prog.String(), iface.String())
		sock, err := openRawSock(ifindex)
		if err != nil {
			return closeFuncs, fmt.Errorf("attach socket/egress failed: %w", err)
		}
		closeFuncs = append(closeFuncs, func() { syscall.Close(sock) })
		f, err := rawSockToFile(sock)
		if err != nil {
			return closeFuncs, fmt.Errorf("attach socket/egress failed: %w", err)
		}
		closeFuncs = append(closeFuncs, func() { f.Close() })
		if err := link.AttachSocketFilter(f, prog); err != nil {
			return closeFuncs, fmt.Errorf("attach socket/egress failed: %w", err)
		}
	}

	if ingress {
		prog := trueOr(iface.L2(), b.objs.PtcpdumpSocketFilterIngressL2, b.objs.PtcpdumpSocketFilterIngressL3)
		log.Infof("attaching socket/ingress %q to %s", prog.String(), iface.String())
		sock, err := openRawSock(ifindex)
		if err != nil {
			return closeFuncs, fmt.Errorf("attach socket/ingress failed: %w", err)
		}
		closeFuncs = append(closeFuncs, func() { syscall.Close(sock) })
		f, err := rawSockToFile(sock)
		if err != nil {
			return closeFuncs, fmt.Errorf("attach socket/ingress failed: %w", err)
		}
		closeFuncs = append(closeFuncs, func() { f.Close() })
		if err := link.AttachSocketFilter(f, prog); err != nil {
			return closeFuncs, fmt.Errorf("attach socket/ingress failed: %w", err)
		}
	}

	return closeFuncs, nil
}

func rawSockToFile(sock int) (*os.File, error) {
	file := os.NewFile(uintptr(sock), fmt.Sprintf("ptcpdump_raw_socket_%d", sock))
	if file == nil {
		return nil, fmt.Errorf("failed to create file from socket fd: %d", sock)
	}
	return file, nil
}

func openRawSock(ifindex int) (int, error) {
	sock, err := syscall.Socket(syscall.AF_PACKET,
		syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC,
		int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return 0, fmt.Errorf("failed to open raw socket: %w", err)
	}
	if ifindex < 0 {
		return sock, nil
	}

	sll := syscall.SockaddrLinklayer{
		Ifindex:  ifindex,
		Protocol: htons(syscall.ETH_P_ALL),
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		syscall.Close(sock)
		return 0, fmt.Errorf("failed to bind raw socket: %w", err)
	}
	return sock, nil
}

func (b *BPF) disableNeedlessPrograms() {
	switch b.opts.backend {
	case types.NetHookBackendTc:
		b.disableCgroupSkb()
		b.disableSocketFilter()
		break
	case types.NetHookBackendCgroupSkb:
		b.disableTc()
		b.disableSocketFilter()
		break
	case types.NetHookBackendSocketFilter:
		b.disableTc()
		b.disableCgroupSkb()
		break
	}

}

func (b *BPF) disableSocketFilter() {
	for k, v := range b.spec.Programs {
		if v.Type == ebpf.SocketFilter {
			delete(b.spec.Programs, k)
		}
	}
}

func (b *BPF) disableTc() {
	for k, v := range b.spec.Programs {
		if v.Type == ebpf.SchedCLS || v.Type == ebpf.SchedACT {
			delete(b.spec.Programs, k)
		}
	}
}
