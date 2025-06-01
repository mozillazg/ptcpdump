package bpf

import (
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/mozillazg/ptcpdump/internal/log"
	"os"
	"syscall"
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

func (b *BPF) AttachSocketFilterHooks(ifindex int, egress, ingress bool) ([]func(), error) {
	var closeFuncs []func()

	if egress {
		log.Info("attaching socket/egress")
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
		if err := link.AttachSocketFilter(f, b.objs.PtcpdumpSocketFilterEgress); err != nil {
			return closeFuncs, fmt.Errorf("attach socket/egress failed: %w", err)
		}
	}

	if ingress {
		log.Info("attaching socket/ingress")
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
		if err := link.AttachSocketFilter(f, b.objs.PtcpdumpSocketFilterIngress); err != nil {
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
