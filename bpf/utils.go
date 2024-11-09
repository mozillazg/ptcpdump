package bpf

import (
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/mozillazg/ptcpdump/internal/log"
)

var errNotSupportTracingProg = errors.New("not support BPF_PROG_TYPE_TRACING")

func (b *BPF) attachFentryOrKprobe(symbol string, fentryProg *ebpf.Program, kprobeProg *ebpf.Program) error {
	var lk link.Link
	var err error

	if !b.skipOptimize {
		lk, err = link.AttachTracing(link.TracingOptions{
			Program:    fentryProg,
			AttachType: ebpf.AttachTraceFEntry,
		})
	} else {
		err = errNotSupportTracingProg
	}

	if err != nil {
		log.Infof("attach fentry/%s failed: %+v", symbol, err)
		lk, err = link.Kprobe(symbol, kprobeProg, &link.KprobeOptions{})
		if err != nil {
			return fmt.Errorf("attach kprobe/%s failed: %w", symbol, err)
		}
		b.links = append(b.links, lk)
	} else {
		b.links = append(b.links, lk)
	}

	return nil
}

func (b *BPF) attachFexitOrKprobe(symbol string, fexitProg *ebpf.Program,
	kprobeProg *ebpf.Program, kretprobeProg *ebpf.Program) error {
	var lk link.Link
	var err error

	if !b.skipOptimize {
		lk, err = link.AttachTracing(link.TracingOptions{
			Program:    fexitProg,
			AttachType: ebpf.AttachTraceFExit,
		})
	} else {
		err = errNotSupportTracingProg
	}

	if err != nil {
		log.Infof("attach fexit/%s failed: %+v", symbol, err)
		if kprobeProg != nil {
			lk, err = link.Kprobe(symbol, kprobeProg, &link.KprobeOptions{})
			if err != nil {
				return fmt.Errorf("attach kprobe/%s failed: %w", symbol, err)
			}
			b.links = append(b.links, lk)
		}
		if kretprobeProg != nil {
			lk, err = link.Kretprobe(symbol, kretprobeProg, &link.KprobeOptions{})
			if err != nil {
				return fmt.Errorf("attach kretprobe/%s failed: %w", symbol, err)
			}
			b.links = append(b.links, lk)
		}
	} else {
		b.links = append(b.links, lk)
	}

	return nil
}
