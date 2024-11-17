package bpf

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/mozillazg/ptcpdump/internal/log"
)

func (b *BPF) attachFentryOrKprobe(symbol string, fentryProg *ebpf.Program, kprobeProg *ebpf.Program) error {
	var lk link.Link
	var err error

	if fentryProg != nil {
		log.Infof("attaching fentry/%s", symbol)
		lk, err = link.AttachTracing(link.TracingOptions{
			Program:    fentryProg,
			AttachType: ebpf.AttachTraceFEntry,
		})
		if err == nil {
			b.links = append(b.links, lk)
			return nil
		}
		log.Infof("attach fentry/%s failed: %+v", symbol, err)
	}

	log.Infof("attaching kprobe/%s", symbol)
	lk, err = link.Kprobe(symbol, kprobeProg, &link.KprobeOptions{})
	if err != nil {
		return fmt.Errorf("attach kprobe/%s failed: %w", symbol, err)
	}
	b.links = append(b.links, lk)

	return nil
}

func (b *BPF) attachFexitOrKprobe(symbol string, fexitProg *ebpf.Program,
	kprobeProg *ebpf.Program, kretprobeProg *ebpf.Program) error {
	var lk link.Link
	var err error

	if fexitProg != nil {
		log.Infof("attaching fentry/%s", symbol)
		lk, err = link.AttachTracing(link.TracingOptions{
			Program:    fexitProg,
			AttachType: ebpf.AttachTraceFExit,
		})
		if err == nil {
			b.links = append(b.links, lk)
			return nil
		}
		log.Infof("attach fexit/%s failed: %+v", symbol, err)
	}

	if kprobeProg != nil {
		log.Infof("attaching kprobe/%s", symbol)
		lk, err = link.Kprobe(symbol, kprobeProg, &link.KprobeOptions{})
		if err != nil {
			return fmt.Errorf("attach kprobe/%s failed: %w", symbol, err)
		}
		b.links = append(b.links, lk)
	}
	if kretprobeProg != nil {
		log.Infof("attaching kretprobe/%s", symbol)
		lk, err = link.Kretprobe(symbol, kretprobeProg, &link.KprobeOptions{})
		if err != nil {
			return fmt.Errorf("attach kretprobe/%s failed: %w", symbol, err)
		}
		b.links = append(b.links, lk)
	}

	return nil
}

func (b *BPF) attachBTFTracepointOrRawTP(name string, btfProg *ebpf.Program, rawProg *ebpf.Program) error {
	var lk link.Link
	var err error

	if btfProg != nil {
		log.Infof("attaching tp_btf/%s", name)
		lk, err = link.AttachTracing(link.TracingOptions{
			Program:    btfProg,
			AttachType: ebpf.AttachTraceRawTp,
		})
		if err == nil {
			b.links = append(b.links, lk)
			return nil
		}
		log.Infof("attach tp_btf/%s failed: %+v", name, err)
	}

	log.Infof("attaching raw_tp/%s", name)
	lk, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    name,
		Program: rawProg,
	})
	if err != nil {
		return fmt.Errorf("attach raw_tp/%s failed: %w", name, err)
	}
	b.links = append(b.links, lk)

	return nil
}
