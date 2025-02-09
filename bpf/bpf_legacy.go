package bpf

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/mozillazg/ptcpdump/internal/log"
)

// $TARGET is set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -no-global-types -target $TARGET bpf_legacy ./ptcpdump.c -- -I./headers -I./headers/$TARGET -I. -Wall -DLEGACY_KERNEL -DNO_CGROUP_PROG -DNO_TRACING -DNO_TCX

func supportCgroupSock() bool {
	if err := features.HaveProgramHelper(ebpf.CGroupSock, asm.FnGetSocketCookie); err != nil {
		log.Infof("%+v", err)
		return false
	}
	if err := features.HaveProgramHelper(ebpf.CGroupSock, asm.FnGetCurrentTask); err != nil {
		log.Infof("%+v", err)
		return false
	}

	return true
}

func kernelVersion(a, b, c int) uint32 {
	if c > 255 {
		c = 255
	}

	return uint32((a << 16) + (b << 8) + c)
}

// map .rodata: map create: read- and write-only maps not supported (requires >= 5.2)
func isLegacyKernel() bool {
	if ok := kernelVersionEqOrGreaterThan(5, 2, 0); ok {
		return false
	}
	return true
}

func supportTcx() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:    ebpf.SchedCLS,
		License: "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		log.Infof("%+v", err)
		return false
	}
	defer prog.Close()

	return true
}

func supportRingBuf() bool {
	log.Info("Checking ringbuf support")
	if err := features.HaveMapType(ebpf.RingBuf); err != nil {
		log.Infof("%+v", err)
		return false
	}
	return true
}

func canUseRingBufSubmitSkb() bool {
	log.Info("Checking ringbuf submit skb support")
	if !supportRingBuf() {
		return false
	}
	// 5.8 ~ 6.7 will raise "R3 min value is outside of the allowed memory range" error
	if ok := kernelVersionEqOrGreaterThan(6, 8, 0); ok {
		return true
	}
	return false
}

func kernelVersionEqOrGreaterThan(a, b, c int) bool {
	versionCode, err := features.LinuxVersionCode()
	if err != nil {
		log.Infof("%+v", err)
		return false
	}
	if versionCode >= kernelVersion(a, b, c) {
		return true
	}
	return false
}

func loadBpfWithData(b []byte) (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(b)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Bpf: %w", err)
	}

	return spec, err
}
