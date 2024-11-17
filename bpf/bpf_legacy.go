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
func isLegacyKernel() (bool, error) {
	versionCode, err := features.LinuxVersionCode()
	if err != nil {
		return false, fmt.Errorf(": %w", err)
	}
	if versionCode < kernelVersion(5, 2, 0) {
		return true, nil
	}
	return false, nil
}

func supportTcx() bool {
	versionCode, _ := features.LinuxVersionCode()
	if versionCode <= 0 {
		return false
	}
	return versionCode >= kernelVersion(6, 6, 0)
}

func loadBpfWithData(b []byte) (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(b)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Bpf: %w", err)
	}

	return spec, err
}
