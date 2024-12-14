package bpf

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/mozillazg/ptcpdump/internal/host"
	"github.com/mozillazg/ptcpdump/internal/log"
)

// $TARGET is set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -no-global-types -target $TARGET bpf_no_tracing ./ptcpdump.c -- -I./headers -I./headers/$TARGET -I. -Wall -DNO_TRACING -DNO_TCX

func supportTracing() bool {
	if err := features.HaveProgramType(ebpf.Tracing); err != nil {
		log.Infof("%+v", err)
		return false
	}
	if release, err := host.GetRelease(); err != nil {
		log.Infof("%+v", err)
	} else {
		if release.Id == "openwrt" {
			log.Infof("openwrt does not support tracing, release is %s %s", release.Id, release.VersionId)
			return false
		}
	}
	return true
}
