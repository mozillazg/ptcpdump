package cmd

import (
	"fmt"
	"os/exec"

	"debug/buildinfo"
	"github.com/cilium/ebpf/link"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/consumer"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/writer"
)

const goTLSSymbolWriteKeyLog = "crypto/tls.(*Config).writeKeyLog"

func getGoKeyLogEventConsumer(opts Options) (*consumer.GoKeyLogEventConsumer, error) {
	var writers []writer.KeyLogWriter

	if opts.writeTLSKeyLogPath != "" {
		w, err := writer.NewKeyLogFileWriter(opts.writeTLSKeyLogPath)
		if err != nil {
			return nil, err
		}
		writers = append(writers, w)
	}

	cr := consumer.NewGoKeyLogEventConsumer(2, writers...)
	return cr, nil
}

func attachGoTLSHooks(opts Options, bf *bpf.BPF) error {
	if len(opts.subProgArgs) == 0 {
		return nil
	}
	path, err := exec.LookPath(opts.subProgArgs[0])
	if err != nil {
		return fmt.Errorf("could not find %s in PATH", opts.subProgArgs[0])
	}
	if _, err := buildinfo.ReadFile(path); err != nil {
		log.Debugf("skip go TLS related logics due to %s", err)
		return nil
	}

	exc, err := link.OpenExecutable(path)
	if err != nil {
		log.Warnf("skip go TLS related logics due to %s", err)
		return nil
	}
	if err := bf.AttachUprobeHook(exc, goTLSSymbolWriteKeyLog, 0, 0); err != nil {
		log.Warnf("skip go TLS related logics due to could not attach go TLS hooks base on %s: %s", path, err)
	}
	return nil
}
