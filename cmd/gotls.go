package cmd

import (
	"debug/elf"
	"errors"
	"fmt"
	"github.com/mozillazg/ptcpdump/internal/gosym"
	"os/exec"
	"time"

	"debug/buildinfo"
	"github.com/cilium/ebpf/link"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/consumer"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/writer"
)

const goTLSSymbolWriteKeyLog = "crypto/tls.(*Config).writeKeyLog"

func getGoKeyLogEventConsumer(opts *Options, packetWriters []writer.PacketWriter) (*consumer.GoKeyLogEventConsumer, error) {
	var keylogWs []writer.KeyLogWriter

	if opts.embedTLSKeyLogToPcapng {
		for _, pw := range packetWriters {
			if pngw, ok := pw.(*writer.PcapNGWriter); ok {
				keylogWs = append(keylogWs, writer.NewKeyLogPcapNGWriter(pngw))
				if opts.delayBeforeHandlePacketEvents == 0 {
					opts.delayBeforeHandlePacketEvents = time.Second * 3
				}
				break
			}
		}
	}
	if opts.writeTLSKeyLogPath != "" {
		w, err := writer.NewKeyLogFileWriter(opts.writeTLSKeyLogPath)
		if err != nil {
			return nil, err
		}
		keylogWs = append(keylogWs, w)
	}

	cr := consumer.NewGoKeyLogEventConsumer(10, keylogWs...)
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
	elff, err := elf.Open(path)
	if err != nil {
		log.Debugf("skip go TLS related logics due to %s", err)
		return nil
	}

	exc, err := link.OpenExecutable(path)
	if err != nil {
		log.Warnf("skip go TLS related logics due to %s", err)
		return nil
	}
	retOffsets, err := gosym.GetGoFuncRetOffsetsFromELF(elff, goTLSSymbolWriteKeyLog)
	if err == nil && len(retOffsets) == 0 {
		err = errors.New("not found any RET instruction")
	}
	if err != nil {
		log.Warnf("skip go TLS related logics due to %s", err)
		return nil
	}
	retOffset := retOffsets[len(retOffsets)-1]
	log.Infof("got retOffsets: %v, will attach at ret offset: %d", retOffsets, retOffset)

	if err := bf.AttachGoTLSUprobeHooks(exc, goTLSSymbolWriteKeyLog,
		0, retOffset, 0); err != nil {
		log.Warnf("skip go TLS related logics due to could not attach go TLS hooks base on %s: %s", path, err)
	}
	return nil
}
