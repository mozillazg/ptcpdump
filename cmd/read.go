package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/mozillazg/ptcpdump/internal/parser"
	"github.com/mozillazg/ptcpdump/internal/writer"
)

func read(ctx context.Context, opts *Options) error {
	fpath := opts.ReadPath()
	log.Warnf("reading from file %s", fpath)

	f, err := os.Open(fpath)
	if err != nil {
		return err
	}
	defer f.Close()

	var p parser.Parser
	pcache := metadata.NewProcessCache()
	stdoutWriter := writer.NewStdoutWriter(opts.getStdout(), pcache)
	opts.applyToStdoutWriter(stdoutWriter)

	ext := filepath.Ext(fpath)
	switch ext {
	case extPcap:
		pr, err := parser.NewPcapParser(f)
		if err != nil {
			return err
		}
		stdoutWriter.Decoder = pr.Decoder()
		p = pr
		break
	default:
		p, err = parser.NewPcapNGParser(f, pcache)
		if err != nil {
			return err
		}
	}

	var n uint
	for {
		e, err := p.Parse()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if err := stdoutWriter.Write(e); err != nil {
			return err
		}
		n++
		if opts.maxPacketCount > 0 && opts.maxPacketCount <= n {
			break
		}
	}
	if opts.onlyPrintCount {
		fmt.Printf("%d packets\n", n)
	}

	return nil
}
