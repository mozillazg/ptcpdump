package cmd

import (
	"context"
	"fmt"
	"github.com/mozillazg/ptcpdump/internal/utils"
	"io"
	"os"
	"path/filepath"

	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/mozillazg/ptcpdump/internal/parser"
	"github.com/mozillazg/ptcpdump/internal/writer"
)

func read(ctx context.Context, opts *Options) error {
	fpath := opts.ReadPath()
	utils.OutStderr("reading from file %s\n", fpath)

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

	var n int64
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
	}
	if opts.onlyPrintCount {
		fmt.Printf("%d packets\n", n)
	}

	return nil
}
