package cmd

import (
	"context"
	"io"
	"os"

	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/mozillazg/ptcpdump/internal/parser"
	"github.com/mozillazg/ptcpdump/internal/writer"
)

func read(ctx context.Context, opts Options) error {
	f, err := os.Open(opts.ReadPath())
	if err != nil {
		return err
	}
	defer f.Close()

	pcache := metadata.NewProcessCache()
	p, err := parser.NewPcapNGParser(f, pcache)
	if err != nil {
		return err
	}
	stdoutWriter := writer.NewStdoutWriter(os.Stdout, pcache)

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
	}

	return nil
}
