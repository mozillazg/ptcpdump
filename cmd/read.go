package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/mozillazg/ptcpdump/internal/parser"
	"github.com/mozillazg/ptcpdump/internal/writer"
	"github.com/x-way/pktdump"
)

func read(ctx context.Context, opts Options) error {
	f, err := os.Open(opts.ReadPath())
	if err != nil {
		return err
	}
	defer f.Close()

	var p parser.Parser
	pcache := metadata.NewProcessCache()
	stdoutWriter := writer.NewStdoutWriter(os.Stdout, pcache)
	stdoutWriter.OneLine = opts.oneLine
	stdoutWriter.PrintNumber = opts.printPacketNumber
	stdoutWriter.NoTimestamp = opts.dontPrintTimestamp
	stdoutWriter.TimestampNano = opts.TimeStampAsNano()
	if opts.onlyPrintCount {
		stdoutWriter.DoNothing = true
	}
	if opts.verbose >= 1 {
		stdoutWriter.FormatStyle = pktdump.FormatStyleVerbose
	}

	ext := filepath.Ext(opts.ReadPath())

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
