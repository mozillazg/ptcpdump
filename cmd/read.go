package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/mozillazg/ptcpdump/internal/parser"
	"github.com/mozillazg/ptcpdump/internal/types"
	"github.com/mozillazg/ptcpdump/internal/utils"
	"github.com/mozillazg/ptcpdump/internal/writer"
)

func read(ctx context.Context, opts *Options) error {
	fpath := opts.ReadPath()
	f, err := getReader(opts)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()
	dataType, err := utils.DetectPcapDataType(f)
	if err != nil {
		return fmt.Errorf("detect pcap data type: %w", err)
	}

	var p parser.Parser
	var jsonWriter *writer.JSONWriter
	pcache := metadata.NewProcessCache()
	stdoutWriter := writer.NewStdoutWriter(opts.getStdout(), pcache)
	opts.applyToStdoutWriter(stdoutWriter)
	if filepath.Ext(opts.WritePath()) == extJSON {
		f, err := os.Create(opts.WritePath())
		if err != nil {
			return fmt.Errorf("open file %s: %w", opts.WritePath(), err)
		}
		jsonWriter = writer.NewJSONWriter(f, pcache)
	}

	ext := filepath.Ext(fpath)
	switch {
	case ext == extPcap, dataType == types.PcapDataTypePcap:
		r, ok, err := f.File()
		if !ok {
			if err != nil {
				log.Infof("%+v", err)
			}
			return errors.New("unsupported data source for the pcap format")
		}
		pr, err := parser.NewPcapParser(r)
		if err != nil {
			return fmt.Errorf("create pcap parser: %w", err)
		}
		stdoutWriter.Decoder = pr.Decoder()
		if jsonWriter != nil {
			jsonWriter.Decoder = pr.Decoder()
		}
		p = pr
		break
	default:
		p, err = parser.NewPcapNGParser(f, pcache)
		if err != nil {
			return fmt.Errorf("create pcapng parser: %w", err)
		}
	}

	var n uint
	for {
		e, err := p.Parse()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("parse packet: %w", err)
		}
		if err := stdoutWriter.Write(e); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("write packet: %w", err)
		}
		if jsonWriter != nil {
			if err := jsonWriter.Write(e); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return fmt.Errorf("write json: %w", err)
			}
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

func getReader(opts *Options) (*types.ReadBuffer, error) {
	fpath := opts.ReadPath()
	log.Warnf("reading from file %s", fpath)

	var r *types.ReadBuffer

	switch fpath {
	case "-":
		r = types.NewReadBuffer(io.NopCloser(os.Stdin))
		break
	default:
		f, err := os.Open(fpath)
		if err != nil {
			return nil, err
		}
		r = types.NewReadBuffer(f)
	}

	return r, nil
}
