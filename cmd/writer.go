package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/mozillazg/ptcpdump/internal"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/mozillazg/ptcpdump/internal/writer"
)

func getWriters(opts *Options, pcache *metadata.ProcessCache) ([]writer.PacketWriter, func() error, error) {
	var writers []writer.PacketWriter
	var rr writer.Rotator
	var err error

	if opts.WritePath() != "" {
		ext := filepath.Ext(opts.WritePath())
		switch {
		case opts.WritePath() == "-":
			w, err := newPcapNgWriter(writer.NewStdoutRotator(), pcache, opts)
			if err != nil {
				return nil, nil, fmt.Errorf(": %w", err)
			}
			w.WithNoBuffer()
			writers = append(writers, w)
			break
		case ext == extPcap:
			rr, err = writer.NewFileRotator(opts.WritePath(), opts.rotatorOption())
			if err != nil {
				return nil, nil, fmt.Errorf(": %w", err)
			}
			w, err := newPcapWriter(rr)
			if err != nil {
				return nil, rr.Close, fmt.Errorf(": %w", err)
			}
			writers = append(writers, w)
			break
		default:
			rr, err = writer.NewFileRotator(opts.WritePath(), opts.rotatorOption())
			if err != nil {
				return nil, nil, fmt.Errorf(": %w", err)
			}
			w, err := newPcapNgWriter(rr, pcache, opts)
			if err != nil {
				return nil, rr.Close, fmt.Errorf(": %w", err)
			}
			writers = append(writers, w)
		}
	}
	if opts.WritePath() == "" || opts.print {
		stdoutWriter := writer.NewStdoutWriter(os.Stdout, pcache)
		opts.applyToStdoutWriter(stdoutWriter)
		writers = append(writers, stdoutWriter)
	}

	closer := func() error {
		if rr != nil {
			rr.Flush()
			return rr.Close()
		}
		return nil
	}

	return writers, closer, nil
}

func newPcapNgWriter(rr writer.Rotator, pcache *metadata.ProcessCache, opts *Options) (*writer.PcapNGWriter, error) {
	devices, err := opts.GetDevices()
	if err != nil {
		return nil, fmt.Errorf(": %w", err)
	}

	interfaceIds := map[string]int{}
	interfaces := []pcapgo.NgInterface{metadata.NewDummyNgInterface(0, opts.pcapFilter)}
	for i, dev := range devices.Devs() {
		index := i + 1
		intf := metadata.NewNgInterface(dev, opts.pcapFilter, index)
		interfaces = append(interfaces, intf)
		interfaceIds[dev.Key()] = index
	}

	f := func(w io.Writer) (*pcapgo.NgWriter, error) {
		pcapNgWriter, err := pcapgo.NewNgWriterInterface(w, interfaces[0], pcapgo.NgWriterOptions{
			SectionInfo: pcapgo.NgSectionInfo{
				Hardware:    runtime.GOARCH,
				OS:          runtime.GOOS,
				Application: fmt.Sprintf("ptcpdump %s", internal.Version),
				Comment:     "ptcpdump: https://github.com/mozillazg/ptcpdump",
			},
		})
		if err != nil {
			return nil, fmt.Errorf(": %w", err)
		}
		for _, ifc := range interfaces[1:] {
			_, err := pcapNgWriter.AddInterface(ifc)
			if err != nil {
				return nil, fmt.Errorf(": %w", err)
			}
		}
		return pcapNgWriter, nil
	}

	wt, err := writer.NewPcapNGWriter(rr, f, pcache, interfaceIds)
	if err != nil {
		return nil, fmt.Errorf(": %w", err)
	}
	wt.WithPcapFilter(opts.pcapFilter)
	wt.WithEnhancedContext(opts.enhancedContext)
	return wt, nil
}

func newPcapWriter(rr writer.Rotator) (*writer.PcapWriter, error) {

	f := func(w io.Writer) (*pcapgo.Writer, error) {
		pcapWriter := pcapgo.NewWriterNanos(w)

		if err := pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
			return nil, fmt.Errorf("writing pcap header: %w", err)
		}
		return pcapWriter, nil
	}

	return writer.NewPcapWriter(rr, f)
}
