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
	var pcapFile *os.File
	var err error

	if opts.WritePath() != "" {
		ext := filepath.Ext(opts.WritePath())
		switch {
		case opts.WritePath() == "-":
			w, err := newPcapNgWriter(os.Stdout, pcache, opts)
			if err != nil {
				return nil, nil, fmt.Errorf(": %w", err)
			}
			w.WithNoBuffer()
			writers = append(writers, w)
			break
		case ext == extPcap:
			pcapFile, err = os.Create(opts.WritePath())
			if err != nil {
				return nil, nil, fmt.Errorf(": %w", err)
			}
			w, err := newPcapWriter(pcapFile)
			if err != nil {
				return nil, pcapFile.Close, fmt.Errorf(": %w", err)
			}
			writers = append(writers, w)
			break
		default:
			pcapFile, err = os.Create(opts.WritePath())
			if err != nil {
				return nil, nil, fmt.Errorf(": %w", err)
			}
			w, err := newPcapNgWriter(pcapFile, pcache, opts)
			if err != nil {
				return nil, pcapFile.Close, fmt.Errorf(": %w", err)
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
		if pcapFile != nil {
			pcapFile.Sync()
			return pcapFile.Close()
		}
		return nil
	}

	return writers, closer, nil
}

func newPcapNgWriter(w io.Writer, pcache *metadata.ProcessCache, opts *Options) (*writer.PcapNGWriter, error) {
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

	if err := pcapNgWriter.Flush(); err != nil {
		return nil, fmt.Errorf("writing pcapNg header: %w", err)
	}

	wt := writer.NewPcapNGWriter(pcapNgWriter, pcache, interfaceIds).WithPcapFilter(opts.pcapFilter)
	wt.WithEnhancedContext(opts.enhancedContext)
	return wt, nil
}

func newPcapWriter(w io.Writer) (*writer.PcapWriter, error) {
	pcapWriter := pcapgo.NewWriterNanos(w)

	if err := pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		return nil, fmt.Errorf("writing pcap header: %w", err)
	}

	return writer.NewPcapWriter(pcapWriter), nil
}
