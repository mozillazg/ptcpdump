package cmd

import (
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/mozillazg/ptcpdump/internal"
	"github.com/mozillazg/ptcpdump/internal/dev"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/mozillazg/ptcpdump/internal/writer"
	"golang.org/x/xerrors"
)

func getWriters(opts Options, pcache *metadata.ProcessCache) ([]writer.PacketWriter, error) {
	var writers []writer.PacketWriter

	if opts.WritePath() != "" {
		ext := filepath.Ext(opts.ReadPath())
		pcapFile, err := os.Create(opts.WritePath())
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		switch ext {
		case extPcap:
			w, err := newPcapWriter(pcapFile)
			if err != nil {
				return nil, xerrors.Errorf(": %w", err)
			}
			writers = append(writers, w)
			break
		default:
			w, err := newPcapNgWriter(pcapFile, pcache)
			if err != nil {
				return nil, xerrors.Errorf(": %w", err)
			}
			writers = append(writers, w)
		}
	}
	if opts.writeFilePath == "" || opts.print {
		stdoutWriter := writer.NewStdoutWriter(os.Stdout, pcache)
		writers = append(writers, stdoutWriter)
	}

	return writers, nil
}

func newPcapNgWriter(w io.Writer, pcache *metadata.ProcessCache) (*writer.PcapNGWriter, error) {
	devices, err := dev.GetDevices(nil)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	var interfaces []pcapgo.NgInterface
	for _, dev := range devices {
		interfaces = append(interfaces, pcapgo.NgInterface{
			Index:      dev.Ifindex,
			Name:       dev.Name,
			Filter:     opts.pcapFilter,
			OS:         runtime.GOOS,
			LinkType:   layers.LinkTypeEthernet,
			SnapLength: uint32(math.MaxUint16),
			//TimestampResolution: 9,
		})
	}
	sort.Slice(interfaces, func(i, j int) bool {
		return interfaces[i].Index < interfaces[j].Index
	})

	pcapNgWriter, err := pcapgo.NewNgWriterInterface(w, interfaces[0], pcapgo.NgWriterOptions{
		SectionInfo: pcapgo.NgSectionInfo{
			Hardware:    runtime.GOARCH,
			OS:          runtime.GOOS,
			Application: fmt.Sprintf("ptcpdump %s", internal.Version),
			Comment:     "ptcpdump: https://github.com/mozillazg/ptcpdump",
		},
	})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	for _, ifc := range interfaces[1:] {
		_, err := pcapNgWriter.AddInterface(ifc)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
	}

	if err := pcapNgWriter.Flush(); err != nil {
		return nil, xerrors.Errorf("writing pcapNg header: %w", err)
	}

	return writer.NewPcapNGWriter(pcapNgWriter, pcache), nil
}

func newPcapWriter(w io.Writer) (*writer.PcapWriter, error) {
	pcapWriter := pcapgo.NewWriterNanos(w)

	if err := pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		return nil, xerrors.Errorf("writing pcap header: %w", err)
	}

	return writer.NewPcapWriter(pcapWriter), nil
}
