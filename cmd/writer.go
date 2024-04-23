package cmd

import (
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/mozillazg/ptcpdump/internal/dev"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/mozillazg/ptcpdump/internal/writer"
	"golang.org/x/xerrors"
	"io"
	"math"
	"os"
)

func getWriters(opts Options, pcache *metadata.ProcessCache) ([]writer.PacketWriter, error) {
	var writers []writer.PacketWriter

	if opts.WritePath() != "" {
		pcapFile, err := os.Create(opts.WritePath())
		if err != nil {
			return nil, err
		}
		pcapWriter, err := newPcapWriter(pcapFile, pcache)
		if err != nil {
			return nil, err
		}
		writers = append(writers, pcapWriter)
	} else {
		stdoutWriter := writer.NewStdoutWriter(os.Stdout, pcache)
		writers = append(writers, stdoutWriter)
	}

	return writers, nil
}

func newPcapWriter(w io.Writer, pcache *metadata.ProcessCache) (*writer.PcapNGWriter, error) {
	devices, err := dev.GetDevices("any")
	if err != nil {
		return nil, err
	}

	var interfaces []pcapgo.NgInterface
	for _, dev := range devices {
		interfaces = append(interfaces, pcapgo.NgInterface{
			Name:       dev.Name,
			Comment:    "ptcpdump interface name",
			LinkType:   layers.LinkTypeEthernet,
			SnapLength: uint32(math.MaxUint16),
		})
	}

	pcapWriter, err := pcapgo.NewNgWriterInterface(w, interfaces[0], pcapgo.NgWriterOptions{})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	for _, ifc := range interfaces[1:] {
		_, err := pcapWriter.AddInterface(ifc)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
	}

	if err := pcapWriter.Flush(); err != nil {
		return nil, xerrors.Errorf("writing pcap header: %w", err)
	}

	return writer.NewPcapNGWriter(pcapWriter, pcache), nil
}
