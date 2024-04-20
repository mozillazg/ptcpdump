package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/event"
	"github.com/mozillazg/ptcpdump/internal/writer"
	"golang.org/x/xerrors"
	"io"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func logErr(err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		// Using %+v will print the whole verifier error, not just the last
		// few lines.
		log.Printf("Verifier error: %+v", ve)
	}
	log.Printf("%+v", err)
}

func parseEvent(pcapWriter *writer.PcapNGWriter, rawSample []byte) {
	pevent, err := event.ParsePacketEvent(rawSample)
	if err != nil {
		logErr(err)
		return
	}

	if err := writer.NewStdoutWriter().Write(pevent); err != nil {
		logErr(err)
	}

	if err := pcapWriter.Write(pevent); err != nil {
		logErr(err)
	}
}

func newPcapWriter(w io.Writer, ifaceNames []string) (*writer.PcapNGWriter, map[string]int, error) {
	if len(ifaceNames) == 0 {
		return nil, nil, xerrors.New("can't create pcap with no ifaceNames")
	}

	var interfaces []pcapgo.NgInterface
	nameIfcs := make(map[string]int)

	for id, name := range ifaceNames {
		interfaces = append(interfaces, pcapgo.NgInterface{
			Name:       fmt.Sprintf("ptcpdump-%s", name),
			Comment:    "ptcpdump iface name",
			LinkType:   layers.LinkTypeEthernet,
			SnapLength: uint32(math.MaxUint16),
		})
		nameIfcs[name] = id
	}

	pcapWriter, err := pcapgo.NewNgWriterInterface(w, interfaces[0], pcapgo.NgWriterOptions{})
	if err != nil {
		return nil, nil, err
	}

	for _, ifc := range interfaces[1:] {
		_, err := pcapWriter.AddInterface(ifc)
		if err != nil {
			return nil, nil, err
		}
	}

	// Flush the header out in case we're writing to stdout, this lets tcpdump print a reassuring message
	if err := pcapWriter.Flush(); err != nil {
		return nil, nil, xerrors.Errorf("writing pcap header: %w", err)
	}

	return writer.NewPcapNGWriter(pcapWriter), nameIfcs, nil
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		logErr(err)
		return
	}
	pcapFile, err := os.Create("ptcpdump.pcapng")
	if err != nil {
		logErr(err)
		return
	}
	pcapWriter, _, err := newPcapWriter(pcapFile, []string{"lo", "enp0s3", "docker0", "wlp4s0", "enp5s0"})
	if err != nil {
		logErr(err)
		return
	}
	defer pcapWriter.Flush()

	bf, err := bpf.NewBPF()
	if err != nil {
		logErr(err)
		return
	}
	if err := bf.Load(); err != nil {
		logErr(err)
		return
	}
	defer bf.Close()

	if err := bf.AttachKprobes(); err != nil {
		logErr(err)
		return
	}

	for _, ifaceName := range []string{"lo", "enp0s3", "docker0", "wlp4s0", "enp5s0"} {
		dev, err := net.InterfaceByName(ifaceName)
		if err != nil {
			log.Printf("get interface by name %s failed: %+v", ifaceName, err)
			continue
		}
		if err := bf.AttachTcHooks(dev); err != nil {
			logErr(err)
			return
		}
	}

	reader, err := bf.NewPacketEventReader()
	if err != nil {
		logErr(err)
		return
	}
	defer reader.Close()

	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()

	log.Println("tracing...")
	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					log.Println("Received signal, exiting...")
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}
			if record.LostSamples > 0 {
				log.Printf("lost %d events", record.LostSamples)
				continue
			}
			parseEvent(pcapWriter, record.RawSample)
		}
	}()

	<-ctx.Done()

	log.Println("bye bye")
}
