package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/event"
	"github.com/mozillazg/ptcpdump/internal/metadata"
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

type Options struct {
	writeFilePath string
}

func (o Options) WritePath() string {
	if o.writeFilePath == "" || o.writeFilePath == "-" {
		return ""
	}
	return o.writeFilePath
}

func logErr(err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		// Using %+v will print the whole verifier error, not just the last
		// few lines.
		log.Printf("Verifier error: %+v", ve)
	}
	log.Printf("%+v", err)
}

func parseNetEvent(writers []writer.PacketWriter, rawSample []byte) {
	pevent, err := event.ParsePacketEvent(rawSample)
	if err != nil {
		logErr(err)
		return
	}

	for _, w := range writers {
		if err := w.Write(pevent); err != nil {
			logErr(err)
		}
	}
}

func parseExecEvent(pcache *metadata.ProcessCache, rawSample []byte) {
	e, err := event.ParseProcessExecEvent(rawSample)
	if err != nil {
		logErr(err)
		return
	}
	pcache.AddItem(*e)
}

func newPcapWriter(w io.Writer, ifaceNames []string, pcache *metadata.ProcessCache) (*writer.PcapNGWriter, map[string]int, error) {
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

	return writer.NewPcapNGWriter(pcapWriter, pcache), nameIfcs, nil
}

func setupFlags() *Options {
	opts := &Options{}
	flag.StringVar(&opts.writeFilePath, "w", "",
		"Write the raw packets to file rather than parsing and printing them out. e.g. ptcpdump.pcapng")
	flag.Parse()
	return opts
}

func main() {
	opts := setupFlags()
	if err := rlimit.RemoveMemlock(); err != nil {
		logErr(err)
		return
	}
	var writers []writer.PacketWriter
	pcache := metadata.NewProcessCache()
	go pcache.Start()

	if opts.WritePath() != "" {
		pcapFile, err := os.Create(opts.WritePath())
		if err != nil {
			logErr(err)
			return
		}
		pcapWriter, _, err := newPcapWriter(pcapFile, []string{"lo", "enp0s3", "docker0", "wlp4s0", "enp5s0"}, pcache)
		if err != nil {
			logErr(err)
			return
		}
		defer func() {
			if err := pcapWriter.Flush(); err != nil {
				logErr(err)
			}
		}()
		writers = append(writers, pcapWriter)
	}
	stdoutWriter := writer.NewStdoutWriter(os.Stdout, pcache)
	writers = append(writers, stdoutWriter)

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
	if err := bf.AttachTracepoints(); err != nil {
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

	packetEventReader, err := bf.NewPacketEventReader()
	if err != nil {
		logErr(err)
		return
	}
	defer packetEventReader.Close()
	execEventReader, err := bf.NewExecEventReader()
	if err != nil {
		logErr(err)
		return
	}
	defer execEventReader.Close()

	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()

	log.Println("tracing...")
	go func() {
	loop:
		for {
			select {
			case <-ctx.Done():
				break loop
			default:
			}
			record, err := packetEventReader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					log.Println("Received signal, exiting...")
					return
				}
				log.Printf("reading from packetEventReader: %s", err)
				continue
			}
			if record.LostSamples > 0 {
				log.Printf("lost %d events", record.LostSamples)
				continue
			}
			parseNetEvent(writers, record.RawSample)
		}
	}()
	go func() {
	loop:
		for {
			select {
			case <-ctx.Done():
				break loop
			default:
			}
			record, err := execEventReader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					log.Println("Received signal, exiting...")
					return
				}
				log.Printf("reading from execEventReader: %s", err)
				continue
			}
			parseExecEvent(pcache, record.RawSample)
		}
	}()

	<-ctx.Done()

	log.Println("bye bye")
}
