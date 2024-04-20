package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/mozillazg/ptcpdump/bpf"
	"golang.org/x/xerrors"
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

func parseEvent(pcapWriter *pcapgo.NgWriter, rawSample []byte) {
	event := bpf.BpfPacketEventT{}
	if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event.Meta); err != nil {
		log.Printf("parse event failed: %+v", err)
		return
	}
	copy(event.Payload[:], rawSample[unsafe.Offsetof(event.Payload):])

	packetType := "=>·  "
	if event.Meta.PacketType == 1 {
		packetType = "  ·=>"
	}

	// Decode a packet
	data := event.Payload[:]
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	var ipv4 *layers.IPv4
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4, _ = ipv4Layer.(*layers.IPv4)
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		log.Printf("%s %s-%d %s:%d => %s:%d",
			packetType, strComm(event.Meta.Comm), event.Meta.Pid,
			ipv4.SrcIP.String(), tcp.SrcPort,
			ipv4.DstIP.String(), tcp.DstPort)
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		log.Printf("%s %s-%d %s:%d => %s:%d",
			packetType, strComm(event.Meta.Comm), event.Meta.Pid,
			ipv4.SrcIP.String(), udp.SrcPort,
			ipv4.DstIP.String(), udp.DstPort)
	}

	payloadLen := int(event.Meta.PayloadLen)
	info := gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		CaptureLength:  payloadLen,
		Length:         payloadLen,
		InterfaceIndex: 0,
	}
	packetData := make([]byte, payloadLen)
	copy(packetData, data[:payloadLen])
	log.Printf("len1: %d, len2: %d", len(packetData), len(data[:payloadLen]))
	opts := pcapgo.NgPacketOptions{
		Comment: fmt.Sprintf("PID: %d\nCOMMAND: %s", event.Meta.Pid, strComm(event.Meta.Comm)),
	}

	if err := pcapWriter.WritePacketWithOptions(info, packetData, opts); err != nil {
		// if err := pcapWriter.WritePacket(info, packetData); err != nil {
		log.Printf("Error writing packet: %+v", err)
	}
	pcapWriter.Flush()
}

func strComm(comm [16]int8) string {
	b := []byte{}
	for _, c := range comm {
		b = append(b, byte(c))
	}
	return string(b)
}

func newPcapWriter(w io.Writer, ifaceNames []string) (*pcapgo.NgWriter, map[string]int, error) {
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

	return pcapWriter, nameIfcs, nil
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		logErr(err)
		return
	}
	pcapFile, err := os.Create("test.pcapng")
	if err != nil {
		logErr(err)
		return
	}
	pcapWriter, _, err := newPcapWriter(pcapFile, []string{"lo", "enp0s3", "docker0"})
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

	for _, ifaceName := range []string{"lo", "enp0s3", "docker0"} {
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
