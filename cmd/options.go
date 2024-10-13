package cmd

import (
	"context"
	"fmt"
	"github.com/mozillazg/ptcpdump/internal/capturer"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/mozillazg/ptcpdump/internal/types"
	"github.com/mozillazg/ptcpdump/internal/writer"
	"github.com/x-way/pktdump"
	"os"
	"path"
	"strings"
	"time"

	"github.com/mozillazg/ptcpdump/internal/metadata/k8s"
)

const (
	extPcap   = ".pcap"
	extPcapNG = ".pcapng"
)

type Options struct {
	ifaces         []string
	pids           []uint
	comm           string
	followForks    bool
	writeFilePath  string
	readFilePath   string
	pcapFilter     string
	listInterfaces bool
	version        bool
	print          bool
	maxPacketCount uint
	direction      string
	oneLine        bool

	printPacketNumber   bool
	dontPrintTimestamp  bool
	onlyPrintCount      bool
	printDataAsHex      int
	printDataAsHexASCII int
	printDataAsASCII    bool

	timeStampPrecision string
	timeStampMicro     bool
	timeStampNano      bool

	dontConvertAddr int
	verbose         int

	containerId   string
	containerName string
	podName       string
	podNamespace  string

	eventChanSize                 uint
	delayBeforeHandlePacketEvents time.Duration
	execEventsWorkerNumber        uint
	logLevel                      string
	snapshotLength                uint32

	dockerEndpoint     string
	containerdEndpoint string
	criRuntimeEndpoint string
	btfPath            string

	writeTLSKeyLogPath     string
	embedTLSKeyLogToPcapng bool

	subProgArgs []string

	mntnsIds []uint32
	netnsIds []uint32
	pidnsIds []uint32

	netNsPaths    []string
	devices       *types.Interfaces
	netNSCache    *metadata.NetNsCache
	deviceCache   *metadata.DeviceCache
	allDev        bool
	allNetNs      bool
	allNewlyNetNs bool
}

func (o Options) filterByContainer() bool {
	return o.containerId != "" || o.containerName != "" || o.podName != ""
}

func (o Options) WritePath() string {
	return o.writeFilePath
}

func (o Options) ReadPath() string {
	return o.readFilePath
}

func (o Options) DirectionIn() bool {
	return o.DirectionInOut() || o.direction == "in"
}
func (o Options) DirectionOut() bool {
	return o.DirectionInOut() || o.direction == "out"
}

func (o Options) DirectionInOut() bool {
	return o.direction == "inout"
}

func (o Options) TimeStampAsNano() bool {
	return o.timeStampNano || o.timeStampPrecision == "nano"
}

func prepareOptions(opts *Options, rawArgs []string, args []string) {
	subProgArgs := getSubProgArgs(rawArgs)
	opts.pcapFilter = strings.Join(args, " ")
	if len(subProgArgs) > 0 {
		opts.subProgArgs = subProgArgs
		opts.pcapFilter = strings.TrimSuffix(opts.pcapFilter, strings.Join(subProgArgs, " "))
	}
	opts.pcapFilter = strings.TrimSpace(opts.pcapFilter)

	if opts.dockerEndpoint != "" {
		opts.dockerEndpoint = getEndpoint(opts.dockerEndpoint)
	}
	// if opts.containerdEndpoint != "" {
	// 	opts.containerdEndpoint = getEndpoint(opts.containerdEndpoint)
	// }
	if opts.criRuntimeEndpoint != "" {
		opts.criRuntimeEndpoint = getEndpoint(opts.criRuntimeEndpoint)
	}

	if opts.podName != "" {
		opts.podName, opts.podNamespace = getPodNameFilter(opts.podName)
	}
}

func getPodNameFilter(raw string) (name, ns string) {
	if !strings.Contains(raw, ".") {
		return raw, "default"
	}
	index := strings.LastIndex(raw, ".")
	return raw[:index], raw[index+1:]
}

func getEndpoint(raw string) string {
	if strings.HasPrefix(raw, "http") {
		return raw
	}
	if strings.HasPrefix(raw, "unix://") {
		return raw
	}
	return fmt.Sprintf("unix://%s", raw)
}

func getDefaultCriRuntimeEndpoint() []string {
	var rs []string
	for _, end := range k8s.DefaultRuntimeEndpoints {
		rs = append(rs, strings.TrimPrefix(end, "unix://"))
	}
	return rs
}

func (o Options) applyToStdoutWriter(w *writer.StdoutWriter) {
	w.OneLine = opts.oneLine
	w.PrintNumber = opts.printPacketNumber
	w.NoTimestamp = opts.dontPrintTimestamp
	w.TimestampNano = opts.TimeStampAsNano()
	if opts.onlyPrintCount {
		w.DoNothing = true
	}
	if opts.verbose >= 1 {
		w.FormatStyle = pktdump.FormatStyleVerbose
	}
	switch {
	case opts.printDataAsHexASCII > 1:
		w.DataStyle = pktdump.ContentStyleHexWithLinkASCII
		break
	case opts.printDataAsHexASCII == 1:
		w.DataStyle = pktdump.ContentStyleHexWithASCII
		break
	case opts.printDataAsHex > 1:
		w.DataStyle = pktdump.ContentStyleHexWithLink
		break
	case opts.printDataAsHex == 1:
		w.DataStyle = pktdump.ContentStyleHex
		break
	case opts.printDataAsASCII:
		w.DataStyle = pktdump.ContentStyleASCII
		break
	}
}

func (o Options) shouldEnableGoTLSHooks() bool {
	if len(o.subProgArgs) == 0 {
		return false
	}
	if o.getWriteTLSKeyLogPath() != "" || o.embedTLSKeyLogToPcapng {
		return true
	}
	return false
}

func (o Options) getWriteTLSKeyLogPath() string {
	if o.writeTLSKeyLogPath != "" {
		return o.writeTLSKeyLogPath
	}
	return os.Getenv("SSLKEYLOGFILE")
}

func (o *Options) GetDevices() (*types.Interfaces, error) {
	if o.devices != nil {
		return o.devices, nil
	}

	log.Infof("before: o.netNsPaths=%v, o.ifaces=%v", o.netNsPaths, o.ifaces)
	if len(o.netNsPaths) > 0 {
		if o.netNsPaths[0] == "any" {
			o.allNetNs = true
			o.netNsPaths = []string{}
		} else if o.netNsPaths[0] == "newly" {
			o.allNewlyNetNs = true
			o.netNsPaths = []string{}
		}
	}
	for i, p := range o.netNsPaths {
		if !strings.Contains(p, "/") {
			o.netNsPaths[i] = path.Join("/run/netns", p)
		}
	}
	if len(o.ifaces) > 0 && o.ifaces[0] == "any" {
		o.allDev = true
		o.ifaces = []string{}
	}

	log.Infof("after: o.netNsPaths=%v, o.ifaces=%v", o.netNsPaths, o.ifaces)

	o.netNSCache = metadata.NewNetNsCache()
	o.deviceCache = metadata.NewDeviceCache(o.netNSCache)
	if err := o.netNSCache.Start(context.TODO()); err != nil {
		return nil, err
	}
	if err := o.deviceCache.Start(context.TODO()); err != nil {
		return nil, err
	}

	if o.allNewlyNetNs {
		o.devices = types.NewInterfaces()
		return o.devices, nil
	}

	var err error
	o.devices, err = o.deviceCache.GetDevices(o.ifaces, o.netNsPaths)
	if err != nil {
		return nil, err
	}

	return o.devices, nil
}

func (o *Options) ToCapturerOptions() *capturer.Options {
	copts := &capturer.Options{
		Pids:                          o.pids,
		Comm:                          o.comm,
		FollowForks:                   o.followForks,
		PcapFilter:                    o.pcapFilter,
		MaxPacketCount:                o.maxPacketCount,
		DirectionIn:                   o.DirectionIn(),
		DirectionOut:                  o.DirectionOut(),
		OneLine:                       o.oneLine,
		PrintPacketNumber:             o.printPacketNumber,
		DontPrintTimestamp:            o.dontPrintTimestamp,
		OnlyPrintCount:                o.onlyPrintCount,
		PrintDataAsHex:                o.printDataAsHex,
		PrintDataAsHexASCII:           o.printDataAsHexASCII,
		PrintDataAsASCII:              o.printDataAsASCII,
		TimeStampPrecision:            o.timeStampPrecision,
		TimeStampMicro:                o.timeStampMicro,
		TimeStampNano:                 o.timeStampNano,
		DontConvertAddr:               o.dontConvertAddr,
		ContainerId:                   o.containerId,
		ContainerName:                 o.containerName,
		PodName:                       o.podName,
		PodNamespace:                  o.podNamespace,
		EventChanSize:                 o.eventChanSize,
		DelayBeforeHandlePacketEvents: o.delayBeforeHandlePacketEvents,
		ExecEventsWorkerNumber:        o.execEventsWorkerNumber,
		SnapshotLength:                o.snapshotLength,
		DockerEndpoint:                o.dockerEndpoint,
		ContainerdEndpoint:            o.containerdEndpoint,
		CriRuntimeEndpoint:            o.criRuntimeEndpoint,
		WriteTLSKeyLogPath:            o.writeTLSKeyLogPath,
		EmbedTLSKeyLogToPcapng:        o.embedTLSKeyLogToPcapng,
		SubProgArgs:                   o.subProgArgs,
		MntnsIds:                      o.mntnsIds,
		NetnsIds:                      o.netnsIds,
		PidnsIds:                      o.pidnsIds,
		BTFPath:                       o.btfPath,
		AllDev:                        o.allDev,
		AllNetNs:                      o.allNetNs,
		AllNewlyNetNs:                 o.allNewlyNetNs,
		NetNsPaths:                    opts.netNsPaths,
		DevNames:                      opts.ifaces,
	}
	return copts
}
