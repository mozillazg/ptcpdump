package cmd

import (
	"fmt"
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
	pid            uint
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

	printPacketNumber  bool
	dontPrintTimestamp bool
	onlyPrintCount     bool
	dontConvertAddr    int
	verbose            int
	containerId        string
	containerName      string

	eventChanSize                 uint
	delayBeforeHandlePacketEvents time.Duration
	execEventsWorkerNumber        uint
	logLevel                      string

	dockerEndpoint     string
	containerdEndpoint string
	criRuntimeEndpoint string

	subProgArgs []string

	mntns_id uint32
	netns_id uint32
	pidns_id uint32
}

func (o Options) filterByContainer() bool {
	return o.containerId != "" || o.containerName != ""
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
