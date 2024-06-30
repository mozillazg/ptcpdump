package cmd

import (
	"errors"
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
	podName            string
	podNamespace       string

	eventChanSize                 uint
	delayBeforeHandlePacketEvents time.Duration
	execEventsWorkerNumber        uint
	logLevel                      string
	snapshotLength                uint32

	dockerEndpoint     string
	containerdEndpoint string
	criRuntimeEndpoint string
	btfPath            string

	subProgArgs []string

	mntnsId uint32
	netnsId uint32
	pidnsId uint32
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
		parts := strings.Split(opts.podName, ".")
		if len(parts) > 2 {
			logFatal(errors.New("the format of `--pod-name` should be NAME.NAMESPACE"))
		}
		opts.podName = parts[0]
		if len(parts) > 1 {
			opts.podNamespace = parts[1]
		} else {
			opts.podNamespace = "default"
		}
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
