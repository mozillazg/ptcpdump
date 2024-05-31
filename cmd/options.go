package cmd

import (
	"strings"
	"time"
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

	eventChanSize                 uint
	delayBeforeHandlePacketEvents time.Duration
	execEventsWorkerNumber        uint

	subProgArgs []string
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
}
