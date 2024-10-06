package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mozillazg/ptcpdump/internal/utils"
	"github.com/spf13/cobra"
)

var opts = Options{}

var rootCmd = &cobra.Command{
	Use: `ptcpdump [flags] [expression] [-- command [args]]

Examples:
  sudo ptcpdump -i any tcp
  sudo ptcpdump -i eth0 -i lo
  sudo ptcpdump -i eth0 --pid 1234 port 80 and host 10.10.1.1
  sudo ptcpdump -i any --pname curl -A
  sudo ptcpdump -i any --container-id 36f0310403b1
  sudo ptcpdump -i any --container-name test
  sudo ptcpdump -i any -- curl ubuntu.com
  sudo ptcpdump -i any -w ptcpdump.pcapng
  sudo ptcpdump -i any -w - | tcpdump -n -r -
  sudo ptcpdump -i any -w - | tshark -r -
  ptcpdump -r ptcpdump.pcapng

Expression: see "man 7 pcap-filter"`,
	DisableFlagsInUseLine: true,
	Short: "ptcpdump is the tcpdump(8) implementation using eBPF, with an extra feature: \n" +
		" it adds process info as packet comments for each Packet when possible.\n" +
		" More info: https://github.com/mozillazg/ptcpdump",
	Run: func(cmd *cobra.Command, args []string) {
		prepareOptions(&opts, os.Args, args)
		setupLogger(opts)

		err := run(opts)
		if err != nil {
			logFatal(err)
		}
	},
}

func init() {
	rootCmd.Flags().StringVarP(&opts.writeFilePath, "write-file", "w", "",
		"Write the raw packets to file rather than parsing and printing them out. They can later be printed with the -r option. Standard output is used if file is '-'. e.g. ptcpdump.pcapng")
	rootCmd.Flags().StringVarP(&opts.readFilePath, "read-file", "r", "",
		"Read packets from file (which was created with the -w option). e.g. ptcpdump.pcapng")
	rootCmd.Flags().StringSliceVarP(&opts.ifaces, "interface", "i", []string{"lo"},
		"Interfaces to capture")
	rootCmd.Flags().UintSliceVar(&opts.pids, "pid", nil, "Filter by process IDs (only TCP and UDP packets are supported)")
	rootCmd.Flags().StringVar(&opts.comm, "pname", "", "Filter by process name (only TCP and UDP packets are supported)")
	rootCmd.Flags().BoolVarP(&opts.followForks, "follow-forks", "f", false,
		"Trace child processes as they are created by currently traced processes when filter by process")
	rootCmd.Flags().BoolVarP(&opts.listInterfaces, "list-interfaces", "D", false,
		"Print the list of the network interfaces available on the system")
	rootCmd.Flags().BoolVar(&opts.version, "version", false,
		"Print the ptcpdump and libpcap version strings and exit")
	rootCmd.Flags().BoolVar(&opts.print, "print", false,
		"Print parsed packet output, even if the raw packets are being saved to a file with the -w flag")
	rootCmd.Flags().UintVarP(&opts.maxPacketCount, "receive-count", "c", 0,
		"Exit after receiving count packets")
	rootCmd.Flags().StringVarP(&opts.direction, "direction", "Q",
		"inout", "Choose send/receive direction for which packets should be captured. Possible values are 'in', 'out' and 'inout'")
	rootCmd.Flags().UintVar(&opts.eventChanSize, "event-chan-size", 20, "Size of event chan")
	rootCmd.Flags().DurationVar(&opts.delayBeforeHandlePacketEvents, "delay-before-handle-packet-events", 0,
		"Delay some durations before handle packet events")
	rootCmd.Flags().UintVar(&opts.execEventsWorkerNumber, "exec-events-worker-number", 50,
		"Number of worker to handle exec events")
	rootCmd.Flags().BoolVar(&opts.oneLine, "oneline", false,
		"Print parsed packet output in a single line")
	rootCmd.Flags().BoolVarP(&opts.printPacketNumber, "number", "#", false,
		"Print an optional packet number at the beginning of the line")
	rootCmd.Flags().BoolVarP(&opts.dontPrintTimestamp, "no-timestamp", "t", false,
		"Don't print a timestamp on each dump line")
	rootCmd.Flags().BoolVar(&opts.onlyPrintCount, "count", false,
		"Print only on stdout the packet count when reading capture file instead of parsing/printing the packets")
	rootCmd.Flags().CountVarP(&opts.dontConvertAddr, "no-convert-addr", "n",
		"Don't convert addresses (i.e., host addresses, port numbers, etc.) to names")
	rootCmd.Flags().CountVarP(&opts.verbose, "verbose", "v",
		"When parsing and printing, produce (slightly more) verbose output")
	rootCmd.Flags().StringVar(&opts.containerId, "container-id", "", "Filter by container id (only TCP and UDP packets are supported)")
	rootCmd.Flags().StringVar(&opts.containerName, "container-name", "", "Filter by container name (only TCP and UDP packets are supported)")
	rootCmd.Flags().StringVar(&opts.podName, "pod-name", "", "Filter by pod name (format: NAME.NAMESPACE, only TCP and UDP packets are supported)")
	rootCmd.Flags().StringVar(&opts.logLevel, "log-level", "warn", `Set the logging level ("debug", "info", "warn", "error", "fatal")`)
	rootCmd.Flags().StringVar(&opts.dockerEndpoint, "docker-address", "/var/run/docker.sock",
		`Address of Docker Engine service`)
	rootCmd.Flags().StringVar(&opts.containerdEndpoint, "containerd-address", "/run/containerd/containerd.sock",
		`Address of containerd service`)
	rootCmd.Flags().StringVar(&opts.criRuntimeEndpoint, "cri-runtime-address", "",
		"Address of CRI container runtime service "+
			fmt.Sprintf("(default: uses in order the first successful one of [%s])",
				strings.Join(getDefaultCriRuntimeEndpoint(), ", ")))
	rootCmd.Flags().Uint32VarP(&opts.snapshotLength, "snapshot-length", "s", 262144,
		"Snarf snaplen bytes of data from each packet rather than the default of 262144 bytes")
	rootCmd.Flags().StringVar(&opts.btfPath, "kernel-btf", "",
		fmt.Sprintf("specify kernel BTF file (default: uses in order the first successful one of [%s]",
			strings.Join([]string{"/sys/kernel/btf/vmlinux", "/var/lib/ptcpdump/btf/vmlinux",
				"/var/lib/ptcpdump/btf/vmlinux-$(uname -r)",
				"/var/lib/ptcpdump/btf/$(uname -r).btf",
				"download BTF file from https://mirrors.openanolis.cn/coolbpf/btf/ and https://github.com/aquasecurity/btfhub-archive/"}, ", ")),
	)
	rootCmd.Flags().StringVar(&opts.timeStampPrecision, "time-stamp-precision", "micro",
		"When capturing, set the time stamp precision for the capture to the format")
	rootCmd.Flags().BoolVar(&opts.timeStampMicro, "micro", false,
		"Shorthands for --time-stamp-precision=micro")
	rootCmd.Flags().BoolVar(&opts.timeStampNano, "nano", false,
		"Shorthands for --time-stamp-precision=nano")
	rootCmd.Flags().CountVarP(&opts.printDataAsHex, "print-data-in-hex", "x",
		"When parsing and printing, in addition to printing the headers of each packet, print the data of each packet in hex")
	rootCmd.Flags().CountVarP(&opts.printDataAsHexASCII, "print-data-in-hex-ascii", "X",
		"When parsing and printing, in addition to printing the headers of each packet, print the data of each packet in hex and ASCII")
	rootCmd.Flags().BoolVarP(&opts.printDataAsASCII, "print-data-in-ascii", "A", false,
		"Print each packet (minus its link level header) in ASCII")

	rootCmd.Flags().StringVar(&opts.writeTLSKeyLogPath, "write-keylog-file", "",
		"Write TLS Key Log file to this path (experimental: only support unstripped Go binary and must combined with `-- CMD [ARGS]`)")
	rootCmd.Flags().BoolVar(&opts.embedTLSKeyLogToPcapng, "embed-keylog-to-pcapng", false,
		"Write TLS Key Log file to this path (experimental: only support unstripped Go binary and must combined with `-- CMD [ARGS]`)")

	rootCmd.Flags().StringSliceVar(&opts.netNsPaths, "netns", []string{},
		"Path to an network namespace file or name")

	silenceKlog()
}

func Execute() error {
	return rootCmd.Execute()
}

func run(opts Options) error {
	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()

	switch {
	case os.Getenv(utils.EnvIsSubProgramLoader) == "true" && len(opts.subProgArgs) > 0:
		return utils.StartSubProcess(ctx, opts.subProgArgs)
	case opts.listInterfaces:
		return listInterfaces(opts)
	case opts.version:
		return printVersion()
	case opts.ReadPath() != "":
		return read(ctx, opts)
	default:
		return capture(ctx, stop, &opts)
	}

	return nil
}
