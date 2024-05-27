package cmd

import (
	"context"
	"github.com/mozillazg/ptcpdump/internal/utils"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"syscall"
)

var opts = Options{}

var rootCmd = &cobra.Command{
	Use: `ptcpdump [flags] [expression] [-- command [args]]

Examples:
  sudo ptcpdump -i any tcp
  sudo ptcpdump -i eth0 -i lo
  sudo ptcpdump -i eth0 --pid 1234 port 80 and host 10.10.1.1
  sudo ptcpdump -i any --pname curl
  sudo ptcpdump -i any -- curl ubuntu.com
  sudo ptcpdump -i any -w ptcpdump.pcapng
  sudo ptcpdump -i any -w - port 80 | tcpdump -n -r -
  sudo ptcpdump -i any -w - port 80 | tshark -r -
  ptcpdump -r ptcpdump.pcapng

Expression: see "man 7 pcap-filter"`,
	DisableFlagsInUseLine: true,
	Short:                 "ptcpdump is the tcpdump(8) implementation using eBPF, with an extra feature: it adds process info as packet comments for each Packet when possible.",
	Run: func(cmd *cobra.Command, args []string) {
		prepareOptions(&opts, os.Args, args)

		err := run(opts)
		if err != nil {
			logErr(err)
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
	rootCmd.Flags().UintVar(&opts.pid, "pid", 0, "Filter by process ID (only TCP and UDP packets are supported)")
	rootCmd.Flags().StringVar(&opts.comm, "pname", "", "Filter by process name (only TCP and UDP packets are supported)")
	rootCmd.Flags().BoolVarP(&opts.followForks, "follow-forks", "f", false,
		"Trace child processes as they are created by currently traced processes when filter by process")
	rootCmd.Flags().BoolVar(&opts.listInterfaces, "list-interfaces", false,
		"Print the list of the network interfaces available on the system")
	rootCmd.Flags().BoolVar(&opts.version, "version", false,
		"Print the ptcpdump and libpcap version strings and exit")
	rootCmd.Flags().BoolVar(&opts.print, "print", false,
		"Print parsed packet output, even if the raw packets are being saved to a file with the -w flag")
	rootCmd.Flags().UintVarP(&opts.maxPacketCount, "receive-count", "c", 0,
		"Exit after receiving count packets")
	rootCmd.Flags().StringVarP(&opts.direction, "direction", "Q",
		"inout", "Choose send/receive direction for which packets should be captured. Possible values are 'in', 'out' and 'inout'")
	rootCmd.Flags().UintVar(&opts.eventChanSize, "event-chan-size", 10, "Size of event chan")
	rootCmd.Flags().DurationVar(&opts.delayBeforeHandlePacketEvents, "delay-before-handle-packet-events", 0,
		"Delay some durations before handle packet events")
	rootCmd.Flags().UintVar(&opts.execEventsWorkerNumber, "exec-events-worker-number", 10,
		"Number of worker to handle exec events")
	rootCmd.Flags().BoolVar(&opts.oneLine, "oneline", false,
		"Print parsed packet output in a single line")
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
		return listInterfaces()
	case opts.version:
		return printVersion()
	case opts.ReadPath() != "":
		return read(ctx, opts)
	default:
		return capture(ctx, stop, opts)
	}

	return nil
}
