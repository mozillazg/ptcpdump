package cmd

import (
	"context"
	"github.com/mozillazg/ptcpdump/internal/consumer"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/spf13/cobra"
	"log"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
)

var opts = Options{}

var rootCmd = &cobra.Command{
	Use: `ptcpdump [flags] [expression]

Examples:
  ptcpdump -i any

  ptcpdump -i eth0 --pid 1234 port 80 and host 10.10.1.1

  ptcpdump -i any --pname curl

  ptcpdump -i any -w ptcpdump.pcapng

Expression: see "man 7 pcap-filter"`,
	DisableFlagsInUseLine: true,
	Short:                 "ptcpdump is the tcpdump(8) implementation using eBPF, with an extra feature: it adds process info as packet comments for each Ethernet frame.",
	Run: func(cmd *cobra.Command, args []string) {
		opts.pcapFilter = strings.Join(args, " ")
		err := run(cmd, args)
		if err != nil {
			logErr(err)
		}
	},
}

func init() {
	rootCmd.Flags().StringVarP(&opts.writeFilePath, "write-file", "w", "",
		"Write the raw packets to file rather than parsing and printing them out. e.g. ptcpdump.pcapng")
	rootCmd.Flags().StringSliceVarP(&opts.ifaces, "interface", "i", []string{"lo"},
		"Interfaces to capture")
	rootCmd.Flags().UintVar(&opts.pid, "pid", 0, "Filter by process ID")
	rootCmd.Flags().StringVar(&opts.comm, "pname", "", "Filter by process name")
	rootCmd.Flags().BoolVarP(&opts.followForks, "follow-forks", "f", false,
		"Include child processes when filter by process")
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
}

func Execute() error {
	return rootCmd.Execute()
}

func run(cmd *cobra.Command, args []string) error {
	switch {
	case opts.listInterfaces:
		return listInterfaces()
	case opts.version:
		return printVersion()
	}

	pcache := metadata.NewProcessCache()
	writers, err := getWriters(opts, pcache)
	if err != nil {
		return err
	}
	defer func() {
		for _, w := range writers {
			w.Flush()
		}
	}()
	go pcache.Start()

	devices, bf, err := attachHooks(opts)
	if err != nil {
		if bf != nil {
			bf.Close()
		}
		return err
	}
	defer bf.Close()

	packetEventReader, err := bf.NewPacketEventReader()
	if err != nil {
		return err
	}
	defer packetEventReader.Close()
	execEventReader, err := bf.NewExecEventReader()
	if err != nil {
		return err
	}
	defer execEventReader.Close()

	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()

	execConsumer := consumer.NewExecEventConsumer(pcache)
	go execConsumer.Start(ctx, execEventReader)
	packetConsumer := consumer.NewPacketEventConsumer(writers, devices)
	go func() {
		packetConsumer.Start(ctx, packetEventReader, opts.maxPacketCount)
		stop()
	}()

	runtime.Gosched()

	log.Println("tracing...")
	<-ctx.Done()
	log.Println("bye bye")

	return nil
}
