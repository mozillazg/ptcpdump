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
	Use:   "ptcpdump",
	Short: "XXX",
	Long:  `XXX.`,
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
	rootCmd.Flags().StringSliceVarP(&opts.ifaces, "interface", "i", []string{"lo"}, "")
	rootCmd.Flags().UintVar(&opts.pid, "pid", 0, "")
	rootCmd.Flags().StringVar(&opts.comm, "pname", "", "")
	rootCmd.Flags().BoolVarP(&opts.followForks, "follow-forks", "f", false,
		"Include child processes when filter by process")
	rootCmd.Flags().BoolVar(&opts.listInterfaces, "list-interfaces", false,
		"Print the list of the network interfaces available on the system")
	rootCmd.Flags().BoolVar(&opts.version, "version", false, "")
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
	go packetConsumer.Start(ctx, packetEventReader)

	runtime.Gosched()

	log.Println("tracing...")
	<-ctx.Done()
	log.Println("bye bye")

	return nil
}
