package cmd

import (
	"errors"
	"flag"
	"io"
	"k8s.io/klog/v2"

	"github.com/cilium/ebpf"
	"github.com/mozillazg/ptcpdump/internal/log"
	plog "github.com/phuslu/log"
)

func logFatal(err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		// Using %+v will print the whole verifier error, not just the last
		// few lines.
		log.Fatalf("Verifier error: %+v", ve)
	}
	log.Fatalf("%+v", err)
}

func setupLogger(opts Options) {
	switch opts.logLevel {
	case "debug":
		log.SetLevel(plog.DebugLevel)
	case "info":
		log.SetLevel(plog.InfoLevel)
	case "warn":
		log.SetLevel(plog.WarnLevel)
	case "error":
		log.SetLevel(plog.ErrorLevel)
	case "fatal":
		log.SetLevel(plog.FatalLevel)
	}
}

func silenceKlog() {
	klog.SetOutput(io.Discard)
	flags := &flag.FlagSet{}
	klog.InitFlags(flags)
	flags.Set("logtostderr", "false")
	flags.Set("alsologtostderr", "false")
}
