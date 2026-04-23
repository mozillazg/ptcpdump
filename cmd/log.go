package cmd

import (
	"errors"
	"flag"
	"io"

	"github.com/cilium/ebpf"
	"github.com/go-logr/logr"
	"github.com/mozillazg/ptcpdump/internal/log"
	plog "github.com/phuslu/log"
	"k8s.io/klog/v2"
)

func logFatal(err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		// Using %+v will print the whole verifier error, not just the last
		// few lines.
		log.Errorf("Verifier error: %+v", ve)
	}
	log.Fatalf("%+v", err)
}

func setupLogger(opts *Options) {
	switch opts.logLevel {
	case "debug":
		log.SetLevel(plog.DebugLevel)
	case "info":
		log.SetLevel(plog.InfoLevel)
	case "warn":
		log.SetLevel(plog.WarnLevel)
		klog.SetLogger(logr.Discard())
	case "error":
		log.SetLevel(plog.ErrorLevel)
		klog.SetLogger(logr.Discard())
	case "fatal":
		log.SetLevel(plog.FatalLevel)
		klog.SetLogger(logr.Discard())
	}
}

func silenceKlog() {
	klog.SetOutput(io.Discard)
	flags := &flag.FlagSet{}
	klog.InitFlags(flags)
	// Opt into the new klog behavior so that -stderrthreshold is honored even
	// when -logtostderr=true (the default).
	// Ref: kubernetes/klog#212, kubernetes/klog#432
	_ = flags.Set("legacy_stderr_threshold_behavior", "false")
	_ = flags.Set("stderrthreshold", "INFO")
	flags.Set("logtostderr", "false")
	flags.Set("alsologtostderr", "false")
}
