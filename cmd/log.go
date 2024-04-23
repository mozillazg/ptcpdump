package cmd

import (
	"errors"
	"github.com/cilium/ebpf"
	"log"
)

func logErr(err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		// Using %+v will print the whole verifier error, not just the last
		// few lines.
		log.Printf("Verifier error: %+v", ve)
	}
	log.Printf("%+v", err)
}
