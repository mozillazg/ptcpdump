package cmd

import (
	"fmt"
	"github.com/gopacket/gopacket/pcap"
	"github.com/mozillazg/ptcpdump/internal"
	"strings"
)

func printVersion() error {
	fmt.Printf("ptcpdump version %s\n", strings.TrimLeft(internal.Version, "v"))
	fmt.Printf("%s\n", pcap.Version())
	return nil
}
