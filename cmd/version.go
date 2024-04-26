package cmd

import (
	"fmt"
	"github.com/gopacket/gopacket/pcap"
	"github.com/mozillazg/ptcpdump/internal"
)

func printVersion() error {
	fmt.Printf("ptcpdump version %s\n", internal.Version)
	fmt.Printf("%s\n", pcap.Version())
	return nil
}
