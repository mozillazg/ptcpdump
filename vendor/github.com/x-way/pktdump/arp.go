package pktdump

import (
	"fmt"
	"net"
	"strings"

	"github.com/gopacket/gopacket/layers"
)

func formatARP(arp *layers.ARP, length int, opts *Options) string {
	builder := strings.Builder{}
	builder.WriteString("ARP")

	senderMac := net.HardwareAddr(arp.SourceHwAddress)
	senderIP := net.IP(arp.SourceProtAddress)
	//targetMac := net.HardwareAddr(arp.DstHwAddress)
	targetIP := net.IP(arp.DstProtAddress)

	switch arp.Operation {
	case layers.ARPRequest:
		builder.WriteString(fmt.Sprintf(", Request who-has %s tell %s", targetIP.String(), senderIP.String()))
	case layers.ARPReply:
		builder.WriteString(fmt.Sprintf(", Reply %s is-at %s", senderIP.String(), senderMac))
	}
	builder.WriteString(fmt.Sprintf(", length %d", length))
	return builder.String()
}
