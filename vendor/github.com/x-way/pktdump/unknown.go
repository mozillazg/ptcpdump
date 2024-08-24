package pktdump

import (
	"fmt"
	"github.com/gopacket/gopacket"
)

func formatUnknown(layer gopacket.Layer, packet gopacket.Packet, opts *Options) string {
	return fmt.Sprintf("%s, %s, length %d", layer.LayerType().String(),
		packet.LinkLayer().LinkFlow().String(), len(layer.LayerPayload()))
}
