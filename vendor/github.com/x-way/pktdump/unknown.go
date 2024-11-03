package pktdump

import (
	"fmt"
	"github.com/gopacket/gopacket"
)

func (f *Formatter) formatUnknown(layer gopacket.Layer, packet gopacket.Packet) string {
	return fmt.Sprintf("%s, %s, length %d", layer.LayerType().String(),
		packet.LinkLayer().LinkFlow().String(), len(layer.LayerPayload()))
}
