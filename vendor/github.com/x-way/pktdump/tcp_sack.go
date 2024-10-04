package pktdump

import (
	"fmt"
	"github.com/gopacket/gopacket/layers"
	"strings"
)

func formatSack(tcp *layers.TCP, opt layers.TCPOption) string {
	buf := strings.Builder{}
	buf.WriteString("sack")
	data := opt.OptionData
	dataLen := len(data)

	buf.WriteString(fmt.Sprintf(" %d ", dataLen/8))

	for i := 0; i < dataLen; i += 8 {
		s := uint32(bytesToUint64(data[i : i+4]))
		e := uint32(bytesToUint64(data[i+4 : i+8]))
		buf.WriteString(fmt.Sprintf("{%d:%d}", s, e))
	}

	return buf.String()
}
