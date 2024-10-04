package pktdump

import (
	"fmt"
	"github.com/gopacket/gopacket/layers"
	"strings"
)

var (
	TCPOptionKindFastopen layers.TCPOptionKind = 34
)

func formatFastOpen(tcp *layers.TCP, opt layers.TCPOption) string {
	buf := strings.Builder{}
	buf.WriteString("tfo")
	data := opt.OptionData
	dataLen := len(data)

	buf.WriteString(" ")
	if dataLen == 0 {
		buf.WriteString(" cookiereq")
	} else {
		buf.WriteString(" cookie ")
		for _, v := range data {
			buf.WriteString(fmt.Sprintf("%02x", v))
		}
	}

	return buf.String()
}
