package pktdump

import (
	"fmt"
	"github.com/gopacket/gopacket/layers"
	"strings"
)

func (f *Formatter) formatSack(tcp *layers.TCP, opt layers.TCPOption, src, dst string) string {
	buf := strings.Builder{}
	buf.WriteString("sack")
	data := opt.OptionData
	dataLen := len(data)
	blockCount := dataLen / 8
	buf.WriteString(fmt.Sprintf(" %d ", blockCount))

	var (
		relBase  uint32
		relative bool
	)
	if f != nil && f.opts.relativeTCPSeqEnabled() {
		reverseKey := makeTCPFlowKey(dst, src, tcp.DstPort, tcp.SrcPort)
		if reverse := f.tcpState[reverseKey]; reverse != nil && reverse.seqInitialized {
			relBase = reverse.baseSeq
			relative = true
		}
	}

	for i := 0; i+8 <= dataLen; i += 8 {
		s := uint32(bytesToUint64(data[i : i+4]))
		e := uint32(bytesToUint64(data[i+4 : i+8]))
		if relative {
			s = s - relBase
			e = e - relBase
		}
		buf.WriteString(fmt.Sprintf("{%d:%d}", uint64(s), uint64(e)))
	}

	return buf.String()
}
