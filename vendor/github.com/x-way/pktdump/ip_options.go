package pktdump

import (
	"encoding/binary"
	"fmt"
	"github.com/gopacket/gopacket/layers"
	"net/netip"
	"strings"
)

const IPOPT_EOL = 0 /* end of option list */
const IPOPT_NOP = 1 /* no operation */

const IPOPT_RR = 7         /* record packet route */
const IPOPT_TS = 68        /* timestamp */
const IPOPT_RFC1393 = 82   /* traceroute RFC 1393 */
const IPOPT_SECURITY = 130 /* provide s,c,h,tcc */
const IPOPT_LSRR = 131     /* loose source route */
const IPOPT_SSRR = 137     /* strict source route */
const IPOPT_RA = 148       /* router-alert, rfc2113 */

func formatIPv4Options(ipv4 *layers.IPv4) string {
	lines := []string{}
loop:
	for _, option := range ipv4.Options {
		switch option.OptionType {
		case IPOPT_EOL:
			lines = append(lines, "EOL")
			break loop
		case IPOPT_NOP:
			lines = append(lines, "NOP")
		case IPOPT_TS:
			lines = append(lines, "timestamp")
		case IPOPT_SECURITY:
			lines = append(lines, "security")
		case IPOPT_RR:
			lines = append(lines, fmt.Sprintf("RR %s", formatIpRoute(option)))
		case IPOPT_SSRR:
			lines = append(lines, fmt.Sprintf("SSRR %s", formatIpRoute(option)))
		case IPOPT_LSRR:
			lines = append(lines, fmt.Sprintf("LSRR %s", formatIpRoute(option)))
		case IPOPT_RA:
			lines = append(lines, "RA")
		case IPOPT_RFC1393:
			lines = append(lines, "traceroute")
		}
	}

	return strings.Join(lines, ",")
}

func formatIpRoute(opt layers.IPv4Option) string {
	length := opt.OptionLength
	if length < 3 || ((length+1)&3) > 0 {
		return fmt.Sprintf(" [bad length %d]", opt.OptionLength)
	}

	var ips []string
	offset := uint8(1)
	for offset < length {
		ipRaw := opt.OptionData[offset : offset+4]
		if len(ipRaw) < 4 {
			break
		}
		ipUint32 := binary.LittleEndian.Uint32(ipRaw)
		addr := ipFromUint32(ipUint32)
		if addr.IsValid() {
			ips = append(ips, addr.String())
		}
		offset += 4
	}
	if len(ips) > 1 {
		ips[0] = ips[0] + ","
	}

	return strings.Join(ips, " ")
}

func ipFromUint32(ipUint32 uint32) netip.Addr {
	data := [4]byte{}
	binary.LittleEndian.PutUint32(data[:], ipUint32)
	addr := netip.AddrFrom4(data)
	if !addr.IsValid() {
		return netip.Addr{}
	}
	str := addr.String()
	if str != "0.0.0.0" && strings.HasPrefix(str, "0.") {
		return netip.Addr{}
	}
	return addr
}
