// Package pktdump formats gopacket.Packet network packets similar to the tcpdump CLI output
package pktdump

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func (f *Formatter) formatPacketTCP(packet *gopacket.Packet, tcp *layers.TCP, src, dst string, length int) string {
	length -= int(tcp.DataOffset) * 4
	if length < 0 {
		length = 0
	}

	if f.opts.Quiet {
		return fmt.Sprintf("%s.%d > %s.%d: tcp %d", src, tcp.SrcPort, dst, tcp.DstPort, length)
	}

	flags := ""
	if tcp.FIN {
		flags += "F"
	}
	if tcp.SYN {
		flags += "S"
	}
	if tcp.RST {
		flags += "R"
	}
	if tcp.PSH {
		flags += "P"
	}
	if tcp.ACK {
		flags += "."
	}
	if tcp.URG {
		flags += "U"
	}
	if tcp.ECE {
		flags += "E"
	}
	if tcp.CWR {
		flags += "W"
	}
	if tcp.NS {
		flags += "N"
	}
	if flags == "" {
		flags = "none"
	}
	out := fmt.Sprintf("%s.%d > %s.%d: Flags [%s]", src, tcp.SrcPort, dst, tcp.DstPort, flags)
	if f.opts.HeaderStyle >= FormatStyleVerbose {
		out += fmt.Sprintf(", cksum 0x%x", tcp.Checksum)
	}

	if f.opts.relativeTCPSeqEnabled() {
		seqPart, ackPart := f.tcpSequenceFields(tcp, src, dst, length)
		if seqPart != "" {
			out += ", " + seqPart
		}
		if ackPart != "" {
			out += ", " + ackPart
		}
		if ackPart == "" && tcp.ACK {
			out += fmt.Sprintf(", ack %d", tcp.Ack)
		}
	} else {
		if length > 0 || tcp.SYN || tcp.FIN || tcp.RST || tcp.ACK {
			if length > 0 {
				out += fmt.Sprintf(", seq %d:%d", tcp.Seq, int(tcp.Seq)+length)
			} else {
				out += fmt.Sprintf(", seq %d", tcp.Seq)
			}
		}
		if tcp.ACK {
			out += fmt.Sprintf(", ack %d", tcp.Ack)
		}
	}

	out += fmt.Sprintf(", win %d", tcp.Window)
	if tcp.URG {
		out += fmt.Sprintf(", urg %d", tcp.Urgent)
	}
	if len(tcp.Options) > 0 {
		out += ", options ["
		for i, opt := range tcp.Options {
			if i > 0 {
				out += ","
			}
			switch opt.OptionType {
			case layers.TCPOptionKindMSS:
				out += fmt.Sprintf("mss %d", binary.BigEndian.Uint16(opt.OptionData))
			case layers.TCPOptionKindNop:
				out += "nop"
			case layers.TCPOptionKindEndList:
				out += "eol"
			case layers.TCPOptionKindWindowScale:
				out += fmt.Sprintf("wscale %d", opt.OptionData[0])
			case layers.TCPOptionKindSACK:
				out += f.formatSack(tcp, opt, src, dst)
			case layers.TCPOptionKindSACKPermitted:
				out += "sackOK"
			case layers.TCPOptionKindTimestamps:
				out += fmt.Sprintf("TS val %d ecr %d", binary.BigEndian.Uint32(opt.OptionData[:4]), binary.BigEndian.Uint32(opt.OptionData[4:8]))
			case layers.TCPOptionKindMultipathTCP:
				out += formatMPTCP(opt)
			case TCPOptionKindFastopen:
				out += formatFastOpen(tcp, opt)
			default:
				out += fmt.Sprintf("unknown-%d", opt.OptionType)
				if len(opt.OptionData) > 0 {
					out += " 0x"
					for _, v := range opt.OptionData {
						out += fmt.Sprintf("%02x", v)
					}
				}
			}
			if opt.OptionType == layers.TCPOptionKindEndList {
				break
			}
		}
		out += "]"
	}
	out += fmt.Sprintf(", length %d", length)

	var haveAppHeader bool
	httpHeader := f.formatHttp(tcp)
	tlsHeader := f.formatTls(packet, tcp, length)
	if len(httpHeader) > 0 || len(tlsHeader) > 0 {
		haveAppHeader = true
	}
	if haveAppHeader {
		out += ": "
	}
	if len(httpHeader) > 0 {
		out += httpHeader
	}
	if len(tlsHeader) > 0 {
		out += tlsHeader
	}

	return out
}

func (f *Formatter) tcpSequenceFields(tcp *layers.TCP, src, dst string, length int) (string, string) {
	if !f.opts.relativeTCPSeqEnabled() {
		return "", ""
	}

	hasControl := tcp.SYN || tcp.FIN || tcp.RST
	shouldPrintSeq := length > 0 || hasControl || !tcp.ACK
	key := makeTCPFlowKey(src, dst, tcp.SrcPort, tcp.DstPort)
	reverseKey := makeTCPFlowKey(dst, src, tcp.DstPort, tcp.SrcPort)

	var dir *tcpDirectionState
	if tcp.SYN && !tcp.ACK {
		dir = f.resetTCPDirection(key, reverseKey)
	} else {
		dir = f.ensureTCPState(key)
	}
	reverse := f.tcpState[reverseKey]

	if !dir.seqInitialized {
		dir.baseSeq = tcp.Seq
		dir.seqInitialized = true
	}

	var seqPart string
	if shouldPrintSeq {
		start := tcp.Seq
		end := start + uint32(length)
		if dir.seqRelative && !tcp.SYN {
			startVal := uint64(start - dir.baseSeq)
			if length > 0 {
				endVal := uint64(end - dir.baseSeq)
				seqPart = fmt.Sprintf("seq %d:%d", startVal, endVal)
			} else {
				seqPart = fmt.Sprintf("seq %d", startVal)
			}
		} else {
			if !dir.seqRelative {
				dir.seqRelative = true
			}
			if length > 0 {
				seqPart = fmt.Sprintf("seq %d:%d", start, end)
			} else {
				seqPart = fmt.Sprintf("seq %d", start)
			}
		}
	}

	var ackPart string
	if tcp.ACK {
		relativeAvailable := reverse != nil && reverse.seqInitialized
		ackVal := uint64(tcp.Ack)
		if !(tcp.SYN && tcp.ACK) && relativeAvailable {
			ackVal = uint64(tcp.Ack - reverse.baseSeq)
		}
		if !dir.ackRelative {
			dir.ackRelative = true
		}
		ackPart = fmt.Sprintf("ack %d", ackVal)
	}

	if tcp.RST {
		delete(f.tcpState, key)
		delete(f.tcpState, reverseKey)
	}

	return seqPart, ackPart
}

func (f *Formatter) formatPacketSIP(sip *layers.SIP, src, dst string, srcPort, dstPort int) string {
	sipStr := "SIP: "
	if sip.IsResponse {
		sipStr += fmt.Sprintf("%s %d %s", sip.Version, sip.ResponseCode, sip.ResponseStatus)
	} else {
		sipStr += fmt.Sprintf("%s %s %s", sip.Method, sip.RequestURI, sip.Version)
	}
	return fmt.Sprintf("%s.%d > %s.%d: %s", src, srcPort, dst, dstPort, sipStr)
}

func (f *Formatter) formatPacketICMPv6(packet *gopacket.Packet, icmp *layers.ICMPv6, src, dst string, length int) string {
	switch icmpType := icmp.TypeCode.Type(); icmpType {
	case layers.ICMPv6TypeEchoRequest:
		if echoLayer := (*packet).Layer(layers.LayerTypeICMPv6Echo); echoLayer != nil {
			echo, _ := echoLayer.(*layers.ICMPv6Echo)
			return fmt.Sprintf("%s > %s: ICMP6, echo request, id %d, seq %d, length %d", src, dst, echo.Identifier, echo.SeqNumber, length)
		}
	case layers.ICMPv6TypeEchoReply:
		if echoLayer := (*packet).Layer(layers.LayerTypeICMPv6Echo); echoLayer != nil {
			echo, _ := echoLayer.(*layers.ICMPv6Echo)
			return fmt.Sprintf("%s > %s: ICMP6, echo reply, id %d, seq %d, length %d", src, dst, echo.Identifier, echo.SeqNumber, length)
		}
	}
	return fmt.Sprintf("%s > %s: ICMP6, length %d", src, dst, length)
}

func (f *Formatter) formatPacketICMPv4(icmp *layers.ICMPv4, src, dst string, length int) string {
	switch icmpType := icmp.TypeCode.Type(); icmpType {
	case layers.ICMPv4TypeEchoRequest:
		return fmt.Sprintf("%s > %s: ICMP echo request, id %d, seq %d, length %d", src, dst, icmp.Id, icmp.Seq, length)
	case layers.ICMPv4TypeEchoReply:
		return fmt.Sprintf("%s > %s: ICMP echo reply, id %d, seq %d, length %d", src, dst, icmp.Id, icmp.Seq, length)
	default:
		return fmt.Sprintf("%s > %s: ICMP, length %d", src, dst, length)
	}
}

func (f *Formatter) formatPacketDNS(dns *layers.DNS, src, dst string, srcPort, dstPort, length int) string {
	dnsStr := ""
	if dns.QR {
		dnsStr = fmt.Sprintf("%d", dns.ID)
		switch dns.OpCode {
		case layers.DNSOpCodeQuery:
			// nothing
		case layers.DNSOpCodeIQuery:
			dnsStr += " inv_q"
		case layers.DNSOpCodeStatus:
			dnsStr += " stat"
		case 3:
			dnsStr += " op3"
		case layers.DNSOpCodeNotify:
			dnsStr += " notify"
		case layers.DNSOpCodeUpdate:
			dnsStr += " update"
		case 6:
			dnsStr += " op6"
		case 7:
			dnsStr += " op7"
		case 8:
			dnsStr += " op8"
		case 9:
			dnsStr += " updateA"
		case 10:
			dnsStr += " updateD"
		case 11:
			dnsStr += " updateDA"
		case 12:
			dnsStr += " updateM"
		case 13:
			dnsStr += " updateMA"
		case 14:
			dnsStr += " zoneInit"
		case 15:
			dnsStr += " zoneRef"
		}
		switch dns.ResponseCode {
		case layers.DNSResponseCodeNoErr:
			// nothing
		case layers.DNSResponseCodeFormErr:
			dnsStr += " FormErr"
		case layers.DNSResponseCodeServFail:
			dnsStr += " ServFail"
		case layers.DNSResponseCodeNXDomain:
			dnsStr += " NXDomain"
		case layers.DNSResponseCodeNotImp:
			dnsStr += " NotImp"
		case layers.DNSResponseCodeRefused:
			dnsStr += " Refused"
		case layers.DNSResponseCodeYXDomain:
			dnsStr += " YXDomain"
		case layers.DNSResponseCodeYXRRSet:
			dnsStr += " YXRRSet"
		case layers.DNSResponseCodeNXRRSet:
			dnsStr += " NXRRSet"
		case layers.DNSResponseCodeNotAuth:
			dnsStr += " NotAuth"
		case layers.DNSResponseCodeNotZone:
			dnsStr += " NotZone"
		case 15:
			dnsStr += " NoChange"
		case 16:
			dnsStr += " BadVers"
		case 23:
			dnsStr += " BadCookie"
		default:
			dnsStr += fmt.Sprintf(" Resp%d", dns.ResponseCode)
		}
		if dns.AA {
			dnsStr += "*"
		}
		if !dns.RA {
			dnsStr += "-"
		}
		if dns.TC {
			dnsStr += "|"
		}
		if (dns.Z & 0x2) == 0x2 {
			dnsStr += "$"
		}

		if dns.QDCount != 1 {
			dnsStr = fmt.Sprintf("%s [%dq]", dnsStr, dns.QDCount)
		}
		dnsStr = fmt.Sprintf("%s %d/%d/%d", dnsStr, dns.ANCount, dns.NSCount, dns.ARCount)
		if dns.ANCount > 0 {
			for i, r := range dns.Answers {
				if i > 0 {
					dnsStr += ","
				}
				if r.Class != layers.DNSClassIN && r.Type != layers.DNSTypeOPT {
					dnsStr += " " + r.Class.String()
				}
				dnsStr += " " + r.Type.String()

				switch r.Type {
				case layers.DNSTypeA, layers.DNSTypeAAAA:
					dnsStr += " " + r.IP.String()
				case layers.DNSTypeCNAME:
					dnsStr += " " + string(r.CNAME) + "."
				case layers.DNSTypeNS:
					dnsStr += " " + string(r.NS) + "."
				case layers.DNSTypeMX:
					dnsStr = fmt.Sprintf("%s %s. %d", dnsStr, string(r.MX.Name), r.MX.Preference)
				case layers.DNSTypeTXT:
					for _, s := range r.TXTs {
						dnsStr = fmt.Sprintf("%s \"%s\"", dnsStr, string(s))
					}
				case layers.DNSTypeSRV:
					dnsStr = fmt.Sprintf("%s %s.:%d %d %d", dnsStr, string(r.SRV.Name), r.SRV.Port, r.SRV.Priority, r.SRV.Weight)
				case layers.DNSTypeURI:
					dnsStr = fmt.Sprintf("%s %d %d %s", dnsStr, r.URI.Priority, r.URI.Weight, string(r.URI.Target))
				case layers.DNSTypeSOA:
					// nothing
				default:
					// nothing
				}
			}
		}
	} else {
		dnsStr = fmt.Sprintf("%d", dns.ID)
		if dns.RD {
			dnsStr += "+"
		}
		if (dns.Z & 0x1) == 0x1 {
			dnsStr += "%"
		}
		if dns.OpCode == layers.DNSOpCodeIQuery {
			if dns.QDCount > 0 {
				dnsStr = fmt.Sprintf("%s [%dq]", dnsStr, dns.QDCount)
			}
			if dns.ANCount != 1 {
				dnsStr = fmt.Sprintf("%s [%da]", dnsStr, dns.ANCount)
			}
		} else {
			if dns.ANCount > 0 {
				dnsStr = fmt.Sprintf("%s [%da]", dnsStr, dns.ANCount)
			}
			if dns.QDCount != 1 {
				dnsStr = fmt.Sprintf("%s [%dq]", dnsStr, dns.QDCount)
			}
		}
		if dns.NSCount > 0 {
			dnsStr = fmt.Sprintf("%s [%dn]", dnsStr, dns.NSCount)
		}
		if dns.ARCount > 0 {
			dnsStr = fmt.Sprintf("%s [%dau]", dnsStr, dns.ARCount)
		}
		if dns.QDCount > 0 {
			for _, q := range dns.Questions {
				dnsStr += " " + q.Type.String()
				if q.Class != layers.DNSClassIN {
					dnsStr += " " + q.Class.String()
				}
				dnsStr += "? " + string(q.Name) + "."
			}
		}
	}
	return fmt.Sprintf("%s.%d > %s.%d: %s (%d)", src, srcPort, dst, dstPort, dnsStr, length)
}

func (f *Formatter) formatPacketUDP(packet *gopacket.Packet, udp *layers.UDP, src, dst string) string {
	length := int(udp.Length) - 8

	if !f.opts.Quiet {
		if udp.SrcPort == 53 || udp.DstPort == 53 || udp.SrcPort == 5353 || udp.DstPort == 5353 {
			if dnsLayer := (*packet).Layer(layers.LayerTypeDNS); dnsLayer != nil {
				dns, _ := dnsLayer.(*layers.DNS)
				return f.formatPacketDNS(dns, src, dst, int(udp.SrcPort), int(udp.DstPort), length)
			}
		}
		if udp.DstPort == 5060 || udp.SrcPort == 5060 {
			if sipLayer := (*packet).Layer(layers.LayerTypeSIP); sipLayer != nil {
				sip, _ := sipLayer.(*layers.SIP)
				return f.formatPacketSIP(sip, src, dst, int(udp.SrcPort), int(udp.DstPort))
			}
		}
	}

	return fmt.Sprintf("%s.%d > %s.%d: UDP, length %d", src, udp.SrcPort, dst, udp.DstPort, length)
}

func (f *Formatter) formatPacketOSPF(ospf layers.OSPF, src, dst string, length int) string {
	var ospfType string
	switch ospf.Type {
	case layers.OSPFHello:
		ospfType = "Hello"
	case layers.OSPFDatabaseDescription:
		ospfType = "Database Description"
	case layers.OSPFLinkStateRequest:
		ospfType = "LS-Request"
	case layers.OSPFLinkStateUpdate:
		ospfType = "LS-Update"
	case layers.OSPFLinkStateAcknowledgment:
		ospfType = "LS-Ack"
	default:
		if ospf.Version == 3 {
			ospfType = fmt.Sprintf("unknown packet type (%d)", ospf.Type)
		} else {
			ospfType = fmt.Sprintf("unknown LS-type %d", ospf.Type)
		}
	}
	return fmt.Sprintf("%s > %s: OSPFv%d, %s, length %d", src, dst, ospf.Version, ospfType, length)
}

func (f *Formatter) formatPacketGRE(gre *layers.GRE, src, dst string, length int) string {
	out := fmt.Sprintf("%s > %s: GREv%d", src, dst, gre.Version)
	switch gre.Version {
	case 0:
		if gre.ChecksumPresent || gre.RoutingPresent {
			out += fmt.Sprintf(", off 0x%x", gre.Offset)
		}
		if gre.KeyPresent {
			out += fmt.Sprintf(", key=0x%x", gre.Key)
		}
		if gre.SeqPresent {
			out += fmt.Sprintf(", seq %d", gre.Seq)
		}
		if gre.RoutingPresent {
			sre := gre.GRERouting
			for sre != nil {
				switch sre.AddressFamily {
				//				case 0x0800:
				//					out += fmt.Sprintf(", (rtaf=ip%s)")
				//				case 0xfffe:
				//					out += fmt.Sprintf(", (rtaf=asn%s)")
				default:
					out += fmt.Sprintf(", (rtaf=0x%x)", sre.AddressFamily)
				}

				sre = sre.Next
			}
		}
		out += fmt.Sprintf(", length %d: ", length)
		switch gre.Protocol {
		case layers.EthernetTypeIPv4:
			out += FormatWithStyle(gopacket.NewPacket(gre.LayerPayload(), layers.LayerTypeIPv4, gopacket.Default), f.opts.HeaderStyle)
		case layers.EthernetTypeIPv6:
			out += FormatWithStyle(gopacket.NewPacket(gre.LayerPayload(), layers.LayerTypeIPv6, gopacket.Default), f.opts.HeaderStyle)
		default:
			out += fmt.Sprintf("gre-proto-0x%x", gre.Protocol&0xffff)
		}
	case 1:
		if gre.KeyPresent {
			out += fmt.Sprintf(", call %d", gre.Key&0xffff)
		}
		if gre.SeqPresent {
			out += fmt.Sprintf(", seq %d", gre.Seq)
		}
		if gre.AckPresent {
			out += fmt.Sprintf(", ack %d", gre.Ack)
		}
		if !gre.SeqPresent {
			out += ", no-payload"
		}
		out += fmt.Sprintf(", length %d: ", length)
		if gre.SeqPresent {
			switch gre.Protocol {
			case layers.EthernetTypePPP:
				if pppLayer := gopacket.NewPacket(gre.LayerPayload(), layers.LayerTypePPP, gopacket.Default).Layer(layers.LayerTypePPP); pppLayer != nil {
					ppp, _ := pppLayer.(*layers.PPP)
					out += f.formatPacketPPP(ppp)
				}
			default:
				out += fmt.Sprintf("gre-proto-0x%x", gre.Protocol&0xffff)
			}
		}
	default:
		out += " ERROR: unknown-version"
	}
	return out
}

func (f *Formatter) formatPacketPPP(ppp *layers.PPP) string {
	switch ppp.PPPType {
	case layers.PPPTypeIPv4:
		return FormatWithStyle(gopacket.NewPacket(ppp.LayerPayload(), layers.LayerTypeIPv4, gopacket.Default), f.opts.HeaderStyle)
	case layers.PPPTypeIPv6:
		return FormatWithStyle(gopacket.NewPacket(ppp.LayerPayload(), layers.LayerTypeIPv6, gopacket.Default), f.opts.HeaderStyle)
	case layers.PPPTypeMPLSUnicast:
		return fmt.Sprintf("MPLS, length %d", len(ppp.LayerPayload()))
	case layers.PPPTypeMPLSMulticast:
		return fmt.Sprintf("MPLS, length %d", len(ppp.LayerPayload()))
	default:
		return fmt.Sprintf("unknown PPP protocol (0x%x)", ppp.PPPType)
	}
}

func (f *Formatter) formatIPv4(ipv4 *layers.IPv4) string {
	fields := []string{}
	fields = append(fields, fmt.Sprintf("tos 0x%x", ipv4.TOS))
	fields = append(fields, fmt.Sprintf("ttl %d", ipv4.TTL))
	fields = append(fields, fmt.Sprintf("id %d", ipv4.Id))
	fields = append(fields, fmt.Sprintf("offset %d", ipv4.FragOffset))
	flags := ipv4.Flags.String()
	if flags == "" {
		flags = "none"
	}
	fields = append(fields, fmt.Sprintf("flags [%s]", flags))
	fields = append(fields, fmt.Sprintf("proto %s (%d)", ipv4.Protocol.String(), ipv4.Protocol))
	fields = append(fields, fmt.Sprintf("length %d", ipv4.Length))

	if f.opts.HeaderStyle >= FormatStyleVerbose {
		options := formatIPv4Options(ipv4)
		if len(options) > 0 {
			fields = append(fields, fmt.Sprintf("options (%s)", options))
		}
	}

	return strings.Join(fields, ", ")
}

func (f *Formatter) formatIPv6(ipv6 *layers.IPv6) string {
	fields := []string{}
	fields = append(fields, fmt.Sprintf("flowlabel 0x%x", ipv6.FlowLabel))
	fields = append(fields, fmt.Sprintf("hlim %d", ipv6.HopLimit))
	fields = append(fields, fmt.Sprintf("next-header %s (%d)", ipv6.NextHeader.String(), ipv6.NextHeader))
	fields = append(fields, fmt.Sprintf("payload length: %d", len(ipv6.Payload)))

	return strings.Join(fields, ", ")
}

func (f *Formatter) formatLinkLayer(packet gopacket.Packet) string {
	var layer gopacket.Layer
	if layer = packet.LinkLayer(); layer == nil {
		return ""
	}

	var nextLayerType gopacket.LayerType
	var length int
	switch layer := layer.(type) {
	case *layers.Ethernet:
		nextLayerType = layer.NextLayerType()
		length = len(layer.LayerPayload())
		break
	default:
		return f.formatUnknown(layer, packet)
	}

	switch nextLayerType {
	case layers.LayerTypeARP:
		if ly := packet.Layer(layers.LayerTypeARP); ly != nil {
			arp, _ := ly.(*layers.ARP)
			return f.formatARP(arp, length)
		}
	}

	return ""
}

// Format parses a packet and returns a string with a textual representation similar to the tcpdump output
var defaultFormatter = NewFormatter(&Options{HeaderStyle: FormatStyleNormal})

func Format(packet gopacket.Packet) string {
	return defaultFormatter.Format(packet)
}

func FormatWithStyle(packet gopacket.Packet, style FormatStyle) string {
	return defaultFormatter.FormatWithOptions(packet, &Options{HeaderStyle: style})
}

func (f *Formatter) formatWithOptions(packet gopacket.Packet) string {
	var net gopacket.Layer
	if f.opts.needFormatLink() && packet.LinkLayer() != nil {
		f.opts.rawContent = append(f.opts.rawContent, packet.LinkLayer().LayerContents()...)
	}
	if net = packet.NetworkLayer(); net == nil {
		return f.formatLinkLayer(packet)
	}
	f.opts.rawContent = append(f.opts.rawContent, net.LayerContents()...)
	style := f.opts.HeaderStyle

	var prefix, src, dst string
	var nextLayerType gopacket.LayerType
	var nextLayerPayload []byte
	var length int
	switch net := net.(type) {
	case *layers.IPv4:
		prefix = fmt.Sprintf("IP ")
		if style >= FormatStyleVerbose {
			prefix = fmt.Sprintf("IP (%s)\n    ", f.formatIPv4(net))
		}
		nextLayerType = net.NextLayerType()
		nextLayerPayload = net.LayerPayload()
		src = net.SrcIP.String()
		dst = net.DstIP.String()
		length = int(net.Length) - int(net.IHL)*4
	case *layers.IPv6:
		prefix = "IP6 "
		if style >= FormatStyleVerbose {
			prefix = fmt.Sprintf("IP6 (%s)\n    ", f.formatIPv6(net))
		}
		nextLayerType = net.NextLayerType()
		nextLayerPayload = net.LayerPayload()
		src = net.SrcIP.String()
		dst = net.DstIP.String()
		length = int(net.Length)
	default:
		return f.formatUnknown(net, packet)
	}

	if packet.TransportLayer() != nil {
		f.opts.rawContent = append(f.opts.rawContent, packet.TransportLayer().LayerContents()...)
		if packet.ApplicationLayer() != nil {
			f.opts.rawContent = append(f.opts.rawContent, packet.ApplicationLayer().LayerContents()...)
		}
	}

	switch nextLayerType {
	case layers.LayerTypeUDP:
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			return prefix + f.formatPacketUDP(&packet, udp, src, dst)
		}
	case layers.LayerTypeTCP:
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			return prefix + f.formatPacketTCP(&packet, tcp, src, dst, length)
		}
	case layers.LayerTypeICMPv6:
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv6)
			return prefix + f.formatPacketICMPv6(&packet, icmp, src, dst, length)
		}
	case layers.LayerTypeOSPF:
		if ospfLayer := packet.Layer(layers.LayerTypeOSPF); ospfLayer != nil {
			switch ospfLayer := ospfLayer.(type) {
			case *layers.OSPFv2:
				if ospfLayer.AuType == 2 {
					length -= 16
				}
				return prefix + f.formatPacketOSPF(ospfLayer.OSPF, src, dst, length)
			case *layers.OSPFv3:
				return prefix + f.formatPacketOSPF(ospfLayer.OSPF, src, dst, length)
			}
		}
	case layers.LayerTypeGRE:
		if greLayer := packet.Layer(layers.LayerTypeGRE); greLayer != nil {
			gre, _ := greLayer.(*layers.GRE)
			return prefix + f.formatPacketGRE(gre, src, dst, length)
		}
	case layers.LayerTypeICMPv4:
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			return prefix + f.formatPacketICMPv4(icmp, src, dst, length)
		}
	case layers.LayerTypeIPv4:
		fallthrough
	case layers.LayerTypeIPv6:
		return prefix + fmt.Sprintf("%s > %s: %s", src, dst, Format(gopacket.NewPacket(nextLayerPayload, nextLayerType, gopacket.Default)))
	}
	return prefix + fmt.Sprintf("%s > %s: %s, length %d", src, dst, nextLayerType, length)
}
