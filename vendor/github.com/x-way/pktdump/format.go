// Package pktdump formats gopacket.Packet network packets similar to the tcpdump CLI output
package pktdump

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func formatPacketTCP(tcp *layers.TCP, src, dst string, length int, style FormatStyle) string {
	length -= int(tcp.DataOffset) * 4
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
	if style >= FormatStyleVerbose {
		out += fmt.Sprintf(", cksum 0x%x", tcp.Checksum)
	}
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
				out += formatSack(tcp, opt)
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
	return out
}

func formatPacketSIP(sip *layers.SIP, src, dst string, srcPort, dstPort int, style FormatStyle) string {
	sipStr := "SIP: "
	if sip.IsResponse {
		sipStr += fmt.Sprintf("%s %d %s", sip.Version, sip.ResponseCode, sip.ResponseStatus)
	} else {
		sipStr += fmt.Sprintf("%s %s %s", sip.Method, sip.RequestURI, sip.Version)
	}
	return fmt.Sprintf("%s.%d > %s.%d: %s", src, srcPort, dst, dstPort, sipStr)
}

func formatPacketICMPv6(packet *gopacket.Packet, icmp *layers.ICMPv6, src, dst string, length int, style FormatStyle) string {
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

func formatPacketICMPv4(icmp *layers.ICMPv4, src, dst string, length int, style FormatStyle) string {
	switch icmpType := icmp.TypeCode.Type(); icmpType {
	case layers.ICMPv4TypeEchoRequest:
		return fmt.Sprintf("%s > %s: ICMP echo request, id %d, seq %d, length %d", src, dst, icmp.Id, icmp.Seq, length)
	case layers.ICMPv4TypeEchoReply:
		return fmt.Sprintf("%s > %s: ICMP echo reply, id %d, seq %d, length %d", src, dst, icmp.Id, icmp.Seq, length)
	default:
		return fmt.Sprintf("%s > %s: ICMP, length %d", src, dst, length)
	}
}

func formatPacketDNS(dns *layers.DNS, src, dst string, srcPort, dstPort, length int, style FormatStyle) string {
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

func formatPacketUDP(packet *gopacket.Packet, udp *layers.UDP, src, dst string, style FormatStyle) string {
	length := int(udp.Length) - 8
	if udp.SrcPort == 53 || udp.DstPort == 53 || udp.SrcPort == 5353 || udp.DstPort == 5353 {
		if dnsLayer := (*packet).Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)
			return formatPacketDNS(dns, src, dst, int(udp.SrcPort), int(udp.DstPort), length, style)
		}
	}
	if udp.DstPort == 5060 || udp.SrcPort == 5060 {
		if sipLayer := (*packet).Layer(layers.LayerTypeSIP); sipLayer != nil {
			sip, _ := sipLayer.(*layers.SIP)
			return formatPacketSIP(sip, src, dst, int(udp.SrcPort), int(udp.DstPort), style)
		}
	}
	return fmt.Sprintf("%s.%d > %s.%d: UDP, length %d", src, udp.SrcPort, dst, udp.DstPort, length)
}

func formatPacketOSPF(ospf layers.OSPF, src, dst string, length int, style FormatStyle) string {
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

func formatPacketGRE(gre *layers.GRE, src, dst string, length int, style FormatStyle) string {
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
			out += FormatWithStyle(gopacket.NewPacket(gre.LayerPayload(), layers.LayerTypeIPv4, gopacket.Default), style)
		case layers.EthernetTypeIPv6:
			out += FormatWithStyle(gopacket.NewPacket(gre.LayerPayload(), layers.LayerTypeIPv6, gopacket.Default), style)
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
					out += formatPacketPPP(ppp, style)
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

func formatPacketPPP(ppp *layers.PPP, style FormatStyle) string {
	switch ppp.PPPType {
	case layers.PPPTypeIPv4:
		return FormatWithStyle(gopacket.NewPacket(ppp.LayerPayload(), layers.LayerTypeIPv4, gopacket.Default), style)
	case layers.PPPTypeIPv6:
		return FormatWithStyle(gopacket.NewPacket(ppp.LayerPayload(), layers.LayerTypeIPv6, gopacket.Default), style)
	case layers.PPPTypeMPLSUnicast:
		return fmt.Sprintf("MPLS, length %d", len(ppp.LayerPayload()))
	case layers.PPPTypeMPLSMulticast:
		return fmt.Sprintf("MPLS, length %d", len(ppp.LayerPayload()))
	default:
		return fmt.Sprintf("unknown PPP protocol (0x%x)", ppp.PPPType)
	}
}

func formatIPv4(ipv4 *layers.IPv4, opts *Options) string {
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

	return strings.Join(fields, ", ")
}

func formatIPv6(ipv6 *layers.IPv6, opts *Options) string {
	fields := []string{}
	fields = append(fields, fmt.Sprintf("flowlabel 0x%x", ipv6.FlowLabel))
	fields = append(fields, fmt.Sprintf("hlim %d", ipv6.HopLimit))
	fields = append(fields, fmt.Sprintf("next-header %s (%d)", ipv6.NextHeader.String(), ipv6.NextHeader))
	fields = append(fields, fmt.Sprintf("payload length: %d", len(ipv6.Payload)))

	return strings.Join(fields, ", ")
}

func formatLinkLayer(packet gopacket.Packet, opts *Options) string {
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
		return formatUnknown(layer, packet, opts)
	}

	switch nextLayerType {
	case layers.LayerTypeARP:
		if ly := packet.Layer(layers.LayerTypeARP); ly != nil {
			arp, _ := ly.(*layers.ARP)
			return formatARP(arp, length, opts)
		}
	}

	return ""
}

// Format parses a packet and returns a string with a textual representation similar to the tcpdump output
func Format(packet gopacket.Packet) string {
	return FormatWithStyle(packet, FormatStyleNormal)
}

func FormatWithStyle(packet gopacket.Packet, style FormatStyle) string {
	return FormatWithOptions(packet, &Options{HeaderStyle: style})
}

func FormatWithOptions(packet gopacket.Packet, opts *Options) string {
	data := formatWithOptions(packet, opts)
	opts.formatContent()
	return data
}

func formatWithOptions(packet gopacket.Packet, opts *Options) string {
	var net gopacket.Layer
	if opts.needFormatLink() && packet.LinkLayer() != nil {
		opts.rawContent = append(opts.rawContent, packet.LinkLayer().LayerContents()...)
	}
	if net = packet.NetworkLayer(); net == nil {
		return formatLinkLayer(packet, opts)
	}
	opts.rawContent = append(opts.rawContent, net.LayerContents()...)
	style := opts.HeaderStyle

	var prefix, src, dst string
	var nextLayerType gopacket.LayerType
	var nextLayerPayload []byte
	var length int
	switch net := net.(type) {
	case *layers.IPv4:
		prefix = fmt.Sprintf("IP ")
		if style >= FormatStyleVerbose {
			prefix = fmt.Sprintf("IP (%s)\n    ", formatIPv4(net, opts))
		}
		nextLayerType = net.NextLayerType()
		nextLayerPayload = net.LayerPayload()
		src = net.SrcIP.String()
		dst = net.DstIP.String()
		length = int(net.Length) - int(net.IHL)*4
	case *layers.IPv6:
		prefix = "IP6 "
		if style >= FormatStyleVerbose {
			prefix = fmt.Sprintf("IP6 (%s)\n    ", formatIPv6(net, opts))
		}
		nextLayerType = net.NextLayerType()
		nextLayerPayload = net.LayerPayload()
		src = net.SrcIP.String()
		dst = net.DstIP.String()
		length = int(net.Length)
	default:
		return formatUnknown(net, packet, opts)
	}

	if packet.TransportLayer() != nil {
		opts.rawContent = append(opts.rawContent, packet.TransportLayer().LayerContents()...)
		if packet.ApplicationLayer() != nil {
			opts.rawContent = append(opts.rawContent, packet.ApplicationLayer().LayerContents()...)
		}
	}

	switch nextLayerType {
	case layers.LayerTypeUDP:
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			return prefix + formatPacketUDP(&packet, udp, src, dst, style)
		}
	case layers.LayerTypeTCP:
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			return prefix + formatPacketTCP(tcp, src, dst, length, style)
		}
	case layers.LayerTypeICMPv6:
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv6)
			return prefix + formatPacketICMPv6(&packet, icmp, src, dst, length, style)
		}
	case layers.LayerTypeOSPF:
		if ospfLayer := packet.Layer(layers.LayerTypeOSPF); ospfLayer != nil {
			switch ospfLayer := ospfLayer.(type) {
			case *layers.OSPFv2:
				if ospfLayer.AuType == 2 {
					length -= 16
				}
				return prefix + formatPacketOSPF(ospfLayer.OSPF, src, dst, length, style)
			case *layers.OSPFv3:
				return prefix + formatPacketOSPF(ospfLayer.OSPF, src, dst, length, style)
			}
		}
	case layers.LayerTypeGRE:
		if greLayer := packet.Layer(layers.LayerTypeGRE); greLayer != nil {
			gre, _ := greLayer.(*layers.GRE)
			return prefix + formatPacketGRE(gre, src, dst, length, style)
		}
	case layers.LayerTypeICMPv4:
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			return prefix + formatPacketICMPv4(icmp, src, dst, length, style)
		}
	case layers.LayerTypeIPv4:
		fallthrough
	case layers.LayerTypeIPv6:
		return prefix + fmt.Sprintf("%s > %s: %s", src, dst, Format(gopacket.NewPacket(nextLayerPayload, nextLayerType, gopacket.Default)))
	}
	return prefix + fmt.Sprintf("%s > %s: %s, length %d", src, dst, nextLayerType, length)
}
