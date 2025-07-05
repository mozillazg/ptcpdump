package pktdump

import (
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"strings"
)

func (f *Formatter) formatTls(packet *gopacket.Packet, tcp *layers.TCP, length int) string {
	if packet == nil {
		return ""
	}
	tls := getTlsLayer(*packet, tcp, length)
	if tls == nil {
		return ""
	}

	var th *layers.TLSRecordHeader

	buf := strings.Builder{}
	var hts []string
	var version layers.TLSVersion
	for _, handshake := range tls.Handshake {
		th = &handshake.TLSRecordHeader
		switch handshake.HandshakeType {
		case layers.TLSHandshakeClientHello:
			hts = append(hts, fmt.Sprintf("%s (SNI=%s)", handshake.HandshakeType, handshake.ClientHello.SNI))
		case layers.TLSHandshakeServerHello:
			hts = append(hts, handshake.HandshakeType.String())
			if len(handshake.ServerHello.SupportedVersions) > 0 {
				version = handshake.ServerHello.SupportedVersions[0]
			}
		}
	}
	if th != nil && len(hts) > 0 {
		if version == 0 {
			version = th.Version
		}
		buf.WriteString(formatTlsVersion(version) + ": ")
		buf.WriteString(strings.Join(hts, ", "))
	}

	return buf.String()
}

func getTlsLayer(packet gopacket.Packet, tcp *layers.TCP, length int) *layers.TLS {
	var tls *layers.TLS
	for _, layer := range (packet).Layers() {
		if layer.LayerType() == layers.LayerTypeTLS {
			tls = layer.(*layers.TLS)
			break
		}
	}
	if tls != nil {
		return tls
	}

	tmp := layers.TLS{}
	payload := tcp.LayerPayload()
	if len(payload) < length {
		for i := 0; i < length-len(payload); i++ {
			payload = append(payload, 0)
		}
	}
	_ = tmp.DecodeFromBytes(payload, gopacket.NilDecodeFeedback)
	if len(tmp.Handshake) > 0 || len(tmp.ChangeCipherSpec) > 0 ||
		len(tmp.Alert) > 0 || len(tmp.AppData) > 0 {
		tls = &tmp
	}

	return tls
}

func getTlsRecordHeader(tls *layers.TLS) *layers.TLSRecordHeader {
	if len(tls.Handshake) > 0 {
		return &tls.Handshake[0].TLSRecordHeader
	}
	if len(tls.ChangeCipherSpec) > 0 {
		return &tls.ChangeCipherSpec[0].TLSRecordHeader
	}
	if len(tls.Alert) > 0 {
		return &tls.Alert[0].TLSRecordHeader
	}
	if len(tls.AppData) > 0 {
		return &tls.AppData[0].TLSRecordHeader
	}
	return nil
}

func formatTlsVersion(tv layers.TLSVersion) string {
	version := tv.String()
	return strings.Replace(version, " ", "v", 1)
}
