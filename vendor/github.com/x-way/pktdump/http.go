package pktdump

import (
	"bytes"
	"github.com/gopacket/gopacket/layers"
	"regexp"
	"strings"
)

var reHttpCommonRequest = regexp.MustCompile(`(?m)^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) /[^\r\n]* HTTP/2?(1\.[01])\r\n.{5,}`)
var reHttpConnectRequest = regexp.MustCompile(`(?m)^CONNECT \S+(:\d+)? HTTP/2?(1\.[01])?\r\n.{5,}`)
var reHttpResponse = regexp.MustCompile(`(?m)^HTTP/2?(1\.[01])? \d{3} [\sA-Za-z']+\r\n.{5,}`)
var httpPrefixes = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("HEAD "),
	[]byte("OPTIONS "),
	[]byte("PATCH "),
	[]byte("CONNECT "),
	[]byte("TRACE "),
	[]byte("HTTP/1.0 "),
	[]byte("HTTP/1.1 "),
}

func (f *Formatter) formatHttp(tcp *layers.TCP) string {
	// GET / HTTP/1.1
	// HTTP/1.1 200 OK
	if len(tcp.Payload) == 0 || len(tcp.Payload) < 16 {
		return ""
	}

	prefix := tcp.Payload[:11]
	havePrefix := false
	for _, p := range httpPrefixes {
		if bytes.HasPrefix(prefix, p) {
			havePrefix = true
			break
		}
	}
	if !havePrefix {
		return ""
	}

	haveHTTP := false
	payload := string(tcp.Payload)
	if reHttpCommonRequest.FindString(payload) != "" ||
		reHttpConnectRequest.FindString(payload) != "" ||
		reHttpResponse.FindString(payload) != "" {
		haveHTTP = true
	}
	if !haveHTTP {
		return ""
	}

	index := bytes.Index(tcp.Payload, []byte("\r\n"))
	if index <= 0 {
		return ""
	}

	buf := strings.Builder{}
	buf.WriteString("HTTP: ")
	buf.WriteString(string(tcp.Payload[:index]))

	if f.opts.HeaderStyle >= FormatStyleVerbose {
		payloadStr := asciiFormat(tcp.Payload)
		var lines []string
		for _, line := range strings.Split(payloadStr, "\n") {
			line = f.opts.ContentIndent + line
			lines = append(lines, line)
		}
		f.opts.FormatedContent = append(f.opts.FormatedContent, strings.Join(lines, "\n")...)
	}

	return buf.String()
}
