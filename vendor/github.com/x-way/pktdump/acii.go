package pktdump

import (
	"bytes"
	"fmt"
	"strings"
)

const (
	asciiLineLength         = 300
	hexDumpBytesPerLine     = 16
	hexDumpShortsPerLine    = hexDumpBytesPerLine / 2
	hexDumpHexStuffPerShort = 5 // 4 hex digits and a space
	hexDumpHexStuffPerLine  = hexDumpHexStuffPerShort * hexDumpShortsPerLine
)

func asciiFormat(cp []byte) string {
	var b bytes.Buffer
	b.Grow(len(cp) + 1)
	b.WriteByte('\n')

	for i, s := range cp {
		if s == '\r' {
			// Don't print CRs at the end of the line
			if i+1 < len(cp) && cp[i+1] != '\n' {
				b.WriteByte('.')
			}
		} else if !isPrintable(s) && s != '\t' && s != ' ' && s != '\n' {
			b.WriteByte('.')
		} else {
			b.WriteByte(s)
		}
	}

	return b.String()
}

func isPrintable(s byte) bool {
	return s >= 32 && s <= 126
}

func hexAndAsciiFormatWithOffset(cp []byte, offset int, indent string) string {
	var builder strings.Builder
	var asciiBuf strings.Builder
	var hexBuf strings.Builder
	length := len(cp)
	nshorts := length / 2
	i := 0

	builder.Grow(length * 2)
	asciiBuf.Grow(asciiLineLength + 1)
	hexBuf.Grow(hexDumpShortsPerLine*hexDumpHexStuffPerShort + 1)

	for nshorts > 0 {
		s1 := cp[0]
		cp = cp[1:]
		s2 := cp[0]
		cp = cp[1:]

		hexBuf.WriteByte(' ')
		hexBuf.WriteString(toHex(s1))
		hexBuf.WriteString(toHex(s2))
		asciiBuf.WriteByte(toAscii(s1))
		asciiBuf.WriteByte(toAscii(s2))
		i++

		if i >= hexDumpShortsPerLine {
			builder.WriteString(fmt.Sprintf(
				"\n%s0x%04x: %-*s  %s", indent, offset, hexDumpHexStuffPerLine,
				hexBuf.String(), asciiBuf.String()))

			i = 0
			offset += hexDumpBytesPerLine
			asciiBuf.Reset()
			hexBuf.Reset()
			asciiBuf.Grow(asciiLineLength + 1)
			hexBuf.Grow(hexDumpShortsPerLine*hexDumpHexStuffPerShort + 1)
		}

		nshorts--
	}

	if length%2 != 0 {
		s1 := cp[0]
		cp = cp[1:]
		hexBuf.WriteByte(' ')
		hexBuf.WriteString(toHex(s1))
		asciiBuf.WriteByte(toAscii(s1))
		i++
	}

	if i > 0 {
		builder.WriteString(fmt.Sprintf(
			"\n%s0x%04x: %-*s  %s", indent, offset, hexDumpHexStuffPerLine,
			hexBuf.String(), asciiBuf.String()))
	}

	return builder.String()
}

func toAscii(b byte) byte {
	if isPrintable(b) {
		return b
	} else {
		return '.'
	}
}

func toHex(b byte) string {
	return fmt.Sprintf("%02x", b)
}

func hexAndAsciiFormat(cp []byte, indent string) string {
	return hexAndAsciiFormatWithOffset(cp, 0, indent)
}

func hexFormatWithOffset(cp []byte, offset int, indent string) string {
	var builder strings.Builder
	length := len(cp)
	nshorts := length / 2
	i := 0
	for nshorts > 0 {
		if (i % hexDumpShortsPerLine) == 0 {
			builder.WriteString(fmt.Sprintf("\n%s0x%04x: ", indent, offset))
			offset += hexDumpBytesPerLine
		}
		s := cp[0]
		cp = cp[1:]
		builder.WriteString(fmt.Sprintf(" %02x%02x", s, cp[0]))
		cp = cp[1:]
		nshorts--
		i++
	}

	if length%2 != 0 {
		if (i % hexDumpShortsPerLine) == 0 {
			builder.WriteString(fmt.Sprintf("\n%s0x%04x: ", indent, offset))
		}
		builder.WriteString(fmt.Sprintf(" %02x", cp[0]))
	}

	return builder.String()
}

func hexFormat(cp []byte, indent string) string {
	return hexFormatWithOffset(cp, 0, indent)
}
