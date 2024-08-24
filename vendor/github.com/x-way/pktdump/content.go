package pktdump

func formatContent(rawContent []byte, style ContentStyle, indent string) string {
	switch style {
	case ContentStyleHex, ContentStyleHexWithLink:
		return hexFormat(rawContent, indent)
	case ContentStyleHexWithASCII, ContentStyleHexWithLinkASCII:
		return hexAndAsciiFormat(rawContent, indent)
	case ContentStyleASCII, ContentStyleASCIIWithLink:
		return asciiFormat(rawContent)
	default:
		return ""
	}
}
