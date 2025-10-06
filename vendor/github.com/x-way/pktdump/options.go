package pktdump

type FormatStyle int
type ContentStyle int

type Options struct {
	HeaderStyle   FormatStyle
	ContentStyle  ContentStyle
	ContentIndent string

	rawContent      []byte
	FormatedContent []byte

	httpPorts []int

	Quiet bool

	RelativeTCPSeq *bool
}

const (
	FormatStyleQuiet FormatStyle = iota
	FormatStyleNormal
	FormatStyleVerbose
	FormatStyleMoreVerbose
	FormatStyleMoreMoreVerbose
)

const (
	ContentStyleQuiet ContentStyle = iota
	ContentStyleHex
	ContentStyleHexWithASCII
	ContentStyleHexWithLink
	ContentStyleHexWithLinkASCII
	ContentStyleASCII
	ContentStyleASCIIWithLink
)

func (o *Options) needFormatLink() bool {
	return o.ContentStyle == ContentStyleHexWithLink ||
		o.ContentStyle == ContentStyleHexWithLinkASCII ||
		o.ContentStyle == ContentStyleASCIIWithLink
}

func (o *Options) formatContent() {
	if len(o.rawContent) == 0 {
		return
	}
	d := formatContent(o.rawContent, o.ContentStyle, o.ContentIndent)
	if d == "" {
		return
	}
	o.FormatedContent = append(o.FormatedContent, []byte(d)...)
}

func (o *Options) ensureDefaults() {
	if o.RelativeTCPSeq == nil {
		o.RelativeTCPSeq = boolPtr(true)
	}
}

func (o *Options) resetContentBuffers() {
	o.rawContent = o.rawContent[:0]
	o.FormatedContent = o.FormatedContent[:0]
}

func (o *Options) relativeTCPSeqEnabled() bool {
	if o == nil {
		return true
	}
	if o.RelativeTCPSeq == nil {
		return true
	}
	return *o.RelativeTCPSeq
}

func (o *Options) SetRelativeTCPSeq(enabled bool) {
	o.RelativeTCPSeq = boolPtr(enabled)
}

func boolPtr(v bool) *bool {
	b := v
	return &b
}
