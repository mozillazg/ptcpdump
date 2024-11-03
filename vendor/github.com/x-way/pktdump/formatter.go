package pktdump

type Formatter struct {
	opts *Options
}

func NewFormatter(opts *Options) *Formatter {
	return &Formatter{opts: opts}
}
