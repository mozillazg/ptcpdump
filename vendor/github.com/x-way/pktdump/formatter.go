package pktdump

import (
	"sync"

	"github.com/gopacket/gopacket"
)

type Formatter struct {
	mu       sync.Mutex
	opts     *Options
	tcpState map[tcpFlowKey]*tcpDirectionState
}

func NewFormatter(opts *Options) *Formatter {
	ensured := ensureOptions(opts)
	return &Formatter{
		opts:     ensured,
		tcpState: make(map[tcpFlowKey]*tcpDirectionState),
	}
}

func ensureOptions(opts *Options) *Options {
	if opts == nil {
		opts = &Options{}
	}
	opts.ensureDefaults()
	return opts
}

func (f *Formatter) Format(packet gopacket.Packet) string {
	return f.FormatWithOptions(packet, f.opts)
}

func (f *Formatter) FormatWithOptions(packet gopacket.Packet, opts *Options) string {
	f.mu.Lock()
	defer f.mu.Unlock()

	prevOpts := f.opts
	currentOpts := ensureOptions(opts)
	currentOpts.resetContentBuffers()
	f.opts = currentOpts
	data := f.formatWithOptions(packet)
	f.opts.formatContent()
	f.opts = prevOpts
	return data
}
