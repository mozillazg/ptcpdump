package elibpcap

import "github.com/cilium/ebpf/asm"

type Options struct {
	AtBpf2Bpf  string
	DirectRead bool
	L2Skb      bool
}

func (o Options) resultLabel() string {
	return "_result_" + o.AtBpf2Bpf
}

func (o Options) labelPrefix() string {
	return "_prefix_" + o.AtBpf2Bpf
}

func (o Options) result() asm.Register {
	return asm.R0
}
