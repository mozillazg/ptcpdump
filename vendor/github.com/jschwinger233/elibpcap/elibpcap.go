package elibpcap

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf/asm"
)

func Inject(filter string, insns asm.Instructions, opts Options) (_ asm.Instructions, err error) {
	if filter == "" {
		return insns, nil
	}

	injectIdx := -1
	for idx, inst := range insns {
		if inst.Symbol() == opts.AtBpf2Bpf {
			injectIdx = idx
			break
		}
	}
	if injectIdx == -1 {
		return insns, fmt.Errorf("Cannot find bpf2bpf: %s", opts.AtBpf2Bpf)
	}

	filterInsns, err := CompileEbpf(filter, opts)
	if err != nil {
		return insns, err
	}

	if opts.Debug {
		log.Printf("injecting pcap filter: %q at %d, instructions: \n%s",
			filter, injectIdx, filterInsns)
	}

	filterInsns[0] = filterInsns[0].WithMetadata(insns[injectIdx].Metadata)
	insns[injectIdx] = insns[injectIdx].WithMetadata(asm.Metadata{})
	return append(insns[:injectIdx],
		append(filterInsns, insns[injectIdx:]...)...,
	), nil
}
