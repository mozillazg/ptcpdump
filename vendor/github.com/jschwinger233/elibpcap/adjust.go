package elibpcap

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
)

const (
	// Negative offsets from RFP (Frame Pointer R10)
	BpfDataReadOffset StackOffset = -8 * (iota + 1) // -8:  Temporary buffer to store data read by bpf_skb_load_bytes
	R1LiveSavedOffset                               // -16: Slot to save the live value of R1 before a helper function call
	R2LiveSavedOffset                               // -24: Slot to save the live value of R2 before a helper function call
	R3LiveSavedOffset                               // -32: Slot to save the live value of R3 before a helper function call

	// These slots are used for values that are present at the entry of the cbpfc-generated code block
	// or are set up by it. They are saved once at the beginning of the adjusted eBPF code block
	// if needed by helper function calls or for restoration.
	PacketStartSavedOnStack // -40: Slot to save R4 (data/PacketStart), saved at the beginning of the adjusted eBPF code block.
	PacketEndSavedOnStack   // -48: Slot to save R5 (data_end/PacketEnd), saved at the beginning of the adjusted eBPF code block.

	// Slot to store the original _skb argument (R1) of the eBPF filter function.
	SkbPtrOriginalArgSlot // -56: Slot to save the original R1 (_skb pointer).

	// AvailableOffset defines the start of the stack space that cbpfc can use (deepest known negative offset).
	// cbpfc.EBPFOpts.StackOffset will be calculated based on this.
	AvailableOffset // -64 (this value itself is negative, representing the size of the stack frame above cbpfc's own usage)
)

/*
If PacketAccessMode != Direct, We have to adjust the ebpf instructions because verifier prevents us from
directly loading data from memory.
*/
func adjustEbpf(insts asm.Instructions, opts Options) (newInsts asm.Instructions, err error) {
	switch opts.PacketAccessMode {
	case BpfProbeReadKernel:
		insts, err = adjustEbpfWithBpfProbeReadKernel(insts, opts)
		if err != nil {
			return nil, err
		}
		break
	case BpfSkbLoadBytes:
		insts, err = adjustEbpfWithBpfSkbLoadBytes(insts, opts)
		if err != nil {
			return nil, err
		}
		break
	case Direct:
		break
	default:
		return nil, fmt.Errorf("unsupported packet access mode: %v", opts.PacketAccessMode)
	}

	return append(insts,
		asm.Mov.Imm(asm.R1, 0).WithSymbol(opts.resultLabel()), // r1 = 0 (_skb)
		asm.Mov.Imm(asm.R2, 0),                                // r2 = 0 (__skb)
		asm.Mov.Imm(asm.R3, 0),                                // r3 = 0 (___skb)
		asm.Mov.Reg(asm.R4, opts.result()),                    // r4 = $result (data)
		asm.Mov.Imm(asm.R5, 0),                                // r5 = 0 (data_end)
	), nil
}
