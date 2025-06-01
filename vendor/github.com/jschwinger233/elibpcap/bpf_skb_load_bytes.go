package elibpcap

import "github.com/cilium/ebpf/asm"

const (
	// Negative offsets from RFP (Frame Pointer R10)
	BpfDataReadOffset StackOffset = -8 * (iota + 1) // -8:  Temporary buffer to store data read by bpf_skb_load_bytes
	R1LiveSavedOffset                               // -16: Slot to save the live value of R1 before a helper function call
	R2LiveSavedOffset                               // -24: Slot to save the live value of R2 before a helper function call
	R3LiveSavedOffset                               // -32: Slot to save the live value of R3 before a helper function call
	R4LiveSavedOffset                               // -40: Slot to save the live value of R4 before a helper function call (e.g., saving original R4/PacketStart before R4 is used as 'len' argument)

	// These slots are used for values that are present at the entry of the cbpfc-generated code block
	// or are set up by it. They are saved once at the beginning of the adjusted eBPF code block
	// if needed by helper function calls or for restoration.
	PacketStartSavedOnStack                         // -48: Slot to save R4 (data/PacketStart), saved at the beginning of the adjusted eBPF code block.
	PacketEndSavedOnStack                           // -56: Slot to save R5 (data_end/PacketEnd), saved at the beginning of the adjusted eBPF code block.

	// Slot to store the original _skb argument (R1) of the eBPF filter function.
	SkbPtrOriginalArgSlot                           // -64: Slot to save the original R1 (_skb pointer).

	// AvailableOffset defines the start of the stack space that cbpfc can use (deepest known negative offset).
	// cbpfc.EBPFOpts.StackOffset will be calculated based on this.
	AvailableOffset                                 // -72 (this value itself is negative, representing the size of the stack frame above cbpfc's own usage)
)

/*
If !DirectRead, We have to adjust the ebpf instructions because verifier prevents us from
directly loading data from memory using raw pointers (except for specific cases like TC BPF direct packet access).
For example, the instruction "r0 = *(u8 *)(r4 +0)" (where R4 is skb->data)
will be converted to use bpf_skb_load_bytes(skb, offset, buffer, size).

The conversion involves:
 1. At the beginning of the filtered block, save the original R1 (sk_buff*), R4 (data), and R5 (data_end) to stack slots
    if they are needed by the helper function logic or for restoration.
 2. For each memory load instruction:
    a. Save live registers (R1-R4) that will be clobbered by arguments setup for bpf_skb_load_bytes or by the call itself.
    b. Setup arguments for bpf_skb_load_bytes:
    - R1 = original sk_buff pointer (loaded from stack).
    - R2 = offset (from cBPF instruction's immediate value, relative to skb->data).
    - R3 = pointer to a temporary buffer on stack (e.g., RFP + BpfDataReadOffset).
    - R4 = size of data to read (from the load instruction's size).
    c. Call bpf_skb_load_bytes.
    d. Load the data from the temporary buffer on stack into the original destination register.
    e. Restore R4 (data/PacketStart) and R5 (data_end/PacketEnd) as they are clobbered by the helper call and
    are essential for subsequent cBPF translated instructions.
    f. Restore other saved live registers (R1-R3), taking care not to overwrite the destination register if it was one of them.
*/
func adjustEbpfForLoadBytes(insts asm.Instructions, opts Options) (newInsts asm.Instructions, err error) {
	// If !DirectRead, prepend instructions to save critical initial registers
	// These are assumed to be R1 (_skb), R4 (data), R5 (data_end) at the entry of the filter function code.
	var prefixInsts asm.Instructions
	prefixInsts = asm.Instructions{
		// Save original R1 (which is _skb, the first argument to the eBPF program/filter function)
		asm.StoreMem(asm.RFP, int16(SkbPtrOriginalArgSlot), asm.R1, asm.DWord),
		// Save R4 (data pointer / PacketStart) and R5 (data_end pointer / PacketEnd)
		// These are used by cBPF translated code and need to be restored after helper calls.
		asm.StoreMem(asm.RFP, int16(PacketStartSavedOnStack), asm.R4, asm.DWord),
		asm.StoreMem(asm.RFP, int16(PacketEndSavedOnStack), asm.R5, asm.DWord),
	}

	// tempReplaceIdx stores the indices of the original load instructions in `insts` that need replacement.
	tempReplaceIdx := []int{}
	// tempReplaceInstsMap maps the original index of a load instruction to its replacement instructions.
	tempReplaceInstsMap := map[int]asm.Instructions{}

	for originalIdx, inst := range insts { // Iterate over the original `ebpfInsts` (passed as `insts`)
		if inst.OpCode.Class().IsLoad() {
			tempReplaceIdx = append(tempReplaceIdx, originalIdx)

			var currentReplacement asm.Instructions

			// Save live R1, R2, R3, R4 before setting up args for bpf_skb_load_bytes.
			currentReplacement = append(currentReplacement,
				asm.StoreMem(asm.RFP, int16(R1LiveSavedOffset), asm.R1, asm.DWord),
				asm.StoreMem(asm.RFP, int16(R2LiveSavedOffset), asm.R2, asm.DWord),
				asm.StoreMem(asm.RFP, int16(R3LiveSavedOffset), asm.R3, asm.DWord),
				asm.StoreMem(asm.RFP, int16(R4LiveSavedOffset), asm.R4, asm.DWord),
			)

			// Setup arguments for bpf_skb_load_bytes(R1=skb*, R2=offset, R3=to_buf_on_stack, R4=len)
			currentReplacement = append(currentReplacement,
				asm.LoadMem(asm.R1, asm.RFP, int16(SkbPtrOriginalArgSlot), asm.DWord),
				asm.Mov.Imm(asm.R2, int32(inst.Offset)),
				asm.Mov.Reg(asm.R3, asm.RFP),
				asm.Add.Imm(asm.R3, int32(BpfDataReadOffset)),
				asm.Mov.Imm(asm.R4, int32(inst.OpCode.Size().Sizeof())),
			)

			currentReplacement = append(currentReplacement, asm.FnSkbLoadBytes.Call())

			currentReplacement = append(currentReplacement,
				asm.LoadMem(inst.Dst, asm.RFP, int16(BpfDataReadOffset), inst.OpCode.Size()),
			)

			currentReplacement = append(currentReplacement,
				asm.LoadMem(asm.R4, asm.RFP, int16(PacketStartSavedOnStack), asm.DWord),
				asm.LoadMem(asm.R5, asm.RFP, int16(PacketEndSavedOnStack), asm.DWord),
			)

			var restoreLiveRegs asm.Instructions
			if inst.Dst != asm.R1 {
				restoreLiveRegs = append(restoreLiveRegs, asm.LoadMem(asm.R1, asm.RFP, int16(R1LiveSavedOffset), asm.DWord))
			}
			if inst.Dst != asm.R2 {
				restoreLiveRegs = append(restoreLiveRegs, asm.LoadMem(asm.R2, asm.RFP, int16(R2LiveSavedOffset), asm.DWord))
			}
			if inst.Dst != asm.R3 {
				restoreLiveRegs = append(restoreLiveRegs, asm.LoadMem(asm.R3, asm.RFP, int16(R3LiveSavedOffset), asm.DWord))
			}
			currentReplacement = append(currentReplacement, restoreLiveRegs...)

			currentReplacement[0].Metadata = inst.Metadata
			tempReplaceInstsMap[originalIdx] = currentReplacement
		}
	}

	finalProcessedInsts := make(asm.Instructions, 0, len(insts)+len(tempReplaceIdx)*10) // Rough estimate
	nextOriginalIdxToProcess := 0
	for _, originalIdxToReplace := range tempReplaceIdx {
		finalProcessedInsts = append(finalProcessedInsts, insts[nextOriginalIdxToProcess:originalIdxToReplace]...)
		finalProcessedInsts = append(finalProcessedInsts, tempReplaceInstsMap[originalIdxToReplace]...)
		nextOriginalIdxToProcess = originalIdxToReplace + 1
	}
	finalProcessedInsts = append(finalProcessedInsts, insts[nextOriginalIdxToProcess:]...)

	resultWithPrefix := append(prefixInsts, finalProcessedInsts...)

	return append(resultWithPrefix,
		asm.Mov.Imm(asm.R1, 0).WithSymbol(opts.resultLabel()),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Imm(asm.R3, 0),
		asm.Mov.Reg(asm.R4, opts.result()),
		asm.Mov.Imm(asm.R5, 0),
	), nil
}
