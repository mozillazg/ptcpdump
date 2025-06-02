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
	R4LiveSavedOffset                               // -40: Slot to save the live value of R4 before a helper function call (e.g., saving original R4/PacketStart before R4 is used as 'len' argument)

	// These slots are used for values that are present at the entry of the cbpfc-generated code block
	// or are set up by it. They are saved once at the beginning of the adjusted eBPF code block
	// if needed by helper function calls or for restoration.
	PacketStartSavedOnStack // -48: Slot to save R4 (data/PacketStart), saved at the beginning of the adjusted eBPF code block.
	PacketEndSavedOnStack   // -56: Slot to save R5 (data_end/PacketEnd), saved at the beginning of the adjusted eBPF code block.

	// Slot to store the original _skb argument (R1) of the eBPF filter function.
	SkbPtrOriginalArgSlot // -64: Slot to save the original R1 (_skb pointer).

	// AvailableOffset defines the start of the stack space that cbpfc can use (deepest known negative offset).
	// cbpfc.EBPFOpts.StackOffset will be calculated based on this.
	AvailableOffset // -72 (this value itself is negative, representing the size of the stack frame above cbpfc's own usage)
)

/*
If !DirectRead, We have to adjust the ebpf instructions because verifier prevents us from
directly loading data from memory using raw pointers (except for specific cases like TC BPF direct packet access).
For example, the instruction "r0 = *(u8 *)(r4 +0)" (where R4 is skb->data)
will be converted to use bpf_skb_load_bytes(skb, offset, buffer, size).

The conversion involves:
 1. At the beginning of the filtered block, save the original R1 (sk_buff*), R4 (data), and R5 (data_end) to stack slots.
 2. For each memory load instruction (`inst`):
    a. Save live registers (R1-R4) that will be clobbered by arguments setup for bpf_skb_load_bytes or by the call itself.
    b. Setup arguments for bpf_skb_load_bytes:
    - R1 (arg1): original sk_buff pointer (from SkbPtrOriginalArgSlot).
    - R2 (arg2): offset relative to skb->data.
    - If inst.Src is PacketStart (R4): offset = inst.Offset.
    - If inst.Src is a dynamic pointer P (e.g., R3 holding skb->data + L4_offset):
    offset = (P_value - PacketStart_original_value) + inst.Offset.
    - R3 (arg3): pointer to a temporary buffer on stack (e.g., RFP + BpfDataReadOffset).
    - R4 (arg4): size of data to read (from the load instruction's size).
    c. Call bpf_skb_load_bytes.
    d. Check R0 (return value). If error, jump to nomatch.
    e. Load the data from the temporary buffer on stack into the original destination register (inst.Dst).
    f. Restore R4 (data/PacketStart) and R5 (data_end/PacketEnd) from their saved slots on stack.
    g. Restore other saved live registers (R1-R3), taking care not to overwrite inst.Dst.
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

	// cbpfc.EBPFOpts.PacketStart is hardcoded to R4 in CompileEbpf.
	cbpfPacketStartReg := asm.R4

	for originalIdx, inst := range insts {
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

			// --- Setup arguments for bpf_skb_load_bytes ---
			// R1 (arg1): original sk_buff pointer (from SkbPtrOriginalArgSlot)
			currentReplacement = append(currentReplacement,
				asm.LoadMem(asm.R1, asm.RFP, int16(SkbPtrOriginalArgSlot), asm.DWord),
			)

			// R2 (arg2): offset_from_skb_data
			if inst.Src == cbpfPacketStartReg {
				// Case 1: Original eBPF load was relative to PacketStart (R4).
				// inst.Offset is the direct offset from skb->data.
				currentReplacement = append(currentReplacement,
					asm.Mov.Imm(asm.R2, int32(inst.Offset)),
				)
			} else {
				// Case 2: Original eBPF load used a source register (inst.Src, e.g., R0-R3)
				// that holds an absolute pointer to the data to be loaded,
				// and inst.Offset is relative to that absolute pointer.
				// We need to calculate offset_for_skb_load_bytes =
				// (value_in_inst.Src_reg - value_of_PacketStart_at_entry) + inst.Offset.

				// Step A: Copy the value from inst.Src register into R2.
				// inst.Src contains the absolute pointer calculated by cbpfc.
				// Need to ensure this Mov doesn't conflict if inst.Src is R2 itself.
				// If inst.Src is R2, R2 already has the correct base pointer.
				// If inst.Src is R0, R1, or R3, copy it to R2.
				switch inst.Src {
				case asm.R0, asm.R1, asm.R3:
					currentReplacement = append(currentReplacement,
						asm.Mov.Reg(asm.R2, inst.Src), // R2 = absolute_pointer_base
					)
				case asm.R2:
					// R2 already holds the absolute_pointer_base, no Mov needed.
				default:
					// This case should ideally not be reached if cbpfc uses R0-R3 as working regs
					// and R4 as PacketStart for its load instructions.
					return nil, fmt.Errorf("adjustEbpf: unhandled inst.Src (%v) for dynamic pointer calculation", inst.Src)
				}

				// Step B: Load original PacketStart value (skb->data pointer at entry) into a temporary register.
				// R0 is suitable as it's clobbered by the helper call / used for return value.
				currentReplacement = append(currentReplacement,
					asm.LoadMem(asm.R0, asm.RFP, int16(PacketStartSavedOnStack), asm.DWord), // R0 = original PacketStart value
				)

				// Step C: R2 = R2 - R0 (i.e., absolute_pointer_base - original_PacketStart_value)
				// This results in offset_of_absolute_pointer_base_from_original_PacketStart.
				currentReplacement = append(currentReplacement,
					asm.Sub.Reg(asm.R2, asm.R0),
				)

				// Step D: R2 = R2 + inst.Offset (add the offset relative to the absolute_pointer_base)
				// Now R2 holds the final offset relative to original PacketStart (skb->data).
				if inst.Offset != 0 { // Optimization: skip if inst.Offset is zero
					currentReplacement = append(currentReplacement,
						asm.Add.Imm(asm.R2, int32(inst.Offset)),
					)
				}
			}

			// R3 (arg3): to_buf_on_stack (RFP + BpfDataReadOffset)
			currentReplacement = append(currentReplacement,
				asm.Mov.Reg(asm.R3, asm.RFP),
				asm.Add.Imm(asm.R3, int32(BpfDataReadOffset)),
			)
			// R4 (arg4): len (from inst.OpCode.Size().Sizeof())
			currentReplacement = append(currentReplacement,
				asm.Mov.Imm(asm.R4, int32(inst.OpCode.Size().Sizeof())),
			)
			// --- End of arguments setup ---

			currentReplacement = append(currentReplacement, asm.FnSkbLoadBytes.Call())

			// Check return value of bpf_skb_load_bytes (in R0)
			nomatchLabel := opts.labelPrefix() + "_nomatch"
			currentReplacement = append(currentReplacement,
				asm.JNE.Imm(asm.R0, 0, nomatchLabel).WithReference(nomatchLabel),
			)

			// Load data from stack buffer to original inst.Dst
			currentReplacement = append(currentReplacement,
				asm.LoadMem(inst.Dst, asm.RFP, int16(BpfDataReadOffset), inst.OpCode.Size()),
			)

			// Restore R4 (PacketStart) and R5 (PacketEnd) from their initially saved values
			currentReplacement = append(currentReplacement,
				asm.LoadMem(asm.R4, asm.RFP, int16(PacketStartSavedOnStack), asm.DWord),
				asm.LoadMem(asm.R5, asm.RFP, int16(PacketEndSavedOnStack), asm.DWord),
			)

			// Restore original live R1, R2, R3 (unless inst.Dst was one of them)
			var restoreLiveRegs asm.Instructions
			if inst.Dst != asm.R1 {
				restoreLiveRegs = append(restoreLiveRegs, asm.LoadMem(asm.R1, asm.RFP, int16(R1LiveSavedOffset), asm.DWord))
			}
			if inst.Dst != asm.R2 {
				// If R2 was inst.Src in the dynamic case, its value might have been changed by the offset calculation.
				// However, the R2LiveSavedOffset holds the value R2 had *before* this entire replacement block.
				// So, restoring from R2LiveSavedOffset is correct.
				restoreLiveRegs = append(restoreLiveRegs, asm.LoadMem(asm.R2, asm.RFP, int16(R2LiveSavedOffset), asm.DWord))
			}
			if inst.Dst != asm.R3 {
				restoreLiveRegs = append(restoreLiveRegs, asm.LoadMem(asm.R3, asm.RFP, int16(R3LiveSavedOffset), asm.DWord))
			}
			// R4 was restored from PacketStartSavedOnStack, not R4LiveSavedOffset, which is correct.
			currentReplacement = append(currentReplacement, restoreLiveRegs...)

			currentReplacement[0].Metadata = inst.Metadata
			tempReplaceInstsMap[originalIdx] = currentReplacement
		}
	}

	finalProcessedInsts := make(asm.Instructions, 0, len(insts)+len(tempReplaceIdx)*15) // Rough estimate
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
