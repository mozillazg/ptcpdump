package elibpcap

import "github.com/cilium/ebpf/asm"

/*
If PacketAccessMode == BpfProbeReadKernel, We have to adjust the ebpf instructions because verifier prevents us from
directly loading data from memory. For example, the instruction "r0 = *(u8 *)(r4 +0)"
will break verifier with error "R4 invalid mem access 'scalar", we therefore
need to convert this direct memory load to bpf_probe_read_kernel function call:

- r1 = r10  // r10 is stack top
- r1 += -8  // r1 = r10-8
- r2 = 1    // r2 = sizeof(u8)
- r3 = r4   // r4 is start of packet data, aka L3 header
- r3 += 0   // r3 = r4+0
- call bpf_probe_read_kernel  // *(r10-8) = *(u8 *)(r4+0)
- r0 = *(u8 *)(r10 -8)  // r0 = *(r10-8)

To safely borrow R1, R2 and R3 for setting up the arguments for
bpf_probe_read_kernel(), we need to save the original values of R1, R2 and R3
on stack, and restore them after the function call.
*/
func adjustEbpfWithBpfProbeReadKernel(insts asm.Instructions, opts Options) (newInsts asm.Instructions, err error) {
	replaceIdx := []int{}
	replaceInsts := map[int]asm.Instructions{}
	for idx, inst := range insts {
		if inst.OpCode.Class().IsLoad() {
			replaceIdx = append(replaceIdx, idx)
			replaceInsts[idx] = append(replaceInsts[idx],

				// Store R1, R2, R3 on stack.
				asm.StoreMem(asm.RFP, int16(R1LiveSavedOffset), asm.R1, asm.DWord),
				asm.StoreMem(asm.RFP, int16(R2LiveSavedOffset), asm.R2, asm.DWord),
				asm.StoreMem(asm.RFP, int16(R3LiveSavedOffset), asm.R3, asm.DWord),

				// bpf_probe_read_kernel(RFP-8, size, inst.Src)
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, int32(BpfDataReadOffset)),
				asm.Mov.Imm(asm.R2, int32(inst.OpCode.Size().Sizeof())),
				asm.Mov.Reg(asm.R3, inst.Src),
				asm.Add.Imm(asm.R3, int32(inst.Offset)),
				asm.FnProbeReadKernel.Call(),

				// inst.Dst = *(RFP-8)
				asm.LoadMem(inst.Dst, asm.RFP, int16(BpfDataReadOffset), inst.OpCode.Size()),

				// Restore R4, R5 from stack. This is needed because bpf_probe_read_kernel always resets R4 and R5 even if they are not used by bpf_probe_read_kernel.
				asm.LoadMem(asm.R4, asm.RFP, int16(PacketStartSavedOnStack), asm.DWord),
				asm.LoadMem(asm.R5, asm.RFP, int16(PacketEndSavedOnStack), asm.DWord),
			)

			// Restore R1, R2, R3 from stack
			restoreInsts := asm.Instructions{
				asm.LoadMem(asm.R1, asm.RFP, int16(R1LiveSavedOffset), asm.DWord),
				asm.LoadMem(asm.R2, asm.RFP, int16(R2LiveSavedOffset), asm.DWord),
				asm.LoadMem(asm.R3, asm.RFP, int16(R3LiveSavedOffset), asm.DWord),
			}

			switch inst.Dst {
			case asm.R1, asm.R2, asm.R3:
				restoreInsts = append(restoreInsts[:inst.Dst-1], restoreInsts[inst.Dst:]...)
			}

			replaceInsts[idx] = append(replaceInsts[idx], restoreInsts...)

			// Metadata is crucial for adjusting jump offsets. We
			// ditched original instructions, which could hold symbol
			// names targeted by other jump instructions, so here we
			// inherit the metadata from the ditched ones.
			replaceInsts[idx][0].Metadata = inst.Metadata
		}
	}

	// Replace the memory load instructions with the new ones
	for i := len(replaceIdx) - 1; i >= 0; i-- {
		idx := replaceIdx[i]
		insts = append(insts[:idx], append(replaceInsts[idx], insts[idx+1:]...)...)
	}

	// Store R4, R5 on stack.
	insts = append([]asm.Instruction{
		asm.StoreMem(asm.RFP, int16(PacketStartSavedOnStack), asm.R4, asm.DWord),
		asm.StoreMem(asm.RFP, int16(PacketEndSavedOnStack), asm.R5, asm.DWord),
	}, insts...)
	return insts, err
}
