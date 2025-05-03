package elibpcap

import (
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
	"golang.org/x/net/bpf"
)

/*
#cgo LDFLAGS: -L/usr/local/lib -lpcap -static
#include <stdlib.h>
#include <pcap.h>
*/
import "C"

type pcapBpfProgram C.struct_bpf_program

const (
	MaxBpfInstructions       = 4096
	bpfInstructionBufferSize = 8 * MaxBpfInstructions
	MAXIMUM_SNAPLEN          = 262144
)

type StackOffset int

const (
	BpfReadKernelOffset StackOffset = -8*(iota+1) - 80
	R1Offset
	R2Offset
	R3Offset
	R4Offset
	R5Offset
	AvailableOffset
)

func CompileEbpf(expr string, opts Options) (insts asm.Instructions, err error) {
	if expr == "__reject_all__" {
		return asm.Instructions{
			asm.Mov.Reg(asm.R4, asm.R5), // r4 = r5 (data = data_end)
		}, nil
	}
	cbpfInsts, err := CompileCbpf(expr, opts.L2Skb)
	if err != nil {
		return
	}

	ebpfInsts, err := cbpfc.ToEBPF(cbpfInsts, cbpfc.EBPFOpts{
		PacketStart: asm.R4,
		PacketEnd:   asm.R5,
		Result:      opts.result(),
		ResultLabel: opts.resultLabel(),
		Working:     [4]asm.Register{asm.R0, asm.R1, asm.R2, asm.R3},
		LabelPrefix: opts.labelPrefix(),
		StackOffset: -int(AvailableOffset),
	})
	if err != nil {
		return
	}

	return adjustEbpf(ebpfInsts, opts)
}

func CompileCbpf(expr string, l2 bool) (insts []bpf.Instruction, err error) {
	if len(expr) == 0 {
		return
	}

	pcapType := C.DLT_RAW
	if l2 {
		pcapType = C.DLT_EN10MB
	}
	pcap := C.pcap_open_dead(C.int(pcapType), MAXIMUM_SNAPLEN)
	if pcap == nil {
		return nil, fmt.Errorf("failed to pcap_open_dead: %+v\n", C.PCAP_ERROR)
	}
	defer C.pcap_close(pcap)

	cexpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cexpr))

	var bpfProg pcapBpfProgram
	if C.pcap_compile(pcap, (*C.struct_bpf_program)(&bpfProg), cexpr, 1, C.PCAP_NETMASK_UNKNOWN) < 0 {
		return nil, fmt.Errorf("failed to pcap_compile '%s': %+v", expr, C.GoString(C.pcap_geterr(pcap)))
	}
	defer C.pcap_freecode((*C.struct_bpf_program)(&bpfProg))

	for _, v := range (*[bpfInstructionBufferSize]C.struct_bpf_insn)(unsafe.Pointer(bpfProg.bf_insns))[0:bpfProg.bf_len:bpfProg.bf_len] {
		insts = append(insts, bpf.RawInstruction{
			Op: uint16(v.code),
			Jt: uint8(v.jt),
			Jf: uint8(v.jf),
			K:  uint32(v.k),
		}.Disassemble())
	}
	return
}

func adjustEbpf(insts asm.Instructions, opts Options) (newInsts asm.Instructions, err error) {
	if !opts.DirectRead {
		replaceIdx := []int{}
		replaceInsts := map[int]asm.Instructions{}
		for idx, inst := range insts {
			if inst.OpCode.Class().IsLoad() {
				replaceIdx = append(replaceIdx, idx)
				replaceInsts[idx] = append(replaceInsts[idx],

					asm.StoreMem(asm.RFP, int16(R1Offset), asm.R1, asm.DWord),
					asm.StoreMem(asm.RFP, int16(R2Offset), asm.R2, asm.DWord),
					asm.StoreMem(asm.RFP, int16(R3Offset), asm.R3, asm.DWord),

					asm.Mov.Reg(asm.R1, asm.RFP),
					asm.Add.Imm(asm.R1, int32(BpfReadKernelOffset)),
					asm.Mov.Imm(asm.R2, int32(inst.OpCode.Size().Sizeof())),
					asm.Mov.Reg(asm.R3, inst.Src),
					asm.Add.Imm(asm.R3, int32(inst.Offset)),
					asm.FnProbeReadKernel.Call(),

					asm.LoadMem(inst.Dst, asm.RFP, int16(BpfReadKernelOffset), inst.OpCode.Size()),

					asm.LoadMem(asm.R4, asm.RFP, int16(R4Offset), asm.DWord),
					asm.LoadMem(asm.R5, asm.RFP, int16(R5Offset), asm.DWord),
				)

				restoreInsts := asm.Instructions{
					asm.LoadMem(asm.R1, asm.RFP, int16(R1Offset), asm.DWord),
					asm.LoadMem(asm.R2, asm.RFP, int16(R2Offset), asm.DWord),
					asm.LoadMem(asm.R3, asm.RFP, int16(R3Offset), asm.DWord),
				}

				switch inst.Dst {
				case asm.R1, asm.R2, asm.R3:
					restoreInsts = append(restoreInsts[:inst.Dst-1], restoreInsts[inst.Dst:]...)
				}

				replaceInsts[idx] = append(replaceInsts[idx], restoreInsts...)
				replaceInsts[idx][0].Metadata = inst.Metadata
			}
		}

		for i := len(replaceIdx) - 1; i >= 0; i-- {
			idx := replaceIdx[i]
			insts = append(insts[:idx], append(replaceInsts[idx], insts[idx+1:]...)...)
		}

		insts = append([]asm.Instruction{
			asm.StoreMem(asm.RFP, int16(R4Offset), asm.R4, asm.DWord),
			asm.StoreMem(asm.RFP, int16(R5Offset), asm.R5, asm.DWord),
		}, insts...)
	}

	return append(insts,
		asm.Mov.Imm(asm.R1, 0).WithSymbol(opts.resultLabel()),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Imm(asm.R3, 0),
		asm.Mov.Reg(asm.R4, opts.result()),
		asm.Mov.Imm(asm.R5, 0),
	), nil
}
