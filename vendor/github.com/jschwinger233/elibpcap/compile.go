package elibpcap

import (
	"fmt"
	"log"
	"unsafe"

	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
	"golang.org/x/net/bpf"
)

/*
#cgo LDFLAGS: -L/usr/local/lib -lpcap
#include <stdlib.h>
#include <pcap.h>
*/
import "C"

type pcapBpfProgram C.struct_bpf_program

const (
	MaxBpfInstructions       = 4096
	bpfInstructionBufferSize = 8 * MaxBpfInstructions
	MAXIMUM_SNAPLEN          = 262144

	RejectAllExpr = "__reject_all__"
)

type StackOffset int

/*
Steps:
1. Compile pcap expresion to cbpf using libpcap
2. Convert cbpf to ebpf using cloudflare/cbpfc
3. [!DirectRead] Convert direct memory load to bpf_probe_read_kernel call
*/
func CompileEbpf(expr string, opts Options) (insts asm.Instructions, err error) {
	if expr == RejectAllExpr {
		return asm.Instructions{
			asm.Mov.Reg(asm.R4, asm.R5), // r4 = r5 (data = data_end)
		}, nil
	}
	cbpfInsts, err := CompileCbpf(expr, opts.L2Skb)
	if err != nil {
		return
	}

	ebpfInsts, err := cbpfc.ToEBPF(cbpfInsts, cbpfc.EBPFOpts{
		// skb->data is at r4, skb->data_end is at r5.
		PacketStart: asm.R4,
		PacketEnd:   asm.R5,
		Result:      opts.result(),
		ResultLabel: opts.resultLabel(),
		// _skb is at R0, __skb is at R1, ___skb is at R2.
		Working:     [4]asm.Register{asm.R0, asm.R1, asm.R2, asm.R3},
		LabelPrefix: opts.labelPrefix(),
		StackOffset: -int(AvailableOffset),
	})
	if err != nil {
		return
	}

	if opts.Debug {
		log.Printf("original eBPF from cbpfc.ToEBPF for %q:\n%s", expr, ebpfInsts)
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
