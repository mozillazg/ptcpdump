//go:build linux && go1.25 && !go1.28

#include "textflag.h"

// CLOCK_REALTIME vDSO read on the g0 stack; the design notes, the reason the
// read must run on g0, and why m.vdsoPC/m.vdsoSP are not set live with the Go
// declarations in fasttime.go. The arm64 twin is fasttime_arm64.s;
// the two are separate files because vet's asmdecl check does not understand
// #ifdef GOARCH guards and would check each block under the other's semantics.
//
// Runtime offsets used below, validated by g0LayoutOK at init:
//
//	g.m        = 0x30
//	m.g0       = 0
//	m.curg     = 0xb8
//	g.sched.sp = 0x38
//	g.stack.lo = 0
//	g.stack.hi = 8
//
// amd64 needs no gsignal stash: the runtime only does that on arm, arm64,
// loong64, ppc64, riscv64 and s390x (see sigFetchG).

// func g0LayoutOK(m uintptr) bool
TEXT ·g0LayoutOK(SB), NOSPLIT, $0-9
	MOVQ	0x30(R14), BX	// m = g.m
	TESTQ	BX, BX
	JZ	bad
	MOVQ	m+0(FP), AX
	CMPQ	AX, BX
	JNE	bad
	MOVQ	0xb8(BX), AX	// m.curg
	CMPQ	R14, AX
	JNE	bad
	MOVQ	0(BX), DX	// g0 = m.g0
	TESTQ	DX, DX
	JZ	bad
	CMPQ	R14, DX
	JEQ	bad
	MOVQ	0(DX), CX	// g0.stack.lo
	MOVQ	8(DX), R8	// g0.stack.hi
	MOVQ	0x38(DX), AX	// g0.sched.sp
	// The saved SP of a parked g0 lies inside g0's own stack. Testing that
	// is stronger than testing the alignment of the saved SP, which is not
	// an invariant of the runtime (amd64 saves it 8 mod 16).
	TESTQ	CX, CX
	JZ	bad
	TESTQ	R8, R8
	JZ	bad
	CMPQ	AX, CX
	JLS	bad		// sched.sp <= stack.lo
	CMPQ	AX, R8
	JA	bad		// sched.sp > stack.hi
	MOVL	$1, AX
	MOVB	AX, ret+8(FP)
	RET
bad:
	MOVL	$0, AX
	MOVB	AX, ret+8(FP)
	RET

// func vdsoCallG0(fn uintptr, ts *timespec) int32
//
// Mirrors runtime.nanotime1: switch to the g0 stack, do one CLOCK_REALTIME vDSO
// read, switch back. Like the arm64 version, a caller already on g0 or gsignal
// fails deliberately, leaving walltime to return zero and its caller to fall
// back to now(), instead of taking a noswitch path.
TEXT ·vdsoCallG0(SB), NOSPLIT, $32-20
	MOVQ	fn+0(FP), AX
	MOVQ	ts+8(FP), R13
	TESTQ	AX, AX
	JZ	bail

	MOVQ	0x30(R14), BX	// m
	MOVQ	0xb8(BX), CX	// m.curg
	CMPQ	R14, CX
	JNE	bail		// on g0 or gsignal: fall back to now()
	MOVQ	SP, R12		// save our SP
	MOVQ	0(BX), DX	// g0 = m.g0
	MOVQ	0x38(DX), SP	// g0.sched.sp
	SUBQ	$16, SP
	ANDQ	$-16, SP

	MOVL	$0, DI		// CLOCK_REALTIME
	LEAQ	0(SP), SI
	CALL	AX
	MOVQ	0(SP), CX
	MOVQ	8(SP), DX
	MOVQ	R12, SP
	TESTL	AX, AX
	JNE	done
	MOVQ	CX, 0(R13)
	MOVQ	DX, 8(R13)
done:
	MOVL	AX, ret+16(FP)
	RET

bail:
	MOVL	$1, AX
	MOVL	AX, ret+16(FP)
	RET
