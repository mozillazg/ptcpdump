//go:build linux && go1.25 && !go1.28

#include "textflag.h"

// CLOCK_REALTIME vDSO read on the g0 stack; the design notes, the reason the
// read must run on g0, and why m.vdsoPC/m.vdsoSP are not set live with the Go
// declarations in fasttime.go. The amd64 twin is fasttime_amd64.s;
// the two are separate files because vet's asmdecl check does not understand
// #ifdef GOARCH guards and would check each block under the other's semantics.
//
// Runtime offsets used below, validated by g0LayoutOK at init:
//
//	g.m        = 48
//	m.g0       = 0
//	m.curg     = 184
//	m.gsignal  = 72
//	g.sched.sp = 56
//	g.stack.lo = 0
//	g.stack.hi = 8

// func g0LayoutOK(m uintptr) bool
TEXT ·g0LayoutOK(SB), NOSPLIT, $0-9
	MOVD	48(g), R21	// m = g.m
	CBZ	R21, bad
	MOVD	m+0(FP), R0
	CMP	R0, R21
	BNE	bad
	MOVD	184(R21), R0	// m.curg
	CMP	g, R0
	BNE	bad
	MOVD	0(R21), R3	// g0 = m.g0
	CBZ	R3, bad
	CMP	g, R3
	BEQ	bad
	MOVD	0(R3), R4	// g0.stack.lo
	MOVD	8(R3), R5	// g0.stack.hi
	MOVD	56(R3), R6	// g0.sched.sp
	// The saved SP of a parked g0 lies inside g0's own stack. Testing that
	// is stronger than testing the alignment of the saved SP, which is not
	// an invariant of the runtime (amd64 saves it 8 mod 16).
	CBZ	R4, bad
	CBZ	R5, bad
	CMP	R4, R6
	BLS	bad		// sched.sp <= stack.lo
	CMP	R5, R6
	BHI	bad		// sched.sp > stack.hi
	MOVD	$1, R0
	MOVB	R0, ret+8(FP)
	RET
bad:
	MOVD	ZR, R0
	MOVB	R0, ret+8(FP)
	RET

// func vdsoCallG0(fn uintptr, ts *timespec) int32
//
// Mirrors runtime.walltime: switch to the g0 stack, stash g at the bottom of
// the gsignal stack so a signal delivered inside the vDSO can still find it
// (golang.org/issue/32912), do one CLOCK_REALTIME vDSO read, switch back. The
// stash is skipped under cgo, where the runtime loads g from TLS instead.
//
// Unlike runtime.walltime there is no noswitch path: a caller already on g0 or
// gsignal fails deliberately, leaving walltime to return zero and its caller to
// fall back to now(), because the runtime reads the stash whenever a signal
// lands in the vDSO and this path only writes it when switching stacks. The
// runtime's own vDSO calls stash on the noswitch path too; falling back is
// simpler than mirroring that here, and the logger is only ever called on
// ordinary goroutines.
TEXT ·vdsoCallG0(SB), NOSPLIT, $32-20
	MOVD	fn+0(FP), R2
	MOVD	ts+8(FP), R25
	CBZ	R2, bail

	MOVD	48(g), R21	// m
	MOVD	184(R21), R0	// m.curg
	CMP	g, R0
	BNE	bail		// on g0 or gsignal: fall back to now()

	MOVD	0(R21), R3	// g0 = m.g0
	MOVD	56(R3), R1	// g0.sched.sp
	MOVD	RSP, R20	// save our SP
	SUB	$32, R1, R1
	AND	$-16, R1, R1
	MOVD	R1, RSP

	// g == m.curg here, so g cannot be m.gsignal and the runtime's
	// "already on the signal stack" check is not needed.
	MOVD	72(R21), R22	// m.gsignal
	CBZ	R22, nosave
	MOVBU	runtime·iscgo(SB), R23	// cgo keeps g in TLS; slot stays unread
	CBNZ	R23, nosave
	MOVD	(R22), R22	// gsignal.stack.lo
	MOVD	g, (R22)
	MOVW	ZR, R0		// CLOCK_REALTIME
	BL	(R2)
	MOVD	0(RSP), R23
	MOVD	8(RSP), R24
	MOVD	ZR, (R22)	// clear g slot
	B	copyout

nosave:
	MOVW	ZR, R0		// CLOCK_REALTIME
	BL	(R2)
	MOVD	0(RSP), R23
	MOVD	8(RSP), R24

copyout:
	MOVD	R20, RSP
	CBNZW	R0, done
	MOVD	R23, (R25)
	MOVD	R24, 8(R25)
done:
	MOVW	R0, ret+16(FP)
	RET

bail:
	MOVW	$1, R0
	MOVW	R0, ret+16(FP)
	RET
