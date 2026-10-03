#include "textflag.h"

// func needEscapeBlocks(b string) bool
//   SI: b.base
//   BX: b.len, a positive multiple of 16
//
// Scans 16 bytes per iteration with SSE2 and reports whether any byte is one
// of the 36 bytes appendEscapedString rewrites: the C0 controls 0x00-0x1f
// plus '"', '\'', '<' and '\\'. The range test is an unsigned saturating
// b - 0x1f followed by a compare against zero, an exact b <= 0x1f test.
TEXT ·needEscapeBlocks(SB), NOSPLIT, $0-17
	MOVQ	b_base+0(FP), SI
	MOVQ	b_len+8(FP), BX

	MOVD	$0x1f1f1f1f, AX
	MOVD	AX, X0
	PUNPCKLBW X0, X0
	PUNPCKLBW X0, X0		// 0x1f
	PXOR	X1, X1			// zero
	MOVD	$0x22222222, AX
	MOVD	AX, X2
	PUNPCKLBW X2, X2
	PUNPCKLBW X2, X2		// '"'
	MOVD	$0x27272727, AX
	MOVD	AX, X3
	PUNPCKLBW X3, X3
	PUNPCKLBW X3, X3		// '\''
	MOVD	$0x3c3c3c3c, AX
	MOVD	AX, X4
	PUNPCKLBW X4, X4
	PUNPCKLBW X4, X4		// '<'
	MOVD	$0x5c5c5c5c, AX
	MOVD	AX, X5
	PUNPCKLBW X5, X5
	PUNPCKLBW X5, X5		// '\\'
	PXOR	X12, X12		// accumulator

	PCALIGN	$16
loop:
	MOVOU	(SI), X6
	MOVO	X6, X7
	PSUBUSB	X0, X7			// t = max(b - 0x1f, 0)
	PCMPEQB	X1, X7			// b <= 0x1f
	MOVO	X6, X9
	PCMPEQB	X2, X9			// '"'
	POR	X9, X7
	MOVO	X6, X9
	PCMPEQB	X3, X9			// '\''
	POR	X9, X7
	MOVO	X6, X9
	PCMPEQB	X4, X9			// '<'
	POR	X9, X7
	PCMPEQB	X5, X6			// '\\'
	POR	X6, X7
	POR	X7, X12

	ADDQ	$16, SI
	SUBQ	$16, BX
	JNZ	loop

	MOVO	X12, X8
	PSHUFD	$0x4e, X8, X9		// swap the two 64-bit halves
	POR	X9, X8
	MOVQ	X8, AX
	TESTQ	AX, AX
	JNZ	found

	MOVB	$0, ret+16(FP)
	RET

found:
	MOVB	$1, ret+16(FP)
	RET
