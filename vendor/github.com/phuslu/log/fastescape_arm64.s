#include "textflag.h"

// The two nibble tables below encode the bytes appendEscapedString rewrites:
// the C0 controls 0x00-0x1f plus '"', '\'', '<' and '\\'. Bit i of a table
// entry marks a byte, and a byte b is one of them exactly when
// loTable[b&0xf] & hiTable[b>>4] != 0. The whole 0x00-0x1f range shares bit 0
// because both high-nibble rows set it, and '<' and '\\' share bit 3 because
// their cross combinations are themselves in the set, so there are no false
// positives.
DATA	·escapeLoTable+0(SB)/8, $0x0501010101030101
DATA	·escapeLoTable+8(SB)/8, $0x0101011901010101
GLOBL	·escapeLoTable(SB), RODATA|NOPTR, $16

DATA	·escapeHiTable+0(SB)/8, $0x0000100008060101
DATA	·escapeHiTable+8(SB)/8, $0x0000000000000000
GLOBL	·escapeHiTable(SB), RODATA|NOPTR, $16

// func needEscapeBlocks(b string) bool
//   R0: b.base
//   R1: b.len, a positive multiple of 16
//
// Scans 16 bytes per iteration with NEON: one nibble extraction, two table
// lookups and one AND decide whether any byte in the block is in the set.
TEXT ·needEscapeBlocks(SB), NOSPLIT, $0-17
	MOVD	b_base+0(FP), R0
	MOVD	b_len+8(FP), R1

	MOVD	$·escapeLoTable(SB), R10
	VLD1	(R10), [V18.B16]
	MOVD	$·escapeHiTable(SB), R11
	VLD1	(R11), [V19.B16]
	MOVD	$0x0f0f0f0f0f0f0f0f, R12
	VMOV	R12, V17.B16		// 0x0f
	VEOR	V20.B16, V20.B16, V20.B16 // accumulator

loop:
	VLD1.P	16(R0), [V6.B16]
	VAND	V17.B16, V6.B16, V7.B16	// low nibbles
	VUSHR	$4, V6.B16, V8.B16	// high nibbles
	VTBL	V7.B16, [V18.B16], V9.B16
	VTBL	V8.B16, [V19.B16], V10.B16
	VAND	V10.B16, V9.B16, V9.B16
	VORR	V9.B16, V20.B16, V20.B16

	SUBS	$16, R1, R1
	BGT	loop

	// Fold the 16 accumulator bytes into one general register with two lane
	// reads and an OR: the cross-lane reduction VUMAXV is only understood by
	// the go1.27 assembler, while these instructions assemble on every
	// supported toolchain.
	VMOV	V20.D[0], R8
	VMOV	V20.D[1], R9
	ORR	R9, R8, R8
	CMP	$0, R8
	CSET	NE, R8
	MOVB	R8, ret+16(FP)
	RET
