package objfile

import "encoding/binary"

type signatureModuleDataInitx64 struct {
	moduleDataPtrLoc       uint64 // offset in signature to the location of the pointer to the PCHeader
	moduleDataPtrOffsetLoc uint64 // Ptr is a relative ptr, we need to include the instruction length + next instruction IP to resolve final VA
	signature              string
	compiledRegex          *RegexAndNeedle
}

type signatureModuleDataInitx86 struct {
	moduleDataPtrLoc uint64 // offset in signature to the location of the pointer to the PCHeader (ptr is absolute addr)
	signature        string
	compiledRegex    *RegexAndNeedle
}

type signatureModuleDataInitPPC struct {
	moduleDataPtrHi uint64
	moduleDataPtrLo uint64
	signature       string
	compiledRegex   *RegexAndNeedle
}

type signatureModuleDataInitARM64 struct {
	moduleDataPtrADRP uint64 // offset to ADRP instruction holding PAGE address
	moduleDataPtrADD  uint64 // offset to ADD instruction holding PAGE offset
	signature         string
	compiledRegex     *RegexAndNeedle
}

type signatureModuleDataInitARM32 struct {
	moduleDataPtrLDR uint64 // offset to LDR instruction holding pc relative imm offset to PCHeader
	signature        string
	compiledRegex    *RegexAndNeedle
}

type SignatureMatch struct {
	moduleDataVA uint64
}

// 0x000000000044D80A: 48 8D 0D 8F DA 26 00                    lea     rcx, runtime_firstmoduledata
// 0x000000000044D811: EB 0D                                   jmp     short loc_44D820
// 0x000000000044D813: 48 8B 89 30 02 00 00                    mov     rcx, [rcx+230h]
var x64sig = signatureModuleDataInitx64{3, 7, `{ 48 8D 0? ?? ?? ?? ?? E? ?? 48 8? 8? ?? 02 00 00 }`, nil}

// 0x00438A94: 8D 05 60 49 6A 00                       lea     eax, off_6A4960
// 0x00438A9A: EB 1A                                   jmp     short loc_438AB6
// ...gap...
// 0x00438AAC: 8B 80 18 01 00 00                       mov     eax, [eax+118h]
// 0x00438AB2: 8B 54 24 20                             mov     edx, [esp+2Ch+var_C]
// 0x00438AB6:
// 0x00438AB6:                         loc_438AB6:                             ; CODE XREF: sub_438A60+3A↑j
// 0x00438AB6: 85 C0                                   test    eax, eax
// 0x00438AB8: 75 E2                                   jnz     short loc_438A9C
var x86sig = signatureModuleDataInitx86{2, `{ 8D ?? ?? ?? ?? ?? EB ?? [0-50] 8B ?? ?? 01 00 00 8B ?? ?? ?? 85 ?? 75 ?? }`, nil}

// 0x0000000000061a74:  3C 80 00 2C    lis  r4, 0x2c       // moduledata
// 0x0000000000061a78:  38 84 80 00    addi r4, r4, 0x8000  // moduledata ((0x2c << 16) - 0x8000)
// 0x0000000000061a7c:  48 00 00 08    b    0x61a84
// 0x0000000000061a80:  E8 84 02 30    ld   r4, 0x230(r4)
// 0x0000000000061a84:  7C 24 00 00    cmpd r4, r0
// 0x0000000000061a88:  41 82 01 A8    beq  0x61c30
var PPC_BE_sig = signatureModuleDataInitPPC{2, 6, `{ 3? 80 00 ?? 3? ?? ?? ?? 48 ?? ?? ?? E? ?? 02 ?? 7C ?? ?? ?? 41 82 ?? ?? }`, nil}

// 0x000000000005C1E8 41 14 00 F0        ADRP            X1, #unk_2E7000    // 0xF0001441 -> 0b1 11 10000 0000000000010100010 00001 -> op=1, immlo=0b11, immhi=0b0000000000010100010
// ........................................................................ // X1 = ((0b0000000000010100010 11 << 12) + 0x5C1E8) = 0b1011100111000111101000 = 0b1011100111000111101000 & 0xFFFFFFFFFFFFF000 = 0x2E7000
// 0x000000000005C1EC 21 80 3D 91        ADD             X1, X1, #firstmoduleData@PAGEOFF // 0x913d8021 -> 0b100 100010 0 111101100000 00001 00001 -> sh = 0, imm12 = 0b111101100000, Rn = 00001, Rb = 00001
// ....................................................................... // X1 = 0x2E7000 + 0b111101100000 (0xF60) = 0x2E7F60
// 0x000000000005C1F0 02 00 00 14        B               loc_5C1F8     0x14 00 00 02
// 0x000000000005C1F4 21 18 41 F9        LDR             X1, [X1,#0x230]
// 0x000000000005C1F8 21 0D 00 B4        CBZ             X1, loc_5C39C   0xb4000d21
// THIS SIG ENCODES the 0x230 struct field offset - might need to mask that more if we see misses - TODO
var ARM64_sig = signatureModuleDataInitARM64{0, 4, `{ ?? ?? ?? (90 | b0 | f0 | d0) ?? ?? ?? 91 ?? ?? ?? (14 | 17) ?? ?? 41 F9 ?? ?? ?? B4 }`, nil}

// 0x0006AA00 80 12 9F E5    LDR             R1, =firstmoduleData   // 0xE59F1280 -> 0b11 100101100111110001001010000000 -> size = 11,
// 0x0006AA04 00 00 00 EA    B               loc_6AA0C
// 0x0006AA08 18 11 91 E5    LDR             R1, [R1,#0x118]
// 0x0006AA0C 00 00 51 E3    CMP             R1, #0
// 0x0006AA10 69 00 00 0A    BEQ             loc_6ABBC
var ARM32_sig = signatureModuleDataInitARM32{0, `{ ?? ?? 9F E5 ?? ?? ?? EA ?? ?? ?? E5 ?? ?? ?? E3 ?? ?? ?? 0A }`, nil}

func findModuleInitPCHeader(data []byte, sectionBase uint64) []SignatureMatch {
	var matches []SignatureMatch = make([]SignatureMatch, 0)

	var x64reg = x64sig.compiledRegex
	if x64reg == nil {
		var err error
		x64reg, err = RegexpPatternFromYaraPattern(x64sig.signature)
		if err != nil {
			panic(err)
		}
		x64sig.compiledRegex = x64reg
	}

	for _, match := range FindRegex(data, x64reg) {
		sigPtr := uint64(match[0]) // from int

		// this is the pointer offset stored in the instruction
		// 0x44E06A:       48 8D 0D 4F F0 24 00 lea     rcx, off_69D0C0 (result: 0x24f04f)
		moduleDataPtrOffset := uint64(binary.LittleEndian.Uint32(data[sigPtr+x64sig.moduleDataPtrLoc:][:4]))

		// the ptr we get is position dependant, add the sigPtr + sectionBase to get current IP, then offset to next instruction
		// as relative ptrs are encoded by the NEXT instruction va, not the current one
		moduleDataIpOffset := sigPtr + sectionBase + x64sig.moduleDataPtrOffsetLoc
		matches = append(matches, SignatureMatch{
			moduleDataPtrOffset + moduleDataIpOffset,
		})
	}

	var x86reg = x86sig.compiledRegex
	if x86reg == nil {
		var err error
		x86reg, err = RegexpPatternFromYaraPattern(x86sig.signature)
		if err != nil {
			panic(err)
		}
		x86sig.compiledRegex = x86reg
	}

	for _, match := range FindRegex(data, x86reg) {
		sigPtr := uint64(match[0]) // from int

		moduleDataPtr := uint64(binary.LittleEndian.Uint32(data[sigPtr+x86sig.moduleDataPtrLoc:][:4]))
		matches = append(matches, SignatureMatch{
			moduleDataPtr,
		})
	}

	var arm64reg = ARM64_sig.compiledRegex
	if arm64reg == nil {
		var err error
		arm64reg, err = RegexpPatternFromYaraPattern(ARM64_sig.signature)
		if err != nil {
			panic(err)
		}
		ARM64_sig.compiledRegex = arm64reg
	}

	for _, match := range FindRegex(data, arm64reg) {
		sigPtr := uint64(match[0]) // from int

		adrp := binary.LittleEndian.Uint32(data[sigPtr+ARM64_sig.moduleDataPtrADRP:][:4])
		add := binary.LittleEndian.Uint32(data[sigPtr+ARM64_sig.moduleDataPtrADD:][:4])
		moduleDataIpOffset := sigPtr + sectionBase

		adrp_immhi := uint64((adrp & 0xFFFFF0) >> 5)
		adrp_immlo := uint64((adrp & 0x60000000) >> 29)
		adrp_imm := adrp_immhi<<2 | adrp_immlo                               // combine hi:lo
		page := ((adrp_imm << 12) + moduleDataIpOffset) & 0xFFFFFFFFFFFFF000 // PAGE imm is aligned to page, left shift 12 and zero lower 12 to align

		// the page offset fills in lower 12
		page_off := uint64((add & 0x3FFC00) >> 10)

		final := page + page_off
		matches = append(matches, SignatureMatch{
			final,
		})
	}

	var arm32reg = ARM32_sig.compiledRegex
	if arm32reg == nil {
		var err error
		arm32reg, err = RegexpPatternFromYaraPattern(ARM32_sig.signature)
		if err != nil {
			panic(err)
		}
		ARM32_sig.compiledRegex = arm32reg
	}

	for _, match := range FindRegex(data, arm32reg) {
		sigPtr := uint64(match[0]) // from int
		ldr := binary.LittleEndian.Uint32(data[sigPtr+ARM32_sig.moduleDataPtrLDR:][:4])
		// ARM PC relative is always +8 due to legacy nonsense
		ldr_pointer_stub := uint64((ldr & 0x00000FFF) + 8)
		final := uint64(binary.LittleEndian.Uint32(data[sigPtr+ARM32_sig.moduleDataPtrLDR+ldr_pointer_stub:][:4]))
		matches = append(matches, SignatureMatch{
			final,
		})
	}

	var ppcBEreg = PPC_BE_sig.compiledRegex
	if ppcBEreg == nil {
		var err error
		ppcBEreg, err = RegexpPatternFromYaraPattern(PPC_BE_sig.signature)
		if err != nil {
			panic(err)
		}
		PPC_BE_sig.compiledRegex = ppcBEreg
	}

	for _, match := range FindRegex(data, ppcBEreg) {
		sigPtr := uint64(match[0]) // from int
		moduleDataPtrHi := int64(binary.BigEndian.Uint16(data[sigPtr+PPC_BE_sig.moduleDataPtrHi:][:2]))
		// addi takes a signed immediate
		moduleDataPtrLo := int64(int16(binary.BigEndian.Uint16(data[sigPtr+PPC_BE_sig.moduleDataPtrLo:][:2])))
		moduleDataIpOffset := uint64((moduleDataPtrHi << 16) + moduleDataPtrLo)
		matches = append(matches, SignatureMatch{
			moduleDataIpOffset,
		})
	}

	return matches
}
