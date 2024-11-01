// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.*/

// Parsing of ELF executables (Linux, FreeBSD, and so on).

package objfile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/mandiant/GoReSym/debug/dwarf"
	"github.com/mandiant/GoReSym/debug/elf"
)

type elfFile struct {
	elf *elf.File
}

func openElf(r io.ReaderAt) (rawFile, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	return &elfFile{f}, nil
}

func (f *elfFile) read_memory(VA uint64, size uint64) (data []byte, err error) {
	for _, prog := range f.elf.Progs {
		if prog.Vaddr <= VA && VA <= prog.Vaddr+prog.Filesz-1 {
			n := prog.Vaddr + prog.Filesz - VA
			if n > size {
				n = size
			}
			data := make([]byte, n)
			_, err := prog.ReadAt(data, int64(VA-prog.Vaddr))
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("Failed to read memory")
}

func (f *elfFile) symbols() ([]Sym, error) {
	elfSyms, err := f.elf.Symbols()
	if err != nil {
		return nil, err
	}

	var syms []Sym
	for _, s := range elfSyms {
		sym := Sym{Addr: s.Value, Name: s.Name, Size: int64(s.Size), Code: '?'}
		switch s.Section {
		case elf.SHN_UNDEF:
			sym.Code = 'U'
		case elf.SHN_COMMON:
			sym.Code = 'B'
		default:
			i := int(s.Section)
			if i < 0 || i >= len(f.elf.Sections) {
				break
			}
			sect := f.elf.Sections[i]
			switch sect.Flags & (elf.SHF_WRITE | elf.SHF_ALLOC | elf.SHF_EXECINSTR) {
			case elf.SHF_ALLOC | elf.SHF_EXECINSTR:
				sym.Code = 'T'
			case elf.SHF_ALLOC:
				sym.Code = 'R'
			case elf.SHF_ALLOC | elf.SHF_WRITE:
				sym.Code = 'D'
			}
		}
		if elf.ST_BIND(s.Info) == elf.STB_LOCAL {
			sym.Code += 'a' - 'A'
		}
		syms = append(syms, sym)
	}

	return syms, nil
}

func (f *elfFile) pcln_scan() (candidates []PclntabCandidate, err error) {
	// 1) Locate pclntab via symbols (standard way)
	foundpcln := false
	var pclntab []byte
	if sect := f.elf.Section(".gopclntab"); sect != nil {
		if pclntab, err = sect.Data(); err == nil {
			foundpcln = true
		}
	}

	pclntab_sigs_le := [][]byte{
		[]byte("\xF1\xFF\xFF\xFF\x00\x00"), // little endian
		[]byte("\xF0\xFF\xFF\xFF\x00\x00"),
		[]byte("\xFA\xFF\xFF\xFF\x00\x00"),
		[]byte("\xFB\xFF\xFF\xFF\x00\x00"),
	}

	pclntab_sigs_be := [][]byte{
		[]byte("\xFF\xFF\xFF\xF1\x00\x00"), // big endian
		[]byte("\xFF\xFF\xFF\xF0\x00\x00"),
		[]byte("\xFF\xFF\xFF\xFA\x00\x00"),
		[]byte("\xFF\xFF\xFF\xFB\x00\x00"),
	}

	// 2) if not found, byte scan for it
	pclntab_sigs := append(pclntab_sigs_le, pclntab_sigs_be...)

	// candidate array for method 4 of scanning
	var stompedmagic_candidates []StompMagicCandidate = make([]StompMagicCandidate, 0)
	for _, sec := range f.elf.Sections {
		// first section is all zeros, skip
		if sec.Type == elf.SHT_NULL {
			continue
		}

		data := f.elf.DataAfterSection(sec)
		if !foundpcln {
			// malware can split the pclntab across multiple sections, re-merge
			// https://github.com/golang/go/blob/2cb9042dc2d5fdf6013305a077d013dbbfbaac06/src/debug/gosym/pclntab.go#L172
			matches := findAllOccurrences(data, pclntab_sigs)
			for _, pclntab_idx := range matches {
				if pclntab_idx != -1 && pclntab_idx < int(sec.Size) {
					pclntab = data[pclntab_idx:]

					var candidate PclntabCandidate
					candidate.Pclntab = pclntab

					candidate.SecStart = uint64(sec.Addr)
					candidate.PclntabVA = candidate.SecStart + uint64(pclntab_idx)

					candidates = append(candidates, candidate)
					// we must scan all signature for all sections. DO NOT BREAK
				}
			}
		} else {
			// 3) if we found it earlier, figure out which section base to return (might be wrong for packed things)
			pclntab_idx := bytes.Index(data, pclntab)
			if pclntab_idx != -1 && pclntab_idx < int(sec.Size) {
				var candidate PclntabCandidate
				candidate.Pclntab = pclntab
				candidate.SecStart = uint64(sec.Addr)
				candidate.PclntabVA = candidate.SecStart + uint64(pclntab_idx)

				candidates = append(candidates, candidate)
			}
		}

		// TODO this scan needs to occur in both big and little endian mode
		// 4) Always try this other way! Sometimes the pclntab magic is stomped as well so our byte OR symbol location fail. Byte scan for the moduledata, use that to find the pclntab instead, fix up magic with all combinations.
		// See the obfuscator 'garble' for an example of randomizing the pclntab magic
		sigResults := findModuleInitPCHeader(data, sec.Addr)
		for _, sigResult := range sigResults {
			// example: off_69D0C0 is the moduleData we found via our scan, the first ptr unk_5DF6E0, is the pclntab!
			// 0x000000000069D0C0 E0 F6 5D 00 00 00 00 00 off_69D0C0      dq offset unk_5DF6E0    ; DATA XREF: runtime_SetFinalizer+119↑o
			// 0x000000000069D0C0                                                                 ; runtime_scanstack+40B↑o ...
			// 0x000000000069D0C8 40 F7 5D 00 00 00 00 00                 dq offset aInternalCpuIni ; "internal/cpu.Initialize"
			// 0x000000000069D0D0 F0                                      db 0F0h
			// 0x000000000069D0D1 BB                                      db 0BBh

			// we don't know the endianess or arch, so we submit all combinations as candidates and sort them out later
			// example: reads out ptr unk_5DF6E0
			pclntabVARaw64, err := f.read_memory(sigResult.moduleDataVA, 8) // assume 64bit
			if err == nil {
				stompedMagicCandidateLE := StompMagicCandidate{
					binary.LittleEndian.Uint64(pclntabVARaw64),
					sigResult.moduleDataVA,
					true,
				}
				stompedMagicCandidateBE := StompMagicCandidate{
					binary.BigEndian.Uint64(pclntabVARaw64),
					sigResult.moduleDataVA,
					false,
				}
				stompedmagic_candidates = append(stompedmagic_candidates, stompedMagicCandidateLE, stompedMagicCandidateBE)
			}

			pclntabVARaw32, err := f.read_memory(sigResult.moduleDataVA, 4) // assume 32bit
			if err == nil {
				stompedMagicCandidateLE := StompMagicCandidate{
					uint64(binary.LittleEndian.Uint32(pclntabVARaw32)),
					sigResult.moduleDataVA,
					true,
				}
				stompedMagicCandidateBE := StompMagicCandidate{
					uint64(binary.BigEndian.Uint32(pclntabVARaw32)),
					sigResult.moduleDataVA,
					false,
				}
				stompedmagic_candidates = append(stompedmagic_candidates, stompedMagicCandidateLE, stompedMagicCandidateBE)
			}
		}
	}

	// even if we found the pclntab without signature scanning it may have a stomped magic. That would break parsing later! So, let's submit new candidates
	// with all the possible magics to get at least one that hopefully parses correctly.
	patched_magic_candidates := make([]PclntabCandidate, 0)
	for _, candidate := range candidates {
		has_some_valid_magic := false
		for _, magic := range append(pclntab_sigs_le, pclntab_sigs_be...) {
			if bytes.Equal(candidate.Pclntab, magic) {
				has_some_valid_magic = true
				break
			}
		}

		if !has_some_valid_magic {
			for _, magic := range append(pclntab_sigs_le, pclntab_sigs_be...) {
				pclntab_copy := make([]byte, len(candidate.Pclntab))
				copy(pclntab_copy, candidate.Pclntab)
				copy(pclntab_copy, magic)

				new_candidate := candidate
				new_candidate.Pclntab = pclntab_copy
				patched_magic_candidates = append(patched_magic_candidates, new_candidate)
				candidate.Pclntab = pclntab_copy
			}
		}
	}

	if len(patched_magic_candidates) > 0 {
		candidates = patched_magic_candidates
	}

	if len(stompedmagic_candidates) != 0 {
		for _, sec := range f.elf.Sections {
			data := f.elf.DataAfterSection(sec)
			for _, stompedMagicCandidate := range stompedmagic_candidates {
				pclntab_va_candidate := stompedMagicCandidate.PclntabVa

				// use data length as some binaries have invalid section length
				if pclntab_va_candidate >= sec.Addr && pclntab_va_candidate < (sec.Addr+sec.Size) && pclntab_va_candidate < (sec.Addr+uint64(len(data))) {
					sec_offset := pclntab_va_candidate - sec.Addr
					pclntab = data[sec_offset:]

					if stompedMagicCandidate.LittleEndian {
						for _, magicLE := range pclntab_sigs_le {
							pclntab_copy := make([]byte, len(pclntab))
							copy(pclntab_copy, pclntab)
							copy(pclntab_copy, magicLE)

							var candidate PclntabCandidate
							candidate.StompMagicCandidateMeta = &stompedMagicCandidate
							candidate.Pclntab = pclntab_copy
							candidate.SecStart = uint64(sec.Addr)
							candidate.PclntabVA = pclntab_va_candidate

							candidates = append(candidates, candidate)
						}
					} else {
						for _, magicBE := range pclntab_sigs_be {
							pclntab_copy := make([]byte, len(pclntab))
							copy(pclntab_copy, pclntab)
							copy(pclntab_copy, magicBE)

							var candidate PclntabCandidate
							candidate.StompMagicCandidateMeta = &stompedMagicCandidate
							candidate.Pclntab = pclntab_copy
							candidate.SecStart = uint64(sec.Addr)
							candidate.PclntabVA = pclntab_va_candidate

							candidates = append(candidates, candidate)
						}
					}
				}
			}
		}
	}

	return candidates, nil
}

func (f *elfFile) pcln() (candidates []PclntabCandidate, err error) {
	candidates, err = f.pcln_scan()
	if err != nil {
		return nil, err
	}

	// 4) symtab is completely optional, but try to find it
	var symtab []byte
	if sect := f.elf.Section(".gosymtab"); sect != nil {
		symtab, err = sect.Data()
	}

	if err == nil {
		for _, c := range candidates {
			c.Symtab = symtab
		}
	}

	return candidates, nil
}

func (f *elfFile) moduledata_scan(pclntabVA uint64, is64bit bool, littleendian bool, ignorelist []uint64) (candidate *ModuleDataCandidate, err error) {
	found := false

	var secStart uint64
	var moduledata []uint8
	var moduledataVA uint64
scan:
	for _, sec := range f.elf.Sections {
		// first section is all zeros, skip
		if sec.Type == elf.SHT_NULL {
			continue
		}

		// malware can split the pclntab across multiple sections, re-merge
		data := f.elf.DataAfterSection(sec)

		// fall back to scanning for structure using address of pclntab, which is first value in struc
		var pclntabVA_bytes []byte
		if is64bit {
			pclntabVA_bytes = make([]byte, 8)
			if littleendian {
				binary.LittleEndian.PutUint64(pclntabVA_bytes, pclntabVA)
			} else {
				binary.BigEndian.PutUint64(pclntabVA_bytes, pclntabVA)
			}
		} else {
			pclntabVA_bytes = make([]byte, 4)
			if littleendian {
				binary.LittleEndian.PutUint32(pclntabVA_bytes, uint32(pclntabVA))
			} else {
				binary.BigEndian.PutUint32(pclntabVA_bytes, uint32(pclntabVA))
			}
		}

		moduledata_idx := bytes.Index(data, pclntabVA_bytes)
		if moduledata_idx != -1 && moduledata_idx < int(sec.Size) {
			moduledata = data[moduledata_idx:]
			moduledataVA = sec.Addr + uint64(moduledata_idx)
			secStart = sec.Addr

			// optionally consult ignore list, to skip past previous (bad) scan results
			for _, ignore := range ignorelist {
				if ignore == secStart+uint64(moduledata_idx) {
					continue scan
				}
			}

			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("moduledata containing section could not be located")
	}

	return &ModuleDataCandidate{SecStart: secStart, ModuledataVA: moduledataVA, Moduledata: moduledata}, nil
}

func (f *elfFile) text() (textStart uint64, text []byte, err error) {
	sect := f.elf.Section(".text")
	if sect == nil {
		return 0, nil, fmt.Errorf("text section not found")
	}
	textStart = sect.Addr
	text, err = sect.Data()
	return
}

func (f *elfFile) rdata() (textStart uint64, text []byte, err error) {
	sect := f.elf.Section(".rodata")
	if sect == nil {
		return 0, nil, fmt.Errorf("rdata section not found")
	}
	textStart = sect.Addr
	text, err = sect.Data()
	return
}

func (f *elfFile) rel_rdata() (textStart uint64, text []byte, err error) {
	sect := f.elf.Section(".data.rel.ro")
	if sect == nil {
		return 0, nil, fmt.Errorf(".data.rel.ro section not found")
	}
	textStart = sect.Addr
	text, err = sect.Data()
	return
}

func (f *elfFile) goarch() string {
	switch f.elf.Machine {
	case elf.EM_386:
		return "386"
	case elf.EM_X86_64:
		return "amd64"
	case elf.EM_ARM:
		return "arm"
	case elf.EM_AARCH64:
		return "arm64"
	case elf.EM_PPC64:
		if f.elf.ByteOrder == binary.LittleEndian {
			return "ppc64le"
		}
		return "ppc64"
	case elf.EM_S390:
		return "s390x"
	}
	return ""
}

func (f *elfFile) loadAddress() (uint64, error) {
	for _, p := range f.elf.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 {
			// The memory mapping that contains the segment
			// starts at an aligned address. Apparently this
			// is what pprof expects, as it uses this and the
			// start address of the mapping to compute PC
			// delta.
			return p.Vaddr - p.Vaddr%p.Align, nil
		}
	}
	return 0, fmt.Errorf("unknown load address")
}

func (f *elfFile) dwarf() (*dwarf.Data, error) {
	return f.elf.DWARF()
}
