// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.*/

// Parsing of Mach-O executables (OS X).

package objfile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/mandiant/GoReSym/debug/dwarf"
	"github.com/mandiant/GoReSym/debug/macho"
)

const stabTypeMask = 0xe0

type machoFile struct {
	macho *macho.File
}

func openMacho(r io.ReaderAt) (rawFile, error) {
	f, err := macho.NewFile(r)
	if err != nil {
		return nil, err
	}
	return &machoFile{f}, nil
}

func (f *machoFile) read_memory(VA uint64, size uint64) (data []byte, err error) {
	for _, load := range f.macho.Loads {
		seg, ok := load.(*macho.Segment)
		if !ok {
			continue
		}
		if seg.Addr <= VA && VA <= seg.Addr+seg.Filesz-1 {
			if seg.Name == "__PAGEZERO" {
				continue
			}
			n := seg.Addr + seg.Filesz - VA
			if n > size {
				n = size
			}
			data := make([]byte, n)
			_, err := seg.ReadAt(data, int64(VA-seg.Addr))
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("Failed to read memory")
}

func (f *machoFile) symbols() ([]Sym, error) {
	if f.macho.Symtab == nil {
		return nil, nil
	}

	// Build sorted list of addresses of all symbols.
	// We infer the size of a symbol by looking at where the next symbol begins.
	var addrs []uint64
	for _, s := range f.macho.Symtab.Syms {
		// Skip stab debug info.
		if s.Type&stabTypeMask == 0 {
			addrs = append(addrs, s.Value)
		}
	}
	sort.Sort(uint64s(addrs))

	var syms []Sym
	for _, s := range f.macho.Symtab.Syms {
		if s.Type&stabTypeMask != 0 {
			// Skip stab debug info.
			continue
		}
		sym := Sym{Name: s.Name, Addr: s.Value, Code: '?'}
		i := sort.Search(len(addrs), func(x int) bool { return addrs[x] > s.Value })
		if i < len(addrs) {
			sym.Size = int64(addrs[i] - s.Value)
		}
		if s.Sect == 0 {
			sym.Code = 'U'
		} else if int(s.Sect) <= len(f.macho.Sections) {
			sect := f.macho.Sections[s.Sect-1]
			switch sect.Seg {
			case "__TEXT", "__DATA_CONST":
				sym.Code = 'R'
			case "__DATA":
				sym.Code = 'D'
			}
			switch sect.Seg + " " + sect.Name {
			case "__TEXT __text":
				sym.Code = 'T'
			case "__DATA __bss", "__DATA __noptrbss":
				sym.Code = 'B'
			}
		}
		syms = append(syms, sym)
	}

	return syms, nil
}

func (f *machoFile) pcln_scan() (candidates []PclntabCandidate, err error) {
	// 1) Locate pclntab via symbols (standard way)
	foundpcln := false
	var pclntab []byte
	if sect := f.macho.Section("__gopclntab"); sect != nil {
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

	// 2) if not found, byte scan for it
	for _, sec := range f.macho.Sections {
		// malware can split the pclntab across multiple sections, re-merge
		data := f.macho.DataAfterSection(sec)

		if !foundpcln {
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
			if pclntab_idx != -1 {
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
		for _, sec := range f.macho.Sections {
			// malware can split the pclntab across multiple sections, re-merge
			data := f.macho.DataAfterSection(sec)
			for _, stompedMagicCandidate := range stompedmagic_candidates {
				pclntab_va_candidate := stompedMagicCandidate.PclntabVa

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

func (f *machoFile) pcln() (candidates []PclntabCandidate, err error) {
	candidates, err = f.pcln_scan()
	if err != nil {
		return nil, err
	}

	// 4) symtab is completely optional, but try to find it
	var symtab []byte
	if sect := f.macho.Section("__gosymtab"); sect != nil {
		symtab, err = sect.Data()
	}

	if err == nil {
		for _, c := range candidates {
			c.Symtab = symtab
		}
	}

	return candidates, nil
}

func (f *machoFile) moduledata_scan(pclntabVA uint64, is64bit bool, littleendian bool, ignorelist []uint64) (candidate *ModuleDataCandidate, err error) {
	found := false

	var secStart uint64
	var moduledata []uint8
	var moduledataVA uint64
scan:
	for _, sec := range f.macho.Sections {
		// malware can split the pclntab across multiple sections, re-merge
		data := f.macho.DataAfterSection(sec)
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
				if ignore == moduledataVA {
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

func (f *machoFile) text() (textStart uint64, text []byte, err error) {
	sect := f.macho.Section("__text")
	if sect == nil {
		return 0, nil, fmt.Errorf("text section not found")
	}
	textStart = sect.Addr
	text, err = sect.Data()
	return
}

func (f *machoFile) rdata() (textStart uint64, text []byte, err error) {
	sect := f.macho.Section("__DATA")
	if sect == nil {
		return 0, nil, fmt.Errorf("data section not found")
	}
	textStart = sect.Addr
	text, err = sect.Data()
	return
}

func (f *machoFile) goarch() string {
	switch f.macho.Cpu {
	case macho.Cpu386:
		return "386"
	case macho.CpuAmd64:
		return "amd64"
	case macho.CpuArm:
		return "arm"
	case macho.CpuArm64:
		return "arm64"
	case macho.CpuPpc64:
		return "ppc64"
	}
	return ""
}

type uint64s []uint64

func (x uint64s) Len() int           { return len(x) }
func (x uint64s) Swap(i, j int)      { x[i], x[j] = x[j], x[i] }
func (x uint64s) Less(i, j int) bool { return x[i] < x[j] }

func (f *machoFile) loadAddress() (uint64, error) {
	if seg := f.macho.Segment("__TEXT"); seg != nil {
		return seg.Addr, nil
	}
	return 0, fmt.Errorf("unknown load address")
}

func (f *machoFile) dwarf() (*dwarf.Data, error) {
	return f.macho.DWARF()
}
