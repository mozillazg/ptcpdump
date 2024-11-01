// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.*/

// Parsing of PE executables (Microsoft Windows).

package objfile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/mandiant/GoReSym/debug/dwarf"
	"github.com/mandiant/GoReSym/debug/pe"
)

type peFile struct {
	pe *pe.File
}

func openPE(r io.ReaderAt) (rawFile, error) {
	f, err := pe.NewFile(r)
	if err != nil {
		return nil, err
	}
	return &peFile{f}, nil
}

func (f *peFile) read_memory(VA uint64, size uint64) (data []byte, err error) {
	var imageBase uint64
	switch oh := f.pe.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
	}

	VA -= imageBase
	for _, sect := range f.pe.Sections {
		if uint64(sect.VirtualAddress) <= VA && VA <= uint64(sect.VirtualAddress+sect.Size-1) {
			n := uint64(sect.VirtualAddress+sect.Size) - VA
			if n > size {
				n = size
			}
			data := make([]byte, n)
			_, err := sect.ReadAt(data, int64(VA-uint64(sect.VirtualAddress)))
			if err != nil {
				return nil, fmt.Errorf("Reading section data failed")
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("Failed to read memory")
}

func (f *peFile) symbols() ([]Sym, error) {
	// Build sorted list of addresses of all symbols.
	// We infer the size of a symbol by looking at where the next symbol begins.
	var addrs []uint64

	var imageBase uint64
	switch oh := f.pe.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
	}

	var syms []Sym
	for _, s := range f.pe.Symbols {
		const (
			N_UNDEF = 0  // An undefined (extern) symbol
			N_ABS   = -1 // An absolute symbol (e_value is a constant, not an address)
			N_DEBUG = -2 // A debugging symbol
		)
		sym := Sym{Name: s.Name, Addr: uint64(s.Value), Code: '?'}
		switch s.SectionNumber {
		case N_UNDEF:
			sym.Code = 'U'
		case N_ABS:
			sym.Code = 'C'
		case N_DEBUG:
			sym.Code = '?'
		default:
			if s.SectionNumber < 0 || len(f.pe.Sections) < int(s.SectionNumber) {
				return nil, fmt.Errorf("invalid section number in symbol table")
			}
			sect := f.pe.Sections[s.SectionNumber-1]
			const (
				text  = 0x20
				data  = 0x40
				bss   = 0x80
				permW = 0x80000000
			)
			ch := sect.Characteristics
			switch {
			case ch&text != 0:
				sym.Code = 'T'
			case ch&data != 0:
				if ch&permW == 0 {
					sym.Code = 'R'
				} else {
					sym.Code = 'D'
				}
			case ch&bss != 0:
				sym.Code = 'B'
			}
			sym.Addr += imageBase + uint64(sect.VirtualAddress)
		}
		syms = append(syms, sym)
		addrs = append(addrs, sym.Addr)
	}

	sort.Sort(uint64s(addrs))
	for i := range syms {
		j := sort.Search(len(addrs), func(x int) bool { return addrs[x] > syms[i].Addr })
		if j < len(addrs) {
			syms[i].Size = int64(addrs[j] - syms[i].Addr)
		}
	}

	return syms, nil
}

func (f *peFile) pcln_scan() (candidates <-chan PclntabCandidate, err error) {
	var imageBase uint64
	switch oh := f.pe.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
	default:
		return nil, fmt.Errorf("pe file format not recognized")
	}

	// 1) Locate pclntab via symbols (standard way)
	foundpcln := false
	var pclntab []byte

	if pclntab, err = loadPETable(f.pe, "runtime.pclntab", "runtime.epclntab"); err == nil {
		foundpcln = true
	} else {
		// We didn't find the symbols, so look for the names used in 1.3 and earlier.
		// TODO: Remove code looking for the old symbols when we no longer care about 1.3.
		var err2 error
		if pclntab, err2 = loadPETable(f.pe, "pclntab", "epclntab"); err2 == nil {
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

	symtab, symtab_err := loadPETable(f.pe, "runtime.symtab", "runtime.esymtab")
	if symtab_err != nil {
		symtab, symtab_err = loadPETable(f.pe, "symtab", "esymtab")
	}

	// 2) if not found, byte scan for it
	pclntab_sigs := append(pclntab_sigs_le, pclntab_sigs_be...)
	ch_tab := make(chan PclntabCandidate)

	send_tab := func(candidate *PclntabCandidate) {
		if symtab_err != nil {
			candidate.Symtab = symtab
			ch_tab <- *candidate
		}
		ch_tab <- *candidate
	}

	send_patched_magic_candidates := func(candidate *PclntabCandidate) {
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
				send_tab(new_candidate)
			}
		}
	}

	send_stomped_magic_candidate := func(stompedMagicCandidate *StompMagicCandidate) {
		for _, sec := range f.pe.Sections {
			// malware can split the pclntab across multiple sections, re-merge
			data := f.pe.DataAfterSection(sec)
			pclntab_va_candidate := stompedMagicCandidate.PclntabVa

			// We must ensure our pointer starts within the first section of the data returned by DataAfterSection so that we use the right base address
			if pclntab_va_candidate >= (imageBase+uint64(sec.VirtualAddress)) && pclntab_va_candidate < (imageBase+uint64(sec.VirtualAddress)+uint64(sec.Size)) && pclntab_va_candidate < (imageBase+uint64(sec.VirtualAddress)+uint64(len(data))) {
				sec_offset := pclntab_va_candidate - (imageBase + uint64(sec.VirtualAddress))
				pclntab = data[sec_offset:]

				if stompedMagicCandidate.LittleEndian {
					for _, magicLE := range pclntab_sigs_le {
						// Make a copy of the pclntab with each magic possible. For when the magic is intentionally corrupted
						// Parsing will fail at some later point for the magics that don't match the version, filtering out that candidate
						pclntab_copy := make([]byte, len(pclntab))
						copy(pclntab_copy, pclntab)
						copy(pclntab_copy, magicLE)

						var candidate PclntabCandidate
						candidate.StompMagicCandidateMeta = stompedMagicCandidate
						candidate.Pclntab = pclntab_copy
						candidate.SecStart = imageBase + uint64(sec.VirtualAddress)
						candidate.PclntabVA = pclntab_va_candidate

						send_tab(&candidate)
					}
				} else {
					for _, magicBE := range pclntab_sigs_be {
						// Make a copy of the pclntab with each magic possible. For when the magic is intentionally corrupted
						// Parsing will fail at some later point for the magics that don't match the version, filtering out that candidate
						pclntab_copy := make([]byte, len(pclntab))
						copy(pclntab_copy, pclntab)
						copy(pclntab_copy, magicBE)

						var candidate PclntabCandidate
						candidate.StompMagicCandidateMeta = stompedMagicCandidate
						candidate.Pclntab = pclntab_copy
						candidate.SecStart = imageBase + uint64(sec.VirtualAddress)
						candidate.PclntabVA = pclntab_va_candidate

						send_tab(&candidate)
					}
				}
			}
		}
	}

	go func() {
		defer close(ch_tab)

		// 2) if not found, byte scan for it
		for _, sec := range f.pe.Sections {
			// malware can split the pclntab across multiple sections, re-merge
			data := f.pe.DataAfterSection(sec)

			if !foundpcln {
				matches := findAllOccurrences(data, pclntab_sigs)
				for _, pclntab_idx := range matches {
					if pclntab_idx != -1 {
						pclntab = data[pclntab_idx:]

						var candidate PclntabCandidate
						candidate.Pclntab = pclntab

						candidate.SecStart = imageBase + uint64(sec.VirtualAddress)
						candidate.PclntabVA = candidate.SecStart + uint64(pclntab_idx)

						send_patched_magic_candidates(&candidate)
						send_tab(&candidate)
						// we must scan all signature for all sections. DO NOT BREAK
					}
				}
			} else {
				// 3) if we found it earlier, figure out which section base to return (might be wrong for packed things)
				pclntab_idx := bytes.Index(data, pclntab)
				if pclntab_idx != -1 {
					var candidate PclntabCandidate
					candidate.Pclntab = pclntab

					candidate.SecStart = imageBase + uint64(sec.VirtualAddress)
					candidate.PclntabVA = candidate.SecStart + uint64(pclntab_idx)

					send_patched_magic_candidates(&candidate)
					send_tab(&candidate)
				}
			}

			// TODO this scan needs to occur in both big and little endian mode
			// 4) Always try this other way! Sometimes the pclntab magic is stomped as well so our byte OR symbol location fail. Byte scan for the moduledata, use that to find the pclntab instead, fix up magic with all combinations.
			// See the obfuscator 'garble' for an example of randomizing the pclntab magic
			sigResults := findModuleInitPCHeader(data, uint64(sec.VirtualAddress)+imageBase)
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
					send_stomped_magic_candidate(&stompedMagicCandidateBE)
					send_stomped_magic_candidate(&stompedMagicCandidateLE)
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
					send_stomped_magic_candidate(&stompedMagicCandidateBE)
					send_stomped_magic_candidate(&stompedMagicCandidateLE)
				}
			}
		}
	}()
	return ch_tab, nil
}

func (f *peFile) pcln() (candidates <-chan PclntabCandidate, err error) {
	candidates, err = f.pcln_scan()
	if err != nil {
		return nil, err
	}

	return candidates, nil
}

func (f *peFile) moduledata_scan(pclntabVA uint64, is64bit bool, littleendian bool, ignorelist []uint64) (candidate *ModuleDataCandidate, err error) {
	var imageBase uint64
	switch oh := f.pe.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
	default:
		return nil, fmt.Errorf("pe file format not recognized")
	}
	found := false

	var moduledata []uint8
	var secStart uint64
	var moduledata_idx = 0
scan:
	for _, sec := range f.pe.Sections {
		// malware can split the pclntab across multiple sections, re-merge
		data := f.pe.DataAfterSection(sec)
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

		moduledata_idx = bytes.Index(data, pclntabVA_bytes)
		if moduledata_idx != -1 && moduledata_idx < int(sec.Size) {
			moduledata = data[moduledata_idx:]
			secStart = imageBase + uint64(sec.VirtualAddress)

			// optionally consult ignore list, to skip past previous (bad) scan results
			if ignorelist != nil {
				for _, ignore := range ignorelist {
					if ignore == secStart+uint64(moduledata_idx) {
						continue scan
					}
				}
			}

			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("moduledata containing section could not be located")
	}

	return &ModuleDataCandidate{SecStart: secStart, ModuledataVA: secStart + uint64(moduledata_idx), Moduledata: moduledata}, nil
}

func (f *peFile) text() (textStart uint64, text []byte, err error) {
	var imageBase uint64
	switch oh := f.pe.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
	default:
		return 0, nil, fmt.Errorf("pe file format not recognized")
	}
	sect := f.pe.Section(".text")
	if sect == nil {
		return 0, nil, fmt.Errorf("text section not found")
	}
	textStart = imageBase + uint64(sect.VirtualAddress)
	text, err = sect.Data()
	return
}

func (f *peFile) rdata() (textStart uint64, text []byte, err error) {
	var imageBase uint64
	switch oh := f.pe.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
	default:
		return 0, nil, fmt.Errorf("pe file format not recognized")
	}
	sect := f.pe.Section(".rdata")
	if sect == nil {
		return 0, nil, fmt.Errorf("rdata section not found")
	}
	textStart = imageBase + uint64(sect.VirtualAddress)
	text, err = sect.Data()
	return
}

func findPESymbol(f *pe.File, name string) (*pe.Symbol, error) {
	for _, s := range f.Symbols {
		if s.Name != name {
			continue
		}
		if s.SectionNumber <= 0 {
			return nil, fmt.Errorf("symbol %s: invalid section number %d", name, s.SectionNumber)
		}
		if len(f.Sections) < int(s.SectionNumber) {
			return nil, fmt.Errorf("symbol %s: section number %d is larger than max %d", name, s.SectionNumber, len(f.Sections))
		}
		return s, nil
	}
	return nil, fmt.Errorf("no %s symbol found", name)
}

func loadPETable(f *pe.File, sname, ename string) ([]byte, error) {
	ssym, err := findPESymbol(f, sname)
	if err != nil {
		return nil, err
	}
	esym, err := findPESymbol(f, ename)
	if err != nil {
		return nil, err
	}
	if ssym.SectionNumber != esym.SectionNumber {
		return nil, fmt.Errorf("%s and %s symbols must be in the same section", sname, ename)
	}

	if uint32(ssym.SectionNumber) > uint32(len(f.Sections)) {
		return nil, fmt.Errorf("pclntab symbol section index out of range")
	}

	sect := f.Sections[ssym.SectionNumber-1]
	data, err := sect.Data()
	if err != nil {
		return nil, err
	}

	if ssym.Value > esym.Value || esym.Value > uint32(len(data)) {
		return nil, fmt.Errorf("pclntab symbols are malformed")
	}

	return data[ssym.Value:esym.Value], nil
}

func (f *peFile) goarch() string {
	switch f.pe.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		return "386"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "amd64"
	case pe.IMAGE_FILE_MACHINE_ARMNT:
		return "arm"
	default:
		return ""
	}
}

func (f *peFile) loadAddress() (uint64, error) {
	return 0, fmt.Errorf("unknown load address")
}

func (f *peFile) dwarf() (*dwarf.Data, error) {
	return f.pe.DWARF()
}
