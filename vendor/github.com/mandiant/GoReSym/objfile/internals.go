/*Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.*/
package objfile

import (
	"bytes"
	"encoding/binary"
)

type size_t64 uint64
type size_t32 uint32
type pvoid64 uint64
type pvoid32 uint32

// All types following this are the binary representation of internal objects.
// These are 'flat', i.e. one pointer level deep. Access to pointers and such
// require a memory read to retrieve the backing data.
// https://github.com/golang/go/blob/23adc139bf1c0c099dd075da076f5a1f3ac700d4/src/reflect/value.go#L2599
type GoSlice64 struct {
	Data     pvoid64
	Len      uint64
	Capacity uint64
}

func (slice *GoSlice64) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, slice)
}

type GoSlice32 struct {
	Data     pvoid32
	Len      size_t32
	Capacity size_t32
}

func (slice *GoSlice32) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, slice)
}

// https://github.com/golang/go/blob/23adc139bf1c0c099dd075da076f5a1f3ac700d4/src/reflect/value.go#L2588
type GoString64 struct {
	Data pvoid64
	Len  size_t64
}

type GoString32 struct {
	Data pvoid32
	Len  size_t32
}

// https://github.com/golang/go/blob/dbd3cf884986c88f5b3350709c0f51fa02330805/src/runtime/stack.go#L583
type GoBitVector64 struct {
	Bitnum   int32
	Bytedata pvoid64
}

type GoBitVector32 struct {
	Bitnum   int32
	Bytedata pvoid32
}

// a function table entry in 'ftab'
type FuncTab12_116_64 struct {
	Entryoffset pvoid64 // relative to runtime.text, ie. VA
	Funcoffset  pvoid64 // relative to ftab table start
}

func (functab *FuncTab12_116_64) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, functab)
}

type FuncTab12_116_32 struct {
	Entryoffset pvoid32 // relative to runtime.text, ie. VA
	Funcoffset  pvoid32 // relative to ftab table start
}

func (functab *FuncTab12_116_32) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, functab)
}

type FuncTab118 struct {
	Entryoffset uint32 // relative to runtime.text, ie. VA
	Funcoffset  uint32 // relative to ftab table start
}

func (functab *FuncTab118) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, functab)
}

// 1.2, runtime 1.5-1.6, 64bit
type ModuleData12_r15_r16_64 struct {
	Pclntable   GoSlice64
	Ftab        GoSlice64
	Filetab     GoSlice64
	Findfunctab pvoid64
	Minpc       pvoid64
	Maxpc       pvoid64

	Text       pvoid64
	Etext      pvoid64
	Noptrdata  pvoid64
	Enoptrdata pvoid64
	Data       pvoid64
	Edata      pvoid64
	Bss        pvoid64
	Ebss       pvoid64
	Noptrbss   pvoid64
	Enoptrbss  pvoid64
	End        pvoid64
	Gcdata     pvoid64
	Gcbss      pvoid64

	Typelinks GoSlice64

	Modulename   GoString64
	Modulehashes GoSlice64
	Gcdatamask   GoBitVector64
	Gcbssmask    GoBitVector64

	Next pvoid64
}

func (moduledata *ModuleData12_r15_r16_64) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, moduledata)
}

type ModuleData12_r15_r16_32 struct {
	Pclntable   GoSlice32
	Ftab        GoSlice32
	Filetab     GoSlice32
	Findfunctab pvoid32
	Minpc       pvoid32
	Maxpc       pvoid32

	Text       pvoid32
	Etext      pvoid32
	Noptrdata  pvoid32
	Enoptrdata pvoid32
	Data       pvoid32
	Edata      pvoid32
	Bss        pvoid32
	Ebss       pvoid32
	Noptrbss   pvoid32
	Enoptrbss  pvoid32
	End        pvoid32
	Gcdata     pvoid32
	Gcbss      pvoid32

	Typelinks GoSlice32

	Modulename   GoString32
	Modulehashes GoSlice32
	Gcdatamask   GoBitVector32
	Gcbssmask    GoBitVector32

	Next pvoid32
}

func (moduledata *ModuleData12_r15_r16_32) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, moduledata)
}

type ModuleData12_r17_64 struct {
	Pclntable   GoSlice64
	Ftab        GoSlice64
	Filetab     GoSlice64
	Findfunctab pvoid64
	Minpc       pvoid64
	Maxpc       pvoid64

	Text       pvoid64
	Etext      pvoid64
	Noptrdata  pvoid64
	Enoptrdata pvoid64
	Data       pvoid64
	Edata      pvoid64
	Bss        pvoid64
	Ebss       pvoid64
	Noptrbss   pvoid64
	Enoptrbss  pvoid64
	End        pvoid64
	Gcdata     pvoid64
	Gcbss      pvoid64
	Types      pvoid64
	Etypes     pvoid64

	Typelinks GoSlice64
	Itablinks GoSlice64

	Modulename   GoString64
	Modulehashes GoSlice64

	Gcdatamask GoBitVector64
	Gcbssmask  GoBitVector64

	Typemap pvoid64
	Next    pvoid64
}

func (moduledata *ModuleData12_r17_64) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, moduledata)
}

type ModuleData12_r17_32 struct {
	Pclntable   GoSlice32
	Ftab        GoSlice32
	Filetab     GoSlice32
	Findfunctab pvoid32
	Minpc       pvoid32
	Maxpc       pvoid32

	Text       pvoid32
	Etext      pvoid32
	Noptrdata  pvoid32
	Enoptrdata pvoid32
	Data       pvoid32
	Edata      pvoid32
	Bss        pvoid32
	Ebss       pvoid32
	Noptrbss   pvoid32
	Enoptrbss  pvoid32
	End        pvoid32
	Gcdata     pvoid32
	Gcbss      pvoid32
	Types      pvoid32
	Etypes     pvoid32

	Typelinks GoSlice32
	Itablinks GoSlice32

	Modulename   GoString32
	Modulehashes GoSlice32

	Gcdatamask GoBitVector32
	Gcbssmask  GoBitVector32

	Typemap pvoid32
	Next    pvoid32
}

func (moduledata *ModuleData12_r17_32) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, moduledata)
}

type ModuleData12_64 struct {
	Pclntable    GoSlice64
	Ftab         GoSlice64
	FileTab      GoSlice64
	Findfunctab  pvoid64
	Minpc        pvoid64
	Maxpc        pvoid64
	Text         pvoid64
	Etext        pvoid64
	Noptrdata    pvoid64
	Enoptrdata   pvoid64
	Data         pvoid64
	Edata        pvoid64
	Bss          pvoid64
	Ebss         pvoid64
	Noptrbss     pvoid64
	Enoptrbss    pvoid64
	End          pvoid64
	Gcdata       pvoid64
	Gcbss        pvoid64
	Types        pvoid64
	Etypes       pvoid64
	Textsectmap  GoSlice64
	Typelinks    GoSlice64
	Itablinks    GoSlice64
	Ptab         GoSlice64
	Pluginpath   GoString64
	Pkghashes    GoSlice64
	Modulename   GoString64
	Modulehashes GoSlice64
	Hasmain      bool
	Gcdatamask   GoBitVector64
	Gcbssmask    GoBitVector64
	Typemap      pvoid64
	Badload      bool
	Next         pvoid64
}

func (moduledata *ModuleData12_64) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, moduledata)
}

type ModuleData12_32 struct {
	Pclntable    GoSlice32
	Ftab         GoSlice32
	FileTab      GoSlice32
	Findfunctab  pvoid32
	Minpc        pvoid32
	Maxpc        pvoid32
	Text         pvoid32
	Etext        pvoid32
	Noptrdata    pvoid32
	Enoptrdata   pvoid32
	Data         pvoid32
	Edata        pvoid32
	Bss          pvoid32
	Ebss         pvoid32
	Noptrbss     pvoid32
	Enoptrbss    pvoid32
	End          pvoid32
	Gcdata       pvoid32
	Gcbss        pvoid32
	Types        pvoid32
	Etypes       pvoid32
	Textsectmap  GoSlice32
	Typelinks    GoSlice32
	Itablinks    GoSlice32
	Ptab         GoSlice32
	Pluginpath   GoString32
	Pkghashes    GoSlice32
	Modulename   GoString32
	Modulehashes GoSlice32
	Hasmain      bool
	Gcdatamask   GoBitVector32
	Gcbssmask    GoBitVector32
	Typemap      pvoid32
	Badload      bool
	Next         pvoid32
}

func (moduledata *ModuleData12_32) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, moduledata)
}

type ModuleData116_64 struct {
	PcHeader     pvoid64
	Funcnametab  GoSlice64
	Cutab        GoSlice64
	Filetab      GoSlice64
	Pctab        GoSlice64
	Pclntable    GoSlice64
	Ftab         GoSlice64
	Findfunctab  pvoid64
	Minpc        pvoid64
	Maxpc        pvoid64
	Text         pvoid64
	Etext        pvoid64
	Noptrdata    pvoid64
	Enoptrdata   pvoid64
	Data         pvoid64
	Edata        pvoid64
	Bss          pvoid64
	Ebss         pvoid64
	Noptrbss     pvoid64
	Enoptrbss    pvoid64
	End          pvoid64
	Gcdata       pvoid64
	Gcbss        pvoid64
	Types        pvoid64
	Etypes       pvoid64
	Textsectmap  GoSlice64
	Typelinks    GoSlice64
	Itablinks    GoSlice64
	Ptab         GoSlice64
	Pluginpath   GoString64
	Pkghashes    GoSlice64
	Modulename   GoString64
	Modulehashes GoSlice64
	Hasmain      bool
	Gcdatamask   GoBitVector64
	Gcbssmask    GoBitVector64
	Typemap      pvoid64
	Badload      bool
	Next         pvoid64
}

func (moduledata *ModuleData116_64) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, moduledata)
}

type ModuleData116_32 struct {
	PcHeader     pvoid32
	Funcnametab  GoSlice32
	Cutab        GoSlice32
	Filetab      GoSlice32
	Pctab        GoSlice32
	Pclntable    GoSlice32
	Ftab         GoSlice32
	Findfunctab  pvoid32
	Minpc        pvoid32
	Maxpc        pvoid32
	Text         pvoid32
	Etext        pvoid32
	Noptrdata    pvoid32
	Enoptrdata   pvoid32
	Data         pvoid32
	Edata        pvoid32
	Bss          pvoid32
	Ebss         pvoid32
	Noptrbss     pvoid32
	Enoptrbss    pvoid32
	End          pvoid32
	Gcdata       pvoid32
	Gcbss        pvoid32
	Types        pvoid32
	Etypes       pvoid32
	Textsectmap  GoSlice32
	Typelinks    GoSlice32
	Itablinks    GoSlice32
	Ptab         GoSlice32
	Pluginpath   GoString32
	Pkghashes    GoSlice32
	Modulename   GoString32
	Modulehashes GoSlice32
	Hasmain      bool
	Gcdatamask   GoBitVector32
	Gcbssmask    GoBitVector32
	Typemap      pvoid32
	Badload      bool
	Next         pvoid32
}

func (moduledata *ModuleData116_32) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, moduledata)
}

type ModuleData118_64 struct {
	PcHeader     pvoid64
	Funcnametab  GoSlice64
	Cutab        GoSlice64
	Filetab      GoSlice64
	Pctab        GoSlice64
	Pclntable    GoSlice64
	Ftab         GoSlice64
	Findfunctab  pvoid64
	Minpc        pvoid64
	Maxpc        pvoid64
	Text         pvoid64
	Etext        pvoid64
	Noptrdata    pvoid64
	Enoptrdata   pvoid64
	Data         pvoid64
	Edata        pvoid64
	Bss          pvoid64
	Ebss         pvoid64
	Noptrbss     pvoid64
	Enoptrbss    pvoid64
	End          pvoid64
	Gcdata       pvoid64
	Gcbss        pvoid64
	Types        pvoid64
	Etypes       pvoid64
	Rodata       pvoid64
	Gofunc       pvoid64
	Textsectmap  GoSlice64
	Typelinks    GoSlice64
	Itablinks    GoSlice64
	Ptab         GoSlice64
	Pluginpath   GoString64
	Pkghashes    GoSlice64
	Modulename   GoString64
	Modulehashes GoSlice64
	Hasmain      bool
	Gcdatamask   GoBitVector64
	Gcbssmask    GoBitVector64
	Typemap      pvoid64
	Badload      bool
	Next         pvoid64
}

func (moduledata *ModuleData118_64) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, moduledata)
}

type ModuleData118_32 struct {
	PcHeader     pvoid32
	Funcnametab  GoSlice32
	Cutab        GoSlice32
	Filetab      GoSlice32
	Pctab        GoSlice32
	Pclntable    GoSlice32
	Ftab         GoSlice32
	Findfunctab  pvoid32
	Minpc        pvoid32
	Maxpc        pvoid32
	Text         pvoid32
	Etext        pvoid32
	Noptrdata    pvoid32
	Enoptrdata   pvoid32
	Data         pvoid32
	Edata        pvoid32
	Bss          pvoid32
	Ebss         pvoid32
	Noptrbss     pvoid32
	Enoptrbss    pvoid32
	End          pvoid32
	Gcdata       pvoid32
	Gcbss        pvoid32
	Types        pvoid32
	Etypes       pvoid32
	Rodata       pvoid32
	Gofunc       pvoid32
	Textsectmap  GoSlice32
	Typelinks    GoSlice32
	Itablinks    GoSlice32
	Ptab         GoSlice32
	Pluginpath   GoString32
	Pkghashes    GoSlice32
	Modulename   GoString32
	Modulehashes GoSlice32
	Hasmain      bool
	Gcdatamask   GoBitVector32
	Gcbssmask    GoBitVector32
	Typemap      pvoid32
	Badload      bool
	Next         pvoid32
}

func (moduledata *ModuleData118_32) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, moduledata)
}

type ModuleData120_64 struct {
	PcHeader     pvoid64
	Funcnametab  GoSlice64
	Cutab        GoSlice64
	Filetab      GoSlice64
	Pctab        GoSlice64
	Pclntable    GoSlice64
	Ftab         GoSlice64
	Findfunctab  pvoid64
	Minpc        pvoid64
	Maxpc        pvoid64
	Text         pvoid64
	Etext        pvoid64
	Noptrdata    pvoid64
	Enoptrdata   pvoid64
	Data         pvoid64
	Edata        pvoid64
	Bss          pvoid64
	Ebss         pvoid64
	Noptrbss     pvoid64
	Enoptrbss    pvoid64
	Covctrs      pvoid64
	Ecovctrs     pvoid64
	End          pvoid64
	Gcdata       pvoid64
	Gcbss        pvoid64
	Types        pvoid64
	Etypes       pvoid64
	Rodata       pvoid64
	Gofunc       pvoid64
	Textsectmap  GoSlice64
	Typelinks    GoSlice64
	Itablinks    GoSlice64
	Ptab         GoSlice64
	Pluginpath   GoString64
	Pkghashes    GoSlice64
	Modulename   GoString64
	Modulehashes GoSlice64
	Hasmain      bool
	Gcdatamask   GoBitVector64
	Gcbssmask    GoBitVector64
	Typemap      pvoid64
	Badload      bool
	Next         pvoid64
}

func (moduledata *ModuleData120_64) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, moduledata)
}

type ModuleData120_32 struct {
	PcHeader     pvoid32
	Funcnametab  GoSlice32
	Cutab        GoSlice32
	Filetab      GoSlice32
	Pctab        GoSlice32
	Pclntable    GoSlice32
	Ftab         GoSlice32
	Findfunctab  pvoid32
	Minpc        pvoid32
	Maxpc        pvoid32
	Text         pvoid32
	Etext        pvoid32
	Noptrdata    pvoid32
	Enoptrdata   pvoid32
	Data         pvoid32
	Edata        pvoid32
	Bss          pvoid32
	Ebss         pvoid32
	Noptrbss     pvoid32
	Enoptrbss    pvoid32
	Covctrs      pvoid32
	Ecovctrs     pvoid32
	End          pvoid32
	Gcdata       pvoid32
	Gcbss        pvoid32
	Types        pvoid32
	Etypes       pvoid32
	Rodata       pvoid32
	Gofunc       pvoid32
	Textsectmap  GoSlice32
	Typelinks    GoSlice32
	Itablinks    GoSlice32
	Ptab         GoSlice32
	Pluginpath   GoString32
	Pkghashes    GoSlice32
	Modulename   GoString32
	Modulehashes GoSlice32
	Hasmain      bool
	Gcdatamask   GoBitVector32
	Gcbssmask    GoBitVector32
	Typemap      pvoid32
	Badload      bool
	Next         pvoid32
}

func (moduledata *ModuleData120_32) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, moduledata)
}

type ModuleData121_64 struct {
	PcHeader     pvoid64
	Funcnametab  GoSlice64
	Cutab        GoSlice64
	Filetab      GoSlice64
	Pctab        GoSlice64
	Pclntable    GoSlice64
	Ftab         GoSlice64
	Findfunctab  pvoid64
	Minpc        pvoid64
	Maxpc        pvoid64
	Text         pvoid64
	Etext        pvoid64
	Noptrdata    pvoid64
	Enoptrdata   pvoid64
	Data         pvoid64
	Edata        pvoid64
	Bss          pvoid64
	Ebss         pvoid64
	Noptrbss     pvoid64
	Enoptrbss    pvoid64
	Covctrs      pvoid64
	Ecovctrs     pvoid64
	End          pvoid64
	Gcdata       pvoid64
	Gcbss        pvoid64
	Types        pvoid64
	Etypes       pvoid64
	Rodata       pvoid64
	Gofunc       pvoid64
	Textsectmap  GoSlice64
	Typelinks    GoSlice64
	Itablinks    GoSlice64
	Ptab         GoSlice64
	Pluginpath   GoString64
	Pkghashes    GoSlice64
	InitTasks    GoSlice64
	Modulename   GoString64
	Modulehashes GoSlice64
	Hasmain      bool
	Gcdatamask   GoBitVector64
	Gcbssmask    GoBitVector64
	Typemap      pvoid64
	Badload      bool
	Next         pvoid64
}

func (moduledata *ModuleData121_64) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, moduledata)
}

type ModuleData121_32 struct {
	PcHeader     pvoid32
	Funcnametab  GoSlice32
	Cutab        GoSlice32
	Filetab      GoSlice32
	Pctab        GoSlice32
	Pclntable    GoSlice32
	Ftab         GoSlice32
	Findfunctab  pvoid32
	Minpc        pvoid32
	Maxpc        pvoid32
	Text         pvoid32
	Etext        pvoid32
	Noptrdata    pvoid32
	Enoptrdata   pvoid32
	Data         pvoid32
	Edata        pvoid32
	Bss          pvoid32
	Ebss         pvoid32
	Noptrbss     pvoid32
	Enoptrbss    pvoid32
	Covctrs      pvoid32
	Ecovctrs     pvoid32
	End          pvoid32
	Gcdata       pvoid32
	Gcbss        pvoid32
	Types        pvoid32
	Etypes       pvoid32
	Rodata       pvoid32
	Gofunc       pvoid32
	Textsectmap  GoSlice32
	Typelinks    GoSlice32
	Itablinks    GoSlice32
	Ptab         GoSlice32
	Pluginpath   GoString32
	Pkghashes    GoSlice32
	InitTasks    GoSlice32
	Modulename   GoString32
	Modulehashes GoSlice32
	Hasmain      bool
	Gcdatamask   GoBitVector32
	Gcbssmask    GoBitVector32
	Typemap      pvoid32
	Badload      bool
	Next         pvoid32
}

func (moduledata *ModuleData121_32) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, moduledata)
}

type Textsect_64 struct {
	Vaddr    pvoid64 // prelinked section vaddr
	End      pvoid64 // vaddr + section length
	Baseaddr pvoid64 // relocated section address
}

func (textsect *Textsect_64) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, textsect)
}

type Textsect_32 struct {
	Vaddr    pvoid32 // prelinked section vaddr
	End      pvoid32 // vaddr + section length
	Baseaddr pvoid32 // relocated section address
}

func (textsect *Textsect_32) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, textsect)
}

type IMethod struct {
	Name nameOff
	Typ  typeOff
}

func (imethod *IMethod) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, imethod)
}

type Kind uint8 // mask & 0x1f

const (
	Invalid Kind = iota
	Bool
	Int
	Int8
	Int16
	Int32
	Int64
	Uint
	Uint8
	Uint16
	Uint32
	Uint64
	Uintptr
	Float32
	Float64
	Complex64
	Complex128
	Array
	Chan
	Func
	Interface
	Map
	Pointer
	Slice
	String
	Struct
	UnsafePointer
)

func (k Kind) String() string {
	switch k {
	case Bool:
		return "Bool"
	case Int:
		return "Int"
	case Int8:
		return "Int8"
	case Int16:
		return "Int16"
	case Int32:
		return "Int32"
	case Int64:
		return "Int64"
	case Uint:
		return "Uint"
	case Uint8:
		return "Uint8"
	case Uint16:
		return "Uint16"
	case Uint32:
		return "Uint32"
	case Uint64:
		return "Uint64"
	case Uintptr:
		return "Uintptr"
	case Float32:
		return "Float32"
	case Complex64:
		return "Complex64"
	case Complex128:
		return "Complex128"
	case Array:
		return "Array"
	case Chan:
		return "Chan"
	case Func:
		return "Func"
	case Interface:
		return "Interface"
	case Map:
		return "Map"
	case Pointer:
		return "Pointer"
	case Slice:
		return "Slice"
	case String:
		return "String"
	case Struct:
		return "Struct"
	case UnsafePointer:
		return "UnsafePointer"
	}
	return "Invalid"
}

type ChanDir uint

const (
	RecvOnly ChanDir               = 1 << iota // <-chan
	SendOnly                                   // chan<-
	SendRecv = RecvOnly | SendOnly             // chan
)

func (d ChanDir) String() string {
	switch d {
	case SendRecv:
		return "Both"
	case SendOnly:
		return "Send"
	case RecvOnly:
		return "Recv"
	}
	return "Invalid"
}

type tflag uint8
type nameOff int32
type typeOff int32

type Rtype15_64 struct {
	Size         size_t64
	Ptrdata      size_t64 // number of bytes in the type that can contain pointers
	Hash         uint32   // hash of type; avoids computation in hash tables
	Unused       uint8    // extra type information flags
	Align        uint8    // alignment of variable with this type
	FieldAlign   uint8    // alignment of struct field with this type
	Kind         Kind     // enumeration for C
	Alg          pvoid64  // algorithm table
	Gcdata       pvoid64  // garbage collection data
	Str          pvoid64  // string form
	UncommonType pvoid64
	PtrToThis    pvoid64 // type for pointer to this type, may be zero
	Zero         pvoid64
}

func (rtype *Rtype15_64) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, rtype)
}

type Rtype15_32 struct {
	Size         size_t32
	Ptrdata      size_t32 // number of bytes in the type that can contain pointers
	Hash         uint32   // hash of type; avoids computation in hash tables
	Unused       uint8    // extra type information flags
	Align        uint8    // alignment of variable with this type
	FieldAlign   uint8    // alignment of struct field with this type
	Kind         Kind     // enumeration for C
	Alg          pvoid32  // algorithm table
	Gcdata       pvoid32  // garbage collection data
	Str          pvoid32  // string form
	UncommonType pvoid32
	PtrToThis    pvoid32 // type for pointer to this type, may be zero
	Zero         pvoid32
}

func (rtype *Rtype15_32) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, rtype)
}

type Rtype16_64 struct {
	Size         size_t64
	Ptrdata      size_t64 // number of bytes in the type that can contain pointers
	Hash         uint32   // hash of type; avoids computation in hash tables
	Unused       uint8    // extra type information flags
	Align        uint8    // alignment of variable with this type
	FieldAlign   uint8    // alignment of struct field with this type
	Kind         Kind     // enumeration for C
	Alg          pvoid64  // algorithm table
	Gcdata       pvoid64  // garbage collection data
	Str          pvoid64  // string form
	UncommonType pvoid64
	PtrToThis    pvoid64 // type for pointer to this type, may be zero
}

func (rtype *Rtype16_64) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, rtype)
}

type Rtype16_32 struct {
	Size         size_t32
	Ptrdata      size_t32 // number of bytes in the type that can contain pointers
	Hash         uint32   // hash of type; avoids computation in hash tables
	Unused       uint8    // extra type information flags
	Align        uint8    // alignment of variable with this type
	FieldAlign   uint8    // alignment of struct field with this type
	Kind         Kind     // enumeration for C
	Alg          pvoid32  // algorithm table
	Gcdata       pvoid32  // garbage collection data
	Str          pvoid32  // string form
	UncommonType pvoid32
	PtrToThis    pvoid32 // type for pointer to this type, may be zero
}

func (rtype *Rtype16_32) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, rtype)
}

type Rtype17_18_19_110_111_112_113_64 struct {
	Size       size_t64
	Ptrdata    size_t64 // number of bytes in the type that can contain pointers
	Hash       uint32   // hash of type; avoids computation in hash tables
	Tflag      tflag    // extra type information flags
	Align      uint8    // alignment of variable with this type
	FieldAlign uint8    // alignment of struct field with this type
	Kind       Kind     // enumeration for C
	Alg        pvoid64  // algorithm table
	Gcdata     pvoid64  // garbage collection data
	Str        nameOff  // string form
	PtrToThis  typeOff  // type for pointer to this type, may be zero
}

func (rtype *Rtype17_18_19_110_111_112_113_64) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, rtype)
}

type Rtype17_18_19_110_111_112_113_32 struct {
	Size       size_t32
	Ptrdata    size_t32 // number of bytes in the type that can contain pointers
	Hash       uint32   // hash of type; avoids computation in hash tables
	Tflag      tflag    // extra type information flags
	Align      uint8    // alignment of variable with this type
	FieldAlign uint8    // alignment of struct field with this type
	Kind       Kind     // enumeration for C
	Alg        pvoid32  // algorithm table
	Gcdata     pvoid32  // garbage collection data
	Str        nameOff  // string form
	PtrToThis  typeOff  // type for pointer to this type, may be zero
}

func (rtype *Rtype17_18_19_110_111_112_113_32) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, rtype)
}

type Rtype114_115_116_117_118_64 struct {
	Size       size_t64
	Ptrdata    size_t64 // number of bytes in the type that can contain pointers
	Hash       uint32   // hash of type; avoids computation in hash tables
	Tflag      tflag    // extra type information flags
	Align      uint8    // alignment of variable with this type
	FieldAlign uint8    // alignment of struct field with this type
	Kind       Kind
	Equal      pvoid64
	Gcdata     pvoid64 // garbage collection data
	Str        nameOff // string form
	PtrToThis  typeOff // type for pointer to this type, may be zero
}

func (rtype *Rtype114_115_116_117_118_64) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, rtype)
}

type Rtype114_115_116_117_118_32 struct {
	Size       size_t32
	Ptrdata    size_t32 // number of bytes in the type that can contain pointers
	Hash       uint32   // hash of type; avoids computation in hash tables
	Tflag      tflag    // extra type information flags
	Align      uint8    // alignment of variable with this type
	FieldAlign uint8    // alignment of struct field with this type
	Kind       Kind
	Equal      pvoid32
	Gcdata     pvoid32 // garbage collection data
	Str        nameOff // string form
	PtrToThis  typeOff // type for pointer to this type, may be zero
}

func (rtype *Rtype114_115_116_117_118_32) parse(rawData []byte, littleEndian bool) error {
	srcBytes := bytes.NewBuffer(rawData)

	var byteOrder binary.ByteOrder
	if littleEndian {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	return binary.Read(srcBytes, byteOrder, rtype)
}

// This is a general structure that just holds the fields I care about
// this lets us return a single type, even though rtypes change between go version
type Type struct {
	VA             uint64
	Str            string
	CStr           string
	Kind           string
	Reconstructed  string `json:",omitempty"` // for Some types we can reconstruct the original definition back to Go code
	CReconstructed string `json:",omitempty"` // for Some types we can reconstruct the original definition back to C code

	// rtypes change between runtime versions. Depending on the 'Kind' additional data follows the 'base' rtype.
	// We store the size so that this base type can be skipped past, and the additional data read directly in a version independant way.
	baseSize uint16
	kindEnum Kind
	flags    tflag
}

// This is a general structure that just holds the fields I care about
// this lets us return a single type, even though moduledata changes between go version
type ModuleData struct {
	VA        uint64
	TextVA    uint64    // adjusted (ex: CGO) .text base that pclntab offsets are relative to
	Types     uint64    // points to type information
	ETypes    uint64    // points to end of type information
	Typelinks GoSlice64 // points to metadata about offsets into types for structures and other types
	ITablinks GoSlice64 // points to metadata about offsets into types for interfaces

	// Some versions of go with 1.2 moduledata use a slice instead of the types + offset typelinks list
	LegacyTypes GoSlice64
}

const (
	// tflagUncommon means that there is a pointer, *uncommonType,
	// just beyond the outer type structure.
	//
	// For example, if t.Kind() == Struct and t.tflag&tflagUncommon != 0,
	// then t has uncommonType data and it can be accessed as:
	//
	//	type tUncommon struct {
	//		structType
	//		u uncommonType
	//	}
	//	u := &(*tUncommon)(unsafe.Pointer(t)).u
	tflagUncommon tflag = 1 << 0

	// tflagExtraStar means the name in the str field has an
	// extraneous '*' prefix. This is because for most types T in
	// a program, the type *T also exists and reusing the str data
	// saves binary size.
	tflagExtraStar tflag = 1 << 1

	// tflagNamed means the type has a name.
	tflagNamed tflag = 1 << 2

	// tflagRegularMemory means that equal and hash functions can treat
	// this type as a single region of t.size bytes.
	tflagRegularMemory tflag = 1 << 3
)

// https://github.com/golang/go/blob/9ecb853cf2252f3cd9ed2e7b3401d17df2d1ab06/src/runtime/symtab.go#L662
func textAddr64(off32 uint64, text uint64, textsectmap []Textsect_64) uint64 {
	off := uint64(off32)
	res := uint64(text) + off
	if len(textsectmap) > 1 {
		for i, sect := range textsectmap {
			// For the last section, include the end address (etext), as it is included in the functab.
			if off >= uint64(sect.Vaddr) && off < uint64(sect.End) || (i == len(textsectmap)-1 && off == uint64(sect.End)) {
				res = uint64(sect.Baseaddr) + off - uint64(sect.Vaddr)
				break
			}
		}
	}
	return uint64(res)
}

func textAddr32(off32 uint64, text uint64, textsectmap []Textsect_32) uint64 {
	off := uint64(off32)
	res := uint64(text) + off
	if len(textsectmap) > 1 {
		for i, sect := range textsectmap {
			// For the last section, include the end address (etext), as it is included in the functab.
			if off >= uint64(sect.Vaddr) && off < uint64(sect.End) || (i == len(textsectmap)-1 && off == uint64(sect.End)) {
				res = uint64(sect.Baseaddr) + off - uint64(sect.Vaddr)
				break
			}
		}
	}
	return uint64(res)
}
