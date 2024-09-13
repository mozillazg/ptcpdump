//go:build go1.22 && !go1.23

// MIT license, copy and modify from https://github.com/tlog-dev/loc

//nolint:unused
package log

import (
	"unsafe"
)

// Fastrandn returns a pseudorandom uint32 in [0,n).
//
//go:noescape
//go:linkname Fastrandn runtime.cheaprandn
func Fastrandn(n uint32) uint32

func pcFileLine(pc uintptr) (file string, line int32) {
	funcInfo := findfunc(pc)
	if funcInfo._func == nil {
		return
	}

	entry := funcInfoEntry(funcInfo)

	if pc > entry {
		// We store the pc of the start of the instruction following
		// the instruction in question (the call or the inline mark).
		// This is done for historical reasons, and to make FuncForPC
		// work correctly for entries in the result of runtime.Callers.
		pc--
	}

	return funcline1(funcInfo, pc, false)
}

func pcFileLineName(pc uintptr) (file string, line int32, name string) {
	funcInfo := findfunc(pc)
	if funcInfo._func == nil {
		return
	}

	entry := funcInfoEntry(funcInfo)

	if pc > entry {
		// We store the pc of the start of the instruction following
		// the instruction in question (the call or the inline mark).
		// This is done for historical reasons, and to make FuncForPC
		// work correctly for entries in the result of runtime.Callers.
		pc--
	}

	file, line = funcline1(funcInfo, pc, false)

	// It's important that interpret pc non-strictly as cgoTraceback may
	// have added bogus PCs with a valid funcInfo but invalid PCDATA.
	u, uf := newInlineUnwinder(funcInfo, pc)
	var sf srcFunc
	if uf.index < 0 {
		f := (*_func)(funcInfo._func)
		sf = srcFunc{funcInfo.datap, f.nameOff, f.startLine, f.funcID}
	} else {
		t := &u.inlTree[uf.index]
		sf = srcFunc{u.f.datap, t.nameOff, t.startLine, t.funcID}
	}
	name = srcFunc_name(sf)

	return
}

type funcInfo struct {
	_func unsafe.Pointer
	datap unsafe.Pointer //nolint:unused
}

// inlinedCall is the encoding of entries in the FUNCDATA_InlTree table.
type inlinedCall struct {
	funcID    uint8 // type of the called function
	_         [3]byte
	nameOff   int32 // offset into pclntab for name of called function
	parentPc  int32 // position of an instruction whose source position is the call site (offset from entry)
	startLine int32 // line number of start of function (func keyword/TEXT directive)
}

type inlineUnwinder struct {
	f       funcInfo
	inlTree *[1 << 20]inlinedCall
}

type inlineFrame struct {
	pc    uintptr
	index int32
}

type srcFunc struct {
	datap     unsafe.Pointer
	nameOff   int32
	startLine int32
	funcID    uint8
}

type _func struct {
	entryOff uint32 // start pc, as offset from moduledata.text/pcHeader.textStart
	nameOff  int32  // function name, as index into moduledata.funcnametab.

	args        int32  // in/out args size
	deferreturn uint32 // offset of start of a deferreturn call instruction from entry, if any.

	pcsp      uint32
	pcfile    uint32
	pcln      uint32
	npcdata   uint32
	cuOffset  uint32 // runtime.cutab offset of this function's CU
	startLine int32  // line number of start of function (func keyword/TEXT directive)
	funcID    uint8  // set for certain special runtime functions
	flag      uint8
	_         [1]byte // pad
	nfuncdata uint8   // must be last, must end on a uint32-aligned boundary
}

//go:linkname findfunc runtime.findfunc
func findfunc(pc uintptr) funcInfo

//go:linkname funcInfoEntry runtime.funcInfo.entry
func funcInfoEntry(f funcInfo) uintptr

//go:linkname funcline1 runtime.funcline1
func funcline1(f funcInfo, targetpc uintptr, strict bool) (file string, line int32)

//go:linkname newInlineUnwinder runtime.newInlineUnwinder
func newInlineUnwinder(f funcInfo, pc uintptr) (inlineUnwinder, inlineFrame)

//go:linkname srcFunc_name runtime.srcFunc.name
func srcFunc_name(srcFunc) string
