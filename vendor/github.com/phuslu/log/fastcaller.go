//go:build go1.22

//nolint:unused
package log

import (
	"unsafe"
)

// The following types mirror the unexported runtime ones, see
// https://github.com/golang/go/blob/master/src/runtime/symtab.go
type funcInfo struct {
	*_func
	datap *moduledata
}

type srcFunc struct {
	datap     *moduledata
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

type moduledata struct {
	pcHeader    unsafe.Pointer
	funcnametab []byte
	cutab       []uint32
	filetab     []byte
	pctab       []byte
	pclntable   []byte

	// omitted
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

func pcFileLine(pc uintptr) (file string, line int) {
	f := findfunc(pc)
	if f._func == nil {
		return
	}

	entry := funcInfoEntry(f)

	if pc > entry {
		// We store the pc of the start of the instruction following
		// the instruction in question (the call or the inline mark).
		// This is done for historical reasons, and to make FuncForPC
		// work correctly for entries in the result of runtime.Callers.
		pc--
	}

	file, line32 := funcline1(f, pc, false)
	return file, int(line32)
}

func pcFileLineName(pc uintptr) (file string, line int, name string) {
	f := findfunc(pc)
	if f._func == nil {
		return
	}

	entry := funcInfoEntry(f)

	if pc > entry {
		// We store the pc of the start of the instruction following
		// the instruction in question (the call or the inline mark).
		// This is done for historical reasons, and to make FuncForPC
		// work correctly for entries in the result of runtime.Callers.
		pc--
	}

	file1, line32 := funcline1(f, pc, false)
	file, line = file1, int(line32)

	// It's important that interpret pc non-strictly as cgoTraceback may
	// have added bogus PCs with a valid funcInfo but invalid PCDATA.
	u, uf := newInlineUnwinder(f, pc)
	var sf srcFunc
	if uf.index < 0 {
		sf = srcFunc{f.datap, f._func.nameOff, f._func.startLine, f._func.funcID}
	} else {
		t := &u.inlTree[uf.index]
		sf = srcFunc{u.f.datap, t.nameOff, t.startLine, t.funcID}
	}
	name = srcFunc_name(sf)

	return
}
