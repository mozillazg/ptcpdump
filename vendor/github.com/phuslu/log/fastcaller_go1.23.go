//go:build go1.23

// MIT license, copy and modify from https://github.com/tlog-dev/loc

//nolint:unused
package log

import (
	"runtime"
	"strings"
	"unsafe"
)

// Fastrandn returns a pseudorandom uint32 in [0,n).
//
//go:noescape
//go:linkname Fastrandn runtime.cheaprandn
func Fastrandn(n uint32) uint32

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

	return (*runtime.Func)(unsafe.Pointer(f._func)).FileLine(pc)
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

	file, line = (*runtime.Func)(unsafe.Pointer(f._func)).FileLine(pc)
	str := &f.datap.funcnametab[f.nameOff]
	ss := stringStruct{str: unsafe.Pointer(str), len: findnull(str)}
	name = *(*string)(unsafe.Pointer(&ss))

	return
}

type stringStruct struct {
	str unsafe.Pointer
	len int
}

//go:nosplit
func findnull(s *byte) int {
	if s == nil {
		return 0
	}

	// pageSize is the unit we scan at a time looking for NULL.
	// It must be the minimum page size for any architecture Go
	// runs on. It's okay (just a minor performance loss) if the
	// actual system page size is larger than this value.
	const pageSize = 4096

	offset := 0
	ptr := unsafe.Pointer(s)
	// IndexByteString uses wide reads, so we need to be careful
	// with page boundaries. Call IndexByteString on
	// [ptr, endOfPage) interval.
	safeLen := int(pageSize - uintptr(ptr)%pageSize)

	for {
		t := *(*string)(unsafe.Pointer(&stringStruct{ptr, safeLen}))
		// Check one page at a time.
		if i := strings.IndexByte(t, 0); i != -1 {
			return offset + i
		}
		// Move to next page
		ptr = unsafe.Pointer(uintptr(ptr) + uintptr(safeLen))
		offset += safeLen
		safeLen = pageSize
	}
}

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

//go:linkname findfunc runtime.findfunc
func findfunc(pc uintptr) funcInfo

//go:linkname funcInfoEntry runtime.funcInfo.entry
func funcInfoEntry(f funcInfo) uintptr
