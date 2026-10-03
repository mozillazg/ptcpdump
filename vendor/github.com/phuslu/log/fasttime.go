//go:build linux && (amd64 || arm64) && go1.25 && !go1.28

package log

import (
	"time"
	"unsafe"
)

// The g/m offsets vdsoCallG0 hardcodes come from the runtime of Go 1.25 through
// 1.27: m.curg and m.gsignal moved from 192/80 to 184/72 in Go 1.25. Every
// other toolchain, and every Go release outside that window, takes the
// fasttime_zzz.go fallback instead, because a wrong offset can sit in an
// integer field, and dereferencing it to check it would fault during package
// init instead of disabling the fast path. Raise the upper bound only after
// checking the offsets against the new release.

// timespec mirrors struct timespec on linux/amd64 and linux/arm64.
type timespec struct {
	sec  int64
	nsec int64
}

// vdsoClockgettimeSym is the kernel's __vdso_clock_gettime entry point. The
// runtime keeps it pullable via linkname on purpose (see badlinkname_linux.go).
//
//go:linkname vdsoClockgettimeSym runtime.vdsoClockgettimeSym
var vdsoClockgettimeSym uintptr

// runtimeGetm returns the current m; g0LayoutOK cross-checks the g.m offset
// against it, so a wrong offset can never be used silently.
//
//go:linkname runtimeGetm runtime.getm
func runtimeGetm() uintptr

// vdsoCallG0 switches to the g0 stack, performs a single vDSO
// CLOCK_REALTIME read and switches back. Implemented per architecture.
// It returns zero on success; on failure it leaves ts unchanged.
//
// A caller that is not running on m.curg (already on g0 or gsignal) fails
// deliberately: the runtime finds g through a stash on the gsignal stack when
// a signal lands inside the vDSO, and this path only writes that stash when
// switching stacks, so such callers are routed through the now() fallback in
// walltime's callers instead, whose runtime implementation does its own stack
// switch and signal bookkeeping.
//
// Unlike the runtime this does not set m.vdsoPC/m.vdsoSP. Doing that would
// need two more hardcoded m offsets, and unlike the g0 offsets they could not
// be validated cheaply: a wrong one would corrupt runtime state instead of
// merely disabling the fast path. The cost is traceback fidelity if
// SIGPROF/SIGQUIT lands inside the handful of instructions spent in the vDSO.
//
//go:noescape
func vdsoCallG0(fn uintptr, ts *timespec) int32

// g0LayoutOK reports whether the g/m field offsets hardcoded in the
// architecture specific assembly still match this toolchain: it walks
// g.m -> m.curg -> m.g0 and checks that the saved SP of g0 lies inside the
// stack of g0. m must be the value returned by runtimeGetm, and any wrong m is
// rejected without dereferencing it. Implemented per architecture.
//
// m.gsignal, which vdsoCallG0 also reads, is deliberately not checked: on a
// mismatched layout that slot can hold a non-pointer, and dereferencing it to
// tell the two apart would fault during package init instead of disabling the
// fast path.
//
//go:noescape
func g0LayoutOK(m uintptr) bool

var vdsoReady = vdsoClockgettimeSym != 0 && g0LayoutOK(runtimeGetm())

// walltime returns sec and nsec of CLOCK_REALTIME with the same precision
// as time.Now, but pays for a single clock read. time.now always reads both
// CLOCK_REALTIME (walltime) and CLOCK_MONOTONIC (nanotime), and the header only
// ever needs the former.
//
// The read is done on the g0 stack because the kernel's clock_gettime may use
// up to a page of stack (stack probes in gettime_sym on hardened kernels), which
// can hit the guard page of a goroutine stack. It also has to run on g0 for the
// signal handling the runtime normally arranges.
//
// When the vDSO is unavailable, the offsets no longer match this toolchain, or
// the vDSO call fails, it returns 0, 0 and leaves the now() fallback to the
// caller. That keeps the body within the compiler's inlining budget of 80: a
// call to a body-less function costs 57 on its own, so calling now() here would
// make it too expensive, while the current body inlines into the header as one
// extra branch. Adding a statement here drops the inlining again; check with
// go build -gcflags=-m when touching this.
func walltime() (sec int64, nsec int32) {
	var ts timespec
	if vdsoReady && vdsoCallG0(vdsoClockgettimeSym, &ts) == 0 {
		return ts.sec, int32(ts.nsec)
	}
	return 0, 0
}

// unixToInternal is the number of seconds from Jan 1 year 1 to the Unix epoch,
// the offset package time adds to a Unix second before storing it in the ext
// field of a Time that carries no monotonic reading (time.unixToInternal).
const unixToInternal int64 = (1969*365 + 1969/4 - 1969/100 + 1969/400) * 86400

// timeTime mirrors struct time.Time.
type timeTime struct {
	wall uint64
	ext  int64
	loc  *time.Location
}

// Now returns the current local time. On the platforms taking this file it is a
// drop-in replacement for time.Now that pays for one CLOCK_REALTIME vDSO read
// instead of the wall clock read, the monotonic clock read, the runtime stack
// switch and the time.Time construction time.Now goes through.
//
// The result is the Time time.Now returns on a system where the monotonic clock
// is unavailable: the nanoseconds in wall, the seconds since Jan 1 year 1 in
// ext, Local in loc, and no monotonic reading, so a comparison or a subtraction
// against a Time that does carry one falls back to the wall clock. walltime
// returning zero, because the vDSO is missing, the g/m offsets no longer match
// this toolchain, or the vDSO call failed, falls back to time.Now instead, as
// does the whole package on the platforms taking fasttime_zzz.go.
//
// The writes assume the field layout package time documents for Time, which has
// been stable since Go 1.9; the build tag on this file holds it to the Go
// releases those offsets were checked against.
func Now() (now time.Time) {
	sec, nsec := walltime()
	if sec == 0 {
		return time.Now()
	}
	// Fill time.Time in place: wall holds the nanoseconds alone, since the
	// 33-bit seconds field has to stay clear while the monotonic flag is not
	// set, ext holds the seconds since Jan 1 year 1, and loc has to point at
	// Local, because the nil loc of a zero Time means UTC to package time and
	// is not the location time.Now returns.
	tt := (*timeTime)(unsafe.Pointer(&now))
	tt.wall = uint64(nsec)
	tt.ext = sec + unixToInternal
	tt.loc = time.Local
	return
}
