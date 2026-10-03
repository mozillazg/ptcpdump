//go:build !(linux && (amd64 || arm64) && go1.25 && !go1.28)

package log

import "time"

// walltime has no vDSO fast path on this platform, with this compiler (gccgo
// has no Go assembler and no runtime vdsoClockgettimeSym), or outside the Go
// releases fasttime.go is written for, so it returns zero and callers fall back
// to now().
func walltime() (sec int64, nsec int32) {
	return 0, 0
}

// Now returns the current local time. This platform, compiler or Go release
// takes no fast path (see fasttime.go), so it is time.Now, monotonic clock
// reading and all.
func Now() time.Time {
	return time.Now()
}
