//go:build !amd64 && !arm64 && !arm && !386 && !mipsle && !riscv64

package log

import (
	"runtime"
)

func goid() (n int) {
	const offset = len("goroutine ")
	var data [32]byte
	b := data[:runtime.Stack(data[:], false)]
	if len(b) <= offset {
		return
	}
	for i := offset; i < len(b); i++ {
		j := int(b[i] - '0')
		if j < 0 || j > 9 {
			break
		}
		n = n*10 + j
	}
	return n
}

// Goid returns the current goroutine id.
// It exactly matches goroutine id of the stack trace.
func Goid() int64 {
	return int64(goid())
}
