//go:build !windows
// +build !windows

package log

import (
	"os"
	"syscall"
	"unsafe"
)

func isTerminal(fd uintptr, os, arch string) bool {
	var trap uintptr // SYS_IOCTL
	switch os {
	case "plan9", "js", "nacl":
		return false
	case "linux", "android":
		switch arch {
		case "amd64":
			trap = 16
		case "arm64":
			trap = 29
		case "mips", "mipsle":
			trap = 4054
		case "mips64", "mips64le":
			trap = 5015
		default:
			trap = 54
		}
	default:
		trap = 54
	}

	var req uintptr // TIOCGETA
	switch os {
	case "linux", "android":
		switch arch {
		case "ppc64", "ppc64le":
			req = 0x402c7413
		case "mips", "mipsle", "mips64", "mips64le":
			req = 0x540d
		default:
			req = 0x5401
		}
	case "darwin":
		switch arch {
		case "amd64", "arm64":
			req = 0x40487413
		default:
			req = 0x402c7413
		}
	default:
		req = 0x402c7413
	}

	var termios [256]byte
	_, _, err := syscall.Syscall6(trap, fd, req, uintptr(unsafe.Pointer(&termios[0])), 0, 0, 0)
	// println(os, arch, err)
	return err == 0
}

// WriteEntry implements Writer.
func (w *ConsoleWriter) WriteEntry(e *Entry) (int, error) {
	out := w.Writer
	if out == nil {
		out = os.Stderr
	}
	return w.write(out, e.buf)
}
