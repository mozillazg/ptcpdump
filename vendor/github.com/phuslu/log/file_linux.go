//go:build linux

package log

import (
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

func (w *FileWriter) WriteV(iovs []syscall.Iovec) (n uintptr, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		if w.Filename == "" {
			n, err = writev(syscall.Stderr, iovs)
			if n == ^uintptr(0) { // -1 means aborted
				n = 0
			}
			return
		}
		if w.EnsureFolder {
			err = os.MkdirAll(filepath.Dir(w.Filename), 0755)
			if err != nil {
				return
			}
		}
		err = w.create()
		if err != nil {
			return
		}
	}

	n, err = writev(int(w.file.Fd()), iovs)
	if n == ^uintptr(0) { // -1 means aborted
		n = 0
	}
	if err != nil {
		return
	}

	w.size += int64(n)
	if w.MaxSize > 0 && w.size > w.MaxSize && w.Filename != "" {
		err = w.rotate()
	}

	return
}

// from https://github.com/golang/go/blob/master/src/internal/poll/fd_writev_unix.go
func writev(fd int, iovecs []syscall.Iovec) (uintptr, error) {
	var (
		r uintptr
		e syscall.Errno
	)
	for {
		r, _, e = syscall.Syscall(syscall.SYS_WRITEV, uintptr(fd), uintptr(unsafe.Pointer(&iovecs[0])), uintptr(len(iovecs)))
		if e != syscall.EINTR {
			break
		}
	}
	if e != 0 {
		return r, e
	}
	return r, nil
}
