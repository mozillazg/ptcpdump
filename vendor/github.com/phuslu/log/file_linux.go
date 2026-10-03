//go:build linux

package log

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// writevFunc is the syscall used by writevFull.  It is a variable so tests can
// inject short writes and errors without a real filesystem failure.
var writevFunc = writev

// errWritevOverflow is reported when writev claims to have written more bytes
// than were requested, which would corrupt the iovec progress accounting.
var errWritevOverflow = errors.New("log: writev wrote more bytes than requested")

// WriteV writes all iovecs to the writer.  It returns the number of bytes
// actually written, which can be smaller than the total iovec length when a
// write error occurs.  The iovecs are advanced in place, so a caller that
// wants to retry a partial write can inspect the leftover iovecs.
func (w *FileWriter) WriteV(iovs []syscall.Iovec) (n uintptr, err error) {
	n, _, err = w.writevAll(iovs)
	return
}

// writevAll writes every byte of iovs while holding the file lock, and returns
// the number of bytes written together with the iovec suffix that has not been
// fully written.  The suffix is what makes a partial write recoverable: the
// caller knows exactly which entries are done and which bytes still need to be
// written.
func (w *FileWriter) writevAll(iovs []syscall.Iovec) (written uintptr, remaining []syscall.Iovec, err error) {
	if len(iovs) == 0 {
		return 0, nil, nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		if w.Filename == "" {
			return writevFull(syscall.Stderr, iovs)
		}
		if w.EnsureFolder {
			err = os.MkdirAll(filepath.Dir(w.Filename), 0755)
			if err != nil {
				return 0, iovs, err
			}
		}
		err = w.create()
		if err != nil {
			return 0, iovs, err
		}
	}

	written, remaining, err = writevFull(int(w.file.Fd()), iovs)
	// Count partially written bytes too, otherwise the rotation size drifts
	// and the next rotation happens too late.
	w.size += int64(written)
	if err == nil && w.MaxSize > 0 && w.size > w.MaxSize && w.Filename != "" {
		err = w.rotate()
	}

	return
}

// writevFull writes all bytes described by iovs to fd, advancing iovs in
// place.  It returns the number of bytes written and the iovec suffix that has
// not been fully written, so callers can account for partial progress and
// retry only the leftover.  A syscall that makes no progress is reported as
// io.ErrShortWrite instead of spinning forever.
func writevFull(fd int, iovs []syscall.Iovec) (written uintptr, remaining []syscall.Iovec, err error) {
	return writevFullWith(fd, iovs, writevFunc)
}

// writevFullWith is writevFull with an injectable syscall, which keeps the
// iovec consumption logic testable without real short writes.
func writevFullWith(fd int, iovs []syscall.Iovec, write func(fd int, iovecs []syscall.Iovec) (uintptr, error)) (written uintptr, remaining []syscall.Iovec, err error) {
	pending := iovecsTrim(iovs)
	for len(pending) > 0 {
		n, e := write(fd, pending)
		if n == ^uintptr(0) { // -1 means aborted
			n = 0
		}
		if n > iovecsLen(pending) {
			return written, pending, errWritevOverflow
		}
		written += n
		pending = consumeIovecs(pending, n)
		// EINTR is retried here instead of being returned, so an injected
		// writev does not have to loop and writever never sees EINTR.
		if e == syscall.EINTR {
			continue
		}
		if e != nil {
			return written, pending, e
		}
		if len(pending) == 0 {
			return written, nil, nil
		}
		if n == 0 {
			return written, pending, io.ErrShortWrite
		}
	}
	return written, nil, nil
}

// iovecsTrim drops leading zero-length iovecs, which writev ignores anyway.
func iovecsTrim(iovs []syscall.Iovec) []syscall.Iovec {
	for len(iovs) > 0 && iovs[0].Len == 0 {
		iovs = iovs[1:]
	}
	return iovs
}

// iovecsLen returns the total number of bytes described by iovs.
func iovecsLen(iovs []syscall.Iovec) (n uintptr) {
	for i := range iovs {
		n += uintptr(iovs[i].Len)
	}
	return
}

// consumeIovecs advances iovs by n bytes in place and returns the remainder.
// Fully consumed iovecs are dropped; a partially consumed iovec keeps its
// buffer pointer advanced by the consumed bytes.
func consumeIovecs(iovs []syscall.Iovec, n uintptr) []syscall.Iovec {
	for len(iovs) > 0 {
		if n >= uintptr(iovs[0].Len) {
			n -= uintptr(iovs[0].Len)
			iovs = iovs[1:]
			continue
		}
		if n > 0 {
			iovs[0].Base = (*byte)(unsafe.Add(unsafe.Pointer(iovs[0].Base), n))
			iovs[0].SetLen(int(iovs[0].Len) - int(n))
		}
		return iovs
	}
	return nil
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
