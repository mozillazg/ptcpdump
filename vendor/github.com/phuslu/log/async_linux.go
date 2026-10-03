//go:build linux && (arm64 || amd64 || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x || loong64)

package log

import (
	"errors"
	"syscall"
	"time"
)

// maxWritevRetries bounds how often a retryable writev error is retried before
// the writer gives up, latches the error and stops serving entries.
const maxWritevRetries = 3

func (w *AsyncWriter) writever() {
	// https://github.com/golang/go/blob/master/src/internal/poll/writev.go#L29
	const IOV_MAX = 1024

	var es [IOV_MAX]*Entry
	var iovs [IOV_MAX]syscall.Iovec

	var (
		pending int
		retries int
		aborted bool
	)

	for {
		// once aborted, discard the leftover and every following entry
		if aborted {
			for i := range pending {
				w.recycle(es[i])
				es[i] = nil
				iovs[i].Base = nil
			}
			pending = 0
		}

		// top up the batch with everything queued, blocking only when there
		// is nothing left to write
		n, done := w.queue.get(es[pending:], pending == 0)
		end := pending + n
		for _, e := range es[pending:end] {
			if aborted || len(e.buf) == 0 {
				w.recycle(e)
				continue
			}
			iovs[pending].Base = &e.buf[0]
			iovs[pending].SetLen(len(e.buf))
			es[pending] = e
			pending++
		}
		// drop the slots left behind by skipped entries
		clear(es[pending:end])

		if pending == 0 {
			if done {
				break
			}
			continue
		}

		// write the batch; the iovecs are advanced in place so each Entry is
		// reclaimed exactly when its bytes were handed to the kernel
		_, remaining, err := w.file.writevAll(iovs[:pending])
		completed := pending - len(remaining)
		for i := range completed {
			w.recycle(es[i])
			es[i] = nil
			iovs[i].Base = nil
		}
		copy(iovs[:], remaining)
		copy(es[:], es[completed:completed+len(remaining)])
		pending = len(remaining)

		if err == nil {
			retries = 0
			continue
		}
		if len(remaining) == 0 {
			// every byte reached the kernel, the error came from rotation or
			// other housekeeping: remember it and keep serving entries
			w.latchErr(err)
			retries = 0
			continue
		}
		if retries < maxWritevRetries && isRetryableWritevError(err) {
			retries++
			time.Sleep(time.Duration(retries) * time.Millisecond)
			continue
		}
		w.latchErr(err)
		aborted = true
	}

	close(w.done)
}

// isRetryableWritevError reports whether err is a transient writev failure
// worth retrying instead of giving up on the batch.  EINTR is absent on
// purpose: writevFullWith already retries it, so it never gets this far.
func isRetryableWritevError(err error) bool {
	return errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.ENOMEM)
}
