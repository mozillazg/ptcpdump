//go:build linux && (arm64 || amd64 || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x || loong64)

package log

import (
	"syscall"
)

func (w *AsyncWriter) writever() {
	// https://github.com/golang/go/blob/master/src/internal/poll/writev.go#L29
	const IOV_MAX = 1024

	var es [IOV_MAX]*Entry
	var iovs [IOV_MAX]syscall.Iovec
	var err error
	var quit bool
	for !quit {
		// wait an item from channel
		es[0] = <-w.ch
		if es[0] == nil {
			break
		}
		iovs[0].Base = &es[0].buf[0]
		iovs[0].Len = uint64(len(es[0].buf))
		// drain the channel
		length := len(w.ch)
		if length > IOV_MAX-1 {
			length = IOV_MAX - 1
		}
		n := 1
		for n <= length {
			es[n] = <-w.ch
			if es[n] == nil {
				quit = true
				break
			}
			iovs[n].Base = &es[n].buf[0]
			iovs[n].Len = uint64(len(es[n].buf))
			n++
		}
		// writev
		_, err = w.file.WriteV(iovs[:n])
		// quit = err != nil
		// return entries to pool
		for i := 0; i < n; i++ {
			epool.Put(es[i])
			es[i] = nil
			iovs[i].Base = nil
		}
	}
	w.chClose <- err
}
