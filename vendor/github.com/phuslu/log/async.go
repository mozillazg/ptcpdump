package log

import (
	"cmp"
	"errors"
	"io"
	"runtime"
	"sync"
	"unsafe"
)

// AsyncWriter is a Writer that writes asynchronously.
type AsyncWriter struct {
	// Writer specifies the writer of output.
	Writer Writer

	// ChannelSize is the capacity of the queue of pending entries.
	// If zero, the default size is 1024
	ChannelSize uint

	// DiscardOnFull determines whether to discard new entry when the queue is full.
	DiscardOnFull bool

	// DisableWritev disables the writev syscall if the Writer is a FileWriter.
	DisableWritev bool

	once  sync.Once
	queue asyncQueue
	done  chan struct{}
	file  *FileWriter

	errOnce  sync.Once
	firstErr error

	closeOnce sync.Once
	closeErr  error
}

// asyncBatch is the maximum number of entries the background writer takes
// from the queue at once.  It matches IOV_MAX, the writev limit on Linux.
const asyncBatch = 1024

func (w *AsyncWriter) init() {
	w.queue.init(cmp.Or(int(w.ChannelSize), asyncBatch))
	w.done = make(chan struct{})
	w.file, _ = w.Writer.(*FileWriter)
	if w.file != nil && runtime.GOOS == "linux" && unsafe.Sizeof(uintptr(0)) == 8 && !w.DisableWritev {
		go w.writever()
	} else {
		go w.writer()
	}
}

// Close implements io.Closer, and closes the underlying Writer.
//
// Close should be called after all producers stopped calling Write or
// WriteEntry.  It waits until every accepted entry has been processed and
// returns the first background write error, if any.  A later successful write
// or a close error of the underlying Writer must not hide that first error.
//
// Calling Close more than once returns the result of the first call.  Writes
// after Close fail with ErrAsyncWriterClosed.
func (w *AsyncWriter) Close() error {
	w.once.Do(w.init)
	w.closeOnce.Do(func() {
		w.queue.close()
		<-w.done
		w.closeErr = w.firstErr
		if closer, ok := w.Writer.(io.Closer); ok {
			if err := closer.Close(); err != nil && w.closeErr == nil {
				w.closeErr = err
			}
		}
	})
	return w.closeErr
}

// latchErr records the first background write error.  Later successes and
// later errors never replace it.
func (w *AsyncWriter) latchErr(err error) {
	if err == nil {
		return
	}
	w.errOnce.Do(func() {
		w.firstErr = err
	})
}

// recycle returns an entry to the pool, unless its buffer grew too large to
// keep around.
func (w *AsyncWriter) recycle(e *Entry) {
	if cap(e.buf) <= bbcap {
		epool.Put(e)
	}
}

var ErrAsyncWriterFull = errors.New("async writer is full")

var ErrAsyncWriterClosed = errors.New("async writer is closed")

var eepool = sync.Pool{
	New: func() any {
		return &Entry{
			Level: InfoLevel,
		}
	},
}

// Write implements io.Writer.
//
// The payload is copied, so the caller may reuse p as soon as Write returns,
// as required by io.Writer; holding on to p would race with the background
// writer and silently corrupt the log.
func (w *AsyncWriter) Write(p []byte) (n int, err error) {
	e := eepool.Get().(*Entry)
	if cap(e.buf) < len(p) {
		e.buf = make([]byte, len(p))
	} else {
		e.buf = e.buf[:len(p)]
	}
	copy(e.buf, p)
	n, err = w.WriteEntry(e)
	if cap(e.buf) <= bbcap {
		e.buf = e.buf[:0]
		eepool.Put(e)
	}
	return
}

// WriteEntry implements Writer.
func (w *AsyncWriter) WriteEntry(e *Entry) (int, error) {
	w.once.Do(w.init)

	// cheating to logger pool
	entry := epool.Get().(*Entry)
	entry.Level = e.Level
	entry.buf, e.buf = e.buf, entry.buf

	// snapshot length before queueing, entry is owned by the writer goroutine afterwards
	n := len(entry.buf)

	if err := w.queue.put(entry, w.DiscardOnFull); err != nil {
		w.recycle(entry)
		return 0, err
	}
	return n, nil
}

func (w *AsyncWriter) writer() {
	var es [asyncBatch]*Entry
	for {
		n, done := w.queue.get(es[:], true)
		for i := range n {
			if w.firstErr == nil {
				if _, err := w.Writer.WriteEntry(es[i]); err != nil {
					w.latchErr(err)
				}
			}
			w.recycle(es[i])
			es[i] = nil
		}
		if done {
			break
		}
	}
	close(w.done)
}

// asyncQueue is a bounded FIFO of entries shared by the producers and the
// background writer.  Unlike a channel, the writer takes a whole batch under
// a single lock, and it frees as many slots as it took at once.
type asyncQueue struct {
	mu       sync.Mutex
	notEmpty sync.Cond
	notFull  sync.Cond
	buf      []*Entry // ring buffer
	head     int
	size     int
	closed   bool
	cwait    bool // the consumer is waiting on notEmpty
	pwait    int  // number of producers waiting on notFull
}

func (q *asyncQueue) init(capacity int) {
	q.notEmpty.L = &q.mu
	q.notFull.L = &q.mu
	q.buf = make([]*Entry, capacity)
}

// put appends e to the queue.  When the queue is full, it returns
// ErrAsyncWriterFull if discard is set, and blocks for a free slot otherwise.
// It returns ErrAsyncWriterClosed once the queue is closed.
func (q *asyncQueue) put(e *Entry, discard bool) error {
	q.mu.Lock()
	for q.size == len(q.buf) && !q.closed {
		if discard {
			q.mu.Unlock()
			return ErrAsyncWriterFull
		}
		q.pwait++
		q.notFull.Wait()
		q.pwait--
	}
	if q.closed {
		q.mu.Unlock()
		return ErrAsyncWriterClosed
	}
	i := q.head + q.size
	if i >= len(q.buf) {
		i -= len(q.buf)
	}
	q.buf[i] = e
	q.size++
	wake := q.cwait
	q.cwait = false
	q.mu.Unlock()
	if wake {
		q.notEmpty.Signal()
	}
	return nil
}

// get moves up to len(dst) queued entries into dst, oldest first, and returns
// how many it moved.  If wait is set, it blocks until an entry is queued or
// the queue is closed.  done reports that the queue is closed and drained, so
// no entry will ever follow.
func (q *asyncQueue) get(dst []*Entry, wait bool) (n int, done bool) {
	q.mu.Lock()
	for wait && q.size == 0 && !q.closed {
		q.cwait = true
		q.notEmpty.Wait()
	}
	n = min(q.size, len(dst))
	if n > 0 {
		// the queued entries wrap around at most once
		k := copy(dst[:n], q.buf[q.head:min(q.head+n, len(q.buf))])
		copy(dst[k:n], q.buf[:n-k])
		if k == n {
			clear(q.buf[q.head : q.head+n])
		} else {
			clear(q.buf[q.head:])
			clear(q.buf[:n-k])
		}
		q.head += n
		if q.head >= len(q.buf) {
			q.head -= len(q.buf)
		}
		q.size -= n
	}
	done = q.closed && q.size == 0
	wake := min(n, q.pwait)
	q.mu.Unlock()
	for range wake {
		q.notFull.Signal()
	}
	return
}

// close marks the queue as closed.  Queued entries can still be taken, but
// put fails from now on, including for producers blocked on a full queue.
func (q *asyncQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	q.notEmpty.Signal()
	q.notFull.Broadcast()
}

var _ Writer = (*AsyncWriter)(nil)
var _ io.Writer = (*AsyncWriter)(nil)
