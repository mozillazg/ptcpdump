package log

import (
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

	// ChannelSize is the size of the data channel, the default size is 1.
	ChannelSize uint

	// DiscardOnFull determines whether to discard new entry when the channel is full.
	DiscardOnFull bool

	// DisableWritev disables the writev syscall if the Writer is a FileWriter.
	DisableWritev bool

	once    sync.Once
	ch      chan *Entry
	chClose chan error
	file    *FileWriter
}

func (w *AsyncWriter) init() {
	w.ch = make(chan *Entry, w.ChannelSize)
	w.chClose = make(chan error)
	w.file, _ = w.Writer.(*FileWriter)
	if w.file != nil && runtime.GOOS == "linux" && unsafe.Sizeof(uintptr(0)) == 8 && !w.DisableWritev {
		go w.writever()
	} else {
		go w.writer()
	}
}

// Close implements io.Closer, and closes the underlying Writer.
func (w *AsyncWriter) Close() (err error) {
	w.once.Do(w.init)
	close(w.ch)
	err = <-w.chClose
	if closer, ok := w.Writer.(io.Closer); ok {
		if err1 := closer.Close(); err1 != nil {
			err = err1
		}
	}
	return
}

var ErrAsyncWriterFull = errors.New("async writer is full")

var eepool = sync.Pool{
	New: func() any {
		return &Entry{
			Level: InfoLevel,
		}
	},
}

// Write implements io.Writer.
func (w *AsyncWriter) Write(p []byte) (n int, err error) {
	e := eepool.Get().(*Entry)
	e.buf = p
	n, err = w.WriteEntry(e)
	e.buf = nil
	eepool.Put(e)
	return
}

// WriteEntry implements Writer.
func (w *AsyncWriter) WriteEntry(e *Entry) (int, error) {
	w.once.Do(w.init)

	// cheating to logger pool
	entry := epool.Get().(*Entry)
	entry.Level = e.Level
	entry.buf, e.buf = e.buf, entry.buf

	if w.DiscardOnFull {
		select {
		case w.ch <- entry:
			return len(entry.buf), nil
		default:
			return 0, ErrAsyncWriterFull
		}
	} else {
		w.ch <- entry
		return len(entry.buf), nil
	}
}

func (w *AsyncWriter) writer() {
	var err error
	for entry := range w.ch {
		if entry == nil {
			break
		}
		_, err = w.Writer.WriteEntry(entry)
		epool.Put(entry)
	}
	w.chClose <- err
}

var _ Writer = (*AsyncWriter)(nil)
var _ io.Writer = (*AsyncWriter)(nil)
