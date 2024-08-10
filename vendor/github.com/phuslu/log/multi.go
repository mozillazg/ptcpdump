package log

import (
	"io"
)

// MultiWriter is an alias for MultiLevelWriter
type MultiWriter = MultiLevelWriter

// MultiLevelWriter is an Writer that log to different writers by different levels
type MultiLevelWriter struct {
	// InfoWriter specifies all the level logs writes to
	InfoWriter Writer

	// WarnWriter specifies the level greater than or equal to WarnLevel writes to
	WarnWriter Writer

	// WarnWriter specifies the level greater than or equal to ErrorLevel writes to
	ErrorWriter Writer

	// ConsoleWriter specifies the console writer
	ConsoleWriter Writer

	// ConsoleLevel specifies the level greater than or equal to it also writes to
	ConsoleLevel Level
}

// Close implements io.Closer, and closes the underlying LeveledWriter.
func (w *MultiLevelWriter) Close() (err error) {
	for _, writer := range []Writer{
		w.InfoWriter,
		w.WarnWriter,
		w.ErrorWriter,
		w.ConsoleWriter,
	} {
		if writer == nil {
			continue
		}
		if closer, ok := writer.(io.Closer); ok {
			if err1 := closer.Close(); err1 != nil {
				err = err1
			}
		}
	}
	return
}

// WriteEntry implements entryWriter.
func (w *MultiLevelWriter) WriteEntry(e *Entry) (n int, err error) {
	var err1 error
	switch e.Level {
	case noLevel, PanicLevel, FatalLevel, ErrorLevel:
		if w.ErrorWriter != nil {
			n, err1 = w.ErrorWriter.WriteEntry(e)
			if err1 != nil && err == nil {
				err = err1
			}
		}
		fallthrough
	case WarnLevel:
		if w.WarnWriter != nil {
			n, err1 = w.WarnWriter.WriteEntry(e)
			if err1 != nil && err == nil {
				err = err1
			}
		}
		fallthrough
	default:
		if w.InfoWriter != nil {
			n, err1 = w.InfoWriter.WriteEntry(e)
			if err1 != nil && err == nil {
				err = err1
			}
		}
	}

	if w.ConsoleWriter != nil && e.Level >= w.ConsoleLevel {
		_, _ = w.ConsoleWriter.WriteEntry(e)
	}

	return
}

var _ Writer = (*MultiLevelWriter)(nil)

// MultiEntryWriter is an array Writer that log to different writers
type MultiEntryWriter []Writer

// Close implements io.Closer, and closes the underlying MultiEntryWriter.
func (w *MultiEntryWriter) Close() (err error) {
	for _, writer := range *w {
		if closer, ok := writer.(io.Closer); ok {
			if err1 := closer.Close(); err1 != nil {
				err = err1
			}
		}
	}
	return
}

// WriteEntry implements entryWriter.
func (w *MultiEntryWriter) WriteEntry(e *Entry) (n int, err error) {
	var err1 error
	for _, writer := range *w {
		n, err1 = writer.WriteEntry(e)
		if err1 != nil && err == nil {
			err = err1
		}
	}
	return
}

var _ Writer = (*MultiEntryWriter)(nil)

// MultiIOWriter is an array io.Writer that log to different writers
type MultiIOWriter []io.Writer

// Close implements io.Closer, and closes the underlying MultiIOWriter.
func (w *MultiIOWriter) Close() (err error) {
	for _, writer := range *w {
		if closer, ok := writer.(io.Closer); ok {
			if err1 := closer.Close(); err1 != nil {
				err = err1
			}
		}
	}
	return
}

// WriteEntry implements entryWriter.
func (w *MultiIOWriter) WriteEntry(e *Entry) (n int, err error) {
	for _, writer := range *w {
		n, err = writer.Write(e.buf)
		if err != nil {
			return
		}
	}

	return
}
