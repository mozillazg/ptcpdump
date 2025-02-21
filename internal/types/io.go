package types

import (
	"bufio"
	"io"
	"os"
)

func NewReadBuffer(r io.ReadCloser) *ReadBuffer {
	return &ReadBuffer{
		r:   r,
		buf: bufio.NewReader(r),
	}
}

type ReadBuffer struct {
	r   io.Closer
	buf *bufio.Reader
}

func (r *ReadBuffer) Read(p []byte) (int, error) {
	return r.buf.Read(p)
}

func (r *ReadBuffer) Peek(n int) ([]byte, error) {
	return r.buf.Peek(n)
}

func (r *ReadBuffer) Close() error {
	return r.r.Close()
}

func (r *ReadBuffer) File() (*os.File, bool, error) {
	f, ok := r.r.(*os.File)
	if !ok {
		return nil, false, nil
	}
	_, err := f.Seek(0, io.SeekStart)
	if err != nil {
		return nil, false, err
	}
	return f, true, nil
}
