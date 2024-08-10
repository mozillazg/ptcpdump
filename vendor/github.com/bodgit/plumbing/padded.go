package plumbing

import (
	"bytes"
	"io"
)

// PaddedReader returns an io.Reader that reads at most n bytes from r. If
// fewer than n bytes are available from r then any remaining bytes return
// fill instead.
func PaddedReader(r io.Reader, n int64, fill byte) io.Reader {
	// Naive, but works
	return io.LimitReader(io.MultiReader(r, bytes.NewBuffer(bytes.Repeat([]byte{fill}, int(n)))), n)
}
