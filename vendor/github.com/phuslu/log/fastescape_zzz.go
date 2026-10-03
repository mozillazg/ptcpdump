//go:build !(amd64 || arm64)

package log

const hasSIMDEscape = false

// needEscapeSIMD is the scalar fallback for platforms without a vector
// implementation. It keeps the exact escapes table predicate.
func needEscapeSIMD(s string) bool {
	for _, c := range []byte(s) {
		if escapes[c] {
			return true
		}
	}
	return false
}
