//go:build amd64 || arm64

package log

const hasSIMDEscape = true

//go:noescape
func needEscapeBlocks(b string) bool

func needEscapeSIMD(s string) bool {
	if n := len(s) &^ 15; n > 0 && needEscapeBlocks(s[:n]) {
		return true
	}
	for _, c := range []byte(s[len(s)&^15:]) {
		if escapes[c] {
			return true
		}
	}
	return false
}
