package log

// simdEscapeThreshold keeps values shorter than two vectors on the scalar path.
const simdEscapeThreshold = 31

// escapes marks every byte that appendEscapedBytes and appendEscapedString
// rewrite: the C0 control bytes, which JSON requires to be escaped, plus the
// characters escaped for HTML safety. It must stay in sync with those two
// functions and with the vector kernels in fastescape_amd64.s and
// fastescape_arm64.s.
var escapes = [256]bool{
	0x00: true, 0x01: true, 0x02: true, 0x03: true,
	0x04: true, 0x05: true, 0x06: true, 0x07: true,
	0x08: true, 0x09: true, 0x0a: true, 0x0b: true,
	0x0c: true, 0x0d: true, 0x0e: true, 0x0f: true,
	0x10: true, 0x11: true, 0x12: true, 0x13: true,
	0x14: true, 0x15: true, 0x16: true, 0x17: true,
	0x18: true, 0x19: true, 0x1a: true, 0x1b: true,
	0x1c: true, 0x1d: true, 0x1e: true, 0x1f: true,

	'"':  true,
	'\'': true,
	'<':  true,
	'\\': true,
}

func appendEscapedBytes(dst, b []byte) []byte {
	n := len(b)
	j := 0
	if n > 0 {
		// Hint the compiler to remove bounds checks in the loop below.
		_ = b[n-1]
	}
	for i := range n {
		c := b[i]
		// Skip ordinary bytes without walking the escape dispatch below.
		if !escapes[c] {
			continue
		}
		// Adjacent escapes have no ordinary bytes to copy.
		if j < i {
			dst = append(dst, b[j:i]...)
		}
		switch c {
		case '"', '\\':
			dst = append(dst, '\\', c)
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			// The remaining control bytes and HTML-sensitive characters.
			dst = append(dst, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
		}
		j = i + 1
	}
	return append(dst, b[j:]...)
}

func appendEscapedString(dst []byte, s string) []byte {
	n := len(s)
	j := 0
	if n > 0 {
		// Hint the compiler to remove bounds checks in the loop below.
		_ = s[n-1]
	}
	for i := range n {
		c := s[i]
		// Skip ordinary bytes without walking the escape dispatch below.
		if !escapes[c] {
			continue
		}
		// Adjacent escapes have no ordinary bytes to copy.
		if j < i {
			dst = append(dst, s[j:i]...)
		}
		switch c {
		case '"', '\\':
			dst = append(dst, '\\', c)
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			// The remaining control bytes and HTML-sensitive characters.
			dst = append(dst, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
		}
		j = i + 1
	}
	return append(dst, s[j:]...)
}

// appendLoggerString appends a string using the scalar escape scan.
func appendLoggerString(dst []byte, s string) []byte {
	for _, c := range []byte(s) {
		if escapes[c] {
			return appendEscapedString(dst, s)
		}
	}
	return append(dst, s...)
}

// appendLoggerBytes appends bytes using the scalar escape scan.
func appendLoggerBytes(dst, b []byte) []byte {
	for _, c := range b {
		if escapes[c] {
			return appendEscapedBytes(dst, b)
		}
	}
	return append(dst, b...)
}

// appendLoggerString2 appends a string after the SIMD escape scan.
func appendLoggerString2(dst []byte, s string) []byte {
	if needEscapeSIMD(s) {
		return appendEscapedString(dst, s)
	}
	return append(dst, s...)
}

// appendLoggerBytes2 appends bytes after the SIMD escape scan.
func appendLoggerBytes2(dst, b []byte) []byte {
	if needEscapeSIMD(b2s(b)) {
		return appendEscapedBytes(dst, b)
	}
	return append(dst, b...)
}
