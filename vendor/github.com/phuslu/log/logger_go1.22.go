//go:build go1.22
// +build go1.22

package log

import (
	"encoding/base64"
)

// Base64 adds base64 encoding of the value to the entry.
func (e *Entry) Base64(key string, value []byte) *Entry {
	if e == nil {
		return nil
	}

	e.buf = append(e.buf, ',', '"')
	e.buf = append(e.buf, key...)
	e.buf = append(e.buf, '"', ':', '"')
	e.buf = base64.StdEncoding.AppendEncode(e.buf, value)
	e.buf = append(e.buf, '"')
	return e
}

// Base64URL adds base64 url encoding of the value to the entry.
func (e *Entry) Base64URL(key string, value []byte) *Entry {
	if e == nil {
		return nil
	}

	e.buf = append(e.buf, ',', '"')
	e.buf = append(e.buf, key...)
	e.buf = append(e.buf, '"', ':', '"')
	e.buf = base64.URLEncoding.AppendEncode(e.buf, value)
	e.buf = append(e.buf, '"')
	return e
}
