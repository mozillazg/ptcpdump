package utils

import (
	"bytes"
	"strings"
)

// TODO: chang all caller to []uint8
func GoString(cstring []int8) string {
	var bs strings.Builder

	for _, i := range cstring {
		b := byte(i)
		if b == '\x00' {
			break
		}
		bs.WriteByte(b)
	}

	return bs.String()
}

func GoStringUint(cstring []uint8) string {
	var bs strings.Builder

	for _, i := range cstring {
		b := byte(i)
		if b == '\x00' {
			break
		}
		bs.WriteByte(b)
	}

	return bs.String()
}

func GoBytes(cchars []int8) []byte {
	var bs bytes.Buffer

	for _, i := range cchars {
		bs.WriteByte(byte(i))
	}

	return bs.Bytes()
}
