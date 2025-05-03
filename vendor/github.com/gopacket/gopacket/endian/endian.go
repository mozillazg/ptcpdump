package endian

import (
	"encoding/binary"
	"math/bits"
)

func isLittleEndian[Bo binary.ByteOrder](bo Bo) bool {
	return bo.Uint16([]byte{0x12, 0x34}) == 0x3412
}

// Htons converts x from host to network byte order.
func Htons(v uint16) uint16 {
	if isLittleEndian(binary.NativeEndian) {
		return bits.ReverseBytes16(v)
	}
	return v
}
