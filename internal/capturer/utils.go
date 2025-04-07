package capturer

import (
	"encoding/binary"
	"net/netip"
)

func addrTo128(addr netip.Addr) [4]uint32 {
	ret := [4]uint32{}
	addr = addr.Unmap()
	switch {
	case addr.Is4():
		a4 := addr.As4()
		ret[0] = binary.LittleEndian.Uint32(a4[:])
		break
	default:
		ip := addr.As16()
		ret[0] = binary.LittleEndian.Uint32(ip[:4])
		ret[1] = binary.LittleEndian.Uint32(ip[4:8])
		ret[2] = binary.LittleEndian.Uint32(ip[8:12])
		ret[3] = binary.LittleEndian.Uint32(ip[12:16])
	}
	return ret
}

func runClosers(funcs []func()) {
	for i := len(funcs) - 1; i >= 0; i-- {
		f := funcs[i]
		if f != nil {
			f()
		}
	}
}
