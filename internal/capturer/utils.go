package capturer

import (
	"encoding/binary"
	"net/netip"
)

func addrTo128(addr netip.Addr) [2]uint64 {
	ret := [2]uint64{}
	addr = addr.Unmap()
	switch {
	case addr.Is4():
		a4 := addr.As4()
		tmp := [4]byte{}
		ip := append([]byte{}, a4[:]...)
		ip = append(ip, tmp[:]...)
		ret[0] = binary.LittleEndian.Uint64(ip[:])
		break
	default:
		ip := addr.As16()
		ret[0] = binary.LittleEndian.Uint64(ip[:8])
		ret[1] = binary.LittleEndian.Uint64(ip[8:16])
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
