package utils

import (
	"encoding/binary"

	"github.com/mozillazg/ptcpdump/internal/types"
)

func DetectPcapDataType(r *types.ReadBuffer) (types.PcapDataType, error) {
	// read the first 4 bytes of the file
	header, err := r.Peek(4)
	if err != nil {
		return "", err
	}

	magicNumber := binary.LittleEndian.Uint32(header)
	switch magicNumber {
	case types.PcapMagicNumberForMicrosecond, types.PcapMagicNumberForNanosecond:
		return types.PcapDataTypePcap, nil
	case types.PcapNgMagicNumber:
		return types.PcapDataTypePcapNg, nil
	}

	return "", nil
}
