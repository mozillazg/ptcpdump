package types

type PcapDataType string

const (
	PcapDataTypePcap   PcapDataType = "pcap"
	PcapDataTypePcapNg PcapDataType = "pcapng"

	PcapMagicNumberForMicrosecond = 0xA1B2C3D4
	PcapMagicNumberForNanosecond  = 0xA1B23C4D
	PcapNgMagicNumber             = 0x0A0D0D0A
)
