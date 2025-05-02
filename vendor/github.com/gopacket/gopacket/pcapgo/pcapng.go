// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcapgo

import (
	"errors"
	"math"
	"net"
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// ErrNgVersionMismatch gets returned for unknown pcapng section versions. This can only happen if ReaderOptions.SkipUnknownVersion == false
var ErrNgVersionMismatch = errors.New("Unknown pcapng Version in Section Header")

// ErrNgLinkTypeMismatch gets returned if the link type of an interface is not the same as the link type from the first interface. This can only happen if ReaderOptions.ErrorOnMismatchingLinkType == true && ReaderOptions.WantMixedLinkType == false
var ErrNgLinkTypeMismatch = errors.New("Link type of current interface is different from first one")

const (
	ngByteOrderMagic = 0x1A2B3C4D

	// We can handle only version 1.0
	ngVersionMajor = 1
	ngVersionMinor = 0
)

type ngBlockType uint32

const (
	ngBlockTypeInterfaceDescriptor ngBlockType = 1          // Interface description block
	ngBlockTypePacket              ngBlockType = 2          // Packet block (deprecated)
	ngBlockTypeSimplePacket        ngBlockType = 3          // Simple packet block
	ngBlockTypeNameResolution      ngBlockType = 4          // Name resolution block
	ngBlockTypeInterfaceStatistics ngBlockType = 5          // Interface statistics block
	ngBlockTypeEnhancedPacket      ngBlockType = 6          // Enhanced packet block
	ngBlockTypeDecryptionSecrets   ngBlockType = 0x0000000A // Decryption secrets block
	ngBlockTypeSectionHeader       ngBlockType = 0x0A0D0D0A // Section header block (same in both endians)
)

const (
	/*
	 * Type describing the format of Decryption Secrets Block (DSB).
	 */
	DSB_SECRETS_TYPE_TLS            uint32 = 0x544c534b /* TLS Key Log */
	DSB_SECRETS_TYPE_SSH            uint32 = 0x5353484b /* SSH Key Log */
	DSB_SECRETS_TYPE_WIREGUARD      uint32 = 0x57474b4c /* WireGuard Key Log */
	DSB_SECRETS_TYPE_ZIGBEE_NWK_KEY uint32 = 0x5a4e574b /* Zigbee NWK Key */
	DSB_SECRETS_TYPE_ZIGBEE_APS_KEY uint32 = 0x5a415053 /* Zigbee APS Key */
)

// define error types for DSB
var (
	ErrUnknownSecretsType = errors.New("Unknown Decryption Secrets Block (DSB) type")
)

type ngOptionCode uint16

const (
	ngOptionCodeEndOfOptions    ngOptionCode = iota // end of options. must be at the end of options in a block
	ngOptionCodeComment                             // comment
	ngOptionCodeHardware                            // description of the hardware
	ngOptionCodeOS                                  // name of the operating system
	ngOptionCodeUserApplication                     // name of the application
)

const (
	ngOptionCodeInterfaceName                ngOptionCode = iota + 2 // interface name
	ngOptionCodeInterfaceDescription                                 // interface description
	ngOptionCodeInterfaceIPV4Address                                 // IPv4 network address and netmask for the interface
	ngOptionCodeInterfaceIPV6Address                                 // IPv6 network address and prefix length for the interface
	ngOptionCodeInterfaceMACAddress                                  // interface hardware MAC address
	ngOptionCodeInterfaceEUIAddress                                  // interface hardware EUI address
	ngOptionCodeInterfaceSpeed                                       // interface speed in bits/s
	ngOptionCodeInterfaceTimestampResolution                         // timestamp resolution
	ngOptionCodeInterfaceTimezone                                    // time zone
	ngOptionCodeInterfaceFilter                                      // capture filter
	ngOptionCodeInterfaceOS                                          // operating system
	ngOptionCodeInterfaceFCSLength                                   // length of the Frame Check Sequence in bits
	ngOptionCodeInterfaceTimestampOffset                             // offset (in seconds) that must be added to packet timestamp
)

const (
	ngOptionCodeInterfaceStatisticsStartTime         ngOptionCode = iota + 2 // Start of capture
	ngOptionCodeInterfaceStatisticsEndTime                                   // End of capture
	ngOptionCodeInterfaceStatisticsInterfaceReceived                         // Packets received by physical interface
	ngOptionCodeInterfaceStatisticsInterfaceDropped                          // Packets dropped by physical interface
	ngOptionCodeInterfaceStatisticsFilterAccept                              // Packets accepted by filter
	ngOptionCodeInterfaceStatisticsOSDrop                                    // Packets dropped by operating system
	ngOptionCodeInterfaceStatisticsDelivered                                 // Packets delivered to user
)

const (
	// Name Resolution Block: record types
	ngNameRecordEnd   uint16 = iota // End of name resolution records
	ngNameRecordIPv4                // IPv4 record
	ngNameRecordIPv6                // IPv6 record
	ngNameRecordEUI48               // EUI-48 record
	ngNameRecordEUI64               // EUI-64 record
)

const (
	// Enhanced Packet Block
	ngOptionCodeEpbFlags     ngOptionCode = iota + 2 // link-layer information
	ngOptionCodeEpbHash                              // hash of the packet
	ngOptionCodeEpbDropCount                         // number of packets lost
	ngOptionCodeEpbPacketID                          // uniquely identifies the packet
	ngOptionCodeEpbQueue                             // identifies on which queue of the interface the specific packet was received
	ngOptionCodeEpbVerdict                           // a verdict of the packet
)

// NgEpbFlag Enhanced Packet Block Flags Word
type NgEpbFlag uint32

const (
	NgEpbFlagDirectionMask     NgEpbFlag = 0b11 // bits 0-1
	NgEpbFlagDirectionUnknown  NgEpbFlag = 0b00 // 00 = information not available
	NgEpbFlagDirectionInbound  NgEpbFlag = 0b01 // 01 = inbound
	NgEpbFlagDirectionOutbound NgEpbFlag = 0b10 // 10 = outbound
)

const (
	NgEpbFlagReceptionTypeMask         NgEpbFlag = 0b11100 // bits 2-4
	NgEpbFlagReceptionTypeNotSpecified NgEpbFlag = 0b00000 // 000 = not specified
	NgEpbFlagReceptionTypeUnicast      NgEpbFlag = 0b00100 // 001 = unicast
	NgEpbFlagReceptionTypeMulticast    NgEpbFlag = 0b01000 // 010 = multicast
	NgEpbFlagReceptionTypeBroadcast    NgEpbFlag = 0b01100 // 011 = broadcast
	NgEpbFlagReceptionTypePromiscuous  NgEpbFlag = 0b10000 // 100 = promiscuous
)

const (
	NgEpbFlagFCSLengthMask         NgEpbFlag = 0b1111100000 // bits 5-8
	NgEpbFlagFCSLengthNotAvailable NgEpbFlag = 0            // 0000 if this information is not available
)

const (
	NgEpbFlagLinkLayerDependentErrorMask                NgEpbFlag = 0xFFFF0000 // bits 16-31
	NgEpbFlagLinkLayerDependentErrorSymbol              NgEpbFlag = 1 << 31    // Bit 31 = symbol error
	NgEpbFlagLinkLayerDependentErrorPreamble            NgEpbFlag = 1 << 30    // Bit 30 = preamble error
	NgEpbFlagLinkLayerDependentErrorStartFrameDelimiter NgEpbFlag = 1 << 29    // Bit 29 = Start Frame Delimiter error
	NgEpbFlagLinkLayerDependentErrorUnalignedFrame      NgEpbFlag = 1 << 28    // Bit 28 = unaligned frame error
	NgEpbFlagLinkLayerDependentErrorInterFrameGap       NgEpbFlag = 1 << 27    // Bit 27 = wrong Inter Frame Gap error
	NgEpbFlagLinkLayerDependentErrorPacketTooShort      NgEpbFlag = 1 << 26    // Bit 26 = packet too short error
	NgEpbFlagLinkLayerDependentErrorPacketTooLong       NgEpbFlag = 1 << 25    // Bit 25 = packet too long error
	NgEpbFlagLinkLayerDependentErrorCRC                 NgEpbFlag = 1 << 24    // Bit 24 = CRC error
)

type NgEpbFlags struct {
	Direction    NgEpbFlag
	Reception    NgEpbFlag
	FCSLen       NgEpbFlag
	LinkLayerErr NgEpbFlag
}

func NewNgEpbFlagFCSLength(n uint8) NgEpbFlag {
	return NgEpbFlag(n<<5) & NgEpbFlagFCSLengthMask
}

func (f *NgEpbFlags) ToUint32() uint32 {
	var result uint32
	result = uint32(f.Direction) & uint32(NgEpbFlagDirectionMask)
	result |= uint32(f.Reception) & uint32(NgEpbFlagReceptionTypeMask)
	result |= uint32(f.FCSLen) & uint32(NgEpbFlagFCSLengthMask)
	result |= uint32(f.LinkLayerErr) & uint32(NgEpbFlagLinkLayerDependentErrorMask)
	return result
}

func (f *NgEpbFlags) FromUint32(value uint32) {
	f.Direction = NgEpbFlag(value & uint32(NgEpbFlagDirectionMask))
	f.Reception = NgEpbFlag(value & uint32(NgEpbFlagReceptionTypeMask))
	f.FCSLen = NgEpbFlag(value & uint32(NgEpbFlagFCSLengthMask))
	f.LinkLayerErr = NgEpbFlag(value & uint32(NgEpbFlagLinkLayerDependentErrorMask))
}

type NgEpbHashAlgorithm uint8

const (
	NgEpbHashAlgorithm2sComplement NgEpbHashAlgorithm = iota // 2s complement (algorithm octet = 0, size = XXX)
	NgEpbHashAlgorithmXOR                                    // XOR (algorithm octet = 1, size=XXX)
	NgEpbHashAlgorithmCRC32                                  // CRC32 (algorithm octet = 2, size = 4)
	NgEpbHashAlgorithmMD5                                    //  MD-5 (algorithm octet = 3, size = 16)
	NgEpbHashAlgorithmSHA1                                   //  SHA-1 (algorithm octet = 4, size = 20)
	NgEpbHashAlgorithmToeplitz                               //  Toeplitz (algorithm octet = 5, size = 4)
)

type NgEpbHash struct {
	Algorithm NgEpbHashAlgorithm
	Hash      []byte
}

func (h NgEpbHash) toBytes() []byte {
	v := []byte{byte(h.Algorithm)}
	v = append(v, h.Hash...)
	return v
}

type NgEpbVerdictType uint8

const (
	NgEpbVerdictTypeHardware     NgEpbVerdictType = iota // Hardware (type octet = 0, size = variable)
	NgEpbVerdictTypeLinuxeBPFTC                          // Linux_eBPF_TC (type octet = 1, size = 8 (64-bit unsigned integer)
	NgEpbVerdictTypeLinuxeBPFXDP                         // Linux_eBPF_XDP (type octet = 2, size = 8 (64-bit unsigned integer)
)

type NgEpbVerdict struct {
	Type NgEpbVerdictType
	Data []byte
}

func (vd NgEpbVerdict) toBytes() []byte {
	v := []byte{byte(vd.Type)}
	v = append(v, vd.Data...)
	return v
}

// ngOption is a pcapng option
type ngOption struct {
	code   ngOptionCode
	value  []byte
	raw    interface{}
	length uint16
}

// ngBlock is a pcapng block header
type ngBlock struct {
	typ    ngBlockType
	length uint32 // remaining length of block
}

// NgResolution represents a pcapng timestamp resolution
type NgResolution uint8

// Binary returns true if the timestamp resolution is a negative power of two. Otherwise NgResolution is a negative power of 10.
func (r NgResolution) Binary() bool {
	if r&0x80 == 0x80 {
		return true
	}
	return false
}

// Exponent returns the negative exponent of the resolution.
func (r NgResolution) Exponent() uint8 {
	return uint8(r) & 0x7f
}

// ToTimestampResolution converts an NgResolution to a gopaket.TimestampResolution
func (r NgResolution) ToTimestampResolution() (ret gopacket.TimestampResolution) {
	if r.Binary() {
		ret.Base = 2
	} else {
		ret.Base = 10
	}
	ret.Exponent = -int(r.Exponent())
	return
}

// NgNoValue64 is a placeholder for an empty numeric 64 bit value.
const NgNoValue64 = math.MaxUint64

// NgInterfaceStatistics hold the statistic for an interface at a single point in time. These values are already supposed to be accumulated. Most pcapng files contain this information at the end of the file/section.
type NgInterfaceStatistics struct {
	// LastUpdate is the last time the statistics were updated.
	LastUpdate time.Time
	// StartTime is the time packet capture started on this interface. This value might be zero if this option is missing.
	StartTime time.Time
	// EndTime is the time packet capture ended on this interface This value might be zero if this option is missing.
	EndTime time.Time
	// Comment can be an arbitrary comment. This value might be empty if this option is missing.
	Comment string
	// PacketsReceived are the number of received packets. This value might be NoValue64 if this option is missing.
	PacketsReceived uint64
	// PacketsReceived are the number of received packets. This value might be NoValue64 if this option is missing.
	PacketsDropped uint64
}

var ngEmptyStatistics = NgInterfaceStatistics{
	PacketsReceived: NgNoValue64,
	PacketsDropped:  NgNoValue64,
}

// NgInterface holds all the information of a pcapng interface.
type NgInterface struct {
	// Name is the name of the interface. This value might be empty if this option is missing.
	Name string
	// Comment can be an arbitrary comment. This value might be empty if this option is missing.
	Comment string
	// Description is a description of the interface. This value might be empty if this option is missing.
	Description string
	// Filter is the filter used during packet capture. This value might be empty if this option is missing.
	Filter string
	// OS is the operating system this interface was controlled by. This value might be empty if this option is missing.
	OS string
	// LinkType is the linktype of the interface.
	LinkType layers.LinkType
	// TimestampResolution is the timestamp resolution of the packets in the pcapng file belonging to this interface.
	TimestampResolution NgResolution
	// TimestampResolution is the timestamp offset in seconds of the packets in the pcapng file belonging to this interface.
	TimestampOffset uint64
	// SnapLength is the maximum packet length captured by this interface. 0 for unlimited
	SnapLength uint32
	// Statistics holds the interface statistics
	Statistics NgInterfaceStatistics

	secondMask uint64
	scaleUp    uint64
	scaleDown  uint64
}

// Resolution returns the timestamp resolution of acquired timestamps before scaling to NanosecondTimestampResolution.
func (i NgInterface) Resolution() gopacket.TimestampResolution {
	return i.TimestampResolution.ToTimestampResolution()
}

// NgSectionInfo contains additional information of a pcapng section
type NgSectionInfo struct {
	// Hardware is the hardware this file was generated on. This value might be empty if this option is missing.
	Hardware string
	// OS is the operating system this file was generated on. This value might be empty if this option is missing.
	OS string
	// Application is the user space application this file was generated with. This value might be empty if this option is missing.
	Application string
	// Comment can be an arbitrary comment. This value might be empty if this option is missing.
	Comment string
}

// NgPacketOptions contains additional information of a pcapng packet
type NgPacketOptions struct {
	// Comments can be multiple arbitrary comments. This value might be empty if this option is missing.
	Comments []string
	// Flags is a 32-bit flags word containing link-layer information
	Flags *NgEpbFlags
	// Hashes contains a list of hash of the packet
	Hashes []NgEpbHash
	// DropCount is a 64-bit unsigned integer value specifying the number of packets lost (by the interface and the operating system)
	// between this packet and the preceding one for the same interface or, for the first packet for an interface,
	// between this packet and the start of the capture process
	DropCount *uint64
	// PacketID is a 64-bit unsigned integer that uniquely identifies the packet
	PacketID *uint64
	// Queue is a 32-bit unsigned integer that identifies on which queue of the interface the specific packet was received
	Queue *uint32
	// Verdicts stores a list of verdict of the packet
	Verdicts []NgEpbVerdict
}

func (opts NgPacketOptions) toNgOptions() []ngOption {
	var ngOpts []ngOption
	for _, comment := range opts.Comments {
		ngOpts = append(ngOpts, ngOption{
			code:   ngOptionCodeComment,
			raw:    comment,
			length: uint16(len(comment)),
		})
	}
	if opts.Flags != nil {
		ngOpts = append(ngOpts, ngOption{
			code:   ngOptionCodeEpbFlags,
			raw:    opts.Flags.ToUint32(),
			length: 4,
		})
	}
	for _, hash := range opts.Hashes {
		v := hash.toBytes()
		ngOpts = append(ngOpts, ngOption{
			code:   ngOptionCodeEpbHash,
			raw:    v,
			length: uint16(len(v)),
		})
	}
	if opts.DropCount != nil {
		v := *opts.DropCount
		ngOpts = append(ngOpts, ngOption{
			code:   ngOptionCodeEpbDropCount,
			raw:    v,
			length: 8,
		})
	}
	if opts.PacketID != nil {
		v := *opts.PacketID
		ngOpts = append(ngOpts, ngOption{
			code:   ngOptionCodeEpbPacketID,
			raw:    v,
			length: 8,
		})
	}
	if opts.Queue != nil {
		v := *opts.Queue
		ngOpts = append(ngOpts, ngOption{
			code:   ngOptionCodeEpbQueue,
			raw:    v,
			length: 4,
		})
	}
	for _, verdict := range opts.Verdicts {
		v := verdict.toBytes()
		ngOpts = append(ngOpts, ngOption{
			code:   ngOptionCodeEpbVerdict,
			raw:    v,
			length: uint16(len(v)),
		})
	}

	return ngOpts
}

type ngAddressType uint16

const (
	ngAddressIPv4 uint16 = iota
	ngAddressIPv6
	ngAddressEUI48
	ngAddressEUI64
)

type NgAddress interface {
	Len() int
}

type NgIPAddress struct {
	Addr netip.Addr
}

func (addr *NgIPAddress) Len() int {
	return addr.Addr.BitLen() / 8
}

type NgEUIAddress struct {
	Addr net.HardwareAddr
}

func (addr *NgEUIAddress) Len() int {
	return len(addr.Addr)
}

type NgNameRecord struct {
	Addr  NgAddress
	Names []string
}
