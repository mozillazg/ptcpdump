package pktdump

import (
	"encoding/binary"
	"fmt"
	"github.com/gopacket/gopacket/layers"
	"strings"
)

// Token represents a value-string pair for lookup.
type Token struct {
	Value uint32
	Str   string
}

// tok2str converts a token value to a string, using the provided lookup table and a fallback format.
func tok2str(tokens []Token, fmts string, value uint32) string {
	for _, token := range tokens {
		if token.Value == value {
			return token.Str
		}
	}
	return fmt.Sprintf(fmts, value)
}

// MPTCPSub represents the subtype of an MPTCP option.
type MPTCPSub uint8

const (
	MPTCPSubCapable    MPTCPSub = 0x0
	MPTCPSubJoin       MPTCPSub = 0x1
	MPTCPSubDSS        MPTCPSub = 0x2
	MPTCPSubAddAddr    MPTCPSub = 0x3
	MPTCPSubRemoveAddr MPTCPSub = 0x4
	MPTCPSubPrio       MPTCPSub = 0x5
	MPTCPSubFail       MPTCPSub = 0x6
	MPTCPSubFClose     MPTCPSub = 0x7
	MPTCPSubTCPRST     MPTCPSub = 0x8
)

// MPTCPOption represents an MPTCP option.
type MPTCPOption struct {
	Kind   uint8
	Len    uint8
	SubEtc uint8 // subtype upper 4 bits, other stuff lower 4 bits
}

// MPTCPSubKind returns the subtype of the MPTCP option.
func (o *MPTCPOption) MPTCPSubKind() MPTCPSub {
	return MPTCPSub((o.SubEtc >> 4) & 0xF)
}

// MP_CAPABLE_A is a flag for the "capable" option.
const MP_CAPABLE_A = 0x80

// MPCapableFlags represents the flags for the "capable" option.
var MPCapableFlags = []Token{
	{MP_CAPABLE_A, "A"},
	{0x40, "B"},
	{0x20, "C"},
	{0x10, "D"},
	{0x08, "E"},
	{0x04, "F"},
	{0x02, "G"},
	{0x01, "H"},
}

// MPCapable represents the "capable" option data.
type MPCapable struct {
	Kind        uint8
	Len         uint8
	SubVer      uint8
	Flags       uint8
	SenderKey   uint64
	ReceiverKey uint64
	DataLen     uint16
}

// MP_CAPABLE_OPT_VERSION returns the version from the "capable" option subtype.
func MP_CAPABLE_OPT_VERSION(subVer uint8) uint8 {
	return (subVer >> 0) & 0xF
}

// MPJoin represents the "join" option data.
type MPJoin struct {
	Kind   uint8
	Len    uint8
	SubB   uint8
	AddrID uint8
	U      struct {
		Syn struct {
			Token uint32
			Nonce uint32
		}
		SynAck struct {
			Mac   uint64
			Nonce uint32
		}
		Ack struct {
			Mac [20]byte
		}
	}
}

// MP_JOIN_B is a flag for the "join" option.
const MP_JOIN_B = 0x01

// MPDSS represents the "dss" option data.
type MPDSS struct {
	Kind  uint8
	Len   uint8
	Sub   uint8
	Flags uint8
}

// MP_DSS_F is a flag for the "dss" option.
const MP_DSS_F = 0x10

// MP_DSS_m is a flag for the "dss" option.
const MP_DSS_m = 0x08

// MP_DSS_M is a flag for the "dss" option.
const MP_DSS_M = 0x04

// MP_DSS_a is a flag for the "dss" option.
const MP_DSS_a = 0x02

// MP_DSS_A is a flag for the "dss" option.
const MP_DSS_A = 0x01

// MPTCPAddrSubEchoBits represents the subtype/echo bits for the "add-addr" option.
var MPTCPAddrSubEchoBits = []Token{
	{0x6, "v0-ip6"},
	{0x4, "v0-ip4"},
	{0x1, "v1-echo"},
	{0x0, "v1"},
}

// MPAddAddr represents the "add-addr" option data.
type MPAddAddr struct {
	Kind    uint8
	Len     uint8
	SubEcho uint8
	AddrID  uint8
	U       struct {
		V4 struct {
			Addr uint32
			Port uint16
			Mac  uint64
		}
		V4NP struct {
			Addr uint32
			Mac  uint64
		}
		V6 struct {
			Addr [16]byte
			Port uint16
			Mac  uint64
		}
		V6NP struct {
			Addr [16]byte
			Mac  uint64
		}
	}
}

// MPRemoveAddr represents the "rem-addr" option data.
type MPRemoveAddr struct {
	Kind    uint8
	Len     uint8
	Sub     uint8
	AddrsID []uint8 // list of addr_id
}

// MPFail represents the "fail" option data.
type MPFail struct {
	Kind    uint8
	Len     uint8
	Sub     uint8
	Resv    uint8
	DataSeq uint64
}

// MPClose represents the "fast-close" option data.
type MPClose struct {
	Kind uint8
	Len  uint8
	Sub  uint8
	Rsv  uint8
	Key  [8]byte
}

// MPPrio represents the "prio" option data.
type MPPrio struct {
	Kind   uint8
	Len    uint8
	SubB   uint8
	AddrID uint8
}

// MP_PRIO_B is a flag for the "prio" option.
const MP_PRIO_B = 0x01

// MPTCPFlags represents the flags for the "tcprst" option.
var MPTCPFlags = []Token{
	{0x08, "U"},
	{0x04, "V"},
	{0x02, "W"},
	{0x01, "T"},
}

// MPTCPRSTReasons represents the reasons for the "tcprst" option.
var MPTCPRSTReasons = []Token{
	{0x06, "Middlebox interference"},
	{0x05, "Unacceptable performance"},
	{0x04, "Too much outstanding data"},
	{0x03, "Administratively prohibited"},
	{0x02, "Lack of resources"},
	{0x01, "MPTCP-specific error"},
	{0x00, "Unspecified error"},
}

// MPTCPRST represents the "tcprst" option data.
type MPTCPRST struct {
	Kind   uint8
	Len    uint8
	SubB   uint8
	Reason uint8
}

// dummyPrint is a placeholder print function for unknown options.
func dummyPrint(options *mptcpPrintOptions, opt layers.TCPOption, buf *strings.Builder) error {
	return nil
}

// mpCapablePrint prints the "capable" option.
func mpCapablePrint(options *mptcpPrintOptions, opt layers.TCPOption, buf *strings.Builder) error {
	mpc := MPCapable{}
	mpc.Kind = uint8(opt.OptionType)
	mpc.Len = opt.OptionLength
	mpc.SubVer = opt.OptionMPTCPMpCapable.Version
	mpc.Flags = opt.OptionMPTCPMpCapable.Flags
	mpc.SenderKey = opt.OptionMPTCPMpCapable.SendKey
	mpc.ReceiverKey = opt.OptionMPTCPMpCapable.ReceivKey
	mpc.DataLen = opt.OptionMPTCPMpCapable.DataLength
	optLen := opt.OptionLength

	version := MP_CAPABLE_OPT_VERSION(mpc.SubVer)
	switch version {
	case 0, 1:
		buf.WriteString(fmt.Sprintf(" v%d", version))
	default:
		return fmt.Errorf("unknown version: %d", version)
	}

	flagsStr := bittok2str(MPCapableFlags, "none", uint32(mpc.Flags))
	buf.WriteString(fmt.Sprintf(" flags [%s]", flagsStr))

	csumEnabled := mpc.Flags&MP_CAPABLE_A != 0
	if csumEnabled {
		buf.WriteString(fmt.Sprintf(" csum"))
	}

	if optLen >= 12 {
		buf.WriteString(fmt.Sprintf(" {0x%x", mpc.SenderKey))
		if optLen >= 20 {
			buf.WriteString(fmt.Sprintf(",0x%x", mpc.ReceiverKey))
		}
		if (optLen == 22 && !csumEnabled) || optLen == 24 {
			buf.WriteString(fmt.Sprintf(",data_len=%d", mpc.DataLen))
		}
		buf.WriteString(fmt.Sprintf("}"))
	}

	return nil
}

// mpJoinPrint prints the "join" option.
func mpJoinPrint(options *mptcpPrintOptions, opt layers.TCPOption, buf *strings.Builder) error {
	mpj := MPJoin{}
	mpj.Kind = uint8(opt.OptionType)
	mpj.Len = opt.OptionLength
	mpj.SubB = opt.OptionMPTCPMpJoin.SubB
	mpj.AddrID = opt.OptionMPTCPMpJoin.AddrID
	optLen := opt.OptionLength

	if optLen != 24 {
		if mpj.SubB&MP_JOIN_B != 0 {
			buf.WriteString(fmt.Sprintf(" backup"))
		}
		buf.WriteString(fmt.Sprintf(" id %d", mpj.AddrID))
	}

	switch optLen {
	case 12: // SYN
		mpj.U.Syn.Token = opt.OptionMPTCPMpJoin.ReceivToken
		mpj.U.Syn.Nonce = opt.OptionMPTCPMpJoin.SendRandNum
		buf.WriteString(fmt.Sprintf(" token 0x%x nonce 0x%x", mpj.U.Syn.Token, mpj.U.Syn.Nonce))
	case 16: // SYN/ACK
		mpj.U.SynAck.Mac = binary.BigEndian.Uint64(opt.OptionMPTCPMpJoin.SendHMAC)
		mpj.U.Syn.Nonce = opt.OptionMPTCPMpJoin.SendRandNum
		buf.WriteString(fmt.Sprintf(" hmac 0x%x nonce 0x%x", mpj.U.SynAck.Mac, mpj.U.SynAck.Nonce))
	case 24: // ACK
		copy(mpj.U.Ack.Mac[:], opt.OptionMPTCPMpJoin.SendHMAC)
		buf.WriteString(fmt.Sprintf(" hmac 0x"))
		for i := 0; i < len(mpj.U.Ack.Mac); i++ {
			buf.WriteString(fmt.Sprintf("%02x", mpj.U.Ack.Mac[i]))
		}
	default:
		return fmt.Errorf("invalid length for join option: %d", optLen)
	}

	return nil
}

var TH_SYN uint8 = (0x02)

// mpDSSPrint prints the "dss" option.
func mpDSSPrint(options *mptcpPrintOptions, opt layers.TCPOption, buf *strings.Builder) error {
	mdss := MPDSS{}
	mdss.Kind = uint8(opt.OptionType)
	mdss.Len = opt.OptionLength
	mdss.Sub = opt.OptionMPTCPDss.SubB
	mdss.Flags = opt.OptionMPTCPDss.Flags
	optLen := opt.OptionLength

	if optLen < 4 {
		return fmt.Errorf("invalid length for dss option: %d", optLen)
	}

	//if flags&TH_SYN != 0 {
	//	return fmt.Errorf("dss option not allowed with SYN flag")
	//}

	if mdss.Flags&MP_DSS_F != 0 {
		buf.WriteString(fmt.Sprintf(" fin"))
	}

	optLen -= 4

	if mdss.Flags&MP_DSS_A != 0 {
		// Ack present
		buf.WriteString(fmt.Sprintf(" ack "))

		// If the 'a' flag is set, we have an 8-byte ack; if it's clear, we have a 4-byte ack.
		if mdss.Flags&MP_DSS_a != 0 {
			if optLen < 8 {
				return fmt.Errorf("invalid length for dss ack: %d", optLen)
			}
			ack := binary.BigEndian.Uint64(opt.OptionMPTCPDss.DataAck)
			buf.WriteString(fmt.Sprintf("%d", ack))
			optLen -= 8
		} else {
			if optLen < 4 {
				return fmt.Errorf("invalid length for dss ack: %d", optLen)
			}
			var ack uint64
			switch len(opt.OptionMPTCPDss.DataAck) {
			case 8:
				ack = binary.BigEndian.Uint64(opt.OptionMPTCPDss.DataAck)
			case 4:
				ack = uint64(binary.BigEndian.Uint32(opt.OptionMPTCPDss.DataAck))
			}
			buf.WriteString(fmt.Sprintf("%d", ack))
			optLen -= 4
		}
	}

	if mdss.Flags&MP_DSS_M != 0 {
		// Data Sequence Number (DSN), Subflow Sequence Number (SSN), Data-Level Length present, and Checksum possibly present.
		buf.WriteString(fmt.Sprintf(" seq "))

		// If the 'm' flag is set, we have an 8-byte NDS; if it's clear, we have a 4-byte DSN.
		if mdss.Flags&MP_DSS_m != 0 {
			if optLen < 8 {
				return fmt.Errorf("invalid length for dss seq: %d", optLen)
			}
			var seq uint64
			switch len(opt.OptionMPTCPDss.DataAck) {
			case 8:
				seq = binary.BigEndian.Uint64(opt.OptionMPTCPDss.DSN)
			case 4:
				seq = uint64(binary.BigEndian.Uint32(opt.OptionMPTCPDss.DSN))
			}
			buf.WriteString(fmt.Sprintf("%d", seq))
			optLen -= 8
		} else {
			if optLen < 4 {
				return fmt.Errorf("invalid length for dss seq: %d", optLen)
			}
			seq := binary.BigEndian.Uint64(opt.OptionMPTCPDss.DSN)
			buf.WriteString(fmt.Sprintf("%d", seq))
			optLen -= 4
		}

		if optLen < 4 {
			return fmt.Errorf("invalid length for dss subseq: %d", optLen)
		}
		subSeq := opt.OptionMPTCPDss.SSN
		buf.WriteString(fmt.Sprintf(" subseq %d", subSeq))
		optLen -= 4

		if optLen < 2 {
			return fmt.Errorf("invalid length for dss len: %d", optLen)
		}
		var length = opt.OptionMPTCPDss.DataLength
		buf.WriteString(fmt.Sprintf(" len %d", length))
		optLen -= 2

		// The Checksum is present only if negotiated.
		// If there are at least 2 bytes left, process the next 2 bytes as the Checksum.
		if optLen >= 2 {
			var csum uint16 = opt.OptionMPTCPDss.Checksum
			buf.WriteString(fmt.Sprintf(" csum 0x%x", csum))
			optLen -= 2
		}
	}

	if optLen != 0 {
		return fmt.Errorf("invalid length for dss option: %d", optLen)
	}

	return nil
}

// addAddrPrint prints the "add-addr" option.
func addAddrPrint(options *mptcpPrintOptions, opt layers.TCPOption, buf *strings.Builder) error {
	addAddr := MPAddAddr{}
	addAddr.Kind = uint8(opt.OptionType)
	addAddr.Len = opt.OptionLength
	addAddr.SubEcho = opt.OptionMPTCPAddAddr.SubEcho
	addAddr.AddrID = opt.OptionMPTCPAddAddr.SubEcho
	optLen := opt.OptionLength

	if !(optLen == 8 || optLen == 10 || optLen == 16 || optLen == 18 || optLen == 20 || optLen == 22 || optLen == 28 || optLen == 30) {
		return fmt.Errorf("invalid length for add-addr option: %d", optLen)
	}

	subEchoStr := tok2str(MPTCPAddrSubEchoBits, "[bad version/echo]", uint32(addAddr.SubEcho&0xF))
	buf.WriteString(fmt.Sprintf(" %s", subEchoStr))
	buf.WriteString(fmt.Sprintf(" id %d", addAddr.AddrID))

	if optLen == 8 || optLen == 10 || optLen == 16 || optLen == 18 {
		addAddr.U.V4.Addr = binary.BigEndian.Uint32(opt.OptionMPTCPAddAddr.Address)
		if optLen == 10 || optLen == 18 {
			addAddr.U.V4.Port = opt.OptionMPTCPAddAddr.Port
		}
		if optLen == 16 {
			addAddr.U.V4NP.Mac = binary.BigEndian.Uint64(opt.OptionMPTCPAddAddr.SendHMAC)
		}
		if optLen == 18 {
			addAddr.U.V4NP.Mac = binary.BigEndian.Uint64(opt.OptionMPTCPAddAddr.SendHMAC)
		}

		buf.WriteString(fmt.Sprintf(" %d", addAddr.U.V4.Addr))
		if optLen == 10 || optLen == 18 {
			buf.WriteString(fmt.Sprintf(":%d", addAddr.U.V4.Port))
		}
		if optLen == 16 {
			buf.WriteString(fmt.Sprintf(" hmac 0x%x", addAddr.U.V4NP.Mac))
		}
		if optLen == 18 {
			buf.WriteString(fmt.Sprintf(" hmac 0x%x", addAddr.U.V4.Mac))
		}
	}

	if optLen == 20 || optLen == 22 || optLen == 28 || optLen == 30 {
		copy(addAddr.U.V6.Addr[:], opt.OptionMPTCPAddAddr.Address)
		if optLen == 22 || optLen == 30 {
			addAddr.U.V6.Port = opt.OptionMPTCPAddAddr.Port
		}
		if optLen == 28 {
			addAddr.U.V6NP.Mac = binary.BigEndian.Uint64(opt.OptionMPTCPAddAddr.SendHMAC)
		}
		if optLen == 30 {
			addAddr.U.V6NP.Mac = binary.BigEndian.Uint64(opt.OptionMPTCPAddAddr.SendHMAC)
		}

		buf.WriteString(fmt.Sprintf(" %v", addAddr.U.V6.Addr))
		if optLen == 22 || optLen == 30 {
			buf.WriteString(fmt.Sprintf(":%d", addAddr.U.V6.Port))
		}
		if optLen == 28 {
			buf.WriteString(fmt.Sprintf(" hmac 0x%x", addAddr.U.V6NP.Mac))
		}
		if optLen == 30 {
			buf.WriteString(fmt.Sprintf(" hmac 0x%x", addAddr.U.V6.Mac))
		}
	}

	return nil
}

// removeAddrPrint prints the "rem-addr" option.
func removeAddrPrint(options *mptcpPrintOptions, opt layers.TCPOption, buf *strings.Builder) error {
	removeAddr := MPRemoveAddr{}
	removeAddr.Kind = uint8(opt.OptionType)
	removeAddr.Len = opt.OptionLength
	removeAddr.Sub = opt.OptionMTCPRemAddr.Sub
	optLen := int(opt.OptionLength)

	if optLen < 4 {
		return fmt.Errorf("invalid length for rem-addr option: %d", optLen)
	}

	optLen -= 3
	removeAddr.AddrsID = make([]uint8, optLen)
	removeAddr.AddrsID = opt.OptionMTCPRemAddr.AddrIDs

	buf.WriteString(fmt.Sprintf(" id"))
	for i := 0; i < optLen; i++ {
		buf.WriteString(fmt.Sprintf(" %d", removeAddr.AddrsID[i]))
	}
	return nil
}

// mpPrioPrint prints the "prio" option.
func mpPrioPrint(options *mptcpPrintOptions, opt layers.TCPOption, buf *strings.Builder) error {
	mpPrio := MPPrio{}
	mpPrio.Kind = uint8(opt.OptionType)
	mpPrio.Len = opt.OptionLength
	mpPrio.SubB = opt.OptionMPTCPMpPrio.SubB
	optLen := opt.OptionLength

	if optLen != 3 && optLen != 4 {
		return fmt.Errorf("invalid length for prio option: %d", optLen)
	}

	if mpPrio.SubB&MP_PRIO_B != 0 {
		buf.WriteString(fmt.Sprintf(" backup"))
	} else {
		buf.WriteString(fmt.Sprintf(" non-backup"))
	}

	if optLen == 4 {
		mpPrio.AddrID = opt.OptionMPTCPMpPrio.AddrID
		buf.WriteString(fmt.Sprintf(" id %d", mpPrio.AddrID))
	}

	return nil
}

// mpFailPrint prints the "fail" option.
func mpFailPrint(options *mptcpPrintOptions, opt layers.TCPOption, buf *strings.Builder) error {
	optLen := opt.OptionLength
	if optLen != 12 {
		return fmt.Errorf("invalid length for fail option: %d", optLen)
	}
	var dataSeq uint64 = opt.OptionMTCPMPFail.DSN
	buf.WriteString(fmt.Sprintf(" seq %d", dataSeq))

	return nil
}

// mpFastClosePrint prints the "fast-close" option.
func mpFastClosePrint(options *mptcpPrintOptions, opt layers.TCPOption, buf *strings.Builder) error {
	optLen := opt.OptionLength
	if optLen != 12 {
		return fmt.Errorf("invalid length for fast-close option: %d", optLen)
	}
	var key = binary.BigEndian.Uint64(opt.OptionMTCPMPFastClose.ReceivKey)
	buf.WriteString(fmt.Sprintf(" key 0x%x", key))

	return nil
}

// mpTCPRSTPrint prints the "tcprst" option.
func mpTCPRSTPrint(options *mptcpPrintOptions, opt layers.TCPOption, buf *strings.Builder) error {
	mpr := MPTCPRST{}
	mpr.Kind = uint8(opt.OptionType)
	mpr.Len = opt.OptionLength
	mpr.SubB = opt.OptionMPTCPMPTcpRst.SubB
	mpr.Reason = opt.OptionMPTCPMPTcpRst.Reason
	optLen := opt.OptionLength

	if optLen != 4 {
		return fmt.Errorf("invalid length for tcprst option: %d", optLen)
	}

	flagsStr := bittok2str(MPTCPFlags, "none", uint32(mpr.SubB))
	buf.WriteString(fmt.Sprintf(" flags [%s]", flagsStr))

	reasonStr := tok2str(MPTCPRSTReasons, "unknown (0x%02x)", uint32(mpr.Reason))
	buf.WriteString(fmt.Sprintf(" reason %s", reasonStr))

	return nil
}

// mptcpPrintOptions represents the options for MPTCP printing.
type mptcpPrintOptions struct {
	// TODO: Add any relevant options here.
}

// MPTCPPrintOptions defines the print functions for each MPTCP option.
var MPTCPPrintOptions = []struct {
	Name  string
	Print func(*mptcpPrintOptions, layers.TCPOption, *strings.Builder) error
}{
	{"capable", mpCapablePrint},
	{"join", mpJoinPrint},
	{"dss", mpDSSPrint},
	{"add-addr", addAddrPrint},
	{"rem-addr", removeAddrPrint},
	{"prio", mpPrioPrint},
	{"fail", mpFailPrint},
	{"fast-close", mpFastClosePrint},
	{"tcprst", mpTCPRSTPrint},
	{"unknown", dummyPrint},
}

// mptcpPrint prints an MPTCP option.
func mptcpPrint(options *mptcpPrintOptions, opt layers.TCPOption) (string, error) {
	buf := strings.Builder{}
	// Ensure the length is valid.
	length := opt.OptionLength
	if length < 3 {
		return "", fmt.Errorf("invalid length for MPTCP option: %d", length)
	}
	buf.WriteString("mptcp")

	// Parse the MPTCP option.
	//mptcpOpt := MPTCPOption{
	//	Kind:   0,
	//	Len:    opt.OptionLength,
	//	SubEtc: uint8(opt.OptionMultipath),
	//}

	// Determine the subtype.
	subtype := MPTCPSub(opt.OptionMultipath)
	if subtype > MPTCPSubTCPRST {
		subtype = MPTCPSubTCPRST + 1
	}

	// Print the option details.
	buf.WriteString(fmt.Sprintf(" %d", length))
	buf.WriteString(fmt.Sprintf(" %s", MPTCPPrintOptions[subtype].Name))

	// Call the corresponding print function for the subtype.
	err := MPTCPPrintOptions[subtype].Print(options, opt, &buf)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// bittok2str converts a set of flags to a string representation.
func bittok2str(tokens []Token, defaultStr string, value uint32) string {
	var strs []string
	for _, token := range tokens {
		if value&token.Value != 0 {
			strs = append(strs, token.Str)
		}
	}
	if len(strs) == 0 {
		return defaultStr
	}
	return fmt.Sprintf("%s", strings.Join(strs, " "))
}

func formatMPTCP(opt layers.TCPOption) string {
	s, _ := mptcpPrint(&mptcpPrintOptions{}, opt)
	return s
}
