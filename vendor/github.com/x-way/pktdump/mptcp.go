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

// MPCapable represents the "capable" option data.
type MPCapable struct {
	Kind        uint8
	Len         uint8
	SubVer      uint8
	SenderKey   uint64
	ReceiverKey uint64
	DataLen     uint16
}

// MPJoin represents the "join" option data.
type MPJoin struct {
	Kind   uint8
	Len    uint8
	Backup bool
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
	AddrID uint8
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
func dummyPrint(options *mptcpPrintOptions, opt layers.TCPOption, buf *strings.Builder) {}

// mpCapablePrint prints the "capable" option.
func mpCapablePrint(options *mptcpPrintOptions, opt layers.TCPOption, buf *strings.Builder) {
	mpc := MPCapable{}
	mpc.Kind = uint8(opt.OptionType)
	mpc.Len = opt.OptionLength
	mpc.SubVer = opt.OptionMPTCPMpCapable.Version
	mpc.SenderKey = bytesToUint64(opt.OptionMPTCPMpCapable.SendKey)
	mpc.ReceiverKey = bytesToUint64(opt.OptionMPTCPMpCapable.ReceivKey)
	mpc.DataLen = opt.OptionMPTCPMpCapable.DataLength
	optLen := opt.OptionLength

	version := mpc.SubVer
	switch version {
	case 0, 1:
		buf.WriteString(fmt.Sprintf(" v%d", version))
	default:
	}

	var flags []string
	if opt.OptionMPTCPMpCapable.A {
		flags = append(flags, "A")
	}
	if opt.OptionMPTCPMpCapable.B {
		flags = append(flags, "B")
	}
	if opt.OptionMPTCPMpCapable.C {
		flags = append(flags, "C")
	}
	if opt.OptionMPTCPMpCapable.D {
		flags = append(flags, "D")
	}
	if opt.OptionMPTCPMpCapable.E {
		flags = append(flags, "E")
	}
	if opt.OptionMPTCPMpCapable.F {
		flags = append(flags, "F")
	}
	if opt.OptionMPTCPMpCapable.G {
		flags = append(flags, "G")
	}
	if opt.OptionMPTCPMpCapable.H {
		flags = append(flags, "H")
	}

	flagsStr := strings.Join(flags, "")
	if flagsStr == "" {
		flagsStr = "none"
	}
	buf.WriteString(fmt.Sprintf(" flags [%s]", flagsStr))

	csumEnabled := opt.OptionMPTCPMpCapable.A
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

	return
}

// mpJoinPrint prints the "join" option.
func mpJoinPrint(options *mptcpPrintOptions, opt layers.TCPOption, buf *strings.Builder) {
	mpj := MPJoin{}
	mpj.Kind = uint8(opt.OptionType)
	mpj.Len = opt.OptionLength
	mpj.Backup = opt.OptionMPTCPMpJoin.Backup
	mpj.AddrID = opt.OptionMPTCPMpJoin.AddrID
	optLen := opt.OptionLength

	if optLen != 24 {
		if mpj.Backup {
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
		mpj.U.SynAck.Mac = bytesToUint64(opt.OptionMPTCPMpJoin.SendHMAC)
		mpj.U.SynAck.Nonce = opt.OptionMPTCPMpJoin.SendRandNum
		buf.WriteString(fmt.Sprintf(" hmac 0x%x nonce 0x%x", mpj.U.SynAck.Mac, mpj.U.SynAck.Nonce))
	case 24: // ACK
		buf.WriteString(fmt.Sprintf(" hmac 0x"))
		for _, v := range opt.OptionMPTCPMpJoin.SendHMAC {
			buf.WriteString(fmt.Sprintf("%02x", v))
		}
	default:
	}
}

// mpDSSPrint prints the "dss" option.
func mpDSSPrint(options *mptcpPrintOptions, opt layers.TCPOption, buf *strings.Builder) {
	mdss := MPDSS{}
	mdss.Kind = uint8(opt.OptionType)
	mdss.Len = opt.OptionLength
	optLen := opt.OptionLength

	if opt.OptionMPTCPDss.F {
		buf.WriteString(fmt.Sprintf(" fin"))
	}

	optLen -= 4

	if opt.OptionMPTCPDss.A {
		// Ack present
		buf.WriteString(fmt.Sprintf(" ack "))

		// If the 'a' flag is set, we have an 8-byte ack; if it's clear, we have a 4-byte ack.
		var ack uint64
		switch len(opt.OptionMPTCPDss.DataAck) {
		case 8:
			ack = bytesToUint64(opt.OptionMPTCPDss.DataAck)
			optLen -= 8
		case 4:
			ack = bytesToUint64(opt.OptionMPTCPDss.DataAck)
			optLen -= 4
		}
		buf.WriteString(fmt.Sprintf("%d", ack))
	}

	if opt.OptionMPTCPDss.M {
		// Data Sequence Number (DSN), Subflow Sequence Number (SSN), Data-Level Length present, and Checksum possibly present.
		buf.WriteString(fmt.Sprintf(" seq "))

		// If the 'm' flag is set, we have an 8-byte NDS; if it's clear, we have a 4-byte DSN.
		var seq uint64
		switch len(opt.OptionMPTCPDss.DSN) {
		case 8:
			seq = bytesToUint64(opt.OptionMPTCPDss.DSN)
			optLen -= 8
		case 4:
			seq = bytesToUint64(opt.OptionMPTCPDss.DSN)
			optLen -= 4
		}
		buf.WriteString(fmt.Sprintf("%d", seq))

		if optLen < 4 {
			return
		}
		subSeq := opt.OptionMPTCPDss.SSN
		buf.WriteString(fmt.Sprintf(" subseq %d", subSeq))
		optLen -= 4

		if optLen < 2 {
			return
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
}

// addAddrPrint prints the "add-addr" option.
func addAddrPrint(options *mptcpPrintOptions, opt layers.TCPOption, buf *strings.Builder) {
	addAddr := MPAddAddr{}
	addAddr.Kind = uint8(opt.OptionType)
	addAddr.Len = opt.OptionLength
	addAddr.AddrID = opt.OptionMPTCPAddAddr.AddrID
	addAddr.SubEcho = opt.OptionMPTCPAddAddr.IPVer
	if opt.OptionMPTCPAddAddr.E {
		addAddr.SubEcho = 0x01
	}

	subEchoStr := tok2str(MPTCPAddrSubEchoBits, "[bad version/echo]", uint32(addAddr.SubEcho))
	buf.WriteString(fmt.Sprintf(" %s", subEchoStr))
	buf.WriteString(fmt.Sprintf(" id %d", addAddr.AddrID))

	buf.WriteString(fmt.Sprintf(" %s", opt.OptionMPTCPAddAddr.Address))
	if opt.OptionMPTCPAddAddr.Port > 0 {
		buf.WriteString(fmt.Sprintf(":%d", opt.OptionMPTCPAddAddr.Port))
	}
	if len(opt.OptionMPTCPAddAddr.SendHMAC) > 0 {
		buf.WriteString(fmt.Sprintf(" hmac 0x%x", bytesToUint64(opt.OptionMPTCPAddAddr.SendHMAC)))
	}
}

// removeAddrPrint prints the "rem-addr" option.
func removeAddrPrint(options *mptcpPrintOptions, opt layers.TCPOption, buf *strings.Builder) {
	removeAddr := MPRemoveAddr{}
	removeAddr.Kind = uint8(opt.OptionType)
	removeAddr.Len = opt.OptionLength

	buf.WriteString(fmt.Sprintf(" id"))
	for _, id := range opt.OptionMTCPRemAddr.AddrIDs {
		buf.WriteString(fmt.Sprintf(" %d", id))
	}
}

// mpPrioPrint prints the "prio" option.
func mpPrioPrint(options *mptcpPrintOptions, opt layers.TCPOption, buf *strings.Builder) {
	mpPrio := MPPrio{}
	mpPrio.Kind = uint8(opt.OptionType)
	mpPrio.Len = opt.OptionLength
	optLen := opt.OptionLength

	if opt.OptionMPTCPMpPrio.Backup {
		buf.WriteString(fmt.Sprintf(" backup"))
	} else {
		buf.WriteString(fmt.Sprintf(" non-backup"))
	}

	if optLen == 4 {
		mpPrio.AddrID = opt.OptionMPTCPMpPrio.AddrID
		buf.WriteString(fmt.Sprintf(" id %d", mpPrio.AddrID))
	}
}

// mpFailPrint prints the "fail" option.
func mpFailPrint(options *mptcpPrintOptions, opt layers.TCPOption, buf *strings.Builder) {
	var dataSeq uint64 = opt.OptionMTCPMPFail.DSN
	buf.WriteString(fmt.Sprintf(" seq %d", dataSeq))
}

// mpFastClosePrint prints the "fast-close" option.
func mpFastClosePrint(options *mptcpPrintOptions, opt layers.TCPOption, buf *strings.Builder) {
	var key = bytesToUint64(opt.OptionMTCPMPFastClose.ReceivKey)
	buf.WriteString(fmt.Sprintf(" key 0x%x", key))
}

// mpTCPRSTPrint prints the "tcprst" option.
func mpTCPRSTPrint(options *mptcpPrintOptions, opt layers.TCPOption, buf *strings.Builder) {
	mpr := MPTCPRST{}
	mpr.Kind = uint8(opt.OptionType)
	mpr.Len = opt.OptionLength
	mpr.Reason = opt.OptionMPTCPMPTcpRst.Reason

	var flags []string
	if opt.OptionMPTCPMPTcpRst.T {
		flags = append(flags, "T")
	}
	if opt.OptionMPTCPMPTcpRst.U {
		flags = append(flags, "U")
	}
	if opt.OptionMPTCPMPTcpRst.V {
		flags = append(flags, "V")
	}
	if opt.OptionMPTCPMPTcpRst.W {
		flags = append(flags, "W")
	}
	flagsStr := strings.Join(flags, "")
	if flagsStr == "" {
		flagsStr = "none"
	}
	buf.WriteString(fmt.Sprintf(" flags [%s]", flagsStr))

	reasonStr := tok2str(MPTCPRSTReasons, "unknown (0x%02x)", uint32(mpr.Reason))
	buf.WriteString(fmt.Sprintf(" reason %s", reasonStr))
}

// mptcpPrintOptions represents the options for MPTCP printing.
type mptcpPrintOptions struct {
	// TODO: Add any relevant options here.
}

// MPTCPPrintOptions defines the print functions for each MPTCP option.
var MPTCPPrintOptions = []struct {
	Name  string
	Print func(*mptcpPrintOptions, layers.TCPOption, *strings.Builder)
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
func mptcpPrint(options *mptcpPrintOptions, opt layers.TCPOption) string {
	buf := strings.Builder{}
	// Ensure the length is valid.
	length := opt.OptionLength

	buf.WriteString("mptcp")

	// Determine the subtype.
	subtype := MPTCPSub(opt.OptionMultipath)
	if subtype > MPTCPSubTCPRST {
		subtype = MPTCPSubTCPRST + 1
	}

	// Print the option details.
	buf.WriteString(fmt.Sprintf(" %d", length))
	buf.WriteString(fmt.Sprintf(" %s", MPTCPPrintOptions[subtype].Name))

	// Call the corresponding print function for the subtype.
	MPTCPPrintOptions[subtype].Print(options, opt, &buf)

	return buf.String()
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

func bytesToUint64(b []byte) uint64 {
	length := len(b)
	if length >= 8 {
		return binary.BigEndian.Uint64(b)
	}
	if length == 4 {
		return uint64(binary.BigEndian.Uint32(b))
	}
	if length == 2 {
		return uint64(binary.BigEndian.Uint16(b))
	}
	return 0
}

func formatMPTCP(opt layers.TCPOption) string {
	return mptcpPrint(&mptcpPrintOptions{}, opt)
}
