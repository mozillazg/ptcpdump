package log

import (
	"sync/atomic"
	"time"
)

var counter = Fastrandn(4294967295)

// XID represents a unique request id
type XID [12]byte

var nilXID XID

// NewXID generates a globally unique XID
func NewXID() XID {
	sec, _, _ := now()
	return NewXIDWithTime(sec)
}

// NewXIDWithTime generates a globally unique XID with unix timestamp
func NewXIDWithTime(timestamp int64) (x XID) {
	// timestamp
	x[0] = byte(timestamp >> 24)
	x[1] = byte(timestamp >> 16)
	x[2] = byte(timestamp >> 8)
	x[3] = byte(timestamp)
	// machine
	x[4] = machine[0]
	x[5] = machine[1]
	x[6] = machine[2]
	// pid
	x[7] = byte(pid >> 8)
	x[8] = byte(pid)
	// counter
	i := atomic.AddUint32(&counter, 1)
	x[9] = byte(i >> 16)
	x[10] = byte(i >> 8)
	x[11] = byte(i)
	return
}

// Time returns the timestamp part of the id.
func (x XID) Time() time.Time {
	return time.Unix(int64(x[0])<<32|int64(x[1])<<16|int64(x[2])<<8|int64(x[3]), 0)
}

// Machine returns the 3-byte machine id part of the id.
func (x XID) Machine() []byte {
	return x[4:7]
}

// Pid returns the process id part of the id.
func (x XID) Pid() uint16 {
	return uint16(x[7])<<8 | uint16(x[8])
}

// Counter returns the incrementing value part of the id.
func (x XID) Counter() uint32 {
	return uint32(x[9])<<16 | uint32(x[10])<<8 | uint32(x[11])
}

const base32 = "0123456789abcdefghijklmnopqrstuv"

func (x XID) encode(dst []byte) {
	dst[19] = base32[(x[11]<<4)&0x1F]
	dst[18] = base32[(x[11]>>1)&0x1F]
	dst[17] = base32[(x[11]>>6)&0x1F|(x[10]<<2)&0x1F]
	dst[16] = base32[x[10]>>3]
	dst[15] = base32[x[9]&0x1F]
	dst[14] = base32[(x[9]>>5)|(x[8]<<3)&0x1F]
	dst[13] = base32[(x[8]>>2)&0x1F]
	dst[12] = base32[x[8]>>7|(x[7]<<1)&0x1F]
	dst[11] = base32[(x[7]>>4)&0x1F|(x[6]<<4)&0x1F]
	dst[10] = base32[(x[6]>>1)&0x1F]
	dst[9] = base32[(x[6]>>6)&0x1F|(x[5]<<2)&0x1F]
	dst[8] = base32[x[5]>>3]
	dst[7] = base32[x[4]&0x1F]
	dst[6] = base32[x[4]>>5|(x[3]<<3)&0x1F]
	dst[5] = base32[(x[3]>>2)&0x1F]
	dst[4] = base32[x[3]>>7|(x[2]<<1)&0x1F]
	dst[3] = base32[(x[2]>>4)&0x1F|(x[1]<<4)&0x1F]
	dst[2] = base32[(x[1]>>1)&0x1F]
	dst[1] = base32[(x[1]>>6)&0x1F|(x[0]<<2)&0x1F]
	dst[0] = base32[x[0]>>3]
}

// String returns a base32 hex lowercased representation of the id.
func (x XID) String() string {
	dst := make([]byte, 20)
	x.encode(dst)
	return b2s(dst)
}

// MarshalText implements encoding/text TextMarshaler interface
func (x XID) MarshalText() (dst []byte, err error) {
	dst = make([]byte, 20)
	x.encode(dst)
	return
}

// MarshalJSON implements encoding/json Marshaler interface
func (x XID) MarshalJSON() (dst []byte, err error) {
	if x == nilXID {
		dst = []byte("null")
	} else {
		dst = make([]byte, 22)
		dst[0] = '"'
		x.encode(dst[1:21])
		dst[21] = '"'
	}
	return
}

// UnmarshalText implements encoding/text TextUnmarshaler interface
func (x *XID) UnmarshalText(text []byte) (err error) {
	*x, err = ParseXID(b2s(text))
	return
}

// UnmarshalJSON implements encoding/json Unmarshaler interface
func (x *XID) UnmarshalJSON(b []byte) (err error) {
	if string(b) == "null" {
		*x = nilXID
		return
	}
	*x, err = ParseXID(b2s(b[1 : len(b)-1]))
	return
}

const base32r = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
	"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\xff\xff\xff\xff\xff\xff" +
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
	"\xff\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18" +
	"\x19\x1a\x1b\x1c\x1d\x1e\x1f\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"

type xidError string

func (e xidError) Error() string { return string(e) }

// ErrInvalidXID is returned when trying to parse an invalid XID
const ErrInvalidXID = xidError("xid: invalid XID")

// ParseXID parses an XID from its string representation
func ParseXID(s string) (x XID, err error) {
	if len(s) != 20 {
		err = ErrInvalidXID
		return
	}
	_ = s[19]
	for i := 0; i < 20; i++ {
		if base32r[s[i]] == 0xff {
			err = ErrInvalidXID
			return
		}
	}
	x[0] = base32r[s[0]]<<3 | base32r[s[1]]>>2
	x[1] = base32r[s[1]]<<6 | base32r[s[2]]<<1 | base32r[s[3]]>>4
	x[2] = base32r[s[3]]<<4 | base32r[s[4]]>>1
	x[3] = base32r[s[4]]<<7 | base32r[s[5]]<<2 | base32r[s[6]]>>3
	x[4] = base32r[s[6]]<<5 | base32r[s[7]]
	x[5] = base32r[s[8]]<<3 | base32r[s[9]]>>2
	x[6] = base32r[s[9]]<<6 | base32r[s[10]]<<1 | base32r[s[11]]>>4
	x[7] = base32r[s[11]]<<4 | base32r[s[12]]>>1
	x[8] = base32r[s[12]]<<7 | base32r[s[13]]<<2 | base32r[s[14]]>>3
	x[9] = base32r[s[14]]<<5 | base32r[s[15]]
	x[10] = base32r[s[16]]<<3 | base32r[s[17]]>>2
	x[11] = base32r[s[17]]<<6 | base32r[s[18]]<<1 | base32r[s[19]]>>4
	return
}
