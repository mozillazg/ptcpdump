package log

import (
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
)

// TSVLogger represents an active logging object that generates lines of TSV output to an io.Writer.
type TSVLogger struct {
	Separator byte
	Writer    io.Writer
}

// TSVEntry represents a tsv log entry. It is instanced by one of TSVLogger and finalized by the Msg method.
type TSVEntry struct {
	buf []byte
	w   io.Writer
	sep byte
}

var tepool = sync.Pool{
	New: func() any {
		return new(TSVEntry)
	},
}

// New starts a new tsv message.
func (l *TSVLogger) New() (e *TSVEntry) {
	e = tepool.Get().(*TSVEntry)
	e.sep = l.Separator
	if l.Writer != nil {
		e.w = l.Writer
	} else {
		e.w = os.Stderr
	}
	if e.sep == 0 {
		e.sep = '\t'
	}
	e.buf = e.buf[:0]
	return
}

// Timestamp adds the current time as UNIX timestamp
func (e *TSVEntry) Timestamp() *TSVEntry {
	var tmp [11]byte
	sec, _, _ := now()
	// separator
	tmp[10] = e.sep
	// seconds
	is := sec % 100 * 2
	sec /= 100
	tmp[9] = smallsString[is+1]
	tmp[8] = smallsString[is]
	is = sec % 100 * 2
	sec /= 100
	tmp[7] = smallsString[is+1]
	tmp[6] = smallsString[is]
	is = sec % 100 * 2
	sec /= 100
	tmp[5] = smallsString[is+1]
	tmp[4] = smallsString[is]
	is = sec % 100 * 2
	sec /= 100
	tmp[3] = smallsString[is+1]
	tmp[2] = smallsString[is]
	is = sec % 100 * 2
	tmp[1] = smallsString[is+1]
	tmp[0] = smallsString[is]
	// append to buf
	e.buf = append(e.buf, tmp[:]...)
	return e
}

// TimestampMS adds the current time with milliseconds as UNIX timestamp
func (e *TSVEntry) TimestampMS() *TSVEntry {
	var tmp [14]byte
	sec, nsec, _ := now()
	// separator
	tmp[13] = e.sep
	// milli seconds
	a := int64(nsec) / 1000000
	is := a % 100 * 2
	tmp[12] = smallsString[is+1]
	tmp[11] = smallsString[is]
	tmp[10] = byte('0' + a/100)
	// seconds
	is = sec % 100 * 2
	sec /= 100
	tmp[9] = smallsString[is+1]
	tmp[8] = smallsString[is]
	is = sec % 100 * 2
	sec /= 100
	tmp[7] = smallsString[is+1]
	tmp[6] = smallsString[is]
	is = sec % 100 * 2
	sec /= 100
	tmp[5] = smallsString[is+1]
	tmp[4] = smallsString[is]
	is = sec % 100 * 2
	sec /= 100
	tmp[3] = smallsString[is+1]
	tmp[2] = smallsString[is]
	is = sec % 100 * 2
	tmp[1] = smallsString[is+1]
	tmp[0] = smallsString[is]
	// append to buf
	e.buf = append(e.buf, tmp[:]...)
	return e
}

// Caller adds the file:line of to the entry.
func (e *TSVEntry) Caller(depth int) *TSVEntry {
	var pc uintptr
	i := caller1(depth, &pc, 1, 1)
	if i < 1 {
		return e
	}
	file, line := pcFileLine(pc)
	for i = len(file) - 1; i >= 0; i-- {
		if file[i] == '/' {
			break
		}
	}
	if i > 0 {
		file = file[i+1:]
	}
	e.buf = append(e.buf, file...)
	e.buf = append(e.buf, ':')
	e.buf = strconv.AppendInt(e.buf, int64(line), 10)
	e.buf = append(e.buf, e.sep)
	return e
}

// Bool append the b as a bool to the entry, the value of output bool is 0 or 1.
func (e *TSVEntry) Bool(b bool) *TSVEntry {
	if b {
		e.buf = append(e.buf, '1', e.sep)
	} else {
		e.buf = append(e.buf, '0', e.sep)
	}
	return e
}

// BoolString append the b as a bool to the entry, the value of output bool is false or true.
func (e *TSVEntry) BoolString(b bool) *TSVEntry {
	if b {
		e.buf = append(e.buf, 't', 'r', 'u', 'e', e.sep)
	} else {
		e.buf = append(e.buf, 'f', 'a', 'l', 's', 'e', e.sep)
	}
	return e
}

// Byte append the b as a byte to the entry.
func (e *TSVEntry) Byte(b byte) *TSVEntry {
	e.buf = append(e.buf, b, e.sep)
	return e
}

// Float64 adds a float64 to the entry.
func (e *TSVEntry) Float64(f float64) *TSVEntry {
	e.buf = strconv.AppendFloat(e.buf, f, 'f', -1, 64)
	e.buf = append(e.buf, e.sep)
	return e
}

// Int64 adds a int64 to the entry.
func (e *TSVEntry) Int64(i int64) *TSVEntry {
	e.buf = strconv.AppendInt(e.buf, i, 10)
	e.buf = append(e.buf, e.sep)
	return e
}

// Uint64 adds a uint64 to the entry.
func (e *TSVEntry) Uint64(i uint64) *TSVEntry {
	e.buf = strconv.AppendUint(e.buf, i, 10)
	e.buf = append(e.buf, e.sep)
	return e
}

// Float32 adds a float32 to the entry.
func (e *TSVEntry) Float32(f float32) *TSVEntry {
	return e.Float64(float64(f))
}

// Int adds a int to the entry.
func (e *TSVEntry) Int(i int) *TSVEntry {
	return e.Int64(int64(i))
}

// Int32 adds a int32 to the entry.
func (e *TSVEntry) Int32(i int32) *TSVEntry {
	return e.Int64(int64(i))
}

// Int16 adds a int16 to the entry.
func (e *TSVEntry) Int16(i int16) *TSVEntry {
	return e.Int64(int64(i))
}

// Int8 adds a int8 to the entry.
func (e *TSVEntry) Int8(i int8) *TSVEntry {
	return e.Int64(int64(i))
}

// Uint32 adds a uint32 to the entry.
func (e *TSVEntry) Uint32(i uint32) *TSVEntry {
	return e.Uint64(uint64(i))
}

// Uint16 adds a uint16 to the entry.
func (e *TSVEntry) Uint16(i uint16) *TSVEntry {
	return e.Uint64(uint64(i))
}

// Uint8 adds a uint8 to the entry.
func (e *TSVEntry) Uint8(i uint8) *TSVEntry {
	return e.Uint64(uint64(i))
}

// Uint adds a uint to the entry.
func (e *TSVEntry) Uint(i uint) *TSVEntry {
	return e.Uint64(uint64(i))
}

// Str adds a string to the entry.
func (e *TSVEntry) Str(val string) *TSVEntry {
	e.buf = append(e.buf, val...)
	e.buf = append(e.buf, e.sep)
	return e
}

// Bytes adds a bytes as string to the entry.
func (e *TSVEntry) Bytes(val []byte) *TSVEntry {
	e.buf = append(e.buf, val...)
	e.buf = append(e.buf, e.sep)
	return e
}

// IPAddr adds IPv4 or IPv6 Address to the entry.
func (e *TSVEntry) IPAddr(ip net.IP) *TSVEntry {
	if ip4 := ip.To4(); ip4 != nil {
		e.buf = strconv.AppendInt(e.buf, int64(ip4[0]), 10)
		e.buf = append(e.buf, '.')
		e.buf = strconv.AppendInt(e.buf, int64(ip4[1]), 10)
		e.buf = append(e.buf, '.')
		e.buf = strconv.AppendInt(e.buf, int64(ip4[2]), 10)
		e.buf = append(e.buf, '.')
		e.buf = strconv.AppendInt(e.buf, int64(ip4[3]), 10)
	} else {
		e.buf = append(e.buf, ip.String()...)
	}
	e.buf = append(e.buf, e.sep)
	return e
}

// NetIPAddr adds IPv4 or IPv6 Address to the entry.
func (e *TSVEntry) NetIPAddr(ip netip.Addr) *TSVEntry {
	e.buf = ip.AppendTo(e.buf)
	e.buf = append(e.buf, e.sep)
	return e
}

// NetIPAddrPort adds IPv4 or IPv6 with Port Address to the entry.
func (e *TSVEntry) NetIPAddrPort(ipPort netip.AddrPort) *TSVEntry {
	e.buf = ipPort.AppendTo(e.buf)
	e.buf = append(e.buf, e.sep)
	return e
}

// NetIPPrefix adds IPv4 or IPv6 Prefix (address and mask) to the entry.
func (e *TSVEntry) NetIPPrefix(pfx netip.Prefix) *TSVEntry {
	e.buf = pfx.AppendTo(e.buf)
	e.buf = append(e.buf, e.sep)
	return e
}

// Encode encodes bytes using enc.AppendEncode to the entry.
func (e *TSVEntry) Encode(key string, val []byte, enc interface {
	AppendEncode(dst, src []byte) []byte
}) *TSVEntry {
	e.buf = enc.AppendEncode(e.buf, val)
	e.buf = append(e.buf, e.sep)
	return e
}

// Msg sends the entry.
func (e *TSVEntry) Msg() {
	if len(e.buf) != 0 {
		e.buf[len(e.buf)-1] = '\n'
	}
	_, _ = e.w.Write(e.buf)
	if cap(e.buf) <= bbcap {
		tepool.Put(e)
	}
}
