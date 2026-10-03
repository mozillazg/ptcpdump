package log

import (
	"context"
	stdLog "log"
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

func stdSlogAttrEval(e *Entry, a slog.Attr) *Entry {
	if a.Equal(slog.Attr{}) {
		return e
	}
	value := a.Value.Resolve()
	switch value.Kind() {
	case slog.KindBool:
		return e.Bool(a.Key, value.Bool())
	case slog.KindInt64:
		return e.Int64(a.Key, value.Int64())
	case slog.KindUint64:
		return e.Uint64(a.Key, value.Uint64())
	case slog.KindString:
		return e.Str(a.Key, value.String())
	case slog.KindFloat64:
		return e.Float64(a.Key, value.Float64())
	case slog.KindDuration:
		return e.Dur(a.Key, value.Duration())
	case slog.KindTime:
		return e.Time(a.Key, value.Time())
	case slog.KindGroup:
		attrs := value.Group()
		if len(attrs) == 0 {
			return e
		}
		if a.Key == "" {
			for _, attr := range attrs {
				e = stdSlogAttrEval(e, attr)
			}
			return e
		}
		e.buf = append(e.buf, ',', '"')
		e.buf = append(e.buf, a.Key...)
		e.buf = append(e.buf, '"', ':')
		i := len(e.buf)
		for _, attr := range attrs {
			e = stdSlogAttrEval(e, attr)
		}
		e.buf[i] = '{'
		e.buf = append(e.buf, '}')
		return e
	case slog.KindAny:
		fallthrough
	default:
		return e.Any(a.Key, value.Any())
	}
}

type stdSlogHandler struct {
	logger Logger

	entry    Entry
	grouping bool
	groups   int
}

// stdSlogTimeHeader holds the "YYYY-MM-DDTHH:MM:SS." rendering of a single
// absolute second. Consecutive log lines almost always share the same second,
// so caching lets header skip absDateTime and the 19 digit writes.
type stdSlogTimeHeader struct {
	sec int64
	b   [20]byte // "2006-01-02T15:04:05."
}

var stdSlogTimeHeaderPointers struct {
	utc   atomic.Pointer[stdSlogTimeHeader]
	local atomic.Pointer[stdSlogTimeHeader]
}

func (h stdSlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return &h
	}
	// See slogJSONHandler.WithAttrs.
	h.entry.buf = h.entry.buf[:len(h.entry.buf):len(h.entry.buf)]
	i := len(h.entry.buf)
	for _, attr := range attrs {
		h.entry = *stdSlogAttrEval(&h.entry, attr)
	}
	if h.grouping {
		h.entry.buf[i] = '{'
	}
	h.grouping = false
	return &h
}

func (h stdSlogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return &h
	}
	h.entry.buf = h.entry.buf[:len(h.entry.buf):len(h.entry.buf)]
	if h.grouping {
		h.entry.buf = append(h.entry.buf, '{')
	} else {
		h.entry.buf = append(h.entry.buf, ',')
	}
	h.entry.buf = append(h.entry.buf, '"')
	h.entry.buf = append(h.entry.buf, name...)
	h.entry.buf = append(h.entry.buf, '"', ':')
	h.grouping = true
	h.groups++
	return &h
}

func (h *stdSlogHandler) Enabled(_ context.Context, level slog.Level) bool {
	switch level {
	case slog.LevelDebug:
		return h.logger.Level <= DebugLevel
	case slog.LevelInfo:
		return h.logger.Level <= InfoLevel
	case slog.LevelWarn:
		return h.logger.Level <= WarnLevel
	case slog.LevelError:
		return h.logger.Level <= ErrorLevel
	}
	return false
}

func (h *stdSlogHandler) header(now time.Time) *Entry {
	e := epool.Get().(*Entry)
	e.buf = e.buf[:0]
	if h.logger.Writer != nil {
		e.w = h.logger.Writer
	} else {
		e.w = IOWriter{os.Stderr}
	}
	// time
	if h.logger.TimeField == "" {
		e.buf = append(e.buf, "{\""...)
		e.buf = append(e.buf, TimeKey...)
		e.buf = append(e.buf, "\":"...)
	} else {
		e.buf = append(e.buf, '{', '"')
		e.buf = append(e.buf, h.logger.TimeField...)
		e.buf = append(e.buf, '"', ':')
	}
	if h.logger.TimeLocation != nil {
		now = now.In(h.logger.TimeLocation)
	}
	switch h.logger.TimeFormat {
	case "":
		sec, nsec := now.Unix(), now.Nanosecond()
		var tp *atomic.Pointer[stdSlogTimeHeader]
		var tmp [32]byte
		var buf []byte
		if timeOffset == 0 {
			// "2006-01-02T15:04:05.999Z"
			tp = &stdSlogTimeHeaderPointers.utc
			tmp[24] = 'Z'
			tmp[25] = '"'
			buf = tmp[:26]
		} else {
			// "2006-01-02T15:04:05.999Z07:00"
			tp = &stdSlogTimeHeaderPointers.local
			tmp[29] = timeZone[5]
			tmp[28] = timeZone[4]
			tmp[27] = timeZone[3]
			tmp[26] = timeZone[2]
			tmp[25] = timeZone[1]
			tmp[24] = timeZone[0]
			tmp[30] = '"'
			buf = tmp[:31]
		}
		tmp[0] = '"'
		if c := tp.Load(); c != nil && c.sec == sec {
			copy(tmp[1:21], c.b[:])
		} else {
			// date time
			abs := uint64(sec + 9223372028715321600 + timeOffset) // unixToInternal + internalToAbsolute + timeOffset
			year, month, day, hour, minute, second := absDateTime(abs)
			nc := &stdSlogTimeHeader{sec: sec}
			// year
			a := year / 100 * 2
			b := year % 100 * 2
			nc.b[0] = smallsString[a]
			nc.b[1] = smallsString[a+1]
			nc.b[2] = smallsString[b]
			nc.b[3] = smallsString[b+1]
			// month
			month *= 2
			nc.b[4] = '-'
			nc.b[5] = smallsString[month]
			nc.b[6] = smallsString[month+1]
			// day
			day *= 2
			nc.b[7] = '-'
			nc.b[8] = smallsString[day]
			nc.b[9] = smallsString[day+1]
			// hour
			hour *= 2
			nc.b[10] = 'T'
			nc.b[11] = smallsString[hour]
			nc.b[12] = smallsString[hour+1]
			// minute
			minute *= 2
			nc.b[13] = ':'
			nc.b[14] = smallsString[minute]
			nc.b[15] = smallsString[minute+1]
			// second
			second *= 2
			nc.b[16] = ':'
			nc.b[17] = smallsString[second]
			nc.b[18] = smallsString[second+1]
			nc.b[19] = '.'
			// publish for the next line
			copy(tmp[1:21], nc.b[:])
			tp.Store(nc)
		}
		// milli seconds
		ms := uint32(nsec) / 1000000
		mb := ms % 100 * 2
		tmp[21] = byte('0' + ms/100)
		tmp[22] = smallsString[mb]
		tmp[23] = smallsString[mb+1]
		// append to e.buf
		e.buf = append(e.buf, buf...)
	case TimeFormatUnix:
		sec := now.Unix()
		// 1595759807
		var tmp [10]byte
		// seconds
		b := sec % 100 * 2
		sec /= 100
		tmp[9] = smallsString[b+1]
		tmp[8] = smallsString[b]
		b = sec % 100 * 2
		sec /= 100
		tmp[7] = smallsString[b+1]
		tmp[6] = smallsString[b]
		b = sec % 100 * 2
		sec /= 100
		tmp[5] = smallsString[b+1]
		tmp[4] = smallsString[b]
		b = sec % 100 * 2
		sec /= 100
		tmp[3] = smallsString[b+1]
		tmp[2] = smallsString[b]
		b = sec % 100 * 2
		tmp[1] = smallsString[b+1]
		tmp[0] = smallsString[b]
		// append to e.buf
		e.buf = append(e.buf, tmp[:]...)
	case TimeFormatUnixMs:
		sec, nsec := now.Unix(), now.Nanosecond()
		// 1595759807105
		var tmp [13]byte
		// milli seconds
		a := int64(nsec) / 1000000
		b := a % 100 * 2
		tmp[12] = smallsString[b+1]
		tmp[11] = smallsString[b]
		tmp[10] = byte('0' + a/100)
		// seconds
		b = sec % 100 * 2
		sec /= 100
		tmp[9] = smallsString[b+1]
		tmp[8] = smallsString[b]
		b = sec % 100 * 2
		sec /= 100
		tmp[7] = smallsString[b+1]
		tmp[6] = smallsString[b]
		b = sec % 100 * 2
		sec /= 100
		tmp[5] = smallsString[b+1]
		tmp[4] = smallsString[b]
		b = sec % 100 * 2
		sec /= 100
		tmp[3] = smallsString[b+1]
		tmp[2] = smallsString[b]
		b = sec % 100 * 2
		tmp[1] = smallsString[b+1]
		tmp[0] = smallsString[b]
		// append to e.buf
		e.buf = append(e.buf, tmp[:]...)
	case TimeFormatUnixWithMs:
		sec, nsec := now.Unix(), now.Nanosecond()
		// 1595759807.105
		var tmp [14]byte
		// milli seconds
		a := int64(nsec) / 1000000
		b := a % 100 * 2
		tmp[13] = smallsString[b+1]
		tmp[12] = smallsString[b]
		tmp[11] = byte('0' + a/100)
		tmp[10] = '.'
		// seconds
		b = sec % 100 * 2
		sec /= 100
		tmp[9] = smallsString[b+1]
		tmp[8] = smallsString[b]
		b = sec % 100 * 2
		sec /= 100
		tmp[7] = smallsString[b+1]
		tmp[6] = smallsString[b]
		b = sec % 100 * 2
		sec /= 100
		tmp[5] = smallsString[b+1]
		tmp[4] = smallsString[b]
		b = sec % 100 * 2
		sec /= 100
		tmp[3] = smallsString[b+1]
		tmp[2] = smallsString[b]
		b = sec % 100 * 2
		tmp[1] = smallsString[b+1]
		tmp[0] = smallsString[b]
		// append to e.buf
		e.buf = append(e.buf, tmp[:]...)
	default:
		e.buf = append(e.buf, '"')
		e.buf = now.AppendFormat(e.buf, h.logger.TimeFormat)
		e.buf = append(e.buf, '"')
	}

	return e
}

func (h *stdSlogHandler) Handle(_ context.Context, r slog.Record) error {
	e := h.header(r.Time)

	// level
	switch r.Level {
	case slog.LevelDebug:
		e.Level = DebugLevel
		e.buf = append(e.buf, ",\""...)
		e.buf = append(e.buf, LevelKey...)
		e.buf = append(e.buf, "\":\""...)
		e.buf = append(e.buf, DebugLevelString...)
		e.buf = append(e.buf, '"')
	case slog.LevelInfo:
		e.Level = InfoLevel
		e.buf = append(e.buf, ",\""...)
		e.buf = append(e.buf, LevelKey...)
		e.buf = append(e.buf, "\":\""...)
		e.buf = append(e.buf, InfoLevelString...)
		e.buf = append(e.buf, '"')
	case slog.LevelWarn:
		e.Level = WarnLevel
		e.buf = append(e.buf, ",\""...)
		e.buf = append(e.buf, LevelKey...)
		e.buf = append(e.buf, "\":\""...)
		e.buf = append(e.buf, WarnLevelString...)
		e.buf = append(e.buf, '"')
	case slog.LevelError:
		e.Level = ErrorLevel
		e.buf = append(e.buf, ",\""...)
		e.buf = append(e.buf, LevelKey...)
		e.buf = append(e.buf, "\":\""...)
		e.buf = append(e.buf, ErrorLevelString...)
		e.buf = append(e.buf, '"')
	default:
		e.Level = noLevel
	}

	if caller := h.logger.Caller; caller != 0 && r.PC != 0 {
		e.caller(1, r.PC, caller < 0)
	}

	// context
	if h.logger.Context != nil {
		e.buf = append(e.buf, h.logger.Context...)
	}

	// msg
	e = e.Str(MessageKey, r.Message)

	// with
	if b := h.entry.buf; len(b) != 0 {
		e = e.Context(b)
	}
	i := len(e.buf)

	// attrs
	r.Attrs(func(attr slog.Attr) bool {
		e = stdSlogAttrEval(e, attr)
		return true
	})

	lastindex := func(buf []byte) int {
		for i := len(buf) - 3; i >= 1; i-- {
			if buf[i] == '"' && (buf[i-1] == ',' || buf[i-1] == '{') {
				return i
			}
		}
		return -1
	}

	// group attrs
	if h.grouping {
		if r.NumAttrs() > 0 {
			e.buf[i] = '{'
		} else if i = lastindex(e.buf); i > 0 {
			e.buf = e.buf[:i-1]
			h.groups--
			for e.buf[len(e.buf)-1] == ':' {
				if i = lastindex(e.buf); i > 0 {
					e.buf = e.buf[:i-1]
					h.groups--
				}
			}
		} else {
			e.buf = append(e.buf, '{')
		}
	}

	// brackets closing
	switch h.groups {
	case 0:
		break
	case 1:
		e.buf = append(e.buf, '}')
	case 2:
		e.buf = append(e.buf, '}', '}')
	case 3:
		e.buf = append(e.buf, '}', '}', '}')
	case 4:
		e.buf = append(e.buf, '}', '}', '}', '}')
	default:
		for range h.groups {
			e.buf = append(e.buf, '}')
		}
	}

	e.Msg("")
	return nil
}

// Slog wraps the Logger to provide *slog.Logger
func (l *Logger) Slog() *slog.Logger {
	return slog.New(&stdSlogHandler{logger: *l})
}

type stdLogWriter struct {
	Logger
}

func (w *stdLogWriter) Write(p []byte) (int, error) {
	if w.Logger.silent(w.Logger.Level) {
		return 0, nil
	}
	e := w.Logger.header(w.Level)
	if caller, full := w.Logger.Caller, false; caller != 0 {
		if caller < 0 {
			caller, full = -caller, true
		}
		var pc uintptr
		e.caller(caller1(caller+2, &pc, 1, 1), pc, full)
	}
	e.Msg(b2s(p))
	return len(p), nil
}

// Std wraps the Logger to provide *stdLog.Logger
func (l *Logger) Std(prefix string, flag int) *stdLog.Logger {
	return stdLog.New(&stdLogWriter{*l}, prefix, flag)
}
