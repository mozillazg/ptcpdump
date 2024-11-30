//go:build go1.21

package log

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

func slogJSONAttrEval(e *Entry, a slog.Attr) *Entry {
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
	case slog.KindFloat64:
		return e.Float64(a.Key, value.Float64())
	case slog.KindString:
		return e.Str(a.Key, value.String())
	case slog.KindTime:
		return e.TimeFormat(a.Key, time.RFC3339Nano, value.Time())
	case slog.KindDuration:
		return e.Int64(a.Key, int64(value.Duration()))
	case slog.KindGroup:
		attrs := value.Group()
		if len(attrs) == 0 {
			return e
		}
		if a.Key == "" {
			for _, attr := range attrs {
				e = slogJSONAttrEval(e, attr)
			}
			return e
		}
		e.buf = append(e.buf, ',', '"')
		e.buf = append(e.buf, a.Key...)
		e.buf = append(e.buf, '"', ':')
		i := len(e.buf)
		for _, attr := range attrs {
			e = slogJSONAttrEval(e, attr)
		}
		e.buf[i] = '{'
		e.buf = append(e.buf, '}')
		return e
	case slog.KindAny:
		return e.Any(a.Key, value.Any())
	default:
		return e.Any(a.Key, value.Any())
	}
}

type slogJSONHandler struct {
	level    slog.Level
	entry    Entry
	grouping bool
	groups   int

	writer  io.Writer
	options *slog.HandlerOptions
}

func (h *slogJSONHandler) Enabled(_ context.Context, level slog.Level) bool {
	return h.level <= level
}

func (h slogJSONHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return &h
	}
	i := len(h.entry.buf)
	for _, attr := range attrs {
		h.entry = *slogJSONAttrEval(&h.entry, attr)
	}
	if h.grouping {
		h.entry.buf[i] = '{'
	}
	h.grouping = false
	return &h
}

func (h slogJSONHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return &h
	}
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

func (h *slogJSONHandler) Handle(_ context.Context, r slog.Record) error {
	e := epool.Get().(*Entry)
	e.buf = e.buf[:0]

	e.buf = append(e.buf, '{')

	// time
	if !r.Time.IsZero() {
		e.buf = append(e.buf, '"')
		e.buf = append(e.buf, slog.TimeKey...)
		e.buf = append(e.buf, `":"`...)
		if timeOffset == 0 || r.Time.Location() == time.Local {
			sec, nsec := r.Time.Unix(), r.Time.Nanosecond()
			var tmp [35]byte
			var buf []byte
			if timeOffset == 0 {
				// 2006-01-02T15:04:05.999Z
				tmp[29] = 'Z'
				buf = tmp[:30]
			} else {
				// 2006-01-02T15:04:05.999999999Z07:00
				tmp[34] = timeZone[5]
				tmp[33] = timeZone[4]
				tmp[32] = timeZone[3]
				tmp[31] = timeZone[2]
				tmp[30] = timeZone[1]
				tmp[29] = timeZone[0]
				buf = tmp[:35]
			}
			// date time
			sec += 9223372028715321600 + timeOffset // unixToInternal + internalToAbsolute + timeOffset
			year, month, day, _ := absDate(uint64(sec), true)
			hour, minute, second := absClock(uint64(sec))
			// year
			a := year / 100 * 2
			b := year % 100 * 2
			tmp[0] = smallsString[a]
			tmp[1] = smallsString[a+1]
			tmp[2] = smallsString[b]
			tmp[3] = smallsString[b+1]
			// month
			month *= 2
			tmp[4] = '-'
			tmp[5] = smallsString[month]
			tmp[6] = smallsString[month+1]
			// day
			day *= 2
			tmp[7] = '-'
			tmp[8] = smallsString[day]
			tmp[9] = smallsString[day+1]
			// hour
			hour *= 2
			tmp[10] = 'T'
			tmp[11] = smallsString[hour]
			tmp[12] = smallsString[hour+1]
			// minute
			minute *= 2
			tmp[13] = ':'
			tmp[14] = smallsString[minute]
			tmp[15] = smallsString[minute+1]
			// second
			second *= 2
			tmp[16] = ':'
			tmp[17] = smallsString[second]
			tmp[18] = smallsString[second+1]
			tmp[19] = '.'
			// nano seconds
			a = int(nsec)
			b = a % 100 * 2
			a /= 100
			tmp[28] = smallsString[b+1]
			tmp[27] = smallsString[b]
			b = a % 100 * 2
			a /= 100
			tmp[26] = smallsString[b+1]
			tmp[25] = smallsString[b]
			b = a % 100 * 2
			a /= 100
			tmp[24] = smallsString[b+1]
			tmp[23] = smallsString[b]
			b = a % 100 * 2
			tmp[22] = smallsString[b+1]
			tmp[21] = smallsString[b]
			tmp[20] = byte('0' + a/100)
			// append to e.buf
			e.buf = append(e.buf, buf...)
		} else {
			e.buf = r.Time.AppendFormat(e.buf, time.RFC3339Nano)
		}
		e.buf = append(e.buf, `",`...)
	}

	// level
	e.buf = append(e.buf, '"')
	e.buf = append(e.buf, slog.LevelKey...)
	switch r.Level {
	case slog.LevelDebug:
		e.buf = append(e.buf, `":"DEBUG"`...)
	case slog.LevelInfo:
		e.buf = append(e.buf, `":"INFO"`...)
	case slog.LevelWarn:
		e.buf = append(e.buf, `":"WARN"`...)
	case slog.LevelError:
		e.buf = append(e.buf, `":"ERROR"`...)
	default:
		e.buf = append(e.buf, `":"`...)
		e.buf = append(e.buf, r.Level.String()...)
		e.buf = append(e.buf, '"')
	}

	// source
	if h.options != nil && h.options.AddSource && r.PC != 0 {
		file, line, name := pcFileLineName(r.PC)
		e.buf = append(e.buf, ',', '"')
		e.buf = append(e.buf, slog.SourceKey...)
		e.buf = append(e.buf, `":{"function":"`...)
		if i := strings.LastIndexByte(name, '/'); i > 0 {
			name = name[i+1:]
		}
		e.buf = append(e.buf, name...)
		e.buf = append(e.buf, `","file":"`...)
		e.buf = append(e.buf, file...)
		e.buf = append(e.buf, `","line":`...)
		e.buf = strconv.AppendInt(e.buf, int64(line), 10)
		// e.buf = append(e.buf, `,"goid":`...)
		// e.buf = strconv.AppendInt(e.buf, int64(goid()), 10)
		e.buf = append(e.buf, '}')
	}

	// msg
	e = e.Str(slog.MessageKey, r.Message)

	// with
	if b := h.entry.buf; len(b) != 0 {
		e = e.Context(b)
	}
	i := len(e.buf)

	// attrs
	r.Attrs(func(attr slog.Attr) bool {
		e = slogJSONAttrEval(e, attr)
		return true
	})

	// rollback helper
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
		e.buf = append(e.buf, '}', '\n')
	case 1:
		e.buf = append(e.buf, '}', '}', '\n')
	case 2:
		e.buf = append(e.buf, '}', '}', '}', '\n')
	case 3:
		e.buf = append(e.buf, '}', '}', '}', '}', '\n')
	case 4:
		e.buf = append(e.buf, '}', '}', '}', '}', '}', '\n')
	default:
		for i := 0; i <= h.groups; i++ {
			e.buf = append(e.buf, '}')
		}
		e.buf = append(e.buf, '\n')
	}

	_, err := h.writer.Write(e.buf)

	if cap(e.buf) <= bbcap {
		epool.Put(e)
	}

	return err
}

type slogLevelvarHandler struct {
	handler slog.Handler
	level   slog.Leveler
}

func (h *slogLevelvarHandler) Enabled(_ context.Context, level slog.Level) bool {
	return h.level.Level() <= level
}

func (h slogLevelvarHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.handler = h.handler.WithAttrs(attrs)
	return &h
}

func (h slogLevelvarHandler) WithGroup(name string) slog.Handler {
	h.handler = h.handler.WithGroup(name)
	return &h
}

func (h *slogLevelvarHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.handler.Handle(ctx, r)
}

// SlogNewJSONHandler returns a drop-in replacement of slog.NewJSONHandler.
func SlogNewJSONHandler(writer io.Writer, options *slog.HandlerOptions) slog.Handler {
	if options != nil && options.ReplaceAttr != nil {
		// TODO: implement ReplaceAttr in a new handler.
		return slog.NewJSONHandler(writer, options)
	}

	handler := &slogJSONHandler{
		writer:  writer,
		options: options,
	}

	if handler.options == nil || handler.options.Level == nil {
		return handler
	}

	if level, ok := handler.options.Level.(slog.Level); ok {
		handler.level = level
		return handler
	}

	return &slogLevelvarHandler{
		handler: handler,
		level:   handler.options.Level,
	}
}
