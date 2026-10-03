package log

import (
	"io"
	"runtime"
	"strconv"
)

// IsTerminal returns whether the given file descriptor is a terminal.
func IsTerminal(fd uintptr) bool {
	return isTerminal(fd, runtime.GOOS, runtime.GOARCH)
}

// ConsoleWriter parses the JSON input and writes it in a colorized, human-friendly format to Writer.
// IMPORTANT: Don't use ConsoleWriter on critical path of a high concurrency and low latency application.
//
// Default output format:
//
//	{Time} {Level} {Goid} {Caller} > {Message} {Key}={Value} {Key}={Value}
//
// Note: The performance of ConsoleWriter is not good enough, because it will
// parses JSON input into structured records, then output in a specific order.
// Roughly 2x faster than logrus.TextFormatter, 0.8x fast as zap.ConsoleEncoder,
// and 5x faster than zerolog.ConsoleWriter.
type ConsoleWriter struct {
	// ColorOutput determines if used colorized output.
	ColorOutput bool

	// QuoteString determines if quoting string values.
	QuoteString bool

	// EndWithMessage determines if output message in the end.
	EndWithMessage bool

	// Formatter specifies an optional text formatter for creating a customized output,
	// If it is set, ColorOutput, QuoteString and EndWithMessage will be ignore.
	Formatter func(w io.Writer, args *FormatterArgs) (n int, err error)

	// Writer is the output destination. using os.Stderr if empty.
	Writer io.Writer
}

// Close implements io.Closer, will closes the underlying Writer if not empty.
func (w *ConsoleWriter) Close() (err error) {
	if w.Writer != nil {
		if closer, ok := w.Writer.(io.Closer); ok {
			err = closer.Close()
		}
	}
	return
}

func (w *ConsoleWriter) write(out io.Writer, p []byte) (int, error) {
	b := bbpool.Get().(*bb)
	b.B = b.B[:0]
	defer bbpool.Put(b)

	b.B = append(b.B, p...)

	var args FormatterArgs
	parseFormatterArgs(b.B, &args)

	switch {
	case args.Time == "":
		return out.Write(p)
	case w.Formatter != nil:
		return w.Formatter(out, &args)
	default:
		return w.format(out, &args)
	}

}

func (w *ConsoleWriter) format(out io.Writer, args *FormatterArgs) (n int, err error) {
	b := bbpool.Get().(*bb)
	b.B = b.B[:0]
	defer bbpool.Put(b)

	const (
		Reset   = "\x1b[0m"
		Black   = "\x1b[30m"
		Red     = "\x1b[31m"
		Green   = "\x1b[32m"
		Yellow  = "\x1b[33m"
		Blue    = "\x1b[34m"
		Magenta = "\x1b[35m"
		Cyan    = "\x1b[36m"
		White   = "\x1b[37m"
		Gray    = "\x1b[90m"
	)

	// colorful level string
	var color, three string
	switch args.Level {
	case "trace":
		color, three = Magenta, "TRC"
	case "debug":
		color, three = Yellow, "DBG"
	case "info":
		color, three = Green, "INF"
	case "warn":
		color, three = Red, "WRN"
	case "error":
		color, three = Red, "ERR"
	case "fatal":
		color, three = Red, "FTL"
	case "panic":
		color, three = Red, "PNC"
	default:
		color, three = Gray, "???"
	}

	// pretty console writer
	ab := appendablebytes(b.B)
	if w.ColorOutput {
		// header
		ab = ab.Str(Gray).Str(args.Time).Str(Reset).Str(" ").Str(color).Str(three).Str(Reset).Str(" ")
		if args.Caller != "" {
			ab = ab.Str(args.Goid).Str(" ").Str(args.Caller).Str(" ").Str(Cyan).Str(">").Str(Reset)
		} else {
			ab = ab.Str(Cyan).Str(">").Str(Reset)
		}
		if !w.EndWithMessage {
			ab = ab.Str(" ").Str(args.Message)
		}
		// key and values
		for _, kv := range args.KeyValues {
			// a quoted value is never the bare null, so a quoted null error
			// value takes the colored branch, same as the fmt version did
			quoted := w.QuoteString && kv.ValueType == 's'
			if kv.Key == "error" && (quoted || kv.Value != "null") {
				ab = ab.Str(" ").Str(Red).Str(kv.Key).Str("=")
			} else {
				ab = ab.Str(" ").Str(Cyan).Str(kv.Key).Str("=").Str(Gray)
			}
			if quoted {
				ab = ab.Quote(kv.Value)
			} else {
				ab = ab.Str(kv.Value)
			}
			ab = ab.Str(Reset)
		}
		// message
		if w.EndWithMessage {
			ab = ab.Str(Reset).Str(" ").Str(args.Message)
		}
	} else {
		// header
		ab = ab.Str(args.Time).Str(" ").Str(three).Str(" ")
		if args.Caller != "" {
			ab = ab.Str(args.Goid).Str(" ").Str(args.Caller).Str(" >")
		} else {
			ab = ab.Str(">")
		}
		if !w.EndWithMessage {
			ab = ab.Str(" ").Str(args.Message)
		}
		// key and values
		for _, kv := range args.KeyValues {
			if w.QuoteString && kv.ValueType == 's' {
				ab = ab.Byte(' ').Str(kv.Key).Byte('=').Quote(kv.Value)
			} else {
				ab = ab.Str(" ").Str(kv.Key).Str("=").Str(kv.Value)
			}
		}
		// message
		if w.EndWithMessage {
			ab = ab.Str(" ").Str(args.Message)
		}
	}

	// add line break if needed
	if ab[len(ab)-1] != '\n' {
		ab = ab.Byte('\n')
	}

	// stack
	if args.Stack != "" {
		ab = ab.Str(args.Stack)
		if args.Stack[len(args.Stack)-1] != '\n' {
			ab = ab.Byte('\n')
		}
	}

	b.B = ab
	return out.Write(b.B)
}

type LogfmtFormatter struct {
	TimeField string
}

func (f LogfmtFormatter) Formatter(out io.Writer, args *FormatterArgs) (n int, err error) {
	b := bbpool.Get().(*bb)
	b.B = b.B[:0]
	defer bbpool.Put(b)

	ab := appendablebytes(b.B).Str(f.TimeField).Str("=").Str(args.Time).Str(" ")
	if args.Level != "" && args.Level[0] != '?' {
		ab = ab.Str("level=").Str(args.Level).Str(" ")
	}
	if args.Caller != "" {
		ab = ab.Str("goid=").Str(args.Goid).Str(" caller=").Quote(args.Caller).Byte(' ')
	}
	if args.Stack != "" {
		ab = ab.Str("stack=").Quote(args.Stack).Byte(' ')
	}
	// key and values
	for _, kv := range args.KeyValues {
		switch kv.ValueType {
		case 't':
			ab = ab.Str(kv.Key).Byte(' ')
		case 'f':
			ab = ab.Str(kv.Key).Str("=false ")
		case 'n':
			ab = ab.Str(kv.Key).Str("=").Str(kv.Value).Byte(' ')
		case 'S':
			ab = ab.Str(kv.Key).Str("=").Str(kv.Value).Byte(' ')
		case 's':
			fallthrough
		default:
			ab = ab.Str(kv.Key).Byte('=').Quote(kv.Value).Byte(' ')
		}
	}
	// message
	ab = ab.Quote(args.Message).Byte('\n')

	b.B = ab
	return out.Write(b.B)
}

var _ Writer = (*ConsoleWriter)(nil)

// appendablebytes is a byte slice with append helpers, it builds output
// without the fmt reflection overhead, for example:
//
//	b := appendablebytes(make([]byte, 0, 1024))
//	b = b.Str("GET ").Str(req.RequestURI).Str(" HTTP/1.1\r\n")
//	for key, values := range req.Header {
//		for _, value := range values {
//			b = b.Str(key).Str(": ").Str(value).Str("\r\n")
//		}
//	}
//	b = b.Str("\r\n")
type appendablebytes []byte

func (b appendablebytes) Str(s string) appendablebytes {
	return append(b, s...)
}

func (b appendablebytes) Bytes(s []byte) appendablebytes {
	return append(b, s...)
}

func (b appendablebytes) Byte(c byte) appendablebytes {
	return append(b, c)
}

func (b appendablebytes) Quote(s string) appendablebytes {
	return strconv.AppendQuote(b, s)
}

func (b appendablebytes) Uint64(i uint64, base int) appendablebytes {
	return strconv.AppendUint(b, i, base)
}

func (b appendablebytes) Int64(i int64, base int) appendablebytes {
	return strconv.AppendInt(b, i, base)
}
