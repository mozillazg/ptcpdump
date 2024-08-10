# phuslog - Fastest structured logging

[![godoc][godoc-img]][godoc]
[![goreport][report-img]][report]
[![build][build-img]][build]
![stability-stable][stability-img]

## Features

* Dependency Free
* Simple and Clean API
* Consistent Writer
    - `IOWriter`, *io.Writer wrapper*
    - `ConsoleWriter`, *colorful & formatting*
    - `FileWriter`, *rotating & effective*
    - `AsyncWriter`, *asynchronously & performant*
    - `MultiLevelWriter`, *multiple level dispatch*
    - `SyslogWriter`, *memory efficient syslog*
* Stdlib Log Adapter
    - `Logger.Std`, *transform to std log instances*
    - `Logger.Slog`, *transform to log/slog instances*
* Third-party Logger Interceptor
    - `logr`, *logr interceptor*
    - `gin`, *gin logging middleware*
    - `gorm`, *gorm logger interface*
    - `fiber`, *fiber logging handler*
    - `grpc`, *grpc logger interceptor*
    - `grpcgateway`, *grpcgateway logger interceptor*
* Useful utility function
    - `Goid()`, *the goroutine id matches stack trace*
    - `NewXID()`, *create a tracing id*
    - `Fastrandn(n uint32)`, *fast pseudorandom uint32 in [0,n)*
    - `IsTerminal(fd uintptr)`, *isatty for golang*
    - `Printf(fmt string, a ...any)`, *printf logging*
    - `SlogNewJSONHandler(io.Writer, *slog.HandlerOptions)`, *drop-in replacement of slog.JSONHandler*
* High Performance
    - [Significantly faster][high-performance] than all other json loggers.

## Interfaces

### Logger
```go
// DefaultLogger is the global logger.
var DefaultLogger = Logger{
	Level:      DebugLevel,
	Caller:     0,
	TimeField:  "",
	TimeFormat: "",
	Writer:     &IOWriter{os.Stderr},
}

// Logger represents an active logging object that generates lines of JSON output to an io.Writer.
type Logger struct {
	// Level defines log levels.
	Level Level

	// Caller determines if adds the file:line of the "caller" key.
	// If Caller is negative, adds the full /path/to/file:line of the "caller" key.
	Caller int

	// TimeField defines the time field name in output.  It uses "time" in if empty.
	TimeField string

	// TimeFormat specifies the time format in output. Uses RFC3339 with millisecond if empty.
	// If set to `TimeFormatUnix/TimeFormatUnixMs`, timestamps will be formatted.
	TimeFormat string

	// TimeLocation specifices that the location of TimeFormat used. Uses time.Local if empty.
	TimeLocation *time.Location

	// Writer specifies the writer of output. It uses a wrapped os.Stderr Writer in if empty.
	Writer Writer
}
```

### ConsoleWriter
```go
// ConsoleWriter parses the JSON input and writes it in a colorized, human-friendly format to Writer.
// IMPORTANT: Don't use ConsoleWriter on critical path of a high concurrency and low latency application.
//
// Default output format:
//     {Time} {Level} {Goid} {Caller} > {Message} {Key}={Value} {Key}={Value}
type ConsoleWriter struct {
	// ColorOutput determines if used colorized output.
	ColorOutput bool

	// QuoteString determines if quoting string values.
	QuoteString bool

	// EndWithMessage determines if output message in the end of line.
	EndWithMessage bool

	// Writer is the output destination. using os.Stderr if empty.
	Writer io.Writer

	// Formatter specifies an optional text formatter for creating a customized output,
	// If it is set, ColorOutput, QuoteString and EndWithMessage will be ignored.
	Formatter func(w io.Writer, args *FormatterArgs) (n int, err error)
}

// FormatterArgs is a parsed sturct from json input
type FormatterArgs struct {
	Time      string // "2019-07-10T05:35:54.277Z"
	Message   string // "a structure message"
	Level     string // "info"
	Caller    string // "main.go:123"
	Goid      string // "1"
	Stack     string // "<stack string>"
	KeyValues []struct {
		Key       string // "foo"
		Value     string // "bar"
	}
}
```

### FileWriter
```go
// FileWriter is an Writer that writes to the specified filename.
type FileWriter struct {
	// Filename is the file to write logs to.  Backup log files will be retained
	// in the same directory.
	Filename string

	// FileMode represents the file's mode and permission bits.  The default
	// mode is 0644
	FileMode os.FileMode

	// MaxSize is the maximum size in bytes of the log file before it gets rotated.
	MaxSize int64

	// MaxBackups is the maximum number of old log files to retain.  The default
	// is to retain all old log files
	MaxBackups int

	// TimeFormat specifies the time format of filename, uses `2006-01-02T15-04-05` as default format.
	// If set with `TimeFormatUnix`, `TimeFormatUnixMs`, times are formated as UNIX timestamp.
	TimeFormat string

	// LocalTime determines if the time used for formatting the timestamps in
	// log files is the computer's local time.  The default is to use UTC time.
	LocalTime bool

	// HostName determines if the hostname used for formatting in log files.
	HostName bool

	// ProcessID determines if the pid used for formatting in log files.
	ProcessID bool

	// EnsureFolder ensures the file directory creation before writing.
	EnsureFolder bool

	// Header specifies an optional header function of log file after rotation,
	Header func(fileinfo os.FileInfo) []byte

	// Cleaner specifies an optional cleanup function of log backups after rotation,
	// if not set, the default behavior is to delete more than MaxBackups log files.
	Cleaner func(filename string, maxBackups int, matches []os.FileInfo)
}
```
*Highlights*:
- FileWriter implements log.Writer and io.Writer interfaces both, it is a recommended alternative to [lumberjack][lumberjack].
- FileWriter creates a symlink to the current logging file, it requires administrator privileges on Windows.
- FileWriter does not rotate if you define a broad TimeFormat value(daily or monthly) until reach its MaxSize.

## Getting Started

### Simple Logging Example

An out of box example. [![playground][play-simple-img]][play-simple]
```go
package main

import (
	"github.com/phuslu/log"
)

func main() {
	log.Info().Str("foo", "bar").Int("number", 42).Msg("hi, phuslog")
	log.Info().Msgf("foo=%s number=%d error=%+v", "bar", 42, "an error")
}

// Output:
//   {"time":"2020-03-22T09:58:41.828Z","level":"info","foo":"bar","number":42,"message":"hi, phuslog"}
//   {"time":"2020-03-22T09:58:41.828Z","level":"info","message":"foo=bar number=42 error=an error"}
```
> Note: By default log writes to `os.Stderr`

### Customize the logger fields:

To customize logger filed name and format. [![playground][play-customize-img]][play-customize]
```go
package main

import (
	"github.com/phuslu/log"
)

func main() {
	log.DefaultLogger = log.Logger{
		Level:      log.InfoLevel,
		Caller:     1,
		TimeField:  "date",
		TimeFormat: "2006-01-02",
		Writer:     &log.IOWriter{os.Stdout},
	}

	log.Info().Str("foo", "bar").Msgf("hello %s", "world")

	logger := log.Logger{
		Level:      log.InfoLevel,
		TimeField:  "ts",
		TimeFormat: log.TimeFormatUnixMs,
	}

	logger.Log().Str("foo", "bar").Msg("")
}

// Output:
//    {"date":"2019-07-04","level":"info","caller":"prog.go:16","foo":"bar","message":"hello world"}
//    {"ts":1257894000000,"foo":"bar"}
```

### Customize the log writer

To allow the use of ordinary functions as log writers, use `WriterFunc`.

```go
logger := log.Logger{
	Writer: log.WriterFunc(func(e *log.Entry) (int, error) {
		if e.Level >= log.ErrorLevel {
			return os.Stderr.Write(e.Value())
		} else {
			return os.Stdout.Write(e.Value())
		}
	}),
}

logger.Info().Msg("a stdout entry")
logger.Error().Msg("a stderr entry")
```

### Pretty Console Writer

To log a human-friendly, colorized output, use `ConsoleWriter`. [![playground][play-pretty-img]][play-pretty]

```go
if log.IsTerminal(os.Stderr.Fd()) {
	log.DefaultLogger = log.Logger{
		TimeFormat: "15:04:05",
		Caller:     1,
		Writer: &log.ConsoleWriter{
			ColorOutput:    true,
			QuoteString:    true,
			EndWithMessage: true,
		},
	}
}

log.Debug().Int("everything", 42).Str("foo", "bar").Msg("hello world")
log.Info().Int("everything", 42).Str("foo", "bar").Msg("hello world")
log.Warn().Int("everything", 42).Str("foo", "bar").Msg("hello world")
log.Error().Err(errors.New("an error")).Msg("hello world")
```
![Pretty logging][pretty-img]
> Note: pretty logging also works on windows console

### Formatting Console Writer

To log with user-defined format(e.g. glog), using `ConsoleWriter.Formatter`. [![playground][play-glog-img]][play-glog]

```go
package main

import (
	"fmt"
	"io"

	"github.com/phuslu/log"
)

type Glog struct {
	Logger log.Logger
}

func (l *Glog) Infof(fmt string, a ...any) { l.Logger.Info().Msgf(fmt, a...) }

func (l *Glog) Warnf(fmt string, a ...any) { l.Logger.Warn().Msgf(fmt, a...) }

func (l *Glog) Errorf(fmt string, a ...any) { l.Logger.Error().Msgf(fmt, a...) }

var glog = &Glog{log.Logger{
	Level:      log.InfoLevel,
	Caller:     2,
	TimeFormat: "0102 15:04:05.999999",
	Writer: &log.ConsoleWriter{Formatter: func(w io.Writer, a *log.FormatterArgs) (int, error) {
		return fmt.Fprintf(w, "%c%s %s %s] %s\n%s", a.Level[0]-32, a.Time, a.Goid, a.Caller, a.Message, a.Stack)
	}},
}}

func main() {
	glog.Infof("hello glog %s", "Info")
	glog.Warnf("hello glog %s", "Warn")
	glog.Errorf("hello glog %s", "Error")
}

// Output:
// I0725 09:59:57.503246 19 console_test.go:183] hello glog Info
// W0725 09:59:57.504247 19 console_test.go:184] hello glog Warn
// E0725 09:59:57.504247 19 console_test.go:185] hello glog Error
```

### Formatting Logfmt output

To log with logfmt format, also using `ConsoleWriter.Formatter`. [![playground][play-logfmt-img]][play-logfmt]

```go
package main

import (
	"io"
	"os"

	"github.com/phuslu/log"
)

func main() {
	log.DefaultLogger = log.Logger{
		Level:      log.InfoLevel,
		Caller:     1,
		TimeField:  "ts",
		TimeFormat: log.TimeFormatUnixWithMs,
		Writer: &log.ConsoleWriter{
			Formatter: log.LogfmtFormatter{"ts"}.Formatter,
			Writer:    io.MultiWriter(os.Stdout, os.Stderr),
		},
	}

	log.Info().Str("foo", "bar").Int("no", 42).Msgf("a logfmt %s", "info")
}

// Output:
// ts=1257894000.000 level=info goid=1 caller="prog.go:20" foo="bar" no=42 "a logfmt info"
// ts=1257894000.000 level=info goid=1 caller="prog.go:20" foo="bar" no=42 "a logfmt info"
```

### Rotating File Writer

To log to a daily-rotating file, use `FileWriter`. [![playground][play-file-img]][play-file]
```go
package main

import (
	"os"
	"path/filepath"
	"time"

	"github.com/phuslu/log"
	"github.com/robfig/cron/v3"
)

func main() {
	logger := log.Logger{
		Level: log.ParseLevel("info"),
		Writer: &log.FileWriter{
			Filename:     "logs/main.log",
			FileMode:     0600,
			MaxSize:      100 * 1024 * 1024,
			MaxBackups:   7,
			EnsureFolder: true,
			LocalTime:    true,
		},
	}

	runner := cron.New(cron.WithLocation(time.Local))
	runner.AddFunc("0 0 * * *", func() { logger.Writer.(*log.FileWriter).Rotate() })
	go runner.Run()

	for {
		time.Sleep(time.Second)
		logger.Info().Msg("hello world")
	}
}
```

### Rotating File Writer within a total size

To rotating log file hourly and keep in a total size, use `FileWriter.Cleaner`.
```go
package main

import (
	"os"
	"path/filepath"
	"time"

	"github.com/phuslu/log"
	"github.com/robfig/cron/v3"
)

func main() {
	logger := log.Logger{
		Level: log.ParseLevel("info"),
		Writer: &log.FileWriter{
			Filename: "main.log",
			MaxSize:  500 * 1024 * 1024,
			Cleaner:  func(filename string, maxBackups int, matches []os.FileInfo) {
				var dir = filepath.Dir(filename)
				var total int64
				for i := len(matches) - 1; i >= 0; i-- {
					total += matches[i].Size()
					if total > 5*1024*1024*1024 {
						os.Remove(filepath.Join(dir, matches[i].Name()))
					}
				}
			},
		},
	}

	runner := cron.New(cron.WithLocation(time.UTC))
	runner.AddFunc("0 * * * *", func() { logger.Writer.(*log.FileWriter).Rotate() })
	go runner.Run()

	for {
		time.Sleep(time.Second)
		logger.Info().Msg("hello world")
	}
}
```

### Rotating File Writer with compression

To rotating log file hourly and compressing after rotation, use `FileWriter.Cleaner`.
```go
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/phuslu/log"
	"github.com/robfig/cron/v3"
)

func main() {
	logger := log.Logger{
		Level: log.ParseLevel("info"),
		Writer: &log.FileWriter{
			Filename: "main.log",
			MaxSize:  500 * 1024 * 1024,
			Cleaner:  func(filename string, maxBackups int, matches []os.FileInfo) {
				var dir = filepath.Dir(filename)
				for i, fi := range matches {
					filename := filepath.Join(dir, fi.Name())
					switch {
					case i > maxBackups:
						os.Remove(filename)
					case !strings.HasSuffix(filename, ".gz"):
						go exec.Command("nice", "gzip", filename).Run()
					}
				}
			},
		},
	}

	runner := cron.New(cron.WithLocation(time.UTC))
	runner.AddFunc("0 * * * *", func() { logger.Writer.(*log.FileWriter).Rotate() })
	go runner.Run()

	for {
		time.Sleep(time.Second)
		logger.Info().Msg("hello world")
	}
}
```

### Async File Writer

For maximum write performance with asynchronous file logging, use `AsyncWriter`.

```go
logger := log.Logger{
	Level: log.InfoLevel,
	Writer: &log.AsyncWriter{
		ChannelSize:   4096,
		Writer:        &log.FileWriter{
			Filename:   "main.log",
			FileMode:   0600,
			MaxSize:    50 * 1024 * 1024,
			MaxBackups: 7,
			LocalTime:  false,
		},
	},
}

logger.Info().Int("number", 42).Str("foo", "bar").Msg("a async info log")
logger.Warn().Int("number", 42).Str("foo", "bar").Msg("a async warn log")
logger.Writer.(io.Closer).Close()
```
*Highlights*:
- To flush data and quit safely, call `.Close()` method explicitly.
- Write performance improves up to 10x under high load with automatic `writev` enabling.

### Random Sample Logger:

To logging only 5% logs, use below idiom.
```go
if log.Fastrandn(100) < 5 {
	log.Log().Msg("hello world")
}
```

### Multiple Dispatching Writer

To log to different writers by different levels, use `MultiLevelWriter`.

```go
log.DefaultLogger.Writer = &log.MultiLevelWriter{
	InfoWriter:    &log.FileWriter{Filename: "main.INFO", MaxSize: 100<<20},
	WarnWriter:    &log.FileWriter{Filename: "main.WARNING", MaxSize: 100<<20},
	ErrorWriter:   &log.FileWriter{Filename: "main.ERROR", MaxSize: 100<<20},
	ConsoleWriter: &log.ConsoleWriter{ColorOutput: true},
	ConsoleLevel:  log.ErrorLevel,
}

log.Info().Int("number", 42).Str("foo", "bar").Msg("a info log")
log.Warn().Int("number", 42).Str("foo", "bar").Msg("a warn log")
log.Error().Int("number", 42).Str("foo", "bar").Msg("a error log")
```

### Multiple Entry Writer
To log to different writers, use `MultiEntryWriter`.

```go
log.DefaultLogger.Writer = &log.MultiEntryWriter{
	&log.ConsoleWriter{ColorOutput: true},
	&log.FileWriter{Filename: "main.log", MaxSize: 100<<20},
	&log.EventlogWriter{Source: ".NET Runtime", ID: 1000},
}

log.Info().Int("number", 42).Str("foo", "bar").Msg("a info log")
```

### Multiple IO Writer

To log to multiple io writers like `io.MultiWriter`, use below idiom. [![playground][play-multiio-img]][play-multiio]

```go
log.DefaultLogger.Writer = &log.MultiIOWriter{
	os.Stdout,
	&log.FileWriter{Filename: "main.log", MaxSize: 100<<20},
}

log.Info().Int("number", 42).Str("foo", "bar").Msg("a info log")
```

### Multiple Combined Logger:

To logging to different logger as you want, use below idiom. [![playground][play-combined-img]][play-combined]
```go
package main

import (
	"github.com/phuslu/log"
)

var logger = struct {
	Console log.Logger
	Access  log.Logger
	Data    log.Logger
}{
	Console: log.Logger{
		TimeFormat: "15:04:05",
		Caller:     1,
		Writer: &log.ConsoleWriter{
			ColorOutput:    true,
			EndWithMessage: true,
		},
	},
	Access: log.Logger{
		Level: log.InfoLevel,
		Writer: &log.FileWriter{
			Filename:   "access.log",
			MaxSize:    50 * 1024 * 1024,
			MaxBackups: 7,
			LocalTime:  false,
		},
	},
	Data: log.Logger{
		Level: log.InfoLevel,
		Writer: &log.FileWriter{
			Filename:   "data.log",
			MaxSize:    50 * 1024 * 1024,
			MaxBackups: 7,
			LocalTime:  false,
		},
	},
}

func main() {
	logger.Console.Info().Msgf("hello world")
	logger.Access.Log().Msgf("handle request")
	logger.Data.Log().Msgf("some data")
}
```

### SyslogWriter

`SyslogWriter` is a memory-efficient, cross-platform, dependency-free syslog writer, outperforms all other structured logging libraries.

```go
package main

import (
	"net"
	"time"

	"github.com/phuslu/log"
)

func main() {
	go func() {
		ln, _ := net.Listen("tcp", "127.0.0.1:1601")
		for {
			conn, _ := ln.Accept()
			go func(c net.Conn) {
				b := make([]byte, 8192)
				n, _ := conn.Read(b)
				println(string(b[:n]))
			}(conn)
		}
	}()

	syslog := log.Logger{
		Level:      log.InfoLevel,
		TimeField:  "ts",
		TimeFormat: log.TimeFormatUnixMs,
		Writer: &log.SyslogWriter{
			Network: "tcp",            // "unixgram",
			Address: "127.0.0.1:1601", // "/run/systemd/journal/syslog",
			Tag:     "",
			Marker:  "@cee:",
			Dial:    net.Dial,
		},
	}

	syslog.Info().Str("foo", "bar").Int("an", 42).Msg("a syslog info")
	syslog.Warn().Str("foo", "bar").Int("an", 42).Msg("a syslog warn")
	time.Sleep(2)
}

// Output:
// <6>2022-07-24T18:48:15+08:00 127.0.0.1:59277 [11516]: @cee:{"ts":1658659695428,"level":"info","foo":"bar","an":42,"message":"a syslog info"}
// <4>2022-07-24T18:48:15+08:00 127.0.0.1:59277 [11516]: @cee:{"ts":1658659695429,"level":"warn","foo":"bar","an":42,"message":"a syslog warn"}
```

### JournalWriter

To log to linux systemd journald, using `JournalWriter`.

```go
log.DefaultLogger.Writer = &log.JournalWriter{
	JournalSocket: "/run/systemd/journal/socket",
}

log.Info().Int("number", 42).Str("foo", "bar").Msg("hello world")
```

### EventlogWriter

To log to windows system event, using `EventlogWriter`.

```go
log.DefaultLogger.Writer = &log.EventlogWriter{
	Source: ".NET Runtime",
	ID:     1000,
}

log.Info().Int("number", 42).Str("foo", "bar").Msg("hello world")
```

### Stdlib Log Adapter

Using wrapped loggers for stdlog. [![playground][play-stdlog-img]][play-stdlog]

```go
package main

import (
	stdlog "log"
	"os"

	"github.com/phuslu/log"
)

func main() {
	var logger *stdlog.Logger = (&log.Logger{
		Level:      log.InfoLevel,
		TimeField:  "date",
		TimeFormat: "2006-01-02",
		Caller:     1,
		Context:    log.NewContext(nil).Str("logger", "mystdlog").Int("myid", 42).Value(),
		Writer:     &log.IOWriter{os.Stdout},
	}).Std("", 0)

	logger.Print("hello from stdlog Print")
	logger.Println("hello from stdlog Println")
	logger.Printf("hello from stdlog %s", "Printf")
}
```

### slog Adapter

Using wrapped loggers for slog. [![playground][play-slog-img]][play-slog]

```go
package main

import (
	"log/slog"

	"github.com/phuslu/log"
)

func main() {
	var logger *slog.Logger = (&log.Logger{
		Level:      log.InfoLevel,
		TimeField:  "date",
		TimeFormat: "2006-01-02",
		Caller:     1,
	}).Slog()

	logger = logger.With("logger", "a_test_slog").With("everything", 42)

	logger.Info("hello from slog Info")
	logger.Warn("hello from slog Warn")
	logger.Error("hello from slog Error")
}
```

### Third-party Logger Interceptor

| Logger | Interceptor |
|---|---|
| logr |  https://github.com/phuslu/log-contrib/tree/master/logr |
| gin |  https://github.com/phuslu/log-contrib/tree/master/gin |
| fiber |  https://github.com/phuslu/log-contrib/tree/master/fiber |
| gorm |  https://github.com/phuslu/log-contrib/tree/master/gorm |
| grpc |  https://github.com/phuslu/log-contrib/tree/master/grpc |
| grpcgateway |  https://github.com/phuslu/log-contrib/tree/master/grpcgateway |

### User-defined Data Structure

To log with user-defined struct effectively, implements `MarshalObject`. [![playground][play-marshal-img]][play-marshal]

```go
package main

import (
	"github.com/phuslu/log"
)

type User struct {
	ID   int
	Name string
	Pass string
}

func (u *User) MarshalObject(e *log.Entry) {
	e.Int("id", u.ID).Str("name", u.Name).Str("password", "***")
}

func main() {
	log.Info().Object("user", &User{1, "neo", "123456"}).Msg("")
	log.Info().EmbedObject(&User{2, "john", "abc"}).Msg("")
}

// Output:
//   {"time":"2020-07-12T05:03:43.949Z","level":"info","user":{"id":1,"name":"neo","password":"***"}}
//   {"time":"2020-07-12T05:03:43.949Z","level":"info","id":2,"name":"john","password":"***"}
```

### Contextual Fields

To add preserved `key:value` pairs to each entry, use `NewContext`. [![playground][play-context-img]][play-context]

```go
logger := log.Logger{
	Level:   log.InfoLevel,
	Context: log.NewContext(nil).Str("ctx", "some_ctx").Value(),
}

logger.Debug().Int("no0", 0).Msg("zero")
logger.Info().Int("no1", 1).Msg("first")
logger.Info().Int("no2", 2).Msg("second")

// Output:
//   {"time":"2020-07-12T05:03:43.949Z","level":"info","ctx":"some_ctx","no1":1,"message":"first"}
//   {"time":"2020-07-12T05:03:43.949Z","level":"info","ctx":"some_ctx","no2":2,"message":"second"}
```

You can make a copy of log and add contextual fields. [![playground][play-context-add-img]][play-context-add]

```go
package main

import (
	"github.com/phuslu/log"
)

func main() {
	sublogger := log.DefaultLogger
	sublogger.Level = log.InfoLevel
	sublogger.Context = log.NewContext(nil).Str("ctx", "some_ctx").Value()

	sublogger.Debug().Int("no0", 0).Msg("zero")
	sublogger.Info().Int("no1", 1).Msg("first")
	sublogger.Info().Int("no2", 2).Msg("second")
	log.Debug().Int("no3", 3).Msg("no context")
}

// Output:
//   {"time":"2021-06-14T06:36:42.904+02:00","level":"info","ctx":"some_ctx","no1":1,"message":"first"}
//   {"time":"2021-06-14T06:36:42.905+02:00","level":"info","ctx":"some_ctx","no2":2,"message":"second"}
//   {"time":"2021-06-14T06:36:42.906+02:00","level":"debug","no3":3,"message":"no context"}
```

### High Performance

<details>
  <summary>The most common benchmarks(disabled/simple/caller/printf/any) against slog/zap/zerolog</summary>

```go
// go test -v -cpu=4 -run=none -bench=. -benchtime=10s -benchmem bench_test.go
package main

import (
	"io"
	"log"
	"log/slog"
	"testing"

	phuslog "github.com/phuslu/log"
	"github.com/rs/zerolog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const msg = "The quick brown fox jumps over the lazy dog"
var obj = struct {Rate string; Low int; High float32}{"15", 16, 123.2}

func BenchmarkSlogDisabled(b *testing.B) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	for i := 0; i < b.N; i++ {
		logger.Debug(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}

func BenchmarkSlogSimple(b *testing.B) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	for i := 0; i < b.N; i++ {
		logger.Info(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}

func BenchmarkSlogPrintf(b *testing.B) {
	slog.SetDefault(slog.New(slog.NewJSONHandler(io.Discard, nil)))
	for i := 0; i < b.N; i++ {
		log.Printf("rate=%s low=%d high=%f msg=%s", "15", 16, 123.2, msg)
	}
}

func BenchmarkSlogCaller(b *testing.B) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{AddSource: true}))
	for i := 0; i < b.N; i++ {
		logger.Info(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}

func BenchmarkSlogAny(b *testing.B) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	for i := 0; i < b.N; i++ {
		logger.Info(msg, "rate", "15", "low", 16, "object", &obj)
	}
}

func BenchmarkSlogPhusDisabled(b *testing.B) {
	logger := slog.New(phuslog.SlogNewJSONHandler(io.Discard, nil))
	for i := 0; i < b.N; i++ {
		logger.Debug(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}

func BenchmarkSlogPhusSimple(b *testing.B) {
	logger := slog.New(phuslog.SlogNewJSONHandler(io.Discard, nil))
	for i := 0; i < b.N; i++ {
		logger.Info(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}

func BenchmarkSlogPhusPrintf(b *testing.B) {
	slog.SetDefault(slog.New(phuslog.SlogNewJSONHandler(io.Discard, nil)))
	for i := 0; i < b.N; i++ {
		log.Printf("rate=%s low=%d high=%f msg=%s", "15", 16, 123.2, msg)
	}
}

func BenchmarkSlogPhusCaller(b *testing.B) {
	logger := slog.New(phuslog.SlogNewJSONHandler(io.Discard, &slog.HandlerOptions{AddSource: true}))
	for i := 0; i < b.N; i++ {
		logger.Info(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}

func BenchmarkSlogPhusAny(b *testing.B) {
	logger := slog.New(phuslog.SlogNewJSONHandler(io.Discard, nil))
	for i := 0; i < b.N; i++ {
		logger.Info(msg, "rate", "15", "low", 16, "object", &obj)
	}
}

func BenchmarkZapDisabled(b *testing.B) {
	logger := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(io.Discard),
		zapcore.InfoLevel,
	)).Sugar()
	for i := 0; i < b.N; i++ {
		logger.Debugw(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}

func BenchmarkZapSimple(b *testing.B) {
	logger := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(io.Discard),
		zapcore.InfoLevel,
	)).Sugar()
	for i := 0; i < b.N; i++ {
		logger.Infow(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}

func BenchmarkZapPrintf(b *testing.B) {
	logger := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(io.Discard),
		zapcore.InfoLevel,
	)).Sugar()
	for i := 0; i < b.N; i++ {
		logger.Infof("rate=%s low=%d high=%f msg=%s", "15", 16, 123.2, msg)
	}
}

func BenchmarkZapCaller(b *testing.B) {
	logger := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(io.Discard),
		zapcore.InfoLevel),
		zap.AddCaller(),
	).Sugar()
	for i := 0; i < b.N; i++ {
		logger.Infow(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}

func BenchmarkZapAny(b *testing.B) {
	logger := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(io.Discard),
		zapcore.InfoLevel,
	)).Sugar()
	for i := 0; i < b.N; i++ {
		logger.Infow(msg, "rate", "15", "low", 16, "object", &obj)
	}
}

func BenchmarkZeroLogDisabled(b *testing.B) {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	logger := zerolog.New(io.Discard).With().Timestamp().Logger()
	for i := 0; i < b.N; i++ {
		logger.Debug().Str("rate", "15").Int("low", 16).Float32("high", 123.2).Msg(msg)
	}
}

func BenchmarkZeroLogSimple(b *testing.B) {
	logger := zerolog.New(io.Discard).With().Timestamp().Logger()
	for i := 0; i < b.N; i++ {
		logger.Info().Str("rate", "15").Int("low", 16).Float32("high", 123.2).Msg(msg)
	}
}

func BenchmarkZeroLogPrintf(b *testing.B) {
	logger := zerolog.New(io.Discard).With().Timestamp().Logger()
	for i := 0; i < b.N; i++ {
		logger.Info().Msgf("rate=%s low=%d high=%f msg=%s", "15", 16, 123.2, msg)
	}
}

func BenchmarkZeroLogCaller(b *testing.B) {
	logger := zerolog.New(io.Discard).With().Caller().Timestamp().Logger()
	for i := 0; i < b.N; i++ {
		logger.Info().Str("rate", "15").Int("low", 16).Float32("high", 123.2).Msg(msg)
	}
}

func BenchmarkZeroLogAny(b *testing.B) {
	logger := zerolog.New(io.Discard).With().Timestamp().Logger()
	for i := 0; i < b.N; i++ {
		logger.Info().Any("rate", "15").Any("low", 16).Any("object", &obj).Msg(msg)
	}
}

func BenchmarkPhusLogDisabled(b *testing.B) {
	logger := phuslog.Logger{Level: phuslog.InfoLevel, Writer: phuslog.IOWriter{io.Discard}}
	for i := 0; i < b.N; i++ {
		logger.Debug().Str("rate", "15").Int("low", 16).Float32("high", 123.2).Msg(msg)
	}
}

func BenchmarkPhusLogSimple(b *testing.B) {
	logger := phuslog.Logger{Writer: phuslog.IOWriter{io.Discard}}
	for i := 0; i < b.N; i++ {
		logger.Info().Str("rate", "15").Int("low", 16).Float32("high", 123.2).Msg(msg)
	}
}

func BenchmarkPhusLogPrintf(b *testing.B) {
	logger := phuslog.Logger{Writer: phuslog.IOWriter{io.Discard}}
	for i := 0; i < b.N; i++ {
		logger.Info().Msgf("rate=%s low=%d high=%f msg=%s", "15", 16, 123.2, msg)
	}
}

func BenchmarkPhusLogCaller(b *testing.B) {
	logger := phuslog.Logger{Caller: 1, Writer: phuslog.IOWriter{io.Discard}}
	for i := 0; i < b.N; i++ {
		logger.Info().Str("rate", "15").Int("low", 16).Float32("high", 123.2).Msg(msg)
	}
}

func BenchmarkPhusLogAny(b *testing.B) {
	logger := phuslog.Logger{Writer: phuslog.IOWriter{io.Discard}}
	for i := 0; i < b.N; i++ {
		logger.Info().Any("rate", "15").Any("low", 16).Any("object", &obj).Msg(msg)
	}
}
```

</details>

A Performance result as below, for daily benchmark results see [github actions][benchmark]
```
goos: linux
goarch: amd64
cpu: AMD EPYC 7763 64-Core Processor

BenchmarkSlogDisabled-4      	715096197	         8.452 ns/op	       0 B/op	       0 allocs/op
BenchmarkSlogSimple-4        	 4394904	      1367 ns/op	     120 B/op	       3 allocs/op
BenchmarkSlogPrintf-4        	 5546492	      1053 ns/op	      80 B/op	       1 allocs/op
BenchmarkSlogCaller-4        	 2708773	      2203 ns/op	     688 B/op	       9 allocs/op
BenchmarkSlogAny-4           	 3936673	      1516 ns/op	     112 B/op	       2 allocs/op

BenchmarkZapDisabled-4       	662012907	         9.076 ns/op	       0 B/op	       0 allocs/op
BenchmarkZapSimple-4         	 6586341	       926.9 ns/op	     384 B/op	       1 allocs/op
BenchmarkZapPrintf-4         	 6375831	       951.9 ns/op	      80 B/op	       1 allocs/op
BenchmarkZapCaller-4         	 3601339	      1673 ns/op	     632 B/op	       3 allocs/op
BenchmarkZapAny-4            	 4649176	      1288 ns/op	     480 B/op	       2 allocs/op

BenchmarkZeroLogDisabled-4   	606002878	         9.908 ns/op	       0 B/op	       0 allocs/op
BenchmarkZeroLogSimple-4     	18342879	       328.7 ns/op	       0 B/op	       0 allocs/op
BenchmarkZeroLogPrintf-4     	 8904566	       669.6 ns/op	      80 B/op	       1 allocs/op
BenchmarkZeroLogCaller-4     	 4687348	      1280 ns/op	     304 B/op	       4 allocs/op
BenchmarkZeroLogAny-4        	 7031146	       851.2 ns/op	      64 B/op	       3 allocs/op

BenchmarkPhusLogDisabled-4   	624706401	         9.599 ns/op	       0 B/op	       0 allocs/op
BenchmarkPhusLogSimple-4     	22249552	       243.1 ns/op	       0 B/op	       0 allocs/op
BenchmarkPhusLogPrintf-4     	11471342	       524.8 ns/op	       0 B/op	       0 allocs/op
BenchmarkPhusLogCaller-4     	12550828	       480.9 ns/op	       0 B/op	       0 allocs/op
BenchmarkPhusLogAny-4        	11623692	       516.4 ns/op	       0 B/op	       0 allocs/op

PASS
ok  	bench	139.331s
```

<details>
  <summary>As slog handlers, comparing with stdlib/zap/zerolog implementations</summary>

```go
// go test -v -cpu=1 -run=none -bench=. -benchtime=10s -benchmem bench_test.go
package bench

import (
	"io"
	"log/slog"
	"testing"

	"github.com/phsym/zeroslog"
	phuslog "github.com/phuslu/log"
	seankhliao "go.seankhliao.com/svcrunner/v3/jsonlog"
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
	"go.uber.org/zap/zapcore"
)

const msg = "The quick brown fox jumps over the lazy dog"

func BenchmarkSlogSimpleStd(b *testing.B) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	for i := 0; i < b.N; i++ {
		logger.Info(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}

func BenchmarkSlogGroupsStd(b *testing.B) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil)).With("a", 1).WithGroup("g").With("b", 2)
	for i := 0; i < b.N; i++ {
		logger.Info(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}

func BenchmarkSlogSimpleZap(b *testing.B) {
	logcore := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(io.Discard),
		zapcore.InfoLevel,
	)
	logger := slog.New(zapslog.NewHandler(logcore, nil))
	for i := 0; i < b.N; i++ {
		logger.Info(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}

func BenchmarkSlogGroupsZap(b *testing.B) {
	logcore := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(io.Discard),
		zapcore.InfoLevel,
	)
	logger := slog.New(zapslog.NewHandler(logcore, nil)).With("a", 1).WithGroup("g").With("b", 2)
	for i := 0; i < b.N; i++ {
		logger.Info(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}

func BenchmarkSlogSimpleZerolog(b *testing.B) {
	logger := slog.New(zeroslog.NewJsonHandler(io.Discard, &zeroslog.HandlerOptions{Level: slog.LevelInfo}))
	for i := 0; i < b.N; i++ {
		logger.Info(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}

func BenchmarkSlogGroupsZerolog(b *testing.B) {
	logger := slog.New(zeroslog.NewJsonHandler(io.Discard, &zeroslog.HandlerOptions{Level: slog.LevelInfo})).With("a", 1).WithGroup("g").With("b", 2)
	for i := 0; i < b.N; i++ {
		logger.Info(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}

func BenchmarkSlogSimpleSeankhliao(b *testing.B) {
	logger := slog.New(seankhliao.New(slog.LevelInfo, io.Discard))
	for i := 0; i < b.N; i++ {
		logger.Info(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}

func BenchmarkSlogGroupsSeankhliao(b *testing.B) {
	logger := slog.New(seankhliao.New(slog.LevelInfo, io.Discard)).With("a", 1).WithGroup("g").With("b", 2)
	for i := 0; i < b.N; i++ {
		logger.Info(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}

func BenchmarkSlogSimplePhuslog(b *testing.B) {
	logger := slog.New((&phuslog.Logger{Writer: phuslog.IOWriter{io.Discard}}).Slog().Handler())
	for i := 0; i < b.N; i++ {
		logger.Info(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}

func BenchmarkSlogGroupsPhuslog(b *testing.B) {
	logger := slog.New((&phuslog.Logger{Writer: phuslog.IOWriter{io.Discard}}).Slog().Handler()).With("a", 1).WithGroup("g").With("b", 2)
	for i := 0; i < b.N; i++ {
		logger.Info(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}

func BenchmarkSlogSimplePhuslogStd(b *testing.B) {
	logger := slog.New(phuslog.SlogNewJSONHandler(io.Discard, nil))
	for i := 0; i < b.N; i++ {
		logger.Info(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}

func BenchmarkSlogGroupsPhuslogStd(b *testing.B) {
	logger := slog.New(phuslog.SlogNewJSONHandler(io.Discard, nil)).With("a", 1).WithGroup("g").With("b", 2)
	for i := 0; i < b.N; i++ {
		logger.Info(msg, "rate", "15", "low", 16, "high", 123.2)
	}
}
```

</details>

A Performance result as below, for daily benchmark results see [github actions][benchmark]
```
goos: linux
goarch: amd64
cpu: AMD EPYC 7763 64-Core Processor                

BenchmarkSlogSimpleStd        	 4314817	      1413 ns/op	     120 B/op	       3 allocs/op
BenchmarkSlogGroupsStd        	 4167734	      1462 ns/op	     120 B/op	       3 allocs/op

BenchmarkSlogSimpleZap        	 4824007	      1245 ns/op	     192 B/op	       1 allocs/op
BenchmarkSlogGroupsZap        	 4800220	      1256 ns/op	     192 B/op	       1 allocs/op

BenchmarkSlogSimpleZerolog    	 7713812	       783.7 ns/op	       0 B/op	       0 allocs/op
BenchmarkSlogGroupsZerolog    	 5506782	      1089 ns/op	     288 B/op	       1 allocs/op

BenchmarkSlogSimplePhuslog    	 8858504	       683.0 ns/op	       0 B/op	       0 allocs/op
BenchmarkSlogGroupsPhuslog    	 8615334	       694.0 ns/op	       0 B/op	       0 allocs/op

BenchmarkSlogSimplePhuslogStd 	 8889276	       666.7 ns/op	       0 B/op	       0 allocs/op
BenchmarkSlogGroupsPhuslogStd 	 8849634	       683.3 ns/op	       0 B/op	       0 allocs/op

PASS
ok  	bench	84.415s
```

In summary, phuslog offers a blend of low latency, minimal memory usage, and efficient logging across various scenarios, making it an excellent option for high-performance logging in Go applications.

## A Real World Example

The example starts a geoip http server which supports change log level dynamically
```go
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/phuslu/iploc"
	"github.com/phuslu/log"
)

type Config struct {
	Listen struct {
		Tcp string
	}
	Log struct {
		Level   string
		Maxsize int64
		Backups int
	}
}

type Handler struct {
	Config       *Config
	AccessLogger log.Logger
}

func (h *Handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	reqID := log.NewXID()
	remoteIP, _, _ := net.SplitHostPort(req.RemoteAddr)
	geo := iploc.Country(net.ParseIP(remoteIP))

	h.AccessLogger.Log().
		Xid("req_id", reqID).
		Str("host", req.Host).
		Bytes("geo", geo).
		Str("remote_ip", remoteIP).
		Str("request_uri", req.RequestURI).
		Str("user_agent", req.UserAgent()).
		Str("referer", req.Referer()).
		Msg("access log")

	switch req.RequestURI {
	case "/debug", "/info", "/warn", "/error":
		log.DefaultLogger.SetLevel(log.ParseLevel(req.RequestURI[1:]))
	default:
		fmt.Fprintf(rw, `{"req_id":"%s","ip":"%s","geo":"%s"}`, reqID, remoteIP, geo)
	}
}

func main() {
	config := new(Config)
	err := json.Unmarshal([]byte(`{
		"listen": {
			"tcp": ":8080"
		},
		"log": {
			"level": "debug",
			"maxsize": 1073741824,
			"backups": 5
		}
	}`), config)
	if err != nil {
		log.Fatal().Msgf("json.Unmarshal error: %+v", err)
	}

	handler := &Handler{
		Config: config,
		AccessLogger: log.Logger{
			Writer: &log.FileWriter{
				Filename:   "access.log",
				MaxSize:    config.Log.Maxsize,
				MaxBackups: config.Log.Backups,
				LocalTime:  true,
			},
		},
	}

	if log.IsTerminal(os.Stderr.Fd()) {
		log.DefaultLogger = log.Logger{
			Level:      log.ParseLevel(config.Log.Level),
			Caller:     1,
			TimeFormat: "15:04:05",
			Writer: &log.ConsoleWriter{
				ColorOutput:    true,
				EndWithMessage: true,
			},
		}
		handler.AccessLogger = log.DefaultLogger
	} else {
		log.DefaultLogger = log.Logger{
			Level: log.ParseLevel(config.Log.Level),
			Writer: &log.FileWriter{
				Filename:   "main.log",
				MaxSize:    config.Log.Maxsize,
				MaxBackups: config.Log.Backups,
				LocalTime:  true,
			},
		}
	}

	server := &http.Server{
		Addr:     config.Listen.Tcp,
		ErrorLog: log.DefaultLogger.Std(log.ErrorLevel, nil, "", 0),
		Handler:  handler,
	}

	log.Fatal().Err(server.ListenAndServe()).Msg("listen failed")
}
```

## Acknowledgment
This log is heavily inspired by [zerolog][zerolog], [glog][glog], [gjson][gjson] and [lumberjack][lumberjack].

[godoc-img]: http://img.shields.io/badge/godoc-reference-5272B4.svg
[godoc]: https://pkg.go.dev/github.com/phuslu/log
[report-img]: https://goreportcard.com/badge/github.com/phuslu/log
[report]: https://goreportcard.com/report/github.com/phuslu/log
[build-img]: https://github.com/phuslu/log/workflows/build/badge.svg
[build]: https://github.com/phuslu/log/actions
[stability-img]: https://img.shields.io/badge/stability-stable-green.svg
[high-performance]: https://github.com/phuslu/log?tab=readme-ov-file#high-performance
[play-simple-img]: https://img.shields.io/badge/playground-NGV25aBKmYH-29BEB0?style=flat&logo=go
[play-simple]: https://go.dev/play/p/NGV25aBKmYH
[play-customize-img]: https://img.shields.io/badge/playground-p9ZSSL4--IaK-29BEB0?style=flat&logo=go
[play-customize]: https://go.dev/play/p/p9ZSSL4-IaK
[play-multiio-img]: https://img.shields.io/badge/playground-MH--J3Je--KEq-29BEB0?style=flat&logo=go
[play-multiio]: https://go.dev/play/p/MH-J3Je-KEq
[play-combined-img]: https://img.shields.io/badge/playground-24d4eDIpDeR-29BEB0?style=flat&logo=go
[play-combined]: https://go.dev/play/p/24d4eDIpDeR
[play-file-img]: https://img.shields.io/badge/playground-tjMc97E2EpW-29BEB0?style=flat&logo=go
[play-file]: https://go.dev/play/p/tjMc97E2EpW
[play-pretty-img]: https://img.shields.io/badge/playground-SCcXG33esvI-29BEB0?style=flat&logo=go
[play-pretty]: https://go.dev/play/p/SCcXG33esvI
[pretty-img]: https://user-images.githubusercontent.com/195836/101993218-cda82380-3cf3-11eb-9aa2-b8b1c832a72e.png
[play-glog-img]: https://img.shields.io/badge/playground-oxSyv3ra5W5-29BEB0?style=flat&logo=go
[play-glog]: https://go.dev/play/p/oxSyv3ra5W5
[play-logfmt-img]: https://img.shields.io/badge/playground-8ZsrWnsWBep-29BEB0?style=flat&logo=go
[play-logfmt]: https://go.dev/play/p/8ZsrWnsWBep
[play-context-img]: https://img.shields.io/badge/playground-oAVAo302faf-29BEB0?style=flat&logo=go
[play-context]: https://go.dev/play/p/oAVAo302faf
[play-context-add-img]: https://img.shields.io/badge/playground-LuCghJxMPHI-29BEB0?style=flat&logo=go
[play-context-add]: https://go.dev/play/p/LuCghJxMPHI
[play-marshal-img]: https://img.shields.io/badge/playground-SoQdwQOaQR2-29BEB0?style=flat&logo=go
[play-marshal]: https://go.dev/play/p/SoQdwQOaQR2
[play-stdlog]: https://go.dev/play/p/LU8vQruS7-S
[play-stdlog-img]: https://img.shields.io/badge/playground-LU8vQruS7--S-29BEB0?style=flat&logo=go
[play-slog]: https://go.dev/play/p/JW3Ts6FcB40
[play-slog-img]: https://img.shields.io/badge/playground-JW3Ts6FcB40-29BEB0?style=flat&logo=go
[benchmark]: https://github.com/phuslu/log/actions?query=workflow%3Abenchmark
[zerolog]: https://github.com/rs/zerolog
[glog]: https://github.com/golang/glog
[gjson]: https://github.com/tidwall/gjson
[lumberjack]: https://github.com/natefinch/lumberjack
