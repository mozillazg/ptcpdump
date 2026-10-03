//go:build linux

package log

import (
	"encoding/binary"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
)

// listenUnixgram is a variable so tests can inject a bind failure, which
// otherwise needs fd or socket buffer exhaustion to trigger.
var listenUnixgram = net.ListenUnixgram

// JournalWriter is an Writer that writes logs to journald.
type JournalWriter struct {
	// JournalSocket specifies socket name, using `/run/systemd/journal/socket` if empty.
	JournalSocket string

	// once guards addr, the destination address never changes.
	once sync.Once
	addr *net.UnixAddr

	mu   sync.Mutex
	conn atomic.Pointer[net.UnixConn]
}

// Close implements io.Closer.
func (w *JournalWriter) Close() (err error) {
	if c := w.conn.Load(); c != nil {
		err = c.Close()
		w.conn.Store(nil)
	}
	return
}

// connect binds the local socket the writer sends from and stores it in
// w.conn.  A bind that failed is retried by the following write, so a
// transient failure does not disable the writer forever.
func (w *JournalWriter) connect() (err error) {
	w.once.Do(func() {
		// unix addr
		w.addr = &net.UnixAddr{
			Net:  "unixgram",
			Name: w.JournalSocket,
		}
		if w.addr.Name == "" {
			w.addr.Name = "/run/systemd/journal/socket"
		}
	})

	// unix conn
	var autobind *net.UnixAddr
	autobind, err = net.ResolveUnixAddr("unixgram", "")
	if err != nil {
		return
	}
	var conn *net.UnixConn
	conn, err = listenUnixgram("unixgram", autobind)
	if err != nil {
		return
	}
	w.conn.Store(conn)
	return
}

// WriteEntry implements Writer.
func (w *JournalWriter) WriteEntry(e *Entry) (n int, err error) {
	if w.conn.Load() == nil {
		w.mu.Lock()
		if w.conn.Load() == nil {
			if err = w.connect(); err != nil {
				w.mu.Unlock()
				return
			}
		}
		w.mu.Unlock()
	}
	conn := w.conn.Load()

	b0 := bbpool.Get().(*bb)
	b0.B = b0.B[:0]
	defer bbpool.Put(b0)
	b0.B = append(b0.B, e.buf...)

	var args FormatterArgs
	parseFormatterArgs(b0.B, &args)
	if args.Time == "" {
		return
	}

	// buffer
	b := bbpool.Get().(*bb)
	b.B = b.B[:0]
	defer bbpool.Put(b)

	print := func(upper bool, name, value string) {
		if upper {
			for _, c := range []byte(name) {
				if 'a' <= c && c <= 'z' {
					c -= 'a' - 'A'
				}
				b.B = append(b.B, c)
			}
		} else {
			b.B = append(b.B, name...)
		}
		if strings.ContainsRune(value, '\n') {
			b.B = append(b.B, '\n')
			b.B = binary.LittleEndian.AppendUint64(b.B, uint64(len(value)))
			b.B = append(b.B, value...)
			b.B = append(b.B, '\n')
		} else {
			b.B = append(b.B, '=')
			b.B = append(b.B, value...)
			b.B = append(b.B, '\n')
		}
	}

	// level
	var priority string
	switch e.Level {
	case TraceLevel:
		priority = "7" // Debug
	case DebugLevel:
		priority = "7" // Debug
	case InfoLevel:
		priority = "6" // Informational
	case WarnLevel:
		priority = "4" // Warning
	case ErrorLevel:
		priority = "3" // Error
	case FatalLevel:
		priority = "2" // Critical
	case PanicLevel:
		priority = "0" // Emergency
	default:
		priority = "5" // Notice
	}
	print(false, "PRIORITY", priority)

	// message
	print(false, "MESSAGE", args.Message)

	// caller
	if args.Caller != "" {
		print(false, "CALLER", args.Caller)
	}

	// goid
	if args.Goid != "" {
		print(false, "GOID", args.Goid)
	}

	// stack
	if args.Stack != "" {
		print(false, "STACK", args.Stack)
	}

	// fields
	for _, kv := range args.KeyValues {
		print(true, kv.Key, kv.Value)
	}

	print(false, "JSON", b2s(e.buf))

	// write
	n, _, err = conn.WriteMsgUnix(b.B, nil, w.addr)
	if err == nil {
		return
	}

	opErr, ok := err.(*net.OpError)
	if !ok || opErr == nil {
		return
	}

	sysErr, ok := opErr.Err.(*os.SyscallError)
	if !ok || sysErr == nil {
		return
	}
	if sysErr.Err != syscall.EMSGSIZE && sysErr.Err != syscall.ENOBUFS {
		return
	}

	// Large log entry, send it via tempfile and ancillary-fd.
	var file *os.File
	file, err = os.CreateTemp("/dev/shm/", "journal.XXXXX")
	if err != nil {
		return
	}
	err = syscall.Unlink(file.Name())
	if err != nil {
		return
	}
	defer file.Close()
	n, err = file.Write(b.B)
	if err != nil {
		return
	}
	rights := syscall.UnixRights(int(file.Fd()))
	_, _, err = conn.WriteMsgUnix([]byte{}, rights, w.addr)
	if err == nil {
		n = len(e.buf)
	}

	return
}

var _ Writer = (*JournalWriter)(nil)
