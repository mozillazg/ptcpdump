//go:build windows
// +build windows

package log

import (
	"io"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

func isTerminal(fd uintptr, _, _ string) bool {
	var mode uint32
	err := syscall.GetConsoleMode(syscall.Handle(fd), &mode)
	if err != nil {
		return false
	}

	return true
}

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	setConsoleMode          = kernel32.NewProc("SetConsoleMode").Call
	setConsoleTextAttribute = kernel32.NewProc("SetConsoleTextAttribute").Call

	muConsole   sync.Mutex
	onceConsole sync.Once
	isvt        bool
)

// WriteEntry implements Writer
func (w *ConsoleWriter) WriteEntry(e *Entry) (n int, err error) {
	onceConsole.Do(func() { isvt = isVirtualTerminal() })

	out := w.Writer
	if out == nil {
		out = os.Stderr
	}
	if isvt {
		n, err = w.write(out, e.buf)
	} else {
		n, err = w.writew(out, e.buf)
	}
	return
}

func (w *ConsoleWriter) writew(out io.Writer, p []byte) (n int, err error) {
	muConsole.Lock()
	defer muConsole.Unlock()

	b := bbpool.Get().(*bb)
	b.B = b.B[:0]
	defer bbpool.Put(b)

	n, err = w.write(b, p)
	if err != nil {
		return
	}
	n = 0
	// uintptr color
	const (
		Black  = 0
		Blue   = 1
		Green  = 2
		Aqua   = 3
		Red    = 4
		Purple = 5
		Yellow = 6
		White  = 7
		Gray   = 8
	)
	// color print
	var cprint = func(color uintptr, b []byte) {
		if color != White {
			setConsoleTextAttribute(uintptr(syscall.Stderr), color)
			defer setConsoleTextAttribute(uintptr(syscall.Stderr), White)
		}
		var i int
		i, err = out.Write(b)
		n += i
	}

	b2 := bbpool.Get().(*bb)
	b2.B = b2.B[:0]
	defer bbpool.Put(b2)

	var color uintptr = White
	var length = len(b.B)
	var c uint32
	for i := 0; i < length; i++ {
		if b.B[i] == '\x1b' {
			switch {
			case length-i > 3 &&
				b.B[i+1] == '[' &&
				'0' <= b.B[i+2] && b.B[i+2] <= '9' &&
				b.B[i+3] == 'm':
				c = uint32(b.B[i+2] - '0')
				i += 3
			case length-i > 4 &&
				b.B[i+1] == '[' &&
				'0' <= b.B[i+2] && b.B[i+2] <= '9' &&
				'0' <= b.B[i+3] && b.B[i+3] <= '9' &&
				b.B[i+4] == 'm':
				c = uint32(b.B[i+2]-'0')*10 + uint32(b.B[i+3]-'0')
				i += 4
			}
			if len(b2.B) > 0 {
				cprint(color, b2.B)
			}
			b2.B = b2.B[:0]
			switch c {
			case 0: // Reset
				color = White
			case 30: // Black
				color = Black
			case 90: // Gray
				color = Gray
			case 31, 91: // Red, BrightRed
				color = Red
			case 32, 92: // Green, BrightGreen
				color = Green
			case 33, 93: // Yellow, BrightYellow
				color = Yellow
			case 34, 94: // Blue, BrightBlue
				color = Blue
			case 35, 95: // Magenta, BrightMagenta
				color = Purple
			case 36, 96: // Cyan, BrightCyan
				color = Aqua
			case 37, 97: // White, BrightWhite
				color = White
			default:
				color = White
			}
		} else {
			b2.B = append(b2.B, b.B[i])
		}
	}

	if len(b2.B) != 0 {
		cprint(White, b2.B)
	}

	return
}

func isVirtualTerminal() bool {
	var h syscall.Handle
	var b [64]uint16
	var n uint32

	// open registry
	err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, syscall.StringToUTF16Ptr(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`), 0, syscall.KEY_READ, &h)
	if err != nil {
		return false
	}
	defer syscall.RegCloseKey(h)

	// read windows build number
	n = uint32(len(b))
	err = syscall.RegQueryValueEx(h, syscall.StringToUTF16Ptr(`CurrentBuild`), nil, nil, (*byte)(unsafe.Pointer(&b[0])), &n)
	if err != nil {
		return false
	}
	for i := 0; i < len(b); i++ {
		if b[i] == 0 {
			break
		}
		n = n*10 + uint32(b[i]-'0')
	}

	// return if lower than windows 10 16257
	if n < 16257 {
		return false
	}

	// get console mode
	err = syscall.GetConsoleMode(syscall.Stderr, &n)
	if err != nil {
		return false
	}

	// enable ENABLE_VIRTUAL_TERMINAL_PROCESSING
	ret, _, _ := setConsoleMode(uintptr(syscall.Stderr), uintptr(n|0x4))
	return ret != 0
}
