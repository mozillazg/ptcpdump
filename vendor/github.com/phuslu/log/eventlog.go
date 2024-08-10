//go:build windows
// +build windows

package log

import (
	"errors"
	"sync"
	"syscall"
	"unsafe"
)

// EventlogWriter is an Writer that writes logs to windows event log.
type EventlogWriter struct {
	// Event Source, must not be empty
	Source string

	// Event ID, using `eid` key in log event if not empty
	ID uintptr

	// Event Host, optional
	Host string

	once       sync.Once
	register   *syscall.LazyProc
	deregister *syscall.LazyProc
	report     *syscall.LazyProc
	handle     uintptr
}

// Write implements io.Closer.
func (w *EventlogWriter) Close() (err error) {
	var ret uintptr
	ret, _, err = syscall.Syscall(w.deregister.Addr(), 1, w.handle, 0, 0)
	if ret > 0 {
		err = nil
	}
	return
}

// WriteEntry implements Writer.
func (w *EventlogWriter) WriteEntry(e *Entry) (n int, err error) {
	w.once.Do(func() {
		if w.ID == 0 {
			err = errors.New("Specify eventlog default id")
			return
		}

		if w.Source == "" {
			err = errors.New("Specify eventlog source")
			return
		}

		var s *uint16
		if w.Host != "" {
			s = syscall.StringToUTF16Ptr(w.Host)
		}

		advapi32 := syscall.NewLazyDLL("advapi32.dll")
		w.register = advapi32.NewProc("RegisterEventSourceW")
		w.deregister = advapi32.NewProc("DeregisterEventSource")
		w.report = advapi32.NewProc("ReportEventW")

		w.handle, _, err = syscall.Syscall(w.register.Addr(), 2, uintptr(unsafe.Pointer(s)), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(w.Source))), 0)
		if w.handle != 0 {
			err = nil
		}
	})

	if err != nil {
		return
	}

	const (
		EVENTLOG_SUCCESS          = 0x0000
		EVENTLOG_ERROR_TYPE       = 0x0001
		EVENTLOG_WARNING_TYPE     = 0x0002
		EVENTLOG_INFORMATION_TYPE = 0x0004
		EVENTLOG_AUDIT_SUCCESS    = 0x0008
		EVENTLOG_AUDIT_FAILURE    = 0x0010
	)

	var etype uint16
	switch e.Level {
	case TraceLevel:
		etype = EVENTLOG_INFORMATION_TYPE
	case DebugLevel:
		etype = EVENTLOG_INFORMATION_TYPE
	case InfoLevel:
		etype = EVENTLOG_INFORMATION_TYPE
	case WarnLevel:
		etype = EVENTLOG_WARNING_TYPE
	case ErrorLevel:
		etype = EVENTLOG_ERROR_TYPE
	case FatalLevel:
		etype = EVENTLOG_AUDIT_FAILURE
	case PanicLevel:
		etype = EVENTLOG_AUDIT_FAILURE
	default:
		etype = EVENTLOG_INFORMATION_TYPE
	}

	var ecat uintptr = 0
	var eid = w.ID
	var ss = []*uint16{syscall.StringToUTF16Ptr(b2s(e.buf))}

	var ret uintptr
	ret, _, err = syscall.Syscall9(w.report.Addr(), 9, w.handle, uintptr(etype), ecat, eid, 0, 1, 0, uintptr(unsafe.Pointer(&ss[0])), 0)
	if ret > 0 {
		err = nil
	}
	if err == nil {
		n = len(e.buf)
	}

	return
}

var _ Writer = (*EventlogWriter)(nil)
