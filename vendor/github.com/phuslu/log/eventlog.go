//go:build windows

package log

import (
	"errors"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// EventlogWriter is a Writer that writes logs to windows event log.
type EventlogWriter struct {
	// Event Source, must not be empty
	Source string

	// Event ID, using `eid` key in log event if not empty
	ID uintptr

	// Event Host, optional
	Host string

	mu     sync.Mutex
	handle uintptr
}

var (
	advapi32                  = syscall.NewLazyDLL("advapi32.dll")
	procRegisterEventSourceW  = advapi32.NewProc("RegisterEventSourceW")
	procDeregisterEventSource = advapi32.NewProc("DeregisterEventSource")
	procReportEventW          = advapi32.NewProc("ReportEventW")
)

// Write implements io.Closer.
func (w *EventlogWriter) Close() (err error) {
	var ret uintptr
	ret, _, err = syscall.Syscall(procDeregisterEventSource.Addr(), 1, w.handle, 0, 0)
	if ret > 0 {
		err = nil
	}
	return
}

func (w *EventlogWriter) connect() (err error) {
	if w.handle != 0 {
		w.Close()
		w.handle = 0
	}

	if w.ID == 0 {
		err = errors.New("Specify eventlog default id")
		return
	}

	if w.Source == "" {
		err = errors.New("Specify eventlog source")
		return
	}

	var host *uint16
	if w.Host != "" {
		host, err = syscall.UTF16PtrFromString(w.Host)
		if err != nil {
			return
		}
	}

	var source *uint16
	source, err = syscall.UTF16PtrFromString(w.Source)
	if err != nil {
		return
	}

	var handle uintptr
	handle, _, err = syscall.Syscall(procRegisterEventSourceW.Addr(), 2, uintptr(unsafe.Pointer(host)), uintptr(unsafe.Pointer(source)), 0)
	if handle != 0 {
		atomic.StoreUintptr(&w.handle, handle)
		err = nil
	}

	return
}

// WriteEntry implements Writer.
func (w *EventlogWriter) WriteEntry(e *Entry) (n int, err error) {
	if atomic.LoadUintptr(&w.handle) != 0 {
		w.mu.Lock()
		if w.handle == 0 {
			err = w.connect()
			if err != nil {
				w.mu.Unlock()
				return
			}
		}
		w.mu.Unlock()
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
	var ss = []*uint16{nil}

	ss[0], err = syscall.UTF16PtrFromString(b2s(e.buf))
	if err != nil {
		return
	}

	var ret uintptr
	ret, _, err = syscall.Syscall9(procReportEventW.Addr(), 9, w.handle, uintptr(etype), ecat, eid, 0, 1, 0, uintptr(unsafe.Pointer(&ss[0])), 0)
	if ret > 0 {
		err = nil
	}
	if err == nil {
		n = len(e.buf)
	}

	return
}

var _ Writer = (*EventlogWriter)(nil)
