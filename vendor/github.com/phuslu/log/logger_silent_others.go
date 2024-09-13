//go:build !amd64

package log

import (
	"sync/atomic"
)

func (l *Logger) silent(level Level) bool {
	return uint32(level) < atomic.LoadUint32((*uint32)(&l.Level))
}
