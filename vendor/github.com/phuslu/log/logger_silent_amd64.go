//go:build amd64
// +build amd64

package log

//gcassert:inline
func (l *Logger) silent(level Level) bool {
	return level < l.Level
}
