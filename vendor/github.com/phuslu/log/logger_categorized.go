package log

import (
	"sync"
)

var categorizedLoggers sync.Map // key: string, value: *Logger

type CategorizedLogger struct {
	Logger
	Category string
}

// Categorized returns a cloned logger for category `name`.
func (l *Logger) Categorized(name string) *CategorizedLogger {
	// Inherit logger with added context
	v, ok := categorizedLoggers.Load(name)
	if ok {
		return v.(*CategorizedLogger)
	}
	n := &CategorizedLogger{
		Logger{
			Level:        l.Level,
			Caller:       l.Caller,
			TimeField:    l.TimeField,
			TimeFormat:   l.TimeFormat,
			TimeLocation: l.TimeLocation,
			Context:      NewContext(l.Context).Str("category", name).Value(),
			Writer:       l.Writer,
		},
		name,
	}
	categorizedLoggers.Store(name, n)
	return n
}
