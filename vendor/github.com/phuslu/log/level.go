package log

// Level defines log levels.
type Level uint32

const (
	// TraceLevel defines trace log level.
	TraceLevel Level = 1
	// DebugLevel defines debug log level.
	DebugLevel Level = 2
	// InfoLevel defines info log level.
	InfoLevel Level = 3
	// WarnLevel defines warn log level.
	WarnLevel Level = 4
	// ErrorLevel defines error log level.
	ErrorLevel Level = 5
	// FatalLevel defines fatal log level.
	FatalLevel Level = 6
	// PanicLevel defines panic log level.
	PanicLevel Level = 7
	// NoLevel defines an absent log level.
	noLevel Level = 8
)

// XXXLevelString defines the string representation.
var (
	TraceLevelString = "trace"
	DebugLevelString = "debug"
	InfoLevelString  = "info"
	WarnLevelString  = "warn"
	ErrorLevelString = "error"
	FatalLevelString = "fatal"
	PanicLevelString = "panic"
)

// String returns the string representation of the Level.
func (l Level) String() (s string) {
	switch l {
	case TraceLevel:
		s = TraceLevelString
	case DebugLevel:
		s = DebugLevelString
	case InfoLevel:
		s = InfoLevelString
	case WarnLevel:
		s = WarnLevelString
	case ErrorLevel:
		s = ErrorLevelString
	case FatalLevel:
		s = FatalLevelString
	case PanicLevel:
		s = PanicLevelString
	default:
		s = "????"
	}
	return
}

// ParseLevel converts a level string into a log Level value.
func ParseLevel(s string) (level Level) {
	switch s {
	case "trace", "Trace", "TRACE", "TRC":
		level = TraceLevel
	case "debug", "Debug", "DEBUG", "DBG":
		level = DebugLevel
	case "info", "Info", "INFO", "INF":
		level = InfoLevel
	case "warn", "Warn", "WARN", "warning", "Warning", "WARNING", "WRN":
		level = WarnLevel
	case "error", "Error", "ERROR", "ERR":
		level = ErrorLevel
	case "fatal", "Fatal", "FATAL", "FTL":
		level = FatalLevel
	case "panic", "Panic", "PANIC", "PNC":
		level = PanicLevel
	default:
		level = noLevel
	}
	return
}
