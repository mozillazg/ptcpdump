package log

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/phuslu/log"
)

var defaultLogger = log.Logger{
	Level:      log.WarnLevel,
	Caller:     0,
	TimeFormat: time.DateTime,
	Writer: &log.ConsoleWriter{
		Formatter: func(w io.Writer, a *log.FormatterArgs) (int, error) {
			return fmt.Fprintf(w, "%s %s %s\n", a.Time, strings.ToUpper(a.Level), a.Message)
		},
	},
}

var debugLogger = log.Logger{
	Level:      log.WarnLevel,
	Caller:     2,
	TimeFormat: time.DateTime,
	Writer: &log.ConsoleWriter{
		Formatter: func(w io.Writer, a *log.FormatterArgs) (int, error) {
			suffix := ""
			if a.Stack != "" {
				suffix += a.Stack + "\n"
			}
			return fmt.Fprintf(w, "%s %s %s] %s\n%s", a.Time, strings.ToUpper(a.Level),
				a.Caller, a.Message, suffix)
		},
	},
}

func SetLevel(level log.Level) {
	defaultLogger.SetLevel(level)
	debugLogger.SetLevel(level)
}

func Debug(msg string) {
	debugLogger.Debug().Msg(msg)
}

func Debugf(format string, v ...any) {
	debugLogger.Debug().Msgf(format, v...)
}

func Info(msg string) {
	debugLogger.Info().Msg(msg)
}

func Infof(format string, v ...any) {
	debugLogger.Info().Msgf(format, v...)
}

func Warn(msg string) {
	defaultLogger.Warn().Msg(msg)
}

func Warnf(format string, v ...any) {
	defaultLogger.Warn().Msgf(format, v...)
}

func DWarnf(format string, v ...any) {
	debugLogger.Warn().Msgf(format, v...)
}

func DWarn(format string) {
	debugLogger.Warn().Msg(format)
}

func Error(msg string) {
	debugLogger.Error().Msg(msg)
}

func Errorf(format string, v ...any) {
	debugLogger.Error().Msgf(format, v...)
}

func Fatal(msg string) {
	debugLogger.Fatal().Msg(msg)
}

func Fatalf(format string, v ...any) {
	debugLogger.Fatal().Msgf(format, v...)
}
