//go:build amd64

package log

/*
   Avoid atomic overhead by referencing these tweets:
   https://x.com/i/status/1782634032884593099
   https://x.com/i/status/1782635198930358747
*/

//gcassert:inline
func (l *Logger) silent(level Level) bool {
	return level < l.Level
}
