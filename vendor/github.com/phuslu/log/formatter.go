package log

import (
	"reflect"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

// FormatterArgs is a parsed struct from json input
type FormatterArgs struct {
	Time       string // "2019-07-10T05:35:54.277Z"
	Level      string // "info"
	Caller     string // "prog.go:42"
	CallerFunc string // "main.main"
	Goid       string // "123"
	Stack      string // "<stack string>"
	Message    string // "a structure message"
	KeyValues  []struct {
		Key       string // "foo"
		Value     string // "bar"
		ValueType byte   // 's'
	}
}

// Get gets the value associated with the given key.
func (args *FormatterArgs) Get(key string) (value string) {
	for i := len(args.KeyValues) - 1; i >= 0; i-- {
		kv := &args.KeyValues[i]
		if kv.Key == key {
			value = kv.Value
			break
		}
	}
	return
}

func formatterArgsPos(key string) (pos int) {
	switch key {
	case "time":
		pos = 1
	case "level":
		pos = 2
	case "caller":
		pos = 3
	case "callerfunc":
		pos = 4
	case "goid":
		pos = 5
	case "stack":
		pos = 6
	case "message", "msg":
		pos = 7
	}
	return
}

// parseFormatterArgs extracts json string to json items
func parseFormatterArgs(json []byte, args *FormatterArgs) {
	// Pre-allocate KeyValues slice to a reasonable capacity.
	// This prevents a race condition that can lead to memory corruption
	// when append is called on a nil slice from multiple goroutines.
	args.KeyValues = make([]struct {
		Key       string
		Value     string
		ValueType byte
	}, 0, 16)

	// treat formatter args as []string
	const size = int(unsafe.Sizeof(FormatterArgs{}) / unsafe.Sizeof(""))
	//nolint:all
	slice := *(*[]string)(unsafe.Pointer(&reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(args)), Len: size, Cap: size,
	}))
	var keys = true
	var key, str []byte
	var ok bool
	var typ byte
	_ = json[len(json)-1] // remove bounds check
	if json[0] != '{' {
		return
	}
	for i := 1; i < len(json); i++ {
		if keys {
			if json[i] != '"' {
				continue
			}
			i, str, _, ok = jsonParseString(json, i+1)
			if !ok {
				return
			}
			key = str[1 : len(str)-1]
		}
		for ; i < len(json); i++ {
			if json[i] <= ' ' || json[i] == ',' || json[i] == ':' {
				continue
			}
			break
		}
		i, typ, str, ok = jsonParseAny(json, i, true)
		if !ok {
			return
		}
		switch typ {
		case 's':
			str = str[1 : len(str)-1]
		case 'S':
			str = jsonUnescape(str[1:len(str)-1], str[:0])
			typ = 's'
		}
		pos := formatterArgsPos(b2s(key))
		if pos == 0 && args.Time == "" {
			pos = 1
		}
		if pos != 0 {
			if pos == 2 && len(str) != 0 && str[len(str)-1] == '\n' {
				str = str[:len(str)-1]
			}
			if slice[pos-1] == "" {
				slice[pos-1] = b2s(str)
			}
		} else {
			args.KeyValues = append(args.KeyValues, struct {
				Key, Value string
				ValueType  byte
			}{b2s(key), b2s(str), typ})
		}
	}

	if args.Level == "" {
		args.Level = "????"
	}
}

func jsonParseString(json []byte, i int) (int, []byte, bool, bool) {
	var s = i
	_ = json[len(json)-1] // remove bounds check
	for ; i < len(json); i++ {
		if json[i] > '\\' {
			continue
		}
		if json[i] == '"' {
			return i + 1, json[s-1 : i+1], false, true
		}
		if json[i] == '\\' {
			i++
			for ; i < len(json); i++ {
				if json[i] > '\\' {
					continue
				}
				if json[i] == '"' {
					// look for an escaped slash
					if json[i-1] == '\\' {
						n := 0
						for j := i - 2; j > 0; j-- {
							if json[j] != '\\' {
								break
							}
							n++
						}
						if n%2 == 0 {
							continue
						}
					}
					return i + 1, json[s-1 : i+1], true, true
				}
			}
			break
		}
	}
	return i, json[s-1:], false, false
}

// jsonParseAny parses the next value from a json string.
// A Result is returned when the hit param is set.
// The return values are (i int, res Result, ok bool)
func jsonParseAny(json []byte, i int, hit bool) (int, byte, []byte, bool) {
	var typ byte
	var val []byte
	_ = json[len(json)-1] // remove bounds check
	for ; i < len(json); i++ {
		if json[i] == '{' || json[i] == '[' {
			i, val = jsonParseSquash(json, i)
			if hit {
				typ = 'o'
			}
			return i, typ, val, true
		}
		if json[i] <= ' ' {
			continue
		}
		switch json[i] {
		case '"':
			i++
			var vesc bool
			var ok bool
			i, val, vesc, ok = jsonParseString(json, i)
			typ = 's'
			if !ok {
				return i, typ, val, false
			}
			if hit && vesc {
				typ = 'S'
			}
			return i, typ, val, true
		case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			i, val = jsonParseNumber(json, i)
			if hit {
				typ = 'n'
			}
			return i, typ, val, true
		case 't', 'f', 'n':
			vc := json[i]
			i, val = jsonParseLiteral(json, i)
			if hit {
				switch vc {
				case 't':
					typ = 't'
				case 'f':
					typ = 'f'
				}
				return i, typ, val, true
			}
		}
	}
	return i, typ, val, false
}

func jsonParseSquash(json []byte, i int) (int, []byte) {
	// expects that the lead character is a '[' or '{' or '('
	// squash the value, ignoring all nested arrays and objects.
	// the first '[' or '{' or '(' has already been read
	s := i
	i++
	depth := 1
	_ = json[len(json)-1] // remove bounds check
	for ; i < len(json); i++ {
		if json[i] >= '"' && json[i] <= '}' {
			switch json[i] {
			case '"':
				i++
				s2 := i
				for ; i < len(json); i++ {
					if json[i] > '\\' {
						continue
					}
					if json[i] == '"' {
						// look for an escaped slash
						if json[i-1] == '\\' {
							n := 0
							for j := i - 2; j > s2-1; j-- {
								if json[j] != '\\' {
									break
								}
								n++
							}
							if n%2 == 0 {
								continue
							}
						}
						break
					}
				}
			case '{', '[', '(':
				depth++
			case '}', ']', ')':
				depth--
				if depth == 0 {
					i++
					return i, json[s:i]
				}
			}
		}
	}
	return i, json[s:]
}

func jsonParseNumber(json []byte, i int) (int, []byte) {
	var s = i
	i++
	_ = json[len(json)-1] // remove bounds check
	for ; i < len(json); i++ {
		if json[i] <= ' ' || json[i] == ',' || json[i] == ']' ||
			json[i] == '}' {
			return i, json[s:i]
		}
	}
	return i, json[s:]
}

func jsonParseLiteral(json []byte, i int) (int, []byte) {
	var s = i
	i++
	_ = json[len(json)-1] // remove bounds check
	for ; i < len(json); i++ {
		if json[i] < 'a' || json[i] > 'z' {
			return i, json[s:i]
		}
	}
	return i, json[s:]
}

// jsonUnescape unescapes a string
func jsonUnescape(json, str []byte) []byte {
	_ = json[len(json)-1] // remove bounds check
	var p [6]byte
	for i := 0; i < len(json); i++ {
		switch {
		default:
			str = append(str, json[i])
		case json[i] < ' ':
			return str
		case json[i] == '\\':
			i++
			if i >= len(json) {
				return str
			}
			switch json[i] {
			default:
				return str
			case '\\':
				str = append(str, '\\')
			case '/':
				str = append(str, '/')
			case 'b':
				str = append(str, '\b')
			case 'f':
				str = append(str, '\f')
			case 'n':
				str = append(str, '\n')
			case 'r':
				str = append(str, '\r')
			case 't':
				str = append(str, '\t')
			case '"':
				str = append(str, '"')
			case 'u':
				if i+5 > len(json) {
					return str
				}
				m, _ := strconv.ParseUint(b2s(json[i+1:i+5]), 16, 64)
				r := rune(m)
				i += 5
				if utf16.IsSurrogate(r) {
					// need another code
					if len(json[i:]) >= 6 && json[i] == '\\' &&
						json[i+1] == 'u' {
						// we expect it to be correct so just consume it
						m, _ = strconv.ParseUint(b2s(json[i+2:i+6]), 16, 64)
						r = utf16.DecodeRune(r, rune(m))
						i += 6
					}
				}
				str = append(str, p[:utf8.EncodeRune(p[:], r)]...)
				i-- // backtrack index by one
			}
		}
	}
	return str
}
