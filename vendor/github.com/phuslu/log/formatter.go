package log

import (
	"bytes"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

// formatterKeyValue is a single member of FormatterArgs.KeyValues. It is an
// alias of the anonymous struct type, so the exported field keeps its type
// while the parser can name the elements.
type formatterKeyValue = struct {
	Key       string // "foo"
	Value     string // "bar"
	ValueType byte   // 's'
}

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

// formatterArgsPos returns the position of a well-known field of FormatterArgs
// for the given json key, or 0 when the key is an ordinary key/value pair.
//
// The built-in names are looked up by length first, so an ordinary key costs a
// single length comparison instead of a comparison against every name. The
// TimeKey, LevelKey, ... variables can be set to any name, they are checked
// afterwards. A custom name that happens to equal the built-in name of another
// field resolves to that built-in field.
func formatterArgsPos(key string) (pos int) {
	switch len(key) {
	case 3:
		if key == "msg" {
			return 7
		}
	case 4:
		switch key {
		case "time":
			return 1
		case "goid":
			return 5
		case "_msg":
			return 7
		}
	case 5:
		switch key {
		case "level":
			return 2
		case "stack":
			return 6
		}
	case 6:
		if key == "caller" {
			return 3
		}
	case 7:
		if key == "message" {
			return 7
		}
	case 10:
		if key == "callerfunc" {
			return 4
		}
	}
	switch key {
	case TimeKey:
		return 1
	case LevelKey:
		return 2
	case CallerKey:
		return 3
	case CallerFuncKey:
		return 4
	case GoidKey:
		return 5
	case StackKey:
		return 6
	case MessageKey:
		return 7
	}
	return 0
}

// jsonVchars is a lookup table for the json tokens that jsonParseSquash has
// to act on, the values are chosen so that the depth can be updated with a
// single add: '"' is a string, the open tokens are +1 and the close ones are
// -1. The table is only inspected for bytes that are not plain content, so
// scanning can proceed eight bytes at a time.
var jsonVchars = [256]byte{
	'"': 2, '{': 3, '(': 3, '[': 3, '}': 1, ')': 1, ']': 1,
}

// parseFormatterArgs extracts json string to json items
func parseFormatterArgs(json []byte, args *FormatterArgs) {
	// Pre-allocate KeyValues slice to a reasonable capacity.
	// This prevents a race condition that can lead to memory corruption
	// when append is called on a nil slice from multiple goroutines.
	args.KeyValues = make([]formatterKeyValue, 0, 16)

	// treat formatter args as []string
	const size = int(unsafe.Sizeof(FormatterArgs{}) / unsafe.Sizeof(""))
	//nolint:all
	slice := unsafe.Slice((*string)(unsafe.Pointer(args)), size)
	var key, str []byte
	var ok bool
	var typ byte
	_ = json[len(json)-1] // remove bounds check
	if json[0] != '{' {
		return
	}
	for i := 1; i < len(json); i++ {
		// An object member key is always followed by a value, so every quote
		// found here starts a key. jsonParseKey returns it unquoted, which is
		// all that is needed for the lookup below.
		if json[i] != '"' {
			continue
		}
		i, key, ok = jsonParseKey(json, i+1)
		if !ok {
			return
		}
		// jsonParseAny skips the ':' and ',' separators by itself, there is
		// no need to filter them out here.
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
			args.KeyValues = append(args.KeyValues, formatterKeyValue{
				b2s(key), b2s(str), typ,
			})
		}
	}

	if args.Level == "" {
		args.Level = "????"
	}
}

// jsonParseKey parses an object member key. It is a slightly different
// version of jsonParseString because the outer quotes are not needed, only
// the key itself. It expects json[i-1] to be the opening quote.
func jsonParseKey(json []byte, i int) (int, []byte, bool) {
	var s = i
	_ = json[len(json)-1] // remove bounds check
	for ; i < len(json); i++ {
		if json[i] > '\\' {
			continue
		}
		if json[i] == '"' {
			return i + 1, json[s:i], true
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
					return i + 1, json[s:i], true
				}
			}
			break
		}
	}
	return i, json[s:], false
}

func jsonParseString(json []byte, i int) (int, []byte, bool, bool) {
	_ = json[len(json)-1] // remove bounds check
	// expects that json[i-1] is the opening quote. A quote is searched for
	// with bytes.IndexByte, which scans a whole register per iteration, and
	// only the rare escaped quote needs the byte by byte walk.
	var s = i - 1
	for {
		j := bytes.IndexByte(json[i:], '"')
		if j < 0 {
			return len(json), json[s:], false, false
		}
		i += j
		if json[i-1] == '\\' {
			// look for an escaped slash
			n := 0
			for j := i - 2; j > 0; j-- {
				if json[j] != '\\' {
					break
				}
				n++
			}
			if n%2 == 0 {
				// the quote is escaped, keep looking for the closing one
				i++
				continue
			}
			// the closing quote is preceded by an odd number of slashes,
			// the string has escapes
			return i + 1, json[s : i+1], true, true
		}
		// a backslash before the closing quote means the string has to be
		// unescaped by the caller
		return i + 1, json[s : i+1], bytes.IndexByte(json[s+1:i], '\\') >= 0, true
	}
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
		var num bool
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
		case 'n':
			if i+1 < len(json) && json[i+1] != 'u' {
				// nan
				num = true
				break
			}
			fallthrough
		case 't', 'f':
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
		case '+', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'i', 'I', 'N':
			num = true
		}
		if num {
			i, val = jsonParseNumber(json, i)
			if hit {
				typ = 'n'
			}
			return i, typ, val, true
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
	var c byte
	for i < len(json) {
		// plain content is skipped eight bytes at a time
		for i < len(json)-8 {
			jslice := json[i : i+8]
			if c = jsonVchars[jslice[0]]; c != 0 {
				goto token
			}
			if c = jsonVchars[jslice[1]]; c != 0 {
				i++
				goto token
			}
			if c = jsonVchars[jslice[2]]; c != 0 {
				i += 2
				goto token
			}
			if c = jsonVchars[jslice[3]]; c != 0 {
				i += 3
				goto token
			}
			if c = jsonVchars[jslice[4]]; c != 0 {
				i += 4
				goto token
			}
			if c = jsonVchars[jslice[5]]; c != 0 {
				i += 5
				goto token
			}
			if c = jsonVchars[jslice[6]]; c != 0 {
				i += 6
				goto token
			}
			if c = jsonVchars[jslice[7]]; c != 0 {
				i += 7
				goto token
			}
			i += 8
		}
		c = jsonVchars[json[i]]
		if c == 0 {
			i++
			continue
		}
	token:
		if c == 2 {
			// '"' string
			i++
			s2 := i
		nextquote:
			for i < len(json)-8 {
				jslice := json[i : i+8]
				if jslice[0] == '"' {
					goto strchkesc
				}
				if jslice[1] == '"' {
					i++
					goto strchkesc
				}
				if jslice[2] == '"' {
					i += 2
					goto strchkesc
				}
				if jslice[3] == '"' {
					i += 3
					goto strchkesc
				}
				if jslice[4] == '"' {
					i += 4
					goto strchkesc
				}
				if jslice[5] == '"' {
					i += 5
					goto strchkesc
				}
				if jslice[6] == '"' {
					i += 6
					goto strchkesc
				}
				if jslice[7] == '"' {
					i += 7
					goto strchkesc
				}
				i += 8
			}
			goto strchkstd
		strchkesc:
			if json[i-1] != '\\' {
				i++
				continue
			}
		strchkstd:
			for i < len(json) {
				if json[i] != '"' {
					i++
					continue
				}
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
						i++
						goto nextquote
					}
				}
				break
			}
		} else {
			// '{', '[', '(', '}', ']', ')'
			// open and close tokens
			depth += int(c) - 2
			if depth == 0 {
				i++
				return i, json[s:i]
			}
		}
		i++
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

// jsonRune decodes the four hex digits of a \uXXXX escape.
func jsonRune(json []byte) rune {
	n, _ := strconv.ParseUint(b2s(json[:4]), 16, 64)
	return rune(n)
}

// jsonUnescape unescapes json into str, which may alias json as long as it
// starts at or before it, an unescaped string is never longer than its
// escaped form.
func jsonUnescape(json, str []byte) []byte {
	_ = json[len(json)-1] // remove bounds check
	var p [utf8.UTFMax]byte
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
				r := jsonRune(json[i+1 : i+5])
				i += 5
				if utf16.IsSurrogate(r) {
					// need another code
					if len(json[i:]) >= 6 && json[i] == '\\' &&
						json[i+1] == 'u' {
						// we expect it to be correct so just consume it
						r = utf16.DecodeRune(r, jsonRune(json[i+2:i+6]))
						i += 6
					}
				}
				// encode into a scratch buffer, utf8.EncodeRune needs
				// enough space for the largest rune
				n := utf8.EncodeRune(p[:], r)
				str = append(str, p[:n]...)
				i-- // backtrack index by one
			}
		}
	}
	return str
}
