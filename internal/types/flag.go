package types

import (
	"fmt"
	"strconv"
	"strings"
)

type FlagTypeFileSize struct {
	val string
	n   uint64
}

func (s *FlagTypeFileSize) Set(val string) error {
	n, err := strconv.ParseUint(val, 10, 64)
	if err == nil {
		s.n = n * 1_000_000
		return nil
	}
	val = strings.ToLower(val)
	switch {
	case strings.HasSuffix(val, "k"):
		val = strings.TrimSuffix(val, "k")
		n, err = strconv.ParseUint(val, 10, 64)
		if err != nil {
			return err
		}
		s.n = n * 1024
		break
	case strings.HasSuffix(val, "kb"):
		val = strings.TrimSuffix(val, "kb")
		n, err = strconv.ParseUint(val, 10, 64)
		if err != nil {
			return err
		}
		s.n = n * 1024
		break
	case strings.HasSuffix(val, "m"):
		val = strings.TrimSuffix(val, "m")
		n, err = strconv.ParseUint(val, 10, 64)
		if err != nil {
			return err
		}
		s.n = n * 1024 * 1024
		break
	case strings.HasSuffix(val, "mb"):
		val = strings.TrimSuffix(val, "mb")
		n, err = strconv.ParseUint(val, 10, 64)
		if err != nil {
			return err
		}
		s.n = n * 1024 * 1024
		break
	case strings.HasSuffix(val, "g"):
		val = strings.TrimSuffix(val, "g")
		n, err = strconv.ParseUint(val, 10, 64)
		if err != nil {
			return err
		}
		s.n = n * 1024 * 1024 * 1024
		break
	case strings.HasSuffix(val, "gb"):
		val = strings.TrimSuffix(val, "gb")
		n, err = strconv.ParseUint(val, 10, 64)
		if err != nil {
			return err
		}
		s.n = n * 1024 * 1024 * 1024
		break
	default:
		return fmt.Errorf("invalid file size: %s", val)
	}

	return nil
}
func (s *FlagTypeFileSize) Type() string {
	return "fileSize"
}

func (s *FlagTypeFileSize) Bytes() int64 {
	return int64(s.n)
}

func (s *FlagTypeFileSize) String() string { return string(s.val) }
