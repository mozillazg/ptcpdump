package utils

import (
	"errors"
	"github.com/mozillazg/ptcpdump/internal/types"
)

func UnwrapErr(err error) error {
	for {
		if v := errors.Unwrap(err); v != nil {
			err = v
		} else {
			return err
		}
	}
}

func RunClosers(funcs []func()) {
	for i := len(funcs) - 1; i >= 0; i-- {
		f := funcs[i]
		if f != nil {
			f()
		}
	}
}

func CloseAll(closers []types.Closer) {
	for i := len(closers) - 1; i >= 0; i-- {
		c := closers[i]
		if c != nil {
			c.Close()
		}
	}
}
