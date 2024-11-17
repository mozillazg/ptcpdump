package utils

import "errors"

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
