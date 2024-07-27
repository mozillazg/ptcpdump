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
