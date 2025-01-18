package types

import "errors"

var ErrDeviceNotFound = errors.New("device not found")

type Closer interface {
	Close() error
}
