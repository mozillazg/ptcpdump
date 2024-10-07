package utils

import (
	"fmt"
	"os"
)

func OutStderr(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format, a...)
}
