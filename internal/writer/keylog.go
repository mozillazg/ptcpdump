package writer

import (
	"fmt"
	"os"
)

type KeyLogWriter interface {
	Write(line string) error
	Flush() error
	Close() error
}

type KeyLogFileWriter struct {
	fpath string
	f     *os.File
}

func NewKeyLogFileWriter(fpath string) (*KeyLogFileWriter, error) {
	f, err := os.OpenFile(fpath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("error opening file %s: %v", fpath, err)
	}
	return &KeyLogFileWriter{
		fpath: fpath,
		f:     f,
	}, nil
}

func (k *KeyLogFileWriter) Write(line string) error {
	_, err := k.f.WriteString(line)
	return err
}

func (k *KeyLogFileWriter) Flush() error {
	return k.f.Sync()
}

func (k *KeyLogFileWriter) Close() error {
	return k.f.Close()
}
