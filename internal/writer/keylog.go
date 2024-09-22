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

type KeyLogPcapNGWriter struct {
	w *PcapNGWriter
}

func NewKeyLogFileWriter(fpath string) (*KeyLogFileWriter, error) {
	f, err := os.OpenFile(fpath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("error opening file %s: %v", fpath, err)
	}
	return &KeyLogFileWriter{
		fpath: fpath,
		f:     f,
	}, nil
}

func NewKeyLogPcapNGWriter(w *PcapNGWriter) *KeyLogPcapNGWriter {
	return &KeyLogPcapNGWriter{w: w}
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

func (k *KeyLogPcapNGWriter) Write(line string) error {
	err := k.w.WriteTLSKeyLog(line)
	return err
}

func (k *KeyLogPcapNGWriter) Flush() error {
	return nil
}

func (k *KeyLogPcapNGWriter) Close() error {
	return nil
}
