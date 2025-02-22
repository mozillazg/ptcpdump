package writer

import (
	"fmt"
	"github.com/mozillazg/ptcpdump/internal/log"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type RotatorOption struct {
	MaxFileNumber    int
	MaxFileSizeBytes int64
}

type Rotator interface {
	Write(p []byte) (n int, err error)
	ShouldRotate(n int) bool
	Rotate() error
	Flush() error
	Close() error
}

type FileRotator struct {
	opt RotatorOption

	fileDir       string
	fileNameNoExt string
	fileExt       string
	file          *os.File
	fileSize      int64
	fileNumber    int

	lock sync.RWMutex
}

type StdoutRotator struct {
	w io.Writer
}

func NewFileRotator(filePath string, opt RotatorOption) (*FileRotator, error) {
	filedir, filename := filepath.Split(filePath)
	ext := filepath.Ext(filename)
	fileNameNoExt := strings.TrimSuffix(strings.TrimSuffix(filename, ext), ".")

	// TODO: change use 0640 as fileMode?
	if opt.MaxFileNumber > 0 && opt.MaxFileSizeBytes > 0 {
		filePath += "0"
	}
	file, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("create file: %w", err)
	}
	return &FileRotator{
		opt:           opt,
		fileDir:       filedir,
		fileNameNoExt: fileNameNoExt,
		fileExt:       ext,
		file:          file,
		fileSize:      0,
		fileNumber:    1,
		lock:          sync.RWMutex{},
	}, nil
}

func (r *FileRotator) Write(p []byte) (n int, err error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	n, err = r.file.Write(p)
	r.fileSize += int64(n)
	return n, err
}

func (r *FileRotator) ShouldRotate(n int) bool {
	if r.opt.MaxFileSizeBytes <= 0 {
		return false
	}

	r.lock.RLock()
	defer r.lock.RUnlock()

	return r.fileSize+int64(n) >= r.opt.MaxFileSizeBytes
}

func (r *FileRotator) Rotate() error {
	r.lock.Lock()
	defer r.lock.Unlock()

	log.Infof("start to rotate file: %s", r.file.Name())
	if err := r.file.Sync(); err != nil {
		return fmt.Errorf("sync file: %w", err)
	}
	if err := r.file.Close(); err != nil {
		return fmt.Errorf("close file: %w", err)
	}

	fileName := r.newFileName()
	filePath := filepath.Join(r.fileDir, fileName)
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	log.Infof("rotated file, new file: %s", fileName)

	r.fileNumber++
	r.file = file
	r.fileSize = 0
	return nil
}

func (r *FileRotator) newFileName() string {
	suffix := ""
	if r.opt.MaxFileNumber > 0 {
		if r.fileNumber < r.opt.MaxFileNumber {
			suffix = fmt.Sprintf("%d", r.fileNumber)
		} else {
			suffix = "0"
			r.fileNumber = 0
		}
	} else if r.opt.MaxFileSizeBytes > 0 {
		suffix = fmt.Sprintf("%d", r.fileNumber)
	}
	return fmt.Sprintf("%s%s%s", r.fileNameNoExt, r.fileExt, suffix)
}

func (r *FileRotator) Flush() error {
	r.lock.Lock()
	defer r.lock.Unlock()

	return r.file.Sync()
}

func (r *FileRotator) Close() error {
	r.lock.Lock()
	defer r.lock.Unlock()

	if err := r.file.Sync(); err != nil {
		return err
	}
	return r.file.Close()
}

func NewStdoutRotator() *StdoutRotator {
	return &StdoutRotator{
		w: os.Stdout,
	}
}

func (s StdoutRotator) Write(p []byte) (n int, err error) {
	return s.w.Write(p)
}

func (s StdoutRotator) ShouldRotate(n int) bool {
	return false
}

func (s StdoutRotator) Rotate() error {
	return nil
}

func (s StdoutRotator) Flush() error {
	return nil
}

func (s StdoutRotator) Close() error {
	return nil
}
