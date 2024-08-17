// Package xz implements simple .xz decompression using external xz program
//
// No shared library (liblzma) dependencies.
package xz

import (
	"io"
	"os/exec"
	"syscall"
)

// Reader does decompression using xz utility
type Reader struct {
	out io.ReadCloser
	cmd *exec.Cmd
}

// NewReader creates .xz decompression reader
//
// Internally it starts xz program, sets up input and output pipes
func NewReader(src io.Reader) (*Reader, error) {
	cmd := exec.Command("xz", "--decompress", "--stdout", "-T0")
	cmd.Stdin = src
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	err = cmd.Start()
	if err != nil {
		return nil, err
	}
	return &Reader{out: out, cmd: cmd}, nil
}

func (rd *Reader) Read(p []byte) (n int, err error) {
	return rd.out.Read(p)
}

func (rd *Reader) Close() error {
	if err := rd.out.Close(); err != nil {
		return err
	}

	if err := rd.cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			status, ok := exitErr.Sys().(syscall.WaitStatus)
			if ok && status.Signaled() && status.Signal() == syscall.SIGPIPE {
				// SIGPIPE is normal because xz's stdout was closed.
				return nil
			}
		}

		return err
	}

	return nil
}
