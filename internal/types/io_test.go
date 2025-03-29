package types

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func TestNewReadBuffer(t *testing.T) {
	r := io.NopCloser(bytes.NewReader([]byte("test data")))
	buf := NewReadBuffer(r)
	if buf == nil {
		t.Errorf("NewReadBuffer() returned nil")
	}
}

func TestReadBuffer_Read(t *testing.T) {
	r := io.NopCloser(bytes.NewReader([]byte("test data")))
	buf := NewReadBuffer(r)
	p := make([]byte, 4)
	n, err := buf.Read(p)
	if err != nil {
		t.Errorf("Read() error = %v", err)
	}
	if n != 4 {
		t.Errorf("Read() = %v, want %v", n, 4)
	}
	if string(p) != "test" {
		t.Errorf("Read() = %v, want %v", string(p), "test")
	}
}

func TestReadBuffer_Peek(t *testing.T) {
	r := io.NopCloser(bytes.NewReader([]byte("test data")))
	buf := NewReadBuffer(r)
	p, err := buf.Peek(4)
	if err != nil {
		t.Errorf("Peek() error = %v", err)
	}
	if string(p) != "test" {
		t.Errorf("Peek() = %v, want %v", string(p), "test")
	}
}

func TestReadBuffer_Close(t *testing.T) {
	r := io.NopCloser(bytes.NewReader([]byte("test data")))
	buf := NewReadBuffer(r)
	err := buf.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestReadBuffer_File(t *testing.T) {
	f, err := os.CreateTemp("", "testfile")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	buf := NewReadBuffer(f)
	file, ok, err := buf.File()
	if err != nil {
		t.Errorf("File() error = %v", err)
	}
	if !ok {
		t.Errorf("File() = %v, want %v", ok, true)
	}
	if file == nil {
		t.Errorf("File() returned nil")
	}
}
