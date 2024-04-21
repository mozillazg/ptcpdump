package event

import (
	"bytes"
	"encoding/binary"
	"github.com/mozillazg/ptcpdump/bpf"
	"golang.org/x/xerrors"
)

type ProcessExec struct {
	Pid int

	Filename          []byte
	FilenameTruncated bool

	Args          []byte
	ArgsTruncated bool
}

func ParseProcessExecEvent(rawSample []byte) (*ProcessExec, error) {
	var p ProcessExec
	event := bpf.BpfExecEventT{}
	if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event); err != nil {
		return nil, xerrors.Errorf("parse event: %w", err)
	}

	if event.ArgsTruncated == 1 {
		p.ArgsTruncated = true
	}
	if event.FilenameTruncated == 1 {
		p.FilenameTruncated = true
	}
	p.Pid = int(event.Pid)
	for i := 0; i < int(event.ArgsSize); i++ {
		b := byte(event.Args[i])
		if b == '\x00' {
			b = ' '
		}
		p.Args = append(p.Args, b)
	}
	for _, i := range event.Filename {
		b := byte(i)
		if b == '\x00' {
			break
		}
		p.Filename = append(p.Filename, b)
	}

	return &p, nil
}

func (p ProcessExec) FilenameStr() string {
	s := string(p.Filename)
	if p.FilenameTruncated {
		s += "..."
	}
	return s
}

func (p ProcessExec) ArgsStr() string {
	s := string(p.Args)
	if p.ArgsTruncated {
		s += "..."
	}
	return s
}
