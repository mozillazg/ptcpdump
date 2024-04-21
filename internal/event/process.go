package event

import (
	"bytes"
	"encoding/binary"
	"github.com/mozillazg/ptcpdump/bpf"
	"golang.org/x/xerrors"
)

type ProcessExec struct {
	Pid       int
	Args      []byte
	Truncated bool
}

func ParseProcessExecEvent(rawSample []byte) (*ProcessExec, error) {
	var p ProcessExec
	event := bpf.BpfExecEventT{}
	if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event); err != nil {
		return nil, xerrors.Errorf("parse event: %w", err)
	}

	if event.Truncated == 1 {
		p.Truncated = true
	}
	p.Pid = int(event.Pid)
	for i := 0; i < int(event.ArgsSize); i++ {
		b := byte(event.Args[i])
		if b == '\x00' {
			b = ' '
		}
		p.Args = append(p.Args, b)
	}

	return &p, nil
}
