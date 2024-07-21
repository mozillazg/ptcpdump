package types

import (
	"path/filepath"
	"strings"
)

type ProcessBase struct {
	Pid          int
	Cmd          string
	CmdTruncated bool

	Args          []string
	ArgsTruncated bool
}

type ProcessNamespace struct {
	PidNamespaceId   int64
	MountNamespaceId int64
	NetNamespaceId   int64
}

type Process struct {
	Parent ProcessBase

	ProcessBase
	ProcessNamespace
}

func (p ProcessBase) MatchComm(name string) bool {
	filename := p.Comm()
	if len(filename) > 15 {
		filename = filename[:15]
	}
	return name == filename
}

func (p ProcessBase) FormatArgs() string {
	s := strings.Join(p.Args, " ")
	if p.ArgsTruncated {
		s += "..."
	}
	return s
}

func (p ProcessBase) Comm() string {
	return filepath.Base(p.Cmd)
}
