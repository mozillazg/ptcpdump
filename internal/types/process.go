package types

import (
	"path/filepath"
	"strings"
)

type ProcessBase struct {
	Pid          int
	Cmd          string
	CmdTruncated bool
	Tid          int
	TName        string

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

type ProcessExec struct {
	PPid int
	Pid  int

	Tid   int
	TName string

	Filename          string
	FilenameTruncated bool

	Args          []string
	ArgsTruncated bool

	PidNs      int64
	MntNs      int64
	Netns      int64
	CgroupName string
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
	// openwrt case: pid 13055, cmd /dev/fd/5, args /usr/sbin/dropbear -F -P /var/run/dropbear.1.pid -p 22 -K 300
	if strings.HasPrefix(p.Cmd, "/dev/fd/") {
		if len(p.Args) > 0 {
			return filepath.Base(p.Args[0])
		}
	}
	return filepath.Base(p.Cmd)
}

func (p ProcessExec) FilenameStr() string {
	s := string(p.Filename)
	if p.FilenameTruncated {
		s += "..."
	}
	return s
}

func (p ProcessExec) ArgsStr() string {
	s := strings.Join(p.Args, " ")
	if p.ArgsTruncated {
		s += "..."
	}
	return s
}

func (p ProcessExec) MatchComm(name string) bool {
	filename := filepath.Base(p.Filename)
	if len(filename) > 15 {
		filename = filename[:15]
	}
	return name == filename
}
