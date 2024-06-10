package event

import (
	"path/filepath"
	"strings"

	"github.com/gopacket/gopacket/pcapgo"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/types"
	"github.com/mozillazg/ptcpdump/internal/utils"
)

type ProcessExec struct {
	Pid int

	Filename          string
	FilenameTruncated bool

	Args          []string
	ArgsTruncated bool

	MntNs      int64
	Netns      int64
	CgroupName string
}

func ParseProcessExecEvent(event bpf.BpfExecEventT) (*ProcessExec, error) {
	var p ProcessExec
	if event.ArgsTruncated == 1 {
		p.ArgsTruncated = true
	}
	if event.FilenameTruncated == 1 {
		p.FilenameTruncated = true
	}

	p.Pid = int(event.Meta.Pid)
	p.MntNs = int64(event.Meta.MntnsId)
	p.Netns = int64(event.Meta.NetnsId)

	bs := strings.Builder{}
	for i := 0; i < int(event.ArgsSize); i++ {
		b := byte(event.Args[i])
		if b == '\x00' {
			p.Args = append(p.Args, bs.String())
			bs.Reset()
		} else {
			bs.WriteByte(b)
		}
	}

	p.Filename = utils.GoString(event.Filename[:])
	p.CgroupName = utils.GoString(event.Meta.CgroupName[:])

	return &p, nil
}

func FromPacketOptions(opts pcapgo.NgPacketOptions) (ProcessExec, types.PacketContext) {
	p := &ProcessExec{}
	pctx := &types.PacketContext{}

	pctx.FromPacketComments(opts.Comments)
	p.Pid = pctx.Pid
	p.Filename = pctx.Cmd
	p.FilenameTruncated = pctx.CmdTruncated
	p.Args = pctx.Args
	p.ArgsTruncated = pctx.ArgsTruncated

	// log.Printf("new packet: %#v, %#v", *p, *pctx)

	return *p, *pctx
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
