package event

import (
	"path/filepath"
	"strconv"
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
	p := ProcessExec{}
	ctx := types.PacketContext{}

	for _, comment := range opts.Comments {
		comment = strings.TrimSpace(comment)
		for _, line := range strings.Split(comment, "\n") {
			line = strings.TrimSpace(line)
			parts := strings.SplitN(line, ":", 2)
			if len(parts) < 2 {
				continue
			}
			key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			switch key {
			case "PID":
				p.Pid, _ = strconv.Atoi(value)
				ctx.Pid = p.Pid
			case "Command":
				if strings.HasSuffix(value, "...") {
					p.FilenameTruncated = true
					value = strings.TrimRight(value, "...")
				}
				p.Filename = value
				ctx.Cmd = value
			case "Args":
				if strings.HasSuffix(value, "...") {
					p.ArgsTruncated = true
					value = strings.TrimRight(value, "...")
				}
				p.Args = strings.Split(value, " ")
				ctx.Args = p.Args
			case "ContainerName":
				ctx.Container.Name = value
			case "ContainerId":
				ctx.Container.Id = value
			case "ContainerImage":
				ctx.Container.Image = value
			case "ContainerLabels":
				ctx.Container.Labels = types.ParseContainerLabels(value)
			default:
			}
		}
	}
	return p, ctx
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
