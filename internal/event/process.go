package event

import (
	"strings"

	"github.com/gopacket/gopacket/pcapgo"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/types"
	"github.com/mozillazg/ptcpdump/internal/utils"
)

func ParseProcessExecEvent(event bpf.BpfExecEventT) (*types.ProcessExec, error) {
	var p types.ProcessExec
	if event.ArgsTruncated == 1 {
		p.ArgsTruncated = true
	}
	if event.FilenameTruncated == 1 {
		p.FilenameTruncated = true
	}

	p.PPid = int(event.Meta.Ppid)
	p.Pid = int(event.Meta.Pid)
	p.PidNs = int64(event.Meta.PidnsId)
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

func FromPacketOptions(opts pcapgo.NgPacketOptions) (types.ProcessExec, types.PacketContext) {
	p := &types.ProcessExec{}
	pctx := &types.PacketContext{
		Process: types.Process{
			ProcessBase: types.ProcessBase{
				UserId: -1,
			},
		},
	}

	pctx.FromPacketComments(opts.Comments)
	p.PPid = pctx.Parent.Pid
	p.Pid = pctx.Pid
	p.Tid = pctx.Tid
	p.Uid = pctx.UserId
	p.TName = pctx.TName
	p.Filename = pctx.Cmd
	p.FilenameTruncated = pctx.CmdTruncated
	p.Args = pctx.Args
	p.ArgsTruncated = pctx.ArgsTruncated

	log.Debugf("new packet: %#v, %#v", *p, *pctx)

	return *p, *pctx
}
