package metadata

import (
	"log"
	"sync"

	"github.com/mozillazg/ptcpdump/internal/event"
	"github.com/mozillazg/ptcpdump/internal/types"
	"github.com/mozillazg/ptcpdump/internal/utils"
	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/xerrors"
)

const defaultProcDir = "/proc"

type ProcessCache struct {
	m map[int]*types.PacketContext

	cc *ContainerCache

	lock sync.RWMutex
}

func NewProcessCache() *ProcessCache {
	return &ProcessCache{
		m:    make(map[int]*types.PacketContext),
		lock: sync.RWMutex{},
	}
}

func (c *ProcessCache) WithContainerCache(cc *ContainerCache) *ProcessCache {
	c.cc = cc
	return c
}

func (c *ProcessCache) Start() {
	if err := c.fillRunningProcesses(); err != nil {
		log.Printf("fill running processes info failed: %+v", err)
	}
}

func (c *ProcessCache) fillRunningProcesses() error {
	ps, err := process.Processes()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	for _, p := range ps {
		filename, _ := p.Exe()
		if filename == "" {
			filename, _ = p.Name()
		}
		args, _ := p.CmdlineSlice()
		e := event.ProcessExec{
			Pid:               int(p.Pid),
			Filename:          filename,
			FilenameTruncated: false,
			Args:              args,
			ArgsTruncated:     false,
			MntNs:             utils.GetMountNamespaceFromPid(int(p.Pid)),
			Netns:             utils.GetNetworkNamespaceFromPid(int(p.Pid)),
		}
		c.AddItem(e)
	}

	return nil
}

func (c *ProcessCache) AddItem(exec event.ProcessExec) {
	c.AddItemWithContext(exec, types.PacketContext{})
}

func (c *ProcessCache) AddItemWithContext(exec event.ProcessExec, rawCtx types.PacketContext) {
	pid := exec.Pid

	ctx := &types.PacketContext{
		Process: types.Process{
			Pid:              exec.Pid,
			MountNamespaceId: int64(exec.MntNs),
			NetNamespaceId:   int64(exec.Netns),
			Cmd:              exec.FilenameStr(),
			Args:             exec.Args,
			ArgsTruncated:    exec.ArgsTruncated,
		},
		Container: rawCtx.Container,
	}
	if c.cc != nil && ctx.Container.Id == "" {
		if ctx.Container.Id == "" && exec.CgroupName != "" {
			// log.Printf("exec name: %#v", exec)
			ctx.Container = c.cc.GetById(exec.CgroupName)
		}
		if ctx.Container.Id == "" {
			ctx.Container = c.cc.GetByPid(ctx.Process.Pid)
		}
		if ctx.Container.Id == "" {
			ctx.Container = c.cc.GetByMntNs(ctx.Process.MountNamespaceId)
		}
		if ctx.Container.Id == "" {
			ctx.Container = c.cc.GetByNetNs(ctx.Process.NetNamespaceId)
		}
	}

	c.lock.Lock()
	c.m[pid] = ctx
	c.lock.Unlock()

	//log.Printf("add new cache: %d", pid)
}

func (c *ProcessCache) Get(pid int, mntNs int) types.PacketContext {
	c.lock.RLock()
	ret := c.m[pid]
	c.lock.RUnlock()

	if ret == nil {
		return types.PacketContext{}
	}

	ctx := *ret
	if ctx.Container.Id == "" && c.cc != nil {
		if ctx.Container.Id == "" {
			ctx.Container = c.cc.GetByPid(ctx.Process.Pid)
		}
		if ctx.Container.Id == "" {
			ctx.Container = c.cc.GetByMntNs(ctx.Process.MountNamespaceId)
		}
		if ctx.Container.Id == "" {
			ctx.Container = c.cc.GetByNetNs(ctx.Process.NetNamespaceId)
		}
	}

	return ctx
}

func (c *ProcessCache) GetPidsByComm(name string) []int {
	c.lock.RLock()
	defer c.lock.RUnlock()

	var pids []int
	for pid, info := range c.m {
		if info.MatchComm(name) {
			pids = append(pids, pid)
		}
	}
	return pids
}
