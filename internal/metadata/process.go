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

var (
	HostMntNs int64
	HostPidNs int64
	HostNetNs int64
)

type ProcessCache struct {
	m map[int]*types.PacketContext

	cc *ContainerCache

	lock sync.RWMutex
}

func init() {
	HostPidNs = utils.GetPidNamespaceFromPid(1)
	HostMntNs = utils.GetMountNamespaceFromPid(1)
	HostNetNs = utils.GetNetworkNamespaceFromPid(1)
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

	// if exec.CgroupName == "" ||
	// 	strings.HasSuffix(exec.CgroupName, ".slice") ||
	// 	strings.HasSuffix(exec.CgroupName, ".service") ||
	// 	strings.HasSuffix(exec.CgroupName, "init.scope") {
	// 	return
	// }
	// if !strings.Contains(exec.Filename, "sleep") {
	// 	return
	// }

	pctx := &types.PacketContext{
		Process: types.Process{
			Pid:              exec.Pid,
			PidNamespaceId:   utils.GetPidNamespaceFromPid(exec.Pid),
			MountNamespaceId: int64(exec.MntNs),
			NetNamespaceId:   int64(exec.Netns),
			Cmd:              exec.FilenameStr(),
			Args:             exec.Args,
			ArgsTruncated:    exec.ArgsTruncated,
		},
		Container: rawCtx.Container,
		Pod:       rawCtx.Pod,
	}
	// log.Printf("new exec event: %#v, %#v\n\n", exec, *pctx)
	if c.cc != nil && pctx.Container.Id == "" {
		pctx.Container = c.getContainer(*pctx, exec.CgroupName)
		if pctx.Container.Id != "" {
			pctx.Pod = c.cc.GetPodByContainer(pctx.Container)
		}
	}

	c.lock.Lock()
	c.m[pid] = pctx
	c.lock.Unlock()

	// log.Printf("add new cache: %d, %#v\n\n", pid, *pctx)
}

func (c *ProcessCache) getContainer(ctx types.PacketContext, cgroupName string) (cr types.Container) {
	cr = ctx.Container
	if cr.Id == "" && cgroupName != "" {
		// log.Printf("exec name: %#v", exec)
		cr = c.cc.GetById(cgroupName)
		// log.Printf("get by cgroup")
	}
	if cr.Id == "" {
		cr = c.cc.GetByPid(ctx.Process.Pid)
		// log.Printf("get by pid")
	}
	if cr.Id == "" {
		cr = c.cc.GetByMntNs(ctx.Process.MountNamespaceId)
		// log.Printf("get by mnt")
	}
	if cr.Id == "" {
		cr = c.cc.GetByNetNs(ctx.Process.NetNamespaceId)
		// log.Printf("get by net")
	}
	return cr
}

func (c *ProcessCache) Get(pid int, mntNs, netNs int, cgroupName string) types.PacketContext {
	c.lock.RLock()
	ret := c.m[pid]
	c.lock.RUnlock()

	if ret == nil {
		return types.PacketContext{}
	}

	pctx := *ret
	pctx.MountNamespaceId = int64(mntNs)
	pctx.NetNamespaceId = int64(netNs)

	// log.Printf("get %#v", pctx)

	if pctx.Container.Id == "" && c.cc != nil {
		pctx.Container = c.getContainer(pctx, cgroupName)
		if pctx.Container.Id != "" {
			pctx.Pod = c.cc.GetPodByContainer(pctx.Container)
		}
	}

	return pctx
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

func (c *ProcessCache) GetPidsByPidNsId(nsid int64) []int {
	c.lock.RLock()
	defer c.lock.RUnlock()

	var pids []int
	for pid, info := range c.m {
		if info.PidNamespaceId == nsid {
			pids = append(pids, pid)
		}
	}
	return pids
}

func (c *ProcessCache) GetPidsByMntNsId(nsid int64) []int {
	c.lock.RLock()
	defer c.lock.RUnlock()

	var pids []int
	for pid, info := range c.m {
		if info.MountNamespaceId == nsid {
			pids = append(pids, pid)
		}
	}
	return pids
}

func (c *ProcessCache) GetPidsByNetNsId(nsid int64) []int {
	c.lock.RLock()
	defer c.lock.RUnlock()

	var pids []int
	for pid, info := range c.m {
		if info.NetNamespaceId == nsid {
			pids = append(pids, pid)
		}
	}
	return pids
}
