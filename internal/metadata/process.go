package metadata

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mozillazg/ptcpdump/internal/event"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/types"
	"github.com/mozillazg/ptcpdump/internal/utils"
	"github.com/shirou/gopsutil/v3/process"
)

const defaultProcDir = "/proc"

var (
	HostMntNs int64
	HostPidNs int64
	HostNetNs int64
)

type ProcessCache struct {
	pids sync.Map // map[int]*types.PacketContext

	deadPids sync.Map // map[int]time.Time

	cc *ContainerCache
}

func init() {
	HostPidNs = utils.GetPidNamespaceFromPid(1)
	HostMntNs = utils.GetMountNamespaceFromPid(1)
	HostNetNs = utils.GetNetworkNamespaceFromPid(1)
}

func NewProcessCache() *ProcessCache {
	return &ProcessCache{
		pids:     sync.Map{},
		deadPids: sync.Map{},
	}
}

func (c *ProcessCache) WithContainerCache(cc *ContainerCache) *ProcessCache {
	c.cc = cc
	return c
}

func (c *ProcessCache) Start(ctx context.Context) {
	if err := c.fillRunningProcesses(ctx); err != nil {
		log.Errorf("fill running processes info failed: %s", err)
	}
	go c.cleanDeadsLoop(ctx)
}

func (c *ProcessCache) fillRunningProcesses(ctx context.Context) error {
	ps, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return fmt.Errorf(": %w", err)
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

func (c *ProcessCache) MarkDead(pid int) {
	c.deadPids.LoadOrStore(pid, time.Now().Add(time.Second*15))
}

func (c *ProcessCache) cleanDeadsLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second * 30)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.jobCleanDead()
		}
	}
}

func (c *ProcessCache) jobCleanDead() {
	var pids []int
	c.deadPids.Range(func(key, value any) bool {
		exp, ok := value.(time.Time)
		if !ok {
			return true
		}
		if time.Now().Before(exp) {
			return true
		}
		pid, ok := key.(int)
		if !ok {
			return true
		}
		pids = append(pids, pid)

		return true
	})

	for _, pid := range pids {
		c.deadPids.Delete(pid)
		c.pids.Delete(pid)
	}
	log.Debugf("cleaned %d dead pids", len(pids))
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
	log.Debugf("new exec event: %#v, %#v", exec, *pctx)

	if c.cc != nil && pctx.Container.Id == "" {
		pctx.Container = c.getContainer(*pctx, exec.CgroupName)
		if pctx.Container.Id != "" {
			pctx.Pod = c.cc.GetPodByContainer(pctx.Container)
		}
	}

	c.pids.Store(pid, pctx)

	log.Debugf("add new cache: %d, %#v", pid, *pctx)
}

func (c *ProcessCache) getContainer(ctx types.PacketContext, cgroupName string) (cr types.Container) {
	cr = ctx.Container
	if cr.Id == "" && cgroupName != "" {
		log.Debugf("exec name: %#v", cgroupName)
		cr = c.cc.GetById(cgroupName)
		log.Debug("get by cgroup")
	}
	if cr.Id == "" {
		cr = c.cc.GetByPid(ctx.Process.Pid)
		log.Debug("get by pid")
	}
	if cr.Id == "" {
		cr = c.cc.GetByMntNs(ctx.Process.MountNamespaceId)
		log.Debug("get by mnt")
	}
	if cr.Id == "" {
		cr = c.cc.GetByNetNs(ctx.Process.NetNamespaceId)
		log.Debug("get by net")
	}
	return cr
}

func (c *ProcessCache) Get(pid int, mntNs, netNs int, cgroupName string) types.PacketContext {
	ret, ok := c.pids.Load(pid)

	if ret == nil || !ok {
		return types.PacketContext{}
	}
	ppx, ok := ret.(*types.PacketContext)
	if ppx == nil || !ok {
		return types.PacketContext{}
	}

	pctx := *ppx
	pctx.MountNamespaceId = int64(mntNs)
	pctx.NetNamespaceId = int64(netNs)

	log.Debugf("get %#v", pctx)

	if pctx.Container.Id == "" && c.cc != nil {
		pctx.Container = c.getContainer(pctx, cgroupName)
		if pctx.Container.Id != "" {
			pctx.Pod = c.cc.GetPodByContainer(pctx.Container)
		}
	}

	return pctx
}

func (c *ProcessCache) GetPidsByComm(name string) []int {
	var pids []int

	c.pids.Range(func(key, value any) bool {
		pid, ok := key.(int)
		if !ok {
			return true
		}
		info, ok := value.(*types.PacketContext)
		if !ok {
			return true
		}
		if info.MatchComm(name) {
			pids = append(pids, pid)
		}
		return true
	})

	return pids
}

func (c *ProcessCache) GetPidsByPidNsId(nsid int64) []int {
	var pids []int

	c.pids.Range(func(key, value any) bool {
		pid, ok := key.(int)
		if !ok {
			return true
		}
		info, ok := value.(*types.PacketContext)
		if !ok {
			return true
		}
		if info.PidNamespaceId == nsid {
			pids = append(pids, pid)
		}
		return true
	})

	return pids
}

func (c *ProcessCache) GetPidsByMntNsId(nsid int64) []int {
	var pids []int

	c.pids.Range(func(key, value any) bool {
		pid, ok := key.(int)
		if !ok {
			return true
		}
		info, ok := value.(*types.PacketContext)
		if !ok {
			return true
		}
		if info.MountNamespaceId == nsid {
			pids = append(pids, pid)
		}
		return true
	})

	return pids
}

func (c *ProcessCache) GetPidsByNetNsId(nsid int64) []int {
	var pids []int

	c.pids.Range(func(key, value any) bool {
		pid, ok := key.(int)
		if !ok {
			return true
		}
		info, ok := value.(*types.PacketContext)
		if !ok {
			return true
		}
		if info.NetNamespaceId == nsid {
			pids = append(pids, pid)
		}
		return true
	})

	return pids
}
