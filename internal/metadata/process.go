package metadata

import (
	"github.com/mozillazg/ptcpdump/internal/event"
	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/xerrors"
	"log"
	"sync"
)

const defaultProcDir = "/proc"

type ProcessCache struct {
	m map[int]*event.ProcessExec

	lock sync.RWMutex
}

func NewProcessCache() *ProcessCache {
	return &ProcessCache{
		m:    make(map[int]*event.ProcessExec),
		lock: sync.RWMutex{},
	}
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
		}
		c.AddItem(e)
	}

	return nil
}

func (c *ProcessCache) AddItem(exec event.ProcessExec) {
	pid := exec.Pid

	c.lock.Lock()
	c.m[pid] = &exec
	c.lock.Unlock()

	//log.Printf("add new cache: %d", pid)
}

func (c *ProcessCache) Get(pid int) event.ProcessExec {
	c.lock.RLock()
	p := c.m[pid]
	c.lock.RUnlock()

	if p == nil {
		return event.ProcessExec{}
	}
	return *p
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
