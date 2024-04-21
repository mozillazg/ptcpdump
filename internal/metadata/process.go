package metadata

import (
	"github.com/mozillazg/ptcpdump/internal/event"
)

type ProcessCache struct {
	m map[int]*event.ProcessExec
}

func NewProcessCache() *ProcessCache {
	return &ProcessCache{
		m: make(map[int]*event.ProcessExec),
	}
}

func (c *ProcessCache) AddItem(exec event.ProcessExec) {
	pid := exec.Pid
	c.m[pid] = &exec

	//log.Printf("add new cache: %d", pid)
}

func (c *ProcessCache) Get(pid int) event.ProcessExec {
	p := c.m[pid]
	if p == nil {
		return event.ProcessExec{}
	}
	return *p
}
