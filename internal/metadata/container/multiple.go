package container

import (
	"context"

	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/metadata/container/containerd"
	"github.com/mozillazg/ptcpdump/internal/metadata/container/docker"
	"github.com/mozillazg/ptcpdump/internal/types"
)

type MultipleEngineMetaData struct {
	engines []MetaData
}

func NewMultipleEngineMetaData() *MultipleEngineMetaData {
	var m MultipleEngineMetaData

	dr, err := docker.NewMetaData("")
	if err != nil {
		log.Infof(err.Error())
		log.Warn("skip Docker Engine integration")
	} else {
		m.engines = append(m.engines, dr)
	}

	cd, err := containerd.NewMultipleNamespacesMetaData("", "")
	if err != nil {
		log.Infof(err.Error())
		log.Warn("skip containerd integration")
	} else {
		for _, c := range cd {
			c := c
			m.engines = append(m.engines, c)
		}
	}

	return &m
}

func (m *MultipleEngineMetaData) Start(ctx context.Context) error {
	for _, e := range m.engines {
		if err := e.Start(ctx); err != nil {
			log.Error(err.Error())
		}
	}

	return nil
}

func (m *MultipleEngineMetaData) GetById(containerId string) types.Container {
	var c types.Container
	for _, e := range m.engines {
		c = e.GetById(containerId)
		if c.Id != "" {
			return c
		}
	}
	return c
}
func (m *MultipleEngineMetaData) GetByMntNs(mntNs int64) types.Container {
	var c types.Container
	for _, e := range m.engines {
		c = e.GetByMntNs(mntNs)
		if c.Id != "" {
			return c
		}
	}
	return c
}
func (m *MultipleEngineMetaData) GetByNetNs(netNs int64) types.Container {
	var c types.Container
	for _, e := range m.engines {
		c = e.GetByNetNs(netNs)
		if c.Id != "" {
			return c
		}
	}
	return c
}
func (m *MultipleEngineMetaData) GetByPid(pid int) types.Container {
	var c types.Container
	for _, e := range m.engines {
		c = e.GetByPid(pid)
		if c.Id != "" {
			return c
		}
	}
	return c
}

func (m *MultipleEngineMetaData) GetByName(name string) []types.Container {
	var cs []types.Container
	for _, e := range m.engines {
		cs = e.GetByName(name)
		if len(cs) > 0 {
			return cs
		}
	}

	return cs
}
