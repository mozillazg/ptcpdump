package metadata

import (
	"context"

	"github.com/mozillazg/ptcpdump/internal/metadata/container/docker"
	"github.com/mozillazg/ptcpdump/internal/types"
)

type ContainerMetaData interface {
	GetById(containerId string) types.Container
	GetByMntNs(mntNs int64) types.Container
	GetByNetNs(netNs int64) types.Container
	GetByPid(pid int) types.Container
}

type ContainerCache struct {
	d ContainerMetaData
}

func NewContainerCache(ctx context.Context) (*ContainerCache, error) {
	d, err := docker.NewMetaData("")
	if err != nil {
		return nil, err
	}

	if err := d.Start(ctx); err != nil {
		return nil, err
	}

	return &ContainerCache{
		d: d,
	}, nil
}

func (c *ContainerCache) GetById(containerId string) types.Container {
	return c.d.GetById(containerId)
}

func (c *ContainerCache) GetByMntNs(mntNs int64) types.Container {
	return c.d.GetByMntNs(mntNs)
}

func (c *ContainerCache) GetByNetNs(ns int64) types.Container {
	return c.d.GetByNetNs(ns)
}

func (c *ContainerCache) GetByPid(pid int) types.Container {
	return c.d.GetByPid(pid)
}
