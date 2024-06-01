package metadata

import (
	"context"

	"github.com/mozillazg/ptcpdump/internal/metadata/container"
	"github.com/mozillazg/ptcpdump/internal/types"
)

type ContainerCache struct {
	d *container.DockerMetaData
}

func NewContainerCache(ctx context.Context) (*ContainerCache, error) {
	d, err := container.NewDockerMetaData("")
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
