package metadata

import (
	"context"

	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/metadata/container"
	"github.com/mozillazg/ptcpdump/internal/metadata/k8s"
	"github.com/mozillazg/ptcpdump/internal/types"
)

type ContainerCache struct {
	d   container.MetaData
	k8s *k8s.MetaData
}

func NewContainerCache(ctx context.Context) (*ContainerCache, error) {
	d := container.NewMultipleEngineMetaData()

	if err := d.Start(ctx); err != nil {
		return nil, err
	}
	k8sd, err := k8s.NewMetaData()
	if err != nil {
		log.Warnf("skip k8s integration: %s", err)
	}

	return &ContainerCache{
		d:   d,
		k8s: k8sd,
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

func (c *ContainerCache) GetByName(containerName string) []types.Container {
	return c.d.GetByName(containerName)
}

func (c *ContainerCache) GetPodByContainer(cr types.Container) types.Pod {
	return c.k8s.GetPodByContainer(cr)
}
