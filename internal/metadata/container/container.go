package container

import (
	"context"

	"github.com/mozillazg/ptcpdump/internal/types"
)

type MetaData interface {
	Start(ctx context.Context) error
	GetById(containerId string) types.Container
	GetByMntNs(mntNs int64) types.Container
	GetByNetNs(netNs int64) types.Container
	GetByPid(pid int) types.Container
	GetByName(name string) []types.Container
	GetByPod(name, namespace string) []types.Container
}

type DummyMetadata struct{}

func (d DummyMetadata) Start(ctx context.Context) error {
	return nil
}

func (d DummyMetadata) GetById(containerId string) types.Container {
	return types.Container{}
}

func (d DummyMetadata) GetByMntNs(mntNs int64) types.Container {
	return types.Container{}
}

func (d DummyMetadata) GetByNetNs(netNs int64) types.Container {
	return types.Container{}
}

func (d DummyMetadata) GetByPid(pid int) types.Container {
	return types.Container{}
}

func (d DummyMetadata) GetByName(name string) []types.Container {
	return nil
}

func (d DummyMetadata) GetByPod(name, namespace string) []types.Container {
	return nil
}
