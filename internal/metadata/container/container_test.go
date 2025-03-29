package container

import (
	"context"
	"reflect"
	"testing"

	"github.com/mozillazg/ptcpdump/internal/types"
)

func TestStartReturnsNilError(t *testing.T) {
	d := DummyMetadata{}
	err := d.Start(context.Background())
	if err != nil {
		t.Errorf("Start() error = %v, wantErr %v", err, nil)
	}
}

func TestGetByIdReturnsEmptyContainer(t *testing.T) {
	d := DummyMetadata{}
	container := d.GetById("any-id")
	if !reflect.DeepEqual(container, types.Container{}) {
		t.Errorf("GetById() = %v, want %v", container, types.Container{})
	}
}

func TestGetByMntNsReturnsEmptyContainer(t *testing.T) {
	d := DummyMetadata{}
	container := d.GetByMntNs(123)
	if !reflect.DeepEqual(container, types.Container{}) {
		t.Errorf("GetByMntNs() = %v, want %v", container, types.Container{})
	}
}

func TestGetByNetNsReturnsEmptyContainer(t *testing.T) {
	d := DummyMetadata{}
	container := d.GetByNetNs(123)
	if !reflect.DeepEqual(container, types.Container{}) {
		t.Errorf("GetByNetNs() = %v, want %v", container, types.Container{})
	}
}

func TestGetByPidReturnsEmptyContainer(t *testing.T) {
	d := DummyMetadata{}
	container := d.GetByPid(123)
	if !reflect.DeepEqual(container, types.Container{}) {
		t.Errorf("GetByPid() = %v, want %v", container, types.Container{})
	}
}

func TestGetByNameReturnsNil(t *testing.T) {
	d := DummyMetadata{}
	containers := d.GetByName("any-name")
	if containers != nil {
		t.Errorf("GetByName() = %v, want %v", containers, nil)
	}
}

func TestGetByPodReturnsNil(t *testing.T) {
	d := DummyMetadata{}
	containers := d.GetByPod("any-name", "any-namespace")
	if containers != nil {
		t.Errorf("GetByPod() = %v, want %v", containers, nil)
	}
}
