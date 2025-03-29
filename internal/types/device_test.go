package types

import (
	"reflect"
	"testing"
)

func TestAddDeviceToInterfaces(t *testing.T) {
	tests := []struct {
		name string
		dev  Device
		want int
	}{
		{
			name: "add single device",
			dev:  Device{Name: "eth0", Ifindex: 1, NetNs: &NetNs{inode: 100}},
			want: 1,
		},
		{
			name: "add another device",
			dev:  Device{Name: "eth1", Ifindex: 2, NetNs: &NetNs{inode: 100}},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := NewInterfaces()
			i.Add(tt.dev)
			if got := len(i.devs); got != tt.want {
				t.Errorf("Add() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMergeInterfaces(t *testing.T) {
	tests := []struct {
		name string
		a    *Interfaces
		b    *Interfaces
		want int
	}{
		{
			name: "merge non-empty interfaces",
			a:    NewInterfaces(),
			b:    NewInterfaces(),
			want: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.a.Add(Device{Name: "eth0", Ifindex: 1, NetNs: &NetNs{inode: 100}})
			tt.b.Add(Device{Name: "eth1", Ifindex: 2, NetNs: &NetNs{inode: 100}})
			tt.a.Merge(tt.b)
			if got := len(tt.a.devs); got != tt.want {
				t.Errorf("Merge() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetDevicesFromInterfaces(t *testing.T) {
	tests := []struct {
		name string
		i    *Interfaces
		want []Device
	}{
		{
			name: "get devices from non-empty interfaces",
			i:    NewInterfaces(),
			want: []Device{
				{Name: "eth0", Ifindex: 1, NetNs: &NetNs{inode: 100}},
				{Name: "eth1", Ifindex: 2, NetNs: &NetNs{inode: 100}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.i.Add(Device{Name: "eth0", Ifindex: 1, NetNs: &NetNs{inode: 100}})
			tt.i.Add(Device{Name: "eth1", Ifindex: 2, NetNs: &NetNs{inode: 100}})
			if got := tt.i.Devs(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Devs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetDeviceByIfindex(t *testing.T) {
	tests := []struct {
		name  string
		i     *Interfaces
		index int
		want  Device
	}{
		{
			name:  "get device by ifindex",
			i:     NewInterfaces(),
			index: 1,
			want:  Device{Name: "eth0", Ifindex: 1, NetNs: &NetNs{inode: 100}},
		},
		{
			name:  "get non-existent device by ifindex",
			i:     NewInterfaces(),
			index: 3,
			want:  Device{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.i.Add(Device{Name: "eth0", Ifindex: 1, NetNs: &NetNs{inode: 100}})
			tt.i.Add(Device{Name: "eth1", Ifindex: 2, NetNs: &NetNs{inode: 100}})
			if got := tt.i.GetByIfindex(tt.index); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetByIfindex() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeviceKey(t *testing.T) {
	tests := []struct {
		name string
		d    Device
		want string
	}{
		{
			name: "device key",
			d:    Device{Name: "eth0", Ifindex: 1, NetNs: &NetNs{inode: 100}},
			want: "100.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.d.Key(); got != tt.want {
				t.Errorf("Key() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeviceString(t *testing.T) {
	tests := []struct {
		name string
		d    Device
		want string
	}{
		{
			name: "device string",
			d:    Device{Name: "eth0", Ifindex: 1, NetNs: &NetNs{inode: 100}},
			want: "{Device ifindex: 1, name: eth0, ns: {NetNs inode: 100, path: }}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.d.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}
