package types

import (
	"fmt"
	"sort"
)

type Device struct {
	Name    string
	Ifindex int
	NetNs   *NetNs
}

type Interfaces struct {
	devs map[string]Device
}

func NewInterfaces() *Interfaces {
	return &Interfaces{devs: make(map[string]Device)}
}

func (i *Interfaces) Add(dev Device) {
	k := i.key(dev)
	i.devs[k] = dev
}

func (i *Interfaces) Merge(b *Interfaces) {
	for _, v := range b.devs {
		v := v
		i.Add(v)
	}
}

func (i *Interfaces) Devs() []Device {
	var devs []Device
	for _, v := range i.devs {
		devs = append(devs, v)
	}
	sort.Slice(devs, func(i, j int) bool {
		if devs[i].NetNs.Inode() < devs[j].NetNs.Inode() {
			return true
		}
		return devs[i].Ifindex < devs[j].Ifindex
	})
	return devs
}

func (i *Interfaces) key(dev Device) string {
	return fmt.Sprintf("%d.%d", dev.NetNs.Inode(), dev.Ifindex)
}

func (i *Interfaces) GetByIfindex(index int) Device {
	for _, v := range i.devs {
		if v.Ifindex == index {
			return v
		}
	}
	return Device{}
}

func (d *Device) String() string {
	return fmt.Sprintf("{Device ifindex: %d, name: %s, ns: %s}", d.Ifindex, d.Name, d.NetNs)
}
