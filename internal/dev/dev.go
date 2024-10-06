package dev

import (
	"fmt"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/utils"
	"net"
	"sort"
	"strconv"
)

var allLinks = map[uint32][]net.Interface{}

type Device struct {
	Name    string
	Ifindex int
	NetNs   *utils.NetNs
}

type Interfaces struct {
	devs map[string]Device
}

func NewInterfaces() *Interfaces {
	return &Interfaces{devs: make(map[string]Device)}
}

func getAllLinks(inode uint32) ([]net.Interface, error) {
	if allLinks[inode] == nil {
		links, err := net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("error getting interfaces: %w", err)
		}
		allLinks[inode] = links
	}

	return allLinks[inode], nil
}

func getDevicesFromNetNs(netNsPath string) (devices map[int]Device, err error) {
	ns, err := utils.NewNetNs(netNsPath)
	if err != nil {
		return nil, fmt.Errorf("error getting net ns: %w", err)
	}

	var finalErr error
	devices = map[int]Device{}

	err = ns.Do(func() {
		interfaces, err := getAllLinks(ns.Inode())
		if err != nil {
			finalErr = fmt.Errorf("error getting interfaces: %w", err)
			return
		}
		for _, interf := range interfaces {
			devices[interf.Index] = Device{
				Name:    interf.Name,
				Ifindex: interf.Index,
				NetNs:   ns,
			}
		}
		return
	})
	if finalErr != nil {
		return nil, finalErr
	}

	log.Infof("got devices from %s: %v", netNsPath, devices)

	return devices, err
}

func GetDevices(names []string, netNsPatch string) (*Interfaces, error) {
	ifindexMap := make(map[int]Device)
	interfaces := NewInterfaces()

	devices, err := getDevicesFromNetNs(netNsPatch)
	if err != nil {
		return nil, fmt.Errorf(": %w", err)
	}
	if len(names) == 0 {
		for _, v := range devices {
			v := v
			interfaces.Add(v)
		}
		return interfaces, nil
	}

	for _, name := range names {
		for _, lk := range devices {
			if lk.Name == name || strconv.Itoa(lk.Ifindex) == name {
				log.Infof("found interface %s", name)
				ifindexMap[lk.Ifindex] = lk
				continue
			}
		}
	}

	for _, v := range ifindexMap {
		v := v
		interfaces.Add(v)
	}
	return interfaces, nil
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
