package metadata

import (
	"context"
	"errors"
	"fmt"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/types"
	"math"
	"net"
	"runtime"
	"sync"
)

type DeviceCache struct {
	nscache  *NetNsCache
	allLinks map[uint32][]net.Interface
	lock     sync.RWMutex
}

func NewDeviceCache(nscache *NetNsCache) *DeviceCache {
	return &DeviceCache{
		nscache:  nscache,
		allLinks: make(map[uint32][]net.Interface),
		lock:     sync.RWMutex{},
	}
}

func (d *DeviceCache) Start(ctx context.Context) error {
	if err := d.init(); err != nil {
		return err
	}
	return nil
}

func (d *DeviceCache) init() error {
	for _, ns := range d.nscache.nsStore {
		_, err := d.getDevicesFromNetNs(ns)
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *DeviceCache) GetDevices(devNames []string, netNsPaths []string) (*types.Interfaces, error) {
	var nsList []*types.NetNs
	interfaces := types.NewInterfaces()

	if len(netNsPaths) > 0 {
		for _, p := range netNsPaths {
			ns, err := d.nscache.GetOrFetchByPath(p)
			if err != nil {
				return nil, err
			}
			nsList = append(nsList, ns)
		}
	} else {
		for _, ns := range d.nscache.nsStore {
			nsList = append(nsList, ns)
		}
	}

	if len(devNames) > 0 {
		for _, ns := range nsList {
			for _, name := range devNames {
				dev, err := d.getDeviceFromNetNs(name, ns)
				if err != nil && !errors.Is(err, types.ErrDeviceNotFound) {
					return nil, err
				}
				interfaces.Add(*dev)
			}
		}
	} else {
		for _, ns := range nsList {
			devices, err := d.getDevicesFromNetNs(ns)
			if err != nil {
				return nil, err
			}
			for _, dev := range devices {
				interfaces.Add(dev)
			}
		}
	}

	return interfaces, nil
}

func (d *DeviceCache) Add(netNsInode uint32, ifindex uint32, name string) {
	_, ok := d.GetByIfindex(int(ifindex), netNsInode)
	if ok {
		return
	}

	d.lock.Lock()
	defer d.lock.Unlock()

	d.allLinks[netNsInode] = append(d.allLinks[netNsInode], net.Interface{
		Index: int(ifindex),
		Name:  name,
	})
}

func (d *DeviceCache) GetByIfindex(ifindex int, netNsInode uint32) (types.Device, bool) {
	d.lock.RLock()
	defer d.lock.RUnlock()

	ns, err := d.nscache.Get(netNsInode)
	if err != nil {
		ns = types.NewNetNsWithInode(netNsInode)
	}

	devs, ok := d.allLinks[netNsInode]
	if !ok {
		for _, links := range d.allLinks {
			for _, dev := range links {
				devs = append(devs, dev)
			}
		}
	}
	for _, dev := range devs {
		if dev.Index == ifindex {
			return types.Device{
				Name:    dev.Name,
				Ifindex: ifindex,
				NetNs:   ns,
			}, true
		}
	}

	return types.Device{
		Name:    fmt.Sprintf("dummy-%d", ifindex),
		Ifindex: ifindex,
		NetNs:   ns,
	}, false
}

func (d *DeviceCache) getDeviceFromNetNs(name string, ns *types.NetNs) (*types.Device, error) {
	devices, err := d.getDevicesFromNetNs(ns)
	if err != nil {
		return nil, err
	}
	for _, device := range devices {
		if device.Name == name {
			return &device, nil
		}
	}
	return nil, types.ErrDeviceNotFound
}

func (d *DeviceCache) getDevicesFromNetNs(ns *types.NetNs) (devices map[int]types.Device, err error) {
	var finalErr error
	devices = map[int]types.Device{}

	err = ns.Do(func() {
		interfaces, err := d.getAllLinks(ns.Inode())
		if err != nil {
			finalErr = fmt.Errorf("error getting interfaces: %w", err)
			return
		}
		for _, interf := range interfaces {
			devices[interf.Index] = types.Device{
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

	log.Infof("got devices from %s: %v", ns, devices)

	return devices, err
}

func (d *DeviceCache) getAllLinks(inode uint32) ([]net.Interface, error) {
	d.lock.Lock()
	defer d.lock.Unlock()

	if d.allLinks[inode] == nil {
		links, err := net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("error getting interfaces: %w", err)
		}
		d.allLinks[inode] = links
	}

	return d.allLinks[inode], nil
}

func NewNgInterface(dev types.Device, filter string, index int) pcapgo.NgInterface {
	comment := fmt.Sprintf("ifIndex: %d", dev.Ifindex)
	if dev.NetNs != nil {
		comment = fmt.Sprintf("%s, netNsInode: %d, netNsPath: %s",
			comment, dev.NetNs.Inode(), dev.NetNs.Path())
	}
	return pcapgo.NgInterface{
		Index:      index,
		Name:       dev.Name,
		Comment:    comment,
		Filter:     filter,
		OS:         runtime.GOOS,
		LinkType:   layers.LinkTypeEthernet,
		SnapLength: uint32(math.MaxUint16),
		//TimestampResolution: 9,
	}
}

func NewDummyNgInterface(index int, filter string) pcapgo.NgInterface {
	return pcapgo.NgInterface{
		Index:      index,
		Name:       fmt.Sprintf("dummy-%d", index),
		Filter:     filter,
		OS:         runtime.GOOS,
		LinkType:   layers.LinkTypeEthernet,
		SnapLength: uint32(math.MaxUint16),
		//TimestampResolution: 9,
	}
}
