package dev

import (
	"github.com/vishvananda/netlink"
	"golang.org/x/xerrors"
)

type Device struct {
	Name    string
	Ifindex int
}

func GetDevices(name string) (map[int]Device, error) {
	var links []netlink.Link
	var err error
	ifindexMap := make(map[int]Device)

	if name == "any" {
		if links, err = netlink.LinkList(); err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
	} else {
		link, err := netlink.LinkByName(name)
		if err != nil {
			return nil, xerrors.Errorf("get device by name (%s): %w", name, err)
		}
		links = append(links, link)
	}

	for _, link := range links {
		linkAttrs := link.Attrs()
		dev := Device{
			Name:    linkAttrs.Name,
			Ifindex: linkAttrs.Index,
		}
		ifindexMap[dev.Ifindex] = dev
	}

	return ifindexMap, nil
}
