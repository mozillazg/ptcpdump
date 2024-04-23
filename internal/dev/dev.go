package dev

import (
	"github.com/vishvananda/netlink"
	"golang.org/x/xerrors"
)

type Device struct {
	Name    string
	Ifindex int
}

func GetDevices(names []string) (map[int]Device, error) {
	var links []netlink.Link
	var err error
	ifindexMap := make(map[int]Device)

	allLinks, err := netlink.LinkList()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if len(names) == 0 || names[0] == "any" {
		links = append(links, allLinks...)
	} else {
		for _, name := range names {
			for _, lk := range allLinks {
				if lk.Attrs().Name == name {
					links = append(links, lk)
				}
			}
		}
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
