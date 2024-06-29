package dev

import (
	"net"
	"sync"

	"golang.org/x/xerrors"
)

var allLinks []net.Interface
var once sync.Once

type Device struct {
	Name    string
	Ifindex int
}

func getAllLinks() ([]net.Interface, error) {
	var err error
	once.Do(func() {
		allLinks, err = net.Interfaces()
	})
	return allLinks, err
}

func GetDevices(names []string) (map[int]Device, error) {
	var links []net.Interface
	var err error
	ifindexMap := make(map[int]Device)

	allLinks, err := getAllLinks()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if len(names) == 0 || names[0] == "any" {
		links = append(links, allLinks...)
	} else {
		for _, name := range names {
			for _, lk := range allLinks {
				if lk.Name == name {
					links = append(links, lk)
					continue
				}
			}
		}
	}

	for _, link := range links {
		dev := Device{
			Name:    link.Name,
			Ifindex: link.Index,
		}
		ifindexMap[dev.Ifindex] = dev
	}

	return ifindexMap, nil
}
