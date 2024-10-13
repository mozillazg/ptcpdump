package metadata

import (
	"context"
	"errors"
	"fmt"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/types"
	"io/fs"
	"os"
	"path"
	"sync"
)

type NetNsCache struct {
	nsStore map[uint32]*types.NetNs
	lock    sync.RWMutex
}

const netnsMountPath = "/run/netns"

func NewNetNsCache() *NetNsCache {
	return &NetNsCache{
		nsStore: make(map[uint32]*types.NetNs),
		lock:    sync.RWMutex{},
	}
}

func (n *NetNsCache) Start(ctx context.Context) error {
	if err := n.init(); err != nil {
		return err
	}
	return nil
}

func (n *NetNsCache) init() error {
	return n.refresh()
}

func (n *NetNsCache) refresh() error {
	pathList, err := getAllNamedNetNsPath()
	if err != nil {
		return err
	}
	for _, p := range pathList {
		if _, err := n.GetOrFetchByPath(p); err != nil {
			return err
		}
	}
	return nil
}

func (n *NetNsCache) Get(inodeId uint32) (*types.NetNs, error) {
	n.lock.RLock()
	defer n.lock.RUnlock()

	ns, ok := n.nsStore[inodeId]
	if !ok {
		return nil, fmt.Errorf("inode %d not found", inodeId)
	}
	return ns, nil
}

func (n *NetNsCache) set(ns *types.NetNs) {
	n.lock.Lock()
	defer n.lock.Unlock()

	n.nsStore[ns.Inode()] = ns
}

func (n *NetNsCache) getByPath(p string) (*types.NetNs, error) {
	n.lock.RLock()
	defer n.lock.RUnlock()

	for _, n := range n.nsStore {
		if n.Path() == p {
			return n, nil
		}
	}
	return nil, fmt.Errorf("netns path %s not found", p)
}

func (n *NetNsCache) GetOrFetchByPath(p string) (*types.NetNs, error) {
	ns, err := n.getByPath(p)
	if err == nil {
		return ns, nil
	}

	ns, err = types.NewNetNs(p)
	if err != nil {
		return nil, err
	}
	log.Infof("add new netns %d with path: %s", ns.Inode(), p)
	n.set(ns)

	return ns, nil
}

func (n *NetNsCache) GetCurrentNs() *types.NetNs {
	p := "/proc/self/ns/net"
	ns, _ := n.GetOrFetchByPath(p)
	return ns
}

func getAllNamedNetNsPath() ([]string, error) {
	ps := []string{"/proc/self/ns/net"}
	dirEntry, err := os.ReadDir(netnsMountPath)
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist) {
			return ps, nil
		}
		return nil, err
	}
	for _, fp := range dirEntry {
		if fp.IsDir() {
			continue
		}
		ps = append(ps, path.Join(netnsMountPath, fp.Name()))
	}
	return ps, nil
}
