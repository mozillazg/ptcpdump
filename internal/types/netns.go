package types

import (
	"fmt"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"runtime"
)

type NetNs struct {
	handle netns.NsHandle
	path   string

	inode uint32
}

func NewNetNs(netNsPath string) (*NetNs, error) {
	handle, err := netns.GetFromPath(netNsPath)
	if err != nil {
		return nil, fmt.Errorf("error getting netns handle from path %s: %w", netNsPath, err)
	}

	var stat unix.Stat_t
	if err := unix.Fstat(int(handle), &stat); err != nil {
		return nil, fmt.Errorf("error getting stats for netns %s: %w", netNsPath, err)
	}

	return &NetNs{handle: handle, path: netNsPath, inode: uint32(stat.Ino)}, nil
}

func NewNetNsWithInode(inode uint32) *NetNs {
	return &NetNs{inode: inode}
}

func (n *NetNs) Do(f func()) (err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origns, getErr := netns.Get()
	if getErr != nil {
		return fmt.Errorf("error getting netns: %w", getErr)
	}
	defer func() {
		err = netns.Set(origns)
		if err == nil {
			err = origns.Close()
		}
	}()

	err = netns.Set(n.handle)
	if err != nil {
		return fmt.Errorf("error setting netns handle: %w", err)
	}

	f()

	return
}

func (n *NetNs) String() string {
	return fmt.Sprintf("{NetNs inode: %d, path: %s}", n.inode, n.path)
}

func (n *NetNs) Path() string {
	return n.path
}

func (n *NetNs) Inode() uint32 {
	return n.inode
}
