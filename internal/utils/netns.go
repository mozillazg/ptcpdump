package utils

import (
	"fmt"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"os"
	"path"
	"runtime"
	"strings"
)

type CloseFunc func()

type NetNs struct {
	handle netns.NsHandle
	path   string

	inode uint32
}

const netnsMountPath = "/var/run/netns"

func GetAllNamedNetNsName() ([]string, error) {
	var ps []string
	dirEntry, err := os.ReadDir(netnsMountPath)
	if err != nil {
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

func NewNetNs(netNsPath string) (*NetNs, error) {
	var handle netns.NsHandle
	var err error
	if netNsPath == "" {
		netNsPath = GetCurrentNetNsPath()
	}
	if !strings.Contains(netNsPath, "/") {
		netNsPath = path.Join(netnsMountPath, netNsPath)
	}

	handle, err = netns.GetFromPath(netNsPath)
	if err != nil {
		return nil, fmt.Errorf("error getting netns handle from path %s: %w", netNsPath, err)
	}

	var stat unix.Stat_t
	if err := unix.Fstat(int(handle), &stat); err != nil {
		return nil, fmt.Errorf("error getting stats for netns %s: %w", netNsPath, err)
	}

	return &NetNs{handle: handle, path: netNsPath, inode: uint32(stat.Ino)}, nil
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
	return fmt.Sprintf("{NetNs id: %d, path: %s}", n.handle, n.path)
}

func (n *NetNs) Path() string {
	return n.path
}

func (n *NetNs) Inode() uint32 {
	return n.inode
}

func GetCurrentNetNsPath() string {
	return fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
}
