package metadata

import (
	"net"
	"testing"

	"github.com/mozillazg/ptcpdump/internal/types"
)

func TestDeviceCacheGetByKnownIfindex(t *testing.T) {
	const (
		wgNetNs     = uint32(100)
		dockerNetNs = uint32(200)
	)
	nsc := NewNetNsCache()
	nsc.set(types.NewNetNsWithInode(wgNetNs))
	nsc.set(types.NewNetNsWithInode(dockerNetNs))

	dc := NewDeviceCache(nsc)
	// the same ifindex exists in two network namespaces
	dc.allLinks[wgNetNs] = []net.Interface{
		{Index: 3, Name: "wg0", HardwareAddr: dummyMac},
		{Index: 7, Name: "veth1", HardwareAddr: dummyMac},
	}
	dc.allLinks[dockerNetNs] = []net.Interface{
		{Index: 3, Name: "docker0", HardwareAddr: dummyMac},
	}

	tests := []struct {
		name      string
		ifindex   int
		netNs     uint32
		wantName  string
		wantNetNs uint32
		wantOk    bool
	}{
		{
			name:      "prefer the given network namespace",
			ifindex:   3,
			netNs:     wgNetNs,
			wantName:  "wg0",
			wantNetNs: wgNetNs,
			wantOk:    true,
		},
		{
			name:      "prefer the given network namespace (other ns)",
			ifindex:   3,
			netNs:     dockerNetNs,
			wantName:  "docker0",
			wantNetNs: dockerNetNs,
			wantOk:    true,
		},
		{
			name:      "unique ifindex",
			ifindex:   7,
			netNs:     wgNetNs,
			wantName:  "veth1",
			wantNetNs: wgNetNs,
			wantOk:    true,
		},
		{
			name:      "unknown netns falls back deterministically",
			ifindex:   3,
			netNs:     0,
			wantName:  "wg0",
			wantNetNs: wgNetNs,
			wantOk:    true,
		},
		{
			name:     "unknown ifindex",
			ifindex:  99,
			netNs:    wgNetNs,
			wantName: "dummy-99",
			wantOk:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := dc.GetByKnownIfindex(tt.ifindex, tt.netNs)
			if ok != tt.wantOk {
				t.Fatalf("GetByKnownIfindex() ok = %v, want %v", ok, tt.wantOk)
			}
			if got.Name != tt.wantName {
				t.Errorf("GetByKnownIfindex() name = %q, want %q", got.Name, tt.wantName)
			}
			if tt.wantOk && got.NetNs.Inode() != tt.wantNetNs {
				t.Errorf("GetByKnownIfindex() netns = %d, want %d", got.NetNs.Inode(), tt.wantNetNs)
			}
		})
	}
}
