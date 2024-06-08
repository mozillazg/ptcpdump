package metadata

import (
	"context"
	"net/netip"

	"github.com/mozillazg/ptcpdump/internal/utils"

	"github.com/shirou/gopsutil/v3/net"
	"golang.org/x/xerrors"
)

type Connection struct {
	LocalIP   netip.Addr
	LocalPort int
	Pid       int
	MntNs     int64
	NetNs     int64
}

func GetCurrentConnects(ctx context.Context, pids []int, all bool) ([]Connection, error) {
	var conns []Connection
	var stats []net.ConnectionStat
	if all {
		sts, err := net.ConnectionsWithoutUidsWithContext(ctx, "all")
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		stats = append(stats, sts...)
	} else {
		for _, pid := range pids {
			sts, err := net.ConnectionsPidWithoutUidsWithContext(ctx, "all", int32(pid))
			if err != nil {
				return nil, xerrors.Errorf(": %w", err)
			}
			stats = append(stats, sts...)
		}
	}
	for _, stat := range stats {
		if stat.Laddr.Port == 0 || stat.Raddr.Port == 0 || stat.Status != "ESTABLISHED" {
			continue
		}
		conn, err := convertConnectionStat(stat)
		if err == nil {
			conns = append(conns, conn)
		}
	}
	return conns, nil
}

func convertConnectionStat(stat net.ConnectionStat) (Connection, error) {
	conn := Connection{}
	addr, _ := netip.ParseAddr(stat.Laddr.IP)
	port := int(stat.Laddr.Port)
	if !addr.IsValid() || port == 0 {
		return conn, xerrors.Errorf("invalid Laddr: %s", stat.Laddr)
	}
	conn.LocalIP = addr
	conn.LocalPort = port
	conn.Pid = int(stat.Pid)
	conn.MntNs = utils.GetMountNamespaceFromPid(conn.Pid)
	conn.NetNs = utils.GetNetworkNamespaceFromPid(conn.Pid)
	return conn, nil
}
