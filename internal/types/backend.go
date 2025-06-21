package types

type NetHookBackend string

const (
	NetHookBackendTc           NetHookBackend = "tc"
	NetHookBackendCgroupSkb    NetHookBackend = "cgroup-skb"
	NetHookBackendTpBtf        NetHookBackend = "tp-btf"
	NetHookBackendSocketFilter NetHookBackend = "socket-filter"
)
