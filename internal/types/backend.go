package types

type NetHookBackend string

const (
	NetHookBackendTc        NetHookBackend = "tc"
	NetHookBackendCgroupSkb NetHookBackend = "cgroup-skb"
)
