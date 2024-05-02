module github.com/mozillazg/ptcpdump

go 1.21.0

require (
	github.com/cilium/ebpf v0.15.0
	github.com/florianl/go-tc v0.4.3
	github.com/gopacket/gopacket v1.2.0
	github.com/jschwinger233/elibpcap v0.0.0-20231010035657-e99300096f5e
	github.com/shirou/gopsutil/v3 v3.24.4
	github.com/spf13/cobra v1.8.0
	github.com/vishvananda/netlink v1.1.0
	github.com/x-way/pktdump v0.0.5
	golang.org/x/sys v0.19.0
	golang.org/x/xerrors v0.0.0-20231012003039-104605ab7028
)

require (
	github.com/cloudflare/cbpfc v0.0.0-20230809125630-31aa294050ff // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mdlayher/netlink v1.6.0 // indirect
	github.com/mdlayher/socket v0.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
)

replace (
	github.com/gopacket/gopacket => github.com/mozillazg/gopacket v0.0.0-20240429121216-bf7893b04e11
	github.com/x-way/pktdump => github.com/mozillazg/pktdump v0.0.0-20240422135914-a9ab652291b1
)
