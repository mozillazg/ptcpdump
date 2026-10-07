module github.com/mozillazg/ptcpdump

go 1.26.6

require (
	github.com/cilium/ebpf v0.18.0
	github.com/containerd/typeurl/v2 v2.3.0
	github.com/florianl/go-tc v0.4.6
	github.com/gopacket/gopacket v1.3.1
	github.com/jschwinger233/elibpcap v1.1.0
	github.com/phuslu/log v1.0.120
	github.com/shirou/gopsutil/v4 v4.25.9
	github.com/spf13/cobra v1.10.2
	github.com/x-way/pktdump v0.0.6
	golang.org/x/sys v0.48.0
)

require (
	github.com/containerd/containerd/api v1.12.0
	github.com/containerd/containerd/v2 v2.4.1
	github.com/containerd/errdefs v1.0.0
	github.com/go-logr/logr v1.4.4
	github.com/mandiant/GoReSym v1.7.2-0.20240819162932-534ca84b42d5
	github.com/mdlayher/netlink v1.7.2
	github.com/moby/moby/api v1.54.2
	github.com/moby/moby/client v0.4.1
	github.com/smira/go-xz v0.1.0
	github.com/stretchr/testify v1.12.1
	github.com/vishvananda/netns v0.0.5
	golang.org/x/arch v0.18.0
	k8s.io/cri-api v0.37.0
	k8s.io/cri-client v0.37.0
	k8s.io/klog/v2 v2.140.0
)

require (
	github.com/Microsoft/go-winio v0.6.3-0.20251027160822-ad3df93bed29 // indirect
	github.com/Microsoft/hcsshim v0.15.0-rc.4 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/cbpfc v0.0.0-20230809125630-31aa294050ff // indirect
	github.com/containerd/cgroups/v3 v3.1.3 // indirect
	github.com/containerd/continuity v0.5.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/log v0.2.0 // indirect
	github.com/containerd/log/otel v0.1.0 // indirect
	github.com/containerd/platforms v1.0.0-rc.5 // indirect
	github.com/containerd/plugin v1.1.0 // indirect
	github.com/containerd/ttrpc v1.2.9 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-connections v0.7.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/ebitengine/purego v0.9.0 // indirect
	github.com/elliotchance/orderedmap v1.4.0 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/klauspost/compress v1.20.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mdlayher/socket v0.6.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/signal v0.7.1 // indirect
	github.com/moby/sys/user v0.4.1 // indirect
	github.com/moby/sys/userns v0.2.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/opencontainers/runtime-spec v1.3.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/sirupsen/logrus v1.10.2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/tklauser/go-sysconf v0.3.15 // indirect
	github.com/tklauser/numcpus v0.10.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.71.0 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/otel/sdk v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/exp v0.0.0-20241108190413-2d47ceb2692f // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260825221802-da73d73af1c5 // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	k8s.io/component-base v0.37.0 // indirect
	k8s.io/utils v0.0.0-20260626114624-be93311217bd // indirect
	rsc.io/binaryregexp v0.2.0 // indirect
)

replace (
	github.com/cilium/ebpf => github.com/mozillazg/ebpf v0.17.3-0.20250621115703-9b903a327ca4
	// github.com/cilium/ebpf => ../../cilium/ebpf
	github.com/gopacket/gopacket => github.com/mozillazg/gopacket v0.0.0-20250705120904-4485e52403a8
	// github.com/gopacket/gopacket => ../../gopacket/gopacket
	// github.com/jschwinger233/elibpcap => ../../jschwinger233/elibpcap
	github.com/x-way/pktdump => github.com/mozillazg/pktdump v0.0.9-0.20251006081716-1f836652cfec
	// github.com/x-way/pktdump => ../../x-way/pktdump
	k8s.io/cri-api => github.com/mozillazg/cri-api v0.32.0-alpha.1.0.20241019013855-3dc36f8743df
	k8s.io/cri-client => github.com/mozillazg/cri-client v0.31.0-alpha.0.0.20241019023238-87687176fd67
)
