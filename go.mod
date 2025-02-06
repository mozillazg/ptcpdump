module github.com/mozillazg/ptcpdump

go 1.23.0

require (
	github.com/cilium/ebpf v0.16.0
	github.com/containerd/containerd v1.7.25
	github.com/containerd/typeurl/v2 v2.2.3
	github.com/docker/docker v27.4.1+incompatible
	github.com/florianl/go-tc v0.4.4
	github.com/gopacket/gopacket v1.3.1
	github.com/jschwinger233/elibpcap v1.0.0
	github.com/phuslu/log v1.0.113
	github.com/shirou/gopsutil/v4 v4.24.12
	github.com/spf13/cobra v1.8.1
	github.com/x-way/pktdump v0.0.6
	golang.org/x/sys v0.28.0
)

require (
	github.com/containerd/containerd/api v1.8.0
	github.com/containerd/errdefs v0.3.0
	github.com/go-logr/logr v1.4.2
	github.com/mandiant/GoReSym v1.7.2-0.20240819162932-534ca84b42d5
	github.com/mdlayher/netlink v1.7.2
	github.com/smira/go-xz v0.1.0
	github.com/stretchr/testify v1.10.0
	github.com/vishvananda/netns v0.0.5
	golang.org/x/arch v0.11.0
	k8s.io/cri-api v0.31.5
	k8s.io/cri-client v0.31.5
	k8s.io/klog/v2 v2.130.1
)

require (
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20230811130428-ced1acdcaa24 // indirect
	github.com/AdamKorcz/go-118-fuzz-build v0.0.0-20230306123547-8075edf89bb0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/Microsoft/hcsshim v0.11.7 // indirect
	github.com/cloudflare/cbpfc v0.0.0-20230809125630-31aa294050ff // indirect
	github.com/containerd/cgroups v1.1.0 // indirect
	github.com/containerd/continuity v0.4.4 // indirect
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v0.2.1 // indirect
	github.com/containerd/ttrpc v1.2.5 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/ebitengine/purego v0.8.1 // indirect
	github.com/elliotchance/orderedmap v1.4.0 // indirect
	github.com/felixge/httpsnoop v1.0.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/klauspost/compress v1.16.7 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/sys/mountinfo v0.6.2 // indirect
	github.com/moby/sys/sequential v0.5.0 // indirect
	github.com/moby/sys/signal v0.7.0 // indirect
	github.com/moby/sys/user v0.3.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/opencontainers/runtime-spec v1.1.0 // indirect
	github.com/opencontainers/selinux v1.11.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.45.0 // indirect
	go.opentelemetry.io/otel v1.28.0 // indirect
	go.opentelemetry.io/otel/metric v1.28.0 // indirect
	go.opentelemetry.io/otel/trace v1.28.0 // indirect
	golang.org/x/exp v0.0.0-20230811145659-89c5cff77bcb // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto v0.0.0-20231211222908-989df2bf70f3 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240701130421-f6361c86f094 // indirect
	google.golang.org/grpc v1.65.0 // indirect
	google.golang.org/protobuf v1.35.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gotest.tools/v3 v3.5.1 // indirect
	k8s.io/component-base v0.26.2 // indirect
	k8s.io/utils v0.0.0-20240711033017-18e509b52bc8 // indirect
	rsc.io/binaryregexp v0.2.0 // indirect
)

replace (
	github.com/cilium/ebpf => github.com/mozillazg/ebpf v0.17.2-0.20250125052608-c310b16eb51c
	// github.com/cilium/ebpf => ../../cilium/ebpf
	github.com/gopacket/gopacket => github.com/mozillazg/gopacket v0.0.0-20241026043817-048341de5231
	// github.com/gopacket/gopacket => ../../gopacket/gopacket
	github.com/x-way/pktdump => github.com/mozillazg/pktdump v0.0.9-0.20241102131745-63c34f34f0d1
	// github.com/x-way/pktdump => ../../x-way/pktdump
	k8s.io/cri-api => github.com/mozillazg/cri-api v0.32.0-alpha.1.0.20241019013855-3dc36f8743df
	k8s.io/cri-client => github.com/mozillazg/cri-client v0.31.0-alpha.0.0.20241019023238-87687176fd67
)
