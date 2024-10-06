module github.com/mozillazg/ptcpdump

go 1.22.0

require (
	github.com/cilium/ebpf v0.15.0
	github.com/containerd/containerd v1.7.20
	github.com/containerd/typeurl/v2 v2.1.1
	github.com/docker/docker v26.1.5+incompatible
	github.com/florianl/go-tc v0.4.4
	github.com/gopacket/gopacket v1.2.0
	github.com/jschwinger233/elibpcap v0.0.0-20231010035657-e99300096f5e
	github.com/phuslu/log v1.0.111
	github.com/shirou/gopsutil/v4 v4.24.8
	github.com/spf13/cobra v1.8.1
	github.com/x-way/pktdump v0.0.5
	golang.org/x/sys v0.24.0
)

require (
	github.com/mandiant/GoReSym v1.7.2-0.20240819162932-534ca84b42d5
	github.com/smira/go-xz v0.1.0
	github.com/stretchr/testify v1.9.0
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74
	golang.org/x/arch v0.10.0
	k8s.io/klog/v2 v2.130.1
)

require (
	github.com/Microsoft/hcsshim/test v0.0.0-00010101000000-000000000000 // indirect
	github.com/containerd/typeurl v1.0.2 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/docker/distribution v2.8.2+incompatible // indirect
	github.com/elliotchance/orderedmap v1.4.0 // indirect
	github.com/gogo/googleapis v1.4.1 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/runc v1.1.14 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apimachinery v0.31.0-alpha.3 // indirect
	k8s.io/apiserver v0.26.2 // indirect
	rsc.io/binaryregexp v0.2.0 // indirect
)

require (
	github.com/prometheus/procfs v0.15.1 // indirect
	k8s.io/component-base v0.31.0-alpha.3 // indirect
	k8s.io/kubernetes v0.31.0-alpha.3
	k8s.io/utils v0.0.0-20230726121419-3b25d923346b // indirect
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/Microsoft/hcsshim v0.11.7 // indirect
	github.com/cloudflare/cbpfc v0.0.0-20230809125630-31aa294050ff // indirect
	github.com/containerd/cgroups v1.1.0 // indirect
	github.com/containerd/continuity v0.4.2 // indirect
	github.com/containerd/errdefs v0.1.0
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/ttrpc v1.2.5 // indirect
	github.com/docker/go-connections v0.5.0 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/go-logr/logr v1.4.2
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mdlayher/netlink v1.6.0 // indirect
	github.com/mdlayher/socket v0.1.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/opencontainers/runtime-spec v1.1.0 // indirect
	github.com/opencontainers/selinux v1.11.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/exp v0.0.0-20230811145659-89c5cff77bcb // indirect
	golang.org/x/net v0.26.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240401170217-c3f982113cda // indirect
	google.golang.org/grpc v1.63.2 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	gotest.tools/v3 v3.5.1 // indirect
	k8s.io/cri-api v0.31.0
)

replace (
	github.com/Microsoft/hcsshim => github.com/Microsoft/hcsshim v0.8.26
	github.com/Microsoft/hcsshim/test => github.com/Microsoft/hcsshim/test v0.0.0-20210514012740-eba372547321
	github.com/containerd/containerd => github.com/containerd/containerd v1.4.13
	github.com/docker/docker => github.com/docker/docker v24.0.9+incompatible
	github.com/gopacket/gopacket => github.com/mozillazg/gopacket v0.0.0-20241005073024-5750600e7922
	// github.com/gopacket/gopacket => ../../gopacket/gopacket
	github.com/x-way/pktdump => github.com/mozillazg/pktdump v0.0.9-0.20241003022253-cbafa8b6312d
	// github.com/x-way/pktdump => ../../x-way/pktdump

	// https://github.com/kubernetes/kubernetes/blob/release-1.24/go.mod
	go.opencensus.io => go.opencensus.io v0.23.0
	go.opentelemetry.io/contrib => go.opentelemetry.io/contrib v0.20.0
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc => go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.20.0
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp => go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.20.0
	go.opentelemetry.io/otel => go.opentelemetry.io/otel v0.20.0
	go.opentelemetry.io/otel/exporters/otlp => go.opentelemetry.io/otel/exporters/otlp v0.20.1
	go.opentelemetry.io/otel/metric => go.opentelemetry.io/otel/metric v0.20.0
	go.opentelemetry.io/otel/oteltest => go.opentelemetry.io/otel/oteltest v0.20.1
	go.opentelemetry.io/otel/sdk => go.opentelemetry.io/otel/sdk v0.20.0
	go.opentelemetry.io/otel/sdk/export/metric => go.opentelemetry.io/otel/sdk/export/metric v0.20.0
	go.opentelemetry.io/otel/sdk/metric => go.opentelemetry.io/otel/sdk/metric v0.20.0
	go.opentelemetry.io/otel/trace => go.opentelemetry.io/otel/trace v0.20.0
	go.opentelemetry.io/proto/otlp => go.opentelemetry.io/proto/otlp v0.7.0
	k8s.io/api => k8s.io/api v0.23.17
	k8s.io/apimachinery => k8s.io/apimachinery v0.24.17
	k8s.io/apiserver => k8s.io/apiserver v0.24.17
	k8s.io/client-go => k8s.io/client-go v0.24.17
	k8s.io/component-base => k8s.io/component-base v0.24.17
	k8s.io/cri-api => k8s.io/kubernetes/staging/src/k8s.io/cri-api v0.0.0-20230824000246-2cb31c9333ad
	k8s.io/kubernetes => k8s.io/kubernetes v1.24.17
)
