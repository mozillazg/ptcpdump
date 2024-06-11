package k8s

import (
	"context"
	"log"
	"time"

	"github.com/mozillazg/ptcpdump/internal/types"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	cri "k8s.io/cri-api/pkg/apis"
	remote "k8s.io/cri-client/pkg"
	"k8s.io/klog/v2"
)

var defaultRuntimeEndpoints = []string{
	"unix:///run/containerd/containerd.sock",
	"unix:///run/crio/crio.sock",
	"unix:///var/run/cri-dockerd.sock",
}

const defaultTimeout = 2 * time.Second

type MetaData struct {
	res cri.RuntimeService
}

func NewMetaData() (*MetaData, error) {
	res, err := getRuntimeService()
	if err != nil {
		log.Print(err)
	}

	return &MetaData{
		res: res,
	}, nil
}

func (m *MetaData) GetPodByContainer(c types.Container) types.Pod {
	p := types.Pod{}
	p.LoadFromContainer(c)
	if m.res != nil {
		tmp := m.GetPodByName(context.TODO(), p.Name)
		p.Labels = tmp.Labels
		p.Annotations = tmp.Annotations
	}
	return p
}

func (m *MetaData) GetPodByName(ctx context.Context, name string) (p types.Pod) {
	sanboxes, err := m.res.ListPodSandbox(ctx, nil)
	if err != nil {
		return
	}
	for _, sanbox := range sanboxes {
		if sanbox.Metadata.Name != name {
			continue
		}
		p.Labels = tidyLabels(sanbox.Labels)
		p.Annotations = sanbox.Annotations
		break
	}
	return p
}

func tidyLabels(raw map[string]string) map[string]string {
	if len(raw) == 0 {
		return raw
	}
	newLabels := make(map[string]string)
	for k, v := range raw {
		if k == types.ContainerLabelKeyPodName ||
			k == types.ContainerLabelKeyPodNamespace ||
			k == types.ContainerLabelKeyPodUid {
			continue
		}
		newLabels[k] = v
	}
	return newLabels
}

func getRuntimeService() (res cri.RuntimeService, err error) {
	logger := klog.Background()
	t := defaultTimeout
	var tp trace.TracerProvider = noop.NewTracerProvider()

	for _, endPoint := range defaultRuntimeEndpoints {
		res, err = remote.NewRemoteRuntimeService(endPoint, t, tp, &logger)
		if err != nil {
			log.Print(err)
			continue
		}
		break
	}

	return res, err
}
