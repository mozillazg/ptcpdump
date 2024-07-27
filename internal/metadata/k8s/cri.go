package k8s

import (
	"context"
	"github.com/mozillazg/ptcpdump/internal/utils"
	"strings"
	"time"

	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/types"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	cri "k8s.io/cri-api/pkg/apis"
	remote "k8s.io/cri-client/pkg"
	"k8s.io/klog/v2"
)

var DefaultRuntimeEndpoints = []string{
	"unix:///run/containerd/containerd.sock",
	"unix:///run/crio/crio.sock",
	"unix:///var/run/cri-dockerd.sock",
	"unix:///var/run/dockershim.sock",
}

const defaultTimeout = 2 * time.Second

type MetaData struct {
	res cri.RuntimeService
}

func NewMetaData(criRuntimeEndpoint string) (*MetaData, error) {
	res, errs := getRuntimeService(criRuntimeEndpoint)
	if len(errs) > 0 {
		log.Warnf("skip kubernetes integration due to [%s]", formatErrors(errs))
	}

	return &MetaData{
		res: res,
	}, nil
}

func (m *MetaData) GetPodByContainer(c types.Container) types.Pod {
	p := types.Pod{}
	p.LoadFromContainer(c)
	if m.res != nil {
		tmp := m.GetPodByName(context.TODO(), p.Name, p.Namespace)
		p.Labels = tmp.Labels
		p.Annotations = tmp.Annotations
	}
	return p
}

func (m *MetaData) GetPodByName(ctx context.Context, name, namespace string) (p types.Pod) {
	if m.res == nil {
		return
	}
	sanboxes, err := m.res.ListPodSandbox(ctx, nil)
	if err != nil {
		log.Errorf("list pod sanbox failed: %s", err)
		return
	}
	for _, sanbox := range sanboxes {
		if sanbox.Metadata.Name != name || sanbox.Metadata.Namespace != namespace {
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

func getRuntimeService(criRuntimeEndpoint string) (res cri.RuntimeService, errs []error) {
	logger := klog.Background()
	t := defaultTimeout
	endpoints := DefaultRuntimeEndpoints
	var tp trace.TracerProvider = noop.NewTracerProvider()
	if criRuntimeEndpoint != "" {
		endpoints = []string{criRuntimeEndpoint}
	}

	for _, endPoint := range endpoints {
		var err error
		log.Debugf("Connect using endpoint %q with %q timeout", endPoint, t)
		res, err = remote.NewRemoteRuntimeService(endPoint, t, tp, &logger)
		if err != nil {
			log.Infof(err.Error())
			errs = append(errs, utils.UnwrapErr(err))
			continue
		}
		log.Debugf("Connected successfully using endpoint: %s", endPoint)
		errs = nil
		break
	}

	return res, errs
}

func formatErrors(errs []error) string {
	var messages []string
	for _, err := range errs {
		err = utils.UnwrapErr(err)
		msg := err.Error()
		if strings.Contains(msg, "while dialing: ") {
			messages = append(messages, strings.Trim(strings.Split(msg, "while dialing: ")[1], `"'`))
		} else {
			messages = append(messages, msg)
		}
	}

	return strings.Join(messages, ", ")
}
