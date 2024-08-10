package cmd

import (
	"context"

	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/mozillazg/ptcpdump/internal/types"
)

func applyContainerFilter(ctx context.Context, opts *Options) (*metadata.ContainerCache, error) {
	cc, err := metadata.NewContainerCache(ctx, opts.dockerEndpoint,
		opts.containerdEndpoint, opts.criRuntimeEndpoint)
	if err != nil {
		if opts.filterByContainer() {
			log.Fatalf("find container failed: %s", err)
		} else {
			log.Warnf("will no container and pod context due to start container cache failed: %s", err)
			return nil, nil
		}
	}
	if !opts.filterByContainer() {
		return cc, nil
	}

	var containers []types.Container

	switch {
	case opts.containerId != "":
		container := cc.GetById(opts.containerId)
		if container.EmptyNS() {
			log.Fatalf("can not find any running container by id %s", opts.containerId)
		}
		containers = append(containers, container)
		break
	case opts.containerName != "":
		cs := cc.GetByName(opts.containerName)
		cs = removeNonFilterAbleContainers(cs)
		if len(cs) > 1 {
			log.Fatalf("found more than one containers by name %s", opts.containerName)
		}
		if len(cs) == 0 {
			log.Fatalf("can not find any running container by name %s", opts.containerName)
		}
		container := cs[0]
		containers = append(containers, container)
		break
	case opts.podName != "":
		cs := cc.GetByPodName(opts.podName, opts.podNamespace)
		cs = removeNonFilterAbleContainers(cs)
		if len(cs) == 0 {
			log.Fatalf("can not find any running pod by name %s in namespace %s", opts.podName, opts.podNamespace)
		}
		containers = append(containers, cs...)
		break
	}

	for _, container := range containers {
		if container.IsSandbox() {
			log.Infof("skip sandbox container: %#v", container)
			continue
		}
		log.Infof("filter by container %#v", container)
		if container.PidNamespace > 0 && container.PidNamespace != metadata.HostPidNs {
			opts.pidnsId = uint32(container.PidNamespace)
		}
		if container.MountNamespace > 0 && container.MountNamespace != metadata.HostMntNs {
			opts.mntnsId = uint32(container.MountNamespace)
		}
		if container.NetworkNamespace > 0 && container.NetworkNamespace != metadata.HostNetNs {
			opts.netnsId = uint32(container.NetworkNamespace)
		}
		opts.followForks = true
	}

	return cc, nil
}

func removeNonFilterAbleContainers(containers []types.Container) []types.Container {
	var final []types.Container
	for _, c := range containers {
		if c.IsSandbox() || c.EmptyNS() {
			continue
		}
		if c.PidNamespace == metadata.HostPidNs &&
			c.MountNamespace == metadata.HostMntNs &&
			c.NetworkNamespace == metadata.HostNetNs {
			continue
		}
		final = append(final, c)
	}
	return final
}
