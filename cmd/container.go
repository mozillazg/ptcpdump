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

	var container types.Container

	switch {
	case opts.containerId != "":
		container = cc.GetById(opts.containerId)
		if container.IsNull() {
			log.Fatalf("can not found any container by id %s", opts.containerId)
		}
		break
	case opts.containerName != "":
		cs := cc.GetByName(opts.containerName)
		if len(cs) == 0 {
			log.Fatalf("can not found any container by name %s", opts.containerName)
		}
		if len(cs) > 1 {
			log.Fatalf("found more than one containers by name %s", opts.containerName)
		}
		container = cs[0]
		break
	}

	log.Debugf("filter by container %#v", container)
	if container.PidNamespace > 0 && container.PidNamespace != metadata.HostPidNs {
		opts.pidns_id = uint32(container.PidNamespace)
	}
	if container.MountNamespace > 0 && container.MountNamespace != metadata.HostMntNs {
		opts.mntns_id = uint32(container.MountNamespace)
	}
	if container.NetworkNamespace > 0 && container.NetworkNamespace != metadata.HostNetNs {
		opts.netns_id = uint32(container.NetworkNamespace)
	}
	opts.followForks = true

	return cc, nil
}
