package cmd

import (
	"context"
	"log"

	"github.com/mozillazg/ptcpdump/internal/metadata"
)

func applyContainerFilter(ctx context.Context, opts *Options) (*metadata.ContainerCache, error) {
	cc, err := metadata.NewContainerCache(ctx)
	if err != nil {
		if opts.containerId != "" {
			log.Fatalf("find container failed: %s", err)
		} else {
			log.Printf("start container cache failed: %s, will no container and pod context", err)
			return nil, nil
		}
	}
	if opts.containerId == "" {
		return cc, nil
	}

	container := cc.GetById(opts.containerId)
	if container.IsNull() {
		log.Fatalf("can not find any container by id %s", opts.containerId)
	}
	// log.Printf("%#v", container)
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
