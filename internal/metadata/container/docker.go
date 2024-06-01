package container

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/mozillazg/ptcpdump/internal/types"
	"github.com/mozillazg/ptcpdump/internal/utils"
	"golang.org/x/xerrors"
)

type DockerMetaData struct {
	client *client.Client

	containerById map[string]types.Container
	mux           sync.RWMutex

	rootMntNs int64
	rootNetNs int64
}

func NewDockerMetaData(host string) (*DockerMetaData, error) {
	opts := []client.Opt{
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	}
	if host != "" {
		opts = append(opts, client.WithHost(host))
	}
	c, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second*5)
	defer cancel()
	if _, err := c.Info(ctx); err != nil {
		return nil, err
	}

	m := DockerMetaData{
		client:        c,
		containerById: make(map[string]types.Container),
		mux:           sync.RWMutex{},
	}
	return &m, nil
}

func (d *DockerMetaData) Start(ctx context.Context) error {
	if err := d.init(ctx); err != nil {
		return err
	}

	go func() {
		d.watchContainerEventsWithRetry(ctx)
	}()
	return nil
}

func (d *DockerMetaData) GetById(containerId string) types.Container {
	d.mux.RLock()
	defer d.mux.RUnlock()

	return d.containerById[containerId]
}

func (d *DockerMetaData) GetByNetNs(netNs int64) types.Container {
	if netNs == 0 || netNs == d.rootNetNs {
		return types.Container{}
	}

	d.mux.RLock()
	defer d.mux.RUnlock()

	for _, c := range d.containerById {
		if c.NetworkNamespace > 0 && c.NetworkNamespace == d.rootNetNs {
			continue
		}
		if c.NetworkNamespace > 0 && c.NetworkNamespace == netNs {
			return c
		}
	}

	return types.Container{}
}

func (d *DockerMetaData) GetByMntNs(mntNs int64) types.Container {
	if mntNs == 0 || mntNs == d.rootMntNs {
		return types.Container{}
	}

	d.mux.RLock()
	defer d.mux.RUnlock()

	for _, c := range d.containerById {
		if c.MountNamespace > 0 && c.MountNamespace == d.rootMntNs {
			continue
		}
		if c.MountNamespace > 0 && c.MountNamespace == mntNs {
			return c
		}
	}

	return types.Container{}
}

func (d *DockerMetaData) GetByPid(pid int) types.Container {
	if pid == 0 {
		return types.Container{}
	}

	d.mux.RLock()
	defer d.mux.RUnlock()

	for _, c := range d.containerById {
		if c.RootPid > 0 && c.RootPid == pid {
			return c
		}
	}

	return types.Container{}
}

func (d *DockerMetaData) init(ctx context.Context) error {
	d.rootMntNs = utils.GetMountNamespaceFromPid(1)
	d.rootNetNs = utils.GetNetworkNamespaceFromPid(1)

	c := d.client
	containers, err := c.ContainerList(ctx, container.ListOptions{
		Filters: filters.NewArgs(filters.Arg("status", "running")),
	})
	if err != nil {
		return xerrors.Errorf("list containers: %w", err)
	}
	for _, cr := range containers {
		d.handleContainerEvent(ctx, cr.ID)
	}
	return nil
}

func (d *DockerMetaData) watchContainerEventsWithRetry(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		d.watchContainerEvents(ctx)

		time.Sleep(time.Second * 15)
	}
}

func (d *DockerMetaData) watchContainerEvents(ctx context.Context) {
	c := d.client

	var chMsg <-chan events.Message
	var chErr <-chan error
	var msg events.Message

	chMsg, chErr = c.Events(ctx, dockertypes.EventsOptions{
		// Filters: filters.NewArgs(
		// 	filters.Arg("type", "container"),
		// 	filters.Arg("event", "exec_create"),
		// 	filters.Arg("event", "exec_start"),
		// ),
	})

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-chErr:
			if errors.Is(err, context.Canceled) {
				return
			}
			log.Printf("docker events failed: %s", err)
			return
		case msg = <-chMsg:
			break
		}

		if msg.Type != events.ContainerEventType {
			continue
		}
		if msg.Action == events.ActionStart ||
			strings.HasPrefix(string(msg.Action), string(events.ActionExecCreate)+": ") ||
			strings.HasPrefix(string(msg.Action), string(events.ActionExecStart)+": ") {
			d.handleContainerEvent(ctx, msg.Actor.ID)
		}
	}
}

func (d *DockerMetaData) handleContainerEvent(ctx context.Context, containerId string) {
	cr, err := d.inspectContainer(ctx, containerId)
	if err != nil {
		log.Print(err)
		return
	}

	d.setContainer(*cr)
}

func (d *DockerMetaData) setContainer(c types.Container) {
	d.mux.Lock()
	defer d.mux.Unlock()

	log.Printf("new container: %#v", c)

	d.containerById[c.Id] = c
}

func (d *DockerMetaData) inspectContainer(ctx context.Context, containerId string) (*types.Container, error) {
	c := d.client

	data, err := c.ContainerInspect(ctx, containerId)
	if err != nil {
		return nil, xerrors.Errorf("inspect container %s: %w", containerId, err)
	}

	cr := &types.Container{
		Id:          containerId,
		Name:        data.Name,
		ImageDigest: data.Image,
	}
	if conf := data.Config; conf != nil {
		cr.Image = conf.Image
		cr.Labels = conf.Labels
	}
	if state := data.State; state != nil && state.Pid != 0 {
		cr.RootPid = state.Pid
		cr.MountNamespace = utils.GetMountNamespaceFromPid(cr.RootPid)
		cr.NetworkNamespace = utils.GetNetworkNamespaceFromPid(cr.RootPid)
	}

	return cr, nil
}

func (d *DockerMetaData) Close() error {
	return d.client.Close()
}
