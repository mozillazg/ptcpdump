package capturer

import (
	"context"
	"fmt"
	ebpfbtf "github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/btf"
	"github.com/mozillazg/ptcpdump/internal/consumer"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"github.com/mozillazg/ptcpdump/internal/types"
	"github.com/mozillazg/ptcpdump/internal/utils"
	"github.com/mozillazg/ptcpdump/internal/writer"
	"strings"
	"syscall"
	"time"
)

type Capturer struct {
	opts *Options

	btfSpec *ebpfbtf.Spec
	bpf     *bpf.BPF

	subProcessFinished  <-chan struct{}
	subProcessLoaderPid int

	packetEvensCh       <-chan bpf.BpfPacketEventWithPayloadT
	execEvensCh         <-chan bpf.BpfExecEventT
	exitEvensCh         <-chan bpf.BpfExitEventT
	goTlsKeyLogEventsCh <-chan bpf.BpfGoKeylogEventT
	newDevCh            <-chan bpf.BpfNewNetdeviceEventT
	devChangeCh         <-chan bpf.BpfNetdeviceChangeEventT
	mountCh             <-chan bpf.BpfMountEventT

	stopByInternal bool
	closeFuncs     []func()
	stopped        chan struct{}
	cgroupPath     string
}

type Options struct {
	Pids           []uint
	Uids           []uint
	Comm           string
	FollowForks    bool
	WriteFilePath  string
	ReadFilePath   string
	PcapFilter     string
	MaxPacketCount uint
	DirectionOut   bool
	DirectionIn    bool
	OneLine        bool
	Quiet          bool
	Backend        types.NetHookBackend

	PrintPacketNumber   bool
	DontPrintTimestamp  bool
	OnlyPrintCount      bool
	PrintDataAsHex      int
	PrintDataAsHexASCII int
	PrintDataAsASCII    bool

	TimeStampPrecision string
	TimeStampMicro     bool
	TimeStampNano      bool

	DontConvertAddr int

	ContainerId   string
	ContainerName string
	PodName       string
	PodNamespace  string

	EventChanSize                 uint
	DelayBeforeHandlePacketEvents time.Duration
	ExecEventsWorkerNumber        uint
	SnapshotLength                uint32
	DisableReverseMatch           bool

	DockerEndpoint     string
	ContainerdEndpoint string
	CriRuntimeEndpoint string

	WriteTLSKeyLogPath     string
	EmbedTLSKeyLogToPcapng bool

	SubProgArgs []string

	MntnsIds []uint32
	NetnsIds []uint32
	PidnsIds []uint32

	BTFPath string

	Connections  []metadata.Connection
	ProcessCache *metadata.ProcessCache
	NetNSCache   *metadata.NetNsCache
	DeviceCache  *metadata.DeviceCache

	Writers []writer.PacketWriter

	Gcr            *consumer.GoKeyLogEventConsumer
	ExecConsumer   *consumer.ExecEventConsumer
	ExitConsumer   *consumer.ExitEventConsumer
	PacketConsumer *consumer.PacketEventConsumer

	NetNsPaths    []string
	DevNames      []string
	Devices       []types.Device
	AllDev        bool
	AllNetNs      bool
	AllNewlyNetNs bool
}

func NewCapturer(opts *Options) *Capturer {
	return &Capturer{opts: opts, stopped: make(chan struct{}, 10)}
}

func (c *Capturer) StartSubProcessLoader(ctx context.Context, program string, subProgramArgs []string) error {
	if len(subProgramArgs) == 0 {
		return nil
	}

	log.Info("start sub process loader")
	var err error
	c.subProcessLoaderPid, c.subProcessFinished, err = utils.StartSubProcessLoader(ctx, program, subProgramArgs)
	if err != nil {
		return err
	}
	log.Infof("will filter by pid: %d", c.subProcessLoaderPid)
	c.opts.Pids = []uint{uint(c.subProcessLoaderPid)}
	c.opts.FollowForks = true

	return nil
}

func (c *Capturer) Prepare() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock failed: %w", err)
	}

	btfspec, err := c.loadBTF()
	if err != nil {
		return fmt.Errorf("load btf failed: %w", err)
	}
	c.btfSpec = btfspec

	c.bpf, err = bpf.NewBPF()
	if err != nil {
		return fmt.Errorf("new bpf failed: %w", err)
	}

	bf := c.bpf
	bpfopts := &bpf.Options{}
	bpfopts = bpfopts.WithPids(c.opts.Pids).
		WithComm(c.opts.Comm).
		WithFollowFork(c.opts.FollowForks).
		WithUids(c.opts.Uids).
		WithPidNsIds(c.opts.PidnsIds).
		WithMntNsIds(c.opts.MntnsIds).
		WithNetNsIds(c.opts.NetnsIds).
		WithMaxPayloadSize(c.opts.SnapshotLength).
		WithDisableReverseMatch(c.opts.DisableReverseMatch).
		WithHookMount(c.opts.AllNetNs || c.opts.AllNewlyNetNs).
		WithHookNetDev(c.opts.AllNetNs || c.opts.AllNewlyNetNs || c.opts.AllDev).
		WithPcapFilter(c.opts.PcapFilter).
		WithBackend(c.opts.Backend).
		WithKernelTypes(c.btfSpec)
	if !c.opts.AllDev {
		bpfopts = bpfopts.WithIfindexes(c.ifindexes())
	}
	if c.opts.Backend != types.NetHookBackendTc && c.opts.Backend != types.NetHookBackendSocketFilter {
		bpfopts = bpfopts.WithHookMount(false).WithHookNetDev(false)
	}

	if err := bf.Load(*bpfopts); err != nil {
		return fmt.Errorf("load bpf failed: %w", err)
	}
	c.closeFuncs = append(c.closeFuncs, bf.Close)

	if len(c.opts.Connections) > 0 {
		if err := updateFlowPidMapValues(bf, c.opts.Connections); err != nil {
			return fmt.Errorf("update flow pid map values failed: %w", err)
		}
	}

	return nil
}

func (c *Capturer) ifindexes() []uint32 {
	var ifindexes []uint32
	for _, dev := range c.opts.Devices {
		ifindexes = append(ifindexes, uint32(dev.Ifindex))
	}
	return ifindexes
}

func (c *Capturer) AttachTracingHooks() error {
	bf := c.bpf

	cgroupPath, err := utils.GetCgroupV2RootDir()
	if err != nil {
		log.Warnf("skip attach cgroup due to get cgroup v2 root dir failed: %s", err)
	}
	log.Infof("cgroup path: %s", cgroupPath)
	if err := bf.AttachCgroups(cgroupPath); err != nil {
		return err
	} else {
		c.cgroupPath = cgroupPath
	}

	if err := bf.AttachKprobes(); err != nil {
		return err
	}
	if err := bf.AttachTracepoints(); err != nil {
		return err
	}

	return nil
}

func (c *Capturer) AttachCaptureHooks() error {
	log.Infof("backend: %s", c.opts.Backend)
	switch c.opts.Backend {
	case types.NetHookBackendCgroupSkb:
		return c.bpf.AttachCgroupSkb(c.cgroupPath, c.opts.DirectionOut, c.opts.DirectionIn)
	case types.NetHookBackendTpBtf:
		return c.bpf.AttachTpBtfCaptureHooks(c.opts.DirectionOut, c.opts.DirectionIn)
	case types.NetHookBackendSocketFilter:
		return c.attachSocketFilterHooksToDevs(c.opts.Devices)
	default:
		return c.attachTcHooksToDevs(c.opts.Devices)
	}
}

func (c *Capturer) attachTcHooksToDevs(devs []types.Device) error {
	for _, iface := range devs {
		err := c.attachTcHooks(iface)
		if err != nil {
			return fmt.Errorf("attach tc hooks for interface %d.%s: %w",
				iface.Ifindex, iface.Name, err)
		}
	}

	return nil
}

func (c *Capturer) attachSocketFilterHooksToDevs(devs []types.Device) error {
	if c.opts.AllDev {
		var anyDevs []types.Device
		idnodes := map[uint32]bool{}
		for _, iface := range devs {
			id := iface.NetNs.Inode()
			if _, ok := idnodes[id]; !ok {
				idnodes[id] = true
				dev := types.NewDummyDevice(-1, iface.NetNs)
				dev.Name = "any"
				anyDevs = append(anyDevs, dev)
			}
		}
		devs = anyDevs
	}

	for _, iface := range devs {
		err := c.attachSocketFilterHooks(iface)
		if err != nil {
			return fmt.Errorf("attach socket filter hooks for interface %d.%s: %w",
				iface.Ifindex, iface.Name, err)
		}
	}

	return nil
}

func (c *Capturer) Start(ctx context.Context, stopFunc context.CancelFunc) error {
	if err := c.pullEvents(ctx); err != nil {
		return err
	}

	go c.opts.ExecConsumer.Start(ctx, c.execEvensCh)
	go c.opts.ExitConsumer.Start(ctx, c.exitEvensCh)
	go c.opts.Gcr.Start(ctx, c.goTlsKeyLogEventsCh)

	go func() {
		c.opts.PacketConsumer.Start(ctx, c.packetEvensCh, c.opts.MaxPacketCount)
		c.stopped <- struct{}{}
	}()

	go c.handleMountEvents()
	go c.handleNewDevEvents()
	go c.handleDevChangeEvents()

	go c.startSubProcess(stopFunc)

	return nil
}

func (c *Capturer) Stop() {
	c.opts.PacketConsumer.Stop()
	c.opts.ExecConsumer.Stop()
	c.opts.ExitConsumer.Stop()
	c.opts.Gcr.Stop()

	for _, w := range c.opts.Writers {
		w.Flush()
	}

	runClosers(c.closeFuncs)
}

func (c *Capturer) Wait() {
	<-c.stopped
}

func (c *Capturer) pullEvents(ctx context.Context) error {
	var err error

	c.packetEvensCh, err = c.bpf.PullPacketEvents(ctx, int(c.opts.EventChanSize), int(c.opts.SnapshotLength))
	if err != nil {
		return err
	}
	c.execEvensCh, err = c.bpf.PullExecEvents(ctx, int(c.opts.EventChanSize))
	if err != nil {
		return err
	}
	c.exitEvensCh, err = c.bpf.PullExitEvents(ctx, int(c.opts.EventChanSize))
	if err != nil {
		return err
	}
	c.goTlsKeyLogEventsCh, err = c.bpf.PullGoKeyLogEvents(ctx, int(c.opts.EventChanSize))
	if err != nil {
		return err
	}

	if c.opts.Backend != types.NetHookBackendCgroupSkb {
		if c.opts.AllDev {
			c.newDevCh, err = c.bpf.PullNewNetDeviceEvents(ctx, int(c.opts.EventChanSize))
			if err != nil {
				return err
			}
			c.devChangeCh, err = c.bpf.PullNetDeviceChangeEvents(ctx, int(c.opts.EventChanSize))
			if err != nil {
				return err
			}
		}
		if c.opts.AllNetNs || c.opts.AllNewlyNetNs {
			c.mountCh, err = c.bpf.PullMountEventEvents(ctx, int(c.opts.EventChanSize))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *Capturer) BPF() *bpf.BPF {
	return c.bpf
}

func (c *Capturer) StopByInternal() bool {
	return c.stopByInternal
}

func (c *Capturer) startSubProcess(stop context.CancelFunc) {
	if c.subProcessLoaderPid == 0 {
		return
	}

	log.Infof("notify loader %d to start sub process", c.subProcessLoaderPid)
	syscall.Kill(c.subProcessLoaderPid, syscall.SIGHUP)

	<-c.subProcessFinished

	log.Info("sub process exited")
	time.Sleep(time.Second * 3)

	c.stopByInternal = true
	time.Sleep(c.opts.DelayBeforeHandlePacketEvents)
	stop()
	c.stopped <- struct{}{}
}

func (c *Capturer) attachTcHooks(iface types.Device) error {
	var finalErr error
	log.Infof("start to attach tc hook to %s in netns %s", iface.Name, iface.NetNs)

	err := iface.NetNs.Do(func() {
		closeFuncs, err := c.bpf.AttachTcHooks(iface, c.opts.DirectionOut, c.opts.DirectionIn)
		if err != nil {
			runClosers(closeFuncs)
			// TODO: use errors.Is(xxx) or ==
			if strings.Contains(err.Error(), "netlink receive: no such file or directory") ||
				strings.Contains(err.Error(), "netlink receive: no such device") {
				log.Warnf("skip interface %s due to %s", iface.Name, err)
				return
			}
			finalErr = err
		} else {
			c.closeFuncs = append(c.closeFuncs, func() {
				iface.NetNs.Do(func() {
					runClosers(closeFuncs)
				})
			})
		}
	})

	if finalErr == nil {
		finalErr = err
	}

	return finalErr
}

func (c *Capturer) attachSocketFilterHooksToNewDev(iface types.Device) error {
	if c.opts.AllDev {
		if iface.NetNs.Inode() == c.opts.NetNSCache.GetCurrentNs().Inode() {
			return nil
		}
	}
	return c.attachSocketFilterHooks(iface)
}

func (c *Capturer) attachSocketFilterHooks(iface types.Device) error {
	var finalErr error
	log.Infof("start to attach socket filter to %s in netns %s", iface.Name, iface.NetNs)

	err := iface.NetNs.Do(func() {
		closeFuncs, err := c.bpf.AttachSocketFilterHooks(iface, c.opts.DirectionOut, c.opts.DirectionIn)
		if err != nil {
			runClosers(closeFuncs)
			// TODO: use errors.Is(xxx) or ==
			if strings.Contains(err.Error(), "netlink receive: no such file or directory") ||
				strings.Contains(err.Error(), "netlink receive: no such device") {
				log.Warnf("skip interface %s due to %s", iface.Name, err)
				return
			}
			finalErr = err
		} else {
			c.closeFuncs = append(c.closeFuncs, func() {
				iface.NetNs.Do(func() {
					runClosers(closeFuncs)
				})
			})
		}
	})

	if finalErr == nil {
		finalErr = err
	}

	return finalErr
}

func (c *Capturer) loadBTF() (*ebpfbtf.Spec, error) {
	log.Info("start load BTF spec")
	btfSpec, btfPath, err := btf.LoadBTFSpec(c.opts.BTFPath)
	if err != nil {
		return btfSpec, err
	}
	if btfPath != btf.DefaultPath {
		log.Warnf("use BTF specs from %s", btfPath)
	}

	return btfSpec, nil
}

func (c *Capturer) handleMountEvents() {
	if c.mountCh == nil {
		return
	}
	for event := range c.mountCh {
		dest := utils.GoString(event.Dest[:])
		if !strings.HasPrefix(dest, "/run/netns/") {
			continue
		}
		_, err := c.opts.NetNSCache.GetOrFetchByPath(dest)
		if err != nil {
			log.Errorf("error: %+v", err)
		}
	}
}

func (c *Capturer) handleNewDevEvents() {
	if c.newDevCh == nil {
		return
	}
	for event := range c.newDevCh {
		dev := event.Dev
		c.opts.DeviceCache.Add(dev.NetnsId, dev.Ifindex, utils.GoString(dev.Name[:]))

		device, _ := c.opts.DeviceCache.GetByIfindex(int(dev.Ifindex), dev.NetnsId)
		if !c.shouldHandleThisNewDev(device) {
			continue
		}

		c.addNewDevToWriter(device)
		log.Infof("start attach tc/socket-filter hooks to %s, triggered by events", device.String())

		switch c.opts.Backend {
		case types.NetHookBackendTc:
			if err := c.attachTcHooks(device); err != nil {
				log.Infof("attach tc hooks to %s failed: %s", device.String(), err)
			}
			break
		case types.NetHookBackendSocketFilter:
			if err := c.attachSocketFilterHooksToNewDev(device); err != nil {
				log.Infof("attach socket filter hooks to %s failed: %s", device.String(), err)
			}
			break
		}
	}
}

func (c *Capturer) handleDevChangeEvents() {
	if c.devChangeCh == nil {
		return
	}
	for event := range c.devChangeCh {
		dev := event.NewDevice
		c.opts.DeviceCache.Add(dev.NetnsId, dev.Ifindex, utils.GoString(dev.Name[:]))

		device, _ := c.opts.DeviceCache.GetByIfindex(int(dev.Ifindex), dev.NetnsId)
		if !c.shouldHandleThisNewDev(device) {
			continue
		}

		c.addNewDevToWriter(device)

		switch c.opts.Backend {
		case types.NetHookBackendTc:
			if err := c.attachTcHooks(device); err != nil {
				log.Infof("attach tc hooks failed: %s", err)
			}
			break
		case types.NetHookBackendSocketFilter:
			if err := c.attachSocketFilterHooksToNewDev(device); err != nil {
				log.Infof("attach socket filter hooks failed: %s", err)
			}
			break
		}
	}
}

func (c *Capturer) addNewDevToWriter(dev types.Device) {
	for _, w := range c.opts.Writers {
		if pw, ok := w.(*writer.PcapNGWriter); ok {
			pw.AddDev(dev)
		}
	}
}

func (c *Capturer) shouldHandleThisNewDev(dev types.Device) bool {
	currNs := c.opts.NetNSCache.GetCurrentNs()
	filterNss := c.getFilterNetNs()
	// check ns
	if !c.opts.AllNetNs {
		if c.opts.AllNewlyNetNs {
			if dev.NetNs.Inode() == currNs.Inode() {
				log.Infof("filter newly netns, ignore current netns dev: %+v", dev)
				return false
			}
		} else {
			var match bool
			for _, ns := range filterNss {
				if dev.NetNs.Inode() == ns.Inode() {
					match = true
					break
				}
			}
			if !match {
				log.Infof("filter some netns, ignore not filter dev: %+v", dev)
			}
		}
	}
	// check dev name
	if !c.opts.AllDev {
		var match bool
		for _, name := range c.opts.DevNames {
			if dev.Name == name {
				match = true
				break
			}
		}
		if !match {
			log.Infof("filter some dev names, ignore not filter dev: %+v", dev)
		}
	}
	return true
}

func (c *Capturer) getFilterNetNs() []*types.NetNs {
	var nss []*types.NetNs
	for _, p := range c.opts.NetNsPaths {
		ns, _ := c.opts.NetNSCache.GetOrFetchByPath(p)
		nss = append(nss, ns)
	}
	return nss
}

func updateFlowPidMapValues(bf *bpf.BPF, conns []metadata.Connection) error {
	data := map[*bpf.BpfFlowPidKeyT]bpf.BpfProcessMetaT{}
	for _, conn := range conns {
		if conn.Pid == 0 {
			continue
		}
		k := bpf.BpfFlowPidKeyT{
			Saddr: addrTo128(conn.LocalIP),
			Sport: uint16(conn.LocalPort),
		}
		v := bpf.BpfProcessMetaT{
			Pid:     uint32(conn.Pid),
			Uid:     uint32(conn.Uid),
			MntnsId: uint32(conn.MntNs),
			NetnsId: uint32(conn.NetNs),
		}
		data[&k] = v
	}
	if err := bf.UpdateFlowPidMapValues(data); err != nil {
		return fmt.Errorf(": %w", err)
	}
	return nil
}
