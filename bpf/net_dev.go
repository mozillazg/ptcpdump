//go:build !arm

package bpf

import (
	"github.com/mozillazg/ptcpdump/internal/log"
)

func (b *BPF) attachNetDevHooks() error {
	if !b.opts.hookNetDev {
		return nil
	}

	err := b.attachFexitOrKprobe("register_netdevice",
		nil, b.objs.PtcpdumpKprobeRegisterNetdevice, b.objs.PtcpdumpKretprobeRegisterNetdevice)
	if err != nil {
		log.Infof("%+v", err)
		return nil
	}

	// TODO: refine
	err = b.attachFexitOrKprobe("__dev_get_by_index",
		nil, nil, b.objs.PtcpdumpKretprobeDevGetByIndex)
	if err != nil {
		log.Infof("%+v", err)
		if isProbeNotSupportErr(err) {
			err = b.attachFexitOrKprobe("dev_get_by_index",
				nil, nil, b.objs.PtcpdumpKretprobeDevGetByIndexLegacy)
		}
		if err != nil {
			log.Infof("%+v", err)
			return nil
		}
	}

	err = b.attachFentryOrKprobe("__dev_change_net_namespace",
		nil, b.objs.PtcpdumpKprobeDevChangeNetNamespace)
	if err != nil {
		log.Infof("%+v", err)
		if isProbeNotSupportErr(err) {
			err = b.attachFentryOrKprobe("dev_change_net_namespace",
				nil, b.objs.PtcpdumpKprobeDevChangeNetNamespaceLegacy)
		}
		if err != nil {
			log.Infof("%+v", err)
			return nil
		}
	}

	err = b.attachFexitOrKprobe("__dev_change_net_namespace",
		nil, nil, b.objs.PtcpdumpKretprobeDevChangeNetNamespace)
	if err != nil {
		log.Infof("%+v", err)
		if isProbeNotSupportErr(err) {
			err = b.attachFexitOrKprobe("dev_change_net_namespace",
				nil, nil, b.objs.PtcpdumpKretprobeDevChangeNetNamespaceLegacy)
		}
		if err != nil {
			log.Infof("%+v", err)
			return nil
		}
	}

	return nil
}
