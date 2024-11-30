package bpf

import (
	"github.com/mozillazg/ptcpdump/internal/log"
)

func (b *BPF) attachNetDevHooks() error {
	if !b.opts.hookNetDev {
		return nil
	}

	err := b.attachFexitOrKprobe("register_netdevice",
		nil, b.objs.KprobeRegisterNetdevice, b.objs.KretprobeRegisterNetdevice)
	if err != nil {
		return err
	}

	// TODO: refine
	err = b.attachFexitOrKprobe("__dev_get_by_index",
		nil, nil, b.objs.KretprobeDevGetByIndex)
	if err != nil {
		log.Infof("%+v", err)
		if isProbeNotSupportErr(err) {
			err = b.attachFexitOrKprobe("dev_get_by_index",
				nil, nil, b.objs.KretprobeDevGetByIndexLegacy)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	err = b.attachFentryOrKprobe("__dev_change_net_namespace",
		nil, b.objs.KprobeDevChangeNetNamespace)
	if err != nil {
		log.Infof("%+v", err)
		if isProbeNotSupportErr(err) {
			err = b.attachFentryOrKprobe("dev_change_net_namespace",
				nil, b.objs.KprobeDevChangeNetNamespaceLegacy)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	err = b.attachFexitOrKprobe("__dev_change_net_namespace",
		nil, nil, b.objs.KretprobeDevChangeNetNamespace)
	if err != nil {
		log.Infof("%+v", err)
		if isProbeNotSupportErr(err) {
			err = b.attachFexitOrKprobe("dev_change_net_namespace",
				nil, nil, b.objs.KretprobeDevChangeNetNamespaceLegacy)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	return nil
}
