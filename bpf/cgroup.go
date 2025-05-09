package bpf

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/mozillazg/ptcpdump/internal/log"
)

type cgroupProgram struct {
	sec       string
	attach    ebpf.AttachType
	prog      *ebpf.Program
	allowFail bool
}

func (b *BPF) AttachCgroups(cgroupPath string) error {
	if cgroupPath == "" {
		b.skipAttachCgroup = true
	}
	if b.skipAttachCgroup {
		log.Info("skipping cgroup attach")
		return nil
	}

	programs := []cgroupProgram{
		{
			sec:    "cgroup/sock_create",
			attach: ebpf.AttachCGroupInetSockCreate,
			prog:   b.objs.PtcpdumpCgroupSockCreate,
		},
		{
			sec:       "cgroup/post_bind4",
			attach:    ebpf.AttachCGroupInet4PostBind,
			prog:      b.objs.PtcpdumpCgroupPostBind4,
			allowFail: true,
		},
		{
			sec:       "cgroup/post_bind4",
			attach:    ebpf.AttachCGroupInet4PostBind,
			prog:      b.objs.PtcpdumpCgroupPostBind4,
			allowFail: true,
		},
		{
			sec:       "cgroup/connect4",
			attach:    ebpf.AttachCGroupInet4Connect,
			prog:      b.objs.PtcpdumpCgroupConnect4,
			allowFail: true,
		},
		{
			sec:       "cgroup/connect6",
			attach:    ebpf.AttachCGroupInet6Connect,
			prog:      b.objs.PtcpdumpCgroupConnect6,
			allowFail: true,
		},
		{
			sec:       "cgroup/sendmsg4",
			attach:    ebpf.AttachCGroupUDP4Sendmsg,
			prog:      b.objs.PtcpdumpCgroupSendmsg4,
			allowFail: true,
		},
		{
			sec:       "cgroup/sendmsg6",
			attach:    ebpf.AttachCGroupUDP6Sendmsg,
			prog:      b.objs.PtcpdumpCgroupSendmsg6,
			allowFail: true,
		},
		{
			sec:       "cgroup/recvmsg4",
			attach:    ebpf.AttachCGroupUDP4Recvmsg,
			prog:      b.objs.PtcpdumpCgroupRecvmsg4,
			allowFail: true,
		},
		{
			sec:       "cgroup/recvmsg6",
			attach:    ebpf.AttachCGroupUDP6Recvmsg,
			prog:      b.objs.PtcpdumpCgroupRecvmsg6,
			allowFail: true,
		},
		{
			sec:    "cgroup/sock_release",
			attach: ebpf.AttachCgroupInetSockRelease,
			prog:   b.objs.PtcpdumpCgroupSockRelease,
		},
	}

	for _, p := range programs {
		log.Infof("attaching %s", p.sec)
		lk, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  p.attach,
			Program: p.prog,
		})
		if err != nil {
			if p.allowFail {
				log.Infof("failed to attach program %s: %+v", p.sec, err)
			} else {
				return fmt.Errorf("attach %s: %w", p.sec, err)
			}
		} else {
			b.links = append(b.links, lk)
		}
	}

	return nil
}

func (b *BPF) disableCgroupSkb() {
	for k, v := range b.spec.Programs {
		if v.Type == ebpf.CGroupSKB {
			delete(b.spec.Programs, k)
		}
	}
}

func (b *BPF) AttachCgroupSkb(cgroupPath string, egress, ingress bool) error {
	if cgroupPath == "" {
		b.skipAttachCgroup = true
	}
	if b.skipAttachCgroup {
		return nil
	}

	if ingress {
		log.Info("attaching cgroup_skb/ingress")
		lk, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  ebpf.AttachCGroupInetIngress,
			Program: b.objs.PtcpdumpCgroupSkbIngress,
		})
		if err != nil {
			return fmt.Errorf("attach cgroup_skb/ingress: %w", err)
		}
		b.links = append(b.links, lk)
	}
	if egress {
		log.Info("attaching cgroup_skb/egress")
		lk, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  ebpf.AttachCGroupInetEgress,
			Program: b.objs.PtcpdumpCgroupSkbEgress,
		})
		if err != nil {
			return fmt.Errorf("attach cgroup_skb/egress: %w", err)
		}
		b.links = append(b.links, lk)
	}

	return nil
}
