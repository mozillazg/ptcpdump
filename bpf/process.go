package bpf

import (
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/mozillazg/ptcpdump/internal/log"
)

func (b *BPF) attachProcessHooks() error {
	err := b.attachBTFTracepointOrRawTP("sched_process_exec",
		b.objs.PtcpdumpTpBtfSchedProcessExec, b.objs.PtcpdumpRawTracepointSchedProcessExec,
	)
	if err != nil {
		log.Infof("%+v", err)
		log.Info("attaching tracepoint/sched/sched_process_exec")
		if lk, err := link.Tracepoint("sched", "sched_process_exec",
			b.objs.PtcpdumpTracepointSchedProcessExec, &link.TracepointOptions{}); err != nil {
			return fmt.Errorf("attach tracepoint/sched/sched_process_exec failed: %w", err)
		} else {
			b.links = append(b.links, lk)
		}
	}

	err = b.attachFentryOrKprobe("acct_process", b.objs.PtcpdumpFentryAcctProcess,
		b.objs.PtcpdumpKprobeAcctProcess)
	if err != nil {
		log.Infof("%+v", err)
		var failed bool
		if err := b.attachBTFTracepointOrRawTP("sched_process_exit",
			b.objs.PtcpdumpTpBtfSchedProcessExit, b.objs.PtcpdumpRawTracepointSchedProcessExit); err != nil {
			log.Infof("%+v", err)
			failed = true
		}
		if failed {
			if err := b.attachFentryOrKprobe("do_exit", b.objs.PtcpdumpFentryDoExit,
				b.objs.PtcpdumpKprobeDoExit); err != nil {
				return fmt.Errorf(": %w", err)
			}
		}
	}

	if b.opts.attachForks() {
		err := b.attachBTFTracepointOrRawTP("sched_process_fork",
			b.objs.PtcpdumpTpBtfSchedProcessFork, b.objs.PtcpdumpRawTracepointSchedProcessFork,
		)
		if err != nil {
			return fmt.Errorf(": %w", err)
		}
	}

	return nil
}
