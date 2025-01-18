package capturer

import (
	"context"
	"errors"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/log"
)

func (c *Capturer) iterTasks(ctx context.Context) error {
	ch, err := c.bpf.IterTasks(ctx, int(c.opts.EventChanSize))

	if err != nil {
		if !errors.Is(err, bpf.ErrIteratorIsNotSupported) {
			log.Infof("iter tasks failed: %s", err)
		}
		if err := c.opts.ProcessCache.FillRunningProcesses(ctx); err != nil {
			log.Warnf("fill running processes failed: %s", err)
		}
		return ctx.Err()
	}

	for event := range ch {
		c.opts.ExecConsumer.HandleExecEvent(event)
	}

	return ctx.Err()
}
