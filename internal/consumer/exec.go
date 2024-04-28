package consumer

import (
	"context"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/event"
	"github.com/mozillazg/ptcpdump/internal/metadata"
	"log"
)

type ExecEventConsumer struct {
	pcache *metadata.ProcessCache
}

func NewExecEventConsumer(pcache *metadata.ProcessCache) *ExecEventConsumer {
	return &ExecEventConsumer{
		pcache: pcache,
	}
}

func (c *ExecEventConsumer) Start(ctx context.Context, ch <-chan bpf.BpfExecEventT) {
	for {
		select {
		case <-ctx.Done():
			return
		case et := <-ch:
			c.parseExecEvent(et)
		}
	}
}

func (c *ExecEventConsumer) parseExecEvent(et bpf.BpfExecEventT) {
	e, err := event.ParseProcessExecEvent(et)
	if err != nil {
		log.Printf("[ExecEventConsumer] parse event failed: %s", err)
		return
	}
	c.pcache.AddItem(*e)
}

func (c *ExecEventConsumer) Stop() {

}
