package consumer

import (
	"context"
	"sync"

	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/event"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/metadata"
)

type ExecEventConsumer struct {
	pcache       *metadata.ProcessCache
	workerNumber int
}

func NewExecEventConsumer(pcache *metadata.ProcessCache, workerNumber int) *ExecEventConsumer {
	return &ExecEventConsumer{
		pcache:       pcache,
		workerNumber: workerNumber,
	}
}

func (c *ExecEventConsumer) Start(ctx context.Context, ch <-chan bpf.BpfExecEventT) {
	wg := sync.WaitGroup{}
	for i := 0; i < c.workerNumber; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.worker(ctx, ch)
		}()
	}
	wg.Wait()
}

func (c *ExecEventConsumer) worker(ctx context.Context, ch <-chan bpf.BpfExecEventT) {
	for {
		select {
		case <-ctx.Done():
			return
		case et := <-ch:
			c.HandleExecEvent(et)
		}
	}
}

func (c *ExecEventConsumer) HandleExecEvent(et bpf.BpfExecEventT) {
	e, err := event.ParseProcessExecEvent(et)
	if err != nil {
		log.Errorf("[ExecEventConsumer] parse event failed: %s", err)
		return
	}
	c.pcache.AddItem(*e)
}

func (c *ExecEventConsumer) Stop() {

}
