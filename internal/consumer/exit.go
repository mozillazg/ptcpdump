package consumer

import (
	"context"
	"github.com/mozillazg/ptcpdump/internal/log"
	"sync"

	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/metadata"
)

type ExitEventConsumer struct {
	pcache       *metadata.ProcessCache
	workerNumber int
}

func NewExitEventConsumer(pcache *metadata.ProcessCache, workerNumber int) *ExitEventConsumer {
	return &ExitEventConsumer{
		pcache:       pcache,
		workerNumber: workerNumber,
	}
}

func (c *ExitEventConsumer) Start(ctx context.Context, ch <-chan bpf.BpfExitEventT) {
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

func (c *ExitEventConsumer) worker(ctx context.Context, ch <-chan bpf.BpfExitEventT) {
	for {
		select {
		case <-ctx.Done():
			return
		case et := <-ch:
			c.handleExitEvent(et)
		}
	}
}

func (c *ExitEventConsumer) handleExitEvent(et bpf.BpfExitEventT) {
	log.Infof("new exit event: pid: %d", et.Pid)
	c.pcache.MarkDead(int(et.Pid))
}

func (c *ExitEventConsumer) Stop() {

}
