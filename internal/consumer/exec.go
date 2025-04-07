package consumer

import (
	"context"
	"github.com/mozillazg/ptcpdump/internal/utils"
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
			c.handleExecEvent(et)
		}
	}
}

func (c *ExecEventConsumer) handleExecEvent(et bpf.BpfExecEventT) {
	log.Infof("new exec event, ppid: %d, pid: %d, comm: %s, args: %s",
		et.Meta.Ppid, et.Meta.Pid, utils.GoString(et.Filename[:]),
		utils.GoString(et.Args[:]))
	e, err := event.ParseProcessExecEvent(et)
	if err != nil {
		log.Errorf("[ExecEventConsumer] parse event failed: %s", err)
		return
	}
	if et.IsClone == 1 {
		e.IsClone = true
	}
	c.pcache.AddItem(*e)
}

func (c *ExecEventConsumer) Stop() {

}
