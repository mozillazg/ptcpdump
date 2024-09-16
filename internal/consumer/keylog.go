package consumer

import (
	"context"
	"fmt"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/log"
	"github.com/mozillazg/ptcpdump/internal/utils"
	"github.com/mozillazg/ptcpdump/internal/writer"
	"sync"
)

type GoKeyLogEventConsumer struct {
	workerNumber int
	ws           []writer.KeyLogWriter
	lock         sync.Mutex
}

func NewGoKeyLogEventConsumer(workerNumber int, ws ...writer.KeyLogWriter) *GoKeyLogEventConsumer {
	return &GoKeyLogEventConsumer{
		workerNumber: workerNumber,
		ws:           ws,
		lock:         sync.Mutex{},
	}
}

func (c *GoKeyLogEventConsumer) Start(ctx context.Context, ch <-chan bpf.BpfGoKeylogEventT) {
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

func (c *GoKeyLogEventConsumer) worker(ctx context.Context, ch <-chan bpf.BpfGoKeylogEventT) {
	for {
		select {
		case <-ctx.Done():
			return
		case et := <-ch:
			c.handleEvent(et)
		}
	}
}

func (c *GoKeyLogEventConsumer) handleEvent(e bpf.BpfGoKeylogEventT) {
	label := utils.GoString(e.Label[:int(e.LabelLen)])
	clientRandom := utils.GoBytes(e.ClientRandom[:int(e.ClientRandomLen)])
	secret := utils.GoBytes(e.Secret[:int(e.SecretLen)])

	line := fmt.Sprintf("%s %x %x\n", label, clientRandom, secret)
	c.write(line)
}

func (c *GoKeyLogEventConsumer) write(line string) {
	c.lock.Lock()
	defer c.lock.Unlock()

	for _, w := range c.ws {
		err := w.Write(line)
		if err != nil {
			log.Warnf("write tls key log with %T failed: %s", w, err)
			continue
		}
		w.Flush()
	}
}

func (c *GoKeyLogEventConsumer) Stop() {
	for _, w := range c.ws {
		w.Close()
	}
}
