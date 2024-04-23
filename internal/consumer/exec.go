package consumer

import (
	"context"
	"errors"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
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

func (c *ExecEventConsumer) Start(ctx context.Context, reader *ringbuf.Reader) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("[ExecEventConsumer] Received signal, exiting...")
				return
			}
			log.Printf("[ExecEventConsumer] read event failed: %s", err)
			continue
		}
		c.parseExecEvent(record.RawSample)
	}
}

func (c *ExecEventConsumer) parseExecEvent(rawSample []byte) {
	e, err := event.ParseProcessExecEvent(rawSample)
	if err != nil {
		log.Printf("[ExecEventConsumer] parse event failed: %s", err)
		return
	}
	c.pcache.AddItem(*e)
}

func (c *ExecEventConsumer) Stop() {

}
