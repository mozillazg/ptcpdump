package capturer

import (
	"context"
	"errors"
	"fmt"
	"github.com/mozillazg/ptcpdump/bpf"
	"github.com/mozillazg/ptcpdump/internal/log"
)

func (c *Capturer) iterConnections(ctx context.Context) error {
	if len(c.opts.Connections) > 0 {
		log.Info("start to update flow pid map values")
		if err := updateFlowPidMapValues(c.bpf, c.opts.Connections); err != nil {
			return fmt.Errorf("update flow pid map values failed: %w", err)
		}
	}

	if err := c.bpf.IterConnections(ctx); err != nil {
		if !errors.Is(err, bpf.ErrIteratorIsNotSupported) {
			log.Infof("iter tasks failed: %s", err)
		}
	}

	return ctx.Err()
}
