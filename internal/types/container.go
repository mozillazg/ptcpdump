package types

import (
	"fmt"
	"strings"
)

type Container struct {
	Id     string
	Name   string
	Labels map[string]string

	RootPid          int
	MountNamespace   int64
	NetworkNamespace int64

	Image       string
	ImageDigest string
}

func (c Container) FormatLabels() string {
	lines := []string{}
	for k, v := range c.Labels {
		lines = append(lines, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(lines, " ")
}
