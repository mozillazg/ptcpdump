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

func ParseContainerLabels(s string) map[string]string {
	labels := make(map[string]string)
	for _, part := range strings.Split(s, " ") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.Split(part, "=")
		if len(kv) == 2 {
			labels[kv[0]] = labels[kv[1]]
		}
	}
	return labels
}
