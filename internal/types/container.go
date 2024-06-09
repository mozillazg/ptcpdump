package types

import (
	"encoding/json"
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

func (c Container) TidyName() string {
	return strings.TrimLeft(c.Name, "/")
}

func (c Container) FormatLabels() string {
	if len(c.Labels) == 0 {
		return "{}"
	}
	b, _ := json.Marshal(c.Labels)
	return string(b)
}

func ParseContainerLabels(s string) map[string]string {
	labels := make(map[string]string)
	json.Unmarshal([]byte(s), &labels)
	return labels
}
