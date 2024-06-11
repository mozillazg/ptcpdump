package types

import (
	"strconv"
	"strings"
)

type PacketContext struct {
	Process
	Container
	Pod
}

func (c *PacketContext) FromPacketComments(comments []string) {
	for _, comment := range comments {
		comment = strings.TrimSpace(comment)
		for _, line := range strings.Split(comment, "\n") {
			line = strings.TrimSpace(line)
			parts := strings.SplitN(line, ":", 2)
			if len(parts) < 2 {
				continue
			}
			key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			switch key {
			case "PID":
				c.Pid, _ = strconv.Atoi(value)
			case "Command":
				if strings.HasSuffix(value, "...") {
					c.CmdTruncated = true
					value = strings.TrimSuffix(value, "...")
				}
				c.Cmd = value
			case "Args":
				if strings.HasSuffix(value, "...") {
					c.ArgsTruncated = true
					value = strings.TrimSuffix(value, "...")
				}
				c.Args = strings.Split(value, " ")
			case "ContainerName":
				c.Container.Name = value
			case "ContainerId":
				c.Container.Id = value
			case "ContainerImage":
				c.Container.Image = value
			case "ContainerLabels":
				c.Container.Labels = ParseContainerLabels(value)
			case "PodName":
				c.Pod.Name = value
			case "PodNamespace":
				c.Pod.Namespace = value
			case "PodUID":
				c.Pod.Uid = value
			case "PodLabels":
				c.Pod.Labels = ParsePodLabels(value)
			case "PodAnnotations":
				c.Pod.Annotations = ParsePodAnnotations(value)
			default:
			}
		}
	}
}
