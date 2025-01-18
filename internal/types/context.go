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
			case "ThreadId", "TID":
				c.Tid, _ = strconv.Atoi(value)
			case "ThreadName":
				c.TName = value
			case "UserId":
				c.UserId, _ = strconv.Atoi(value)
			case "GroupId":
				c.GroupId, _ = strconv.Atoi(value)
			case "ParentPID":
				c.Parent.Pid, _ = strconv.Atoi(value)
			case "Command", "Cmd", "ParentCommand", "ParentCmd":
				var CmdTruncated bool
				if strings.HasSuffix(value, "...") {
					CmdTruncated = true
					value = strings.TrimSuffix(value, "...")
				}
				switch key {
				case "Command", "Cmd":
					c.Cmd = value
					c.CmdTruncated = CmdTruncated
				case "ParentCommand", "ParentCmd":
					c.Parent.Cmd = value
					c.Parent.CmdTruncated = CmdTruncated
				}
			case "Args", "ParentArgs":
				var ArgsTruncated bool
				if strings.HasSuffix(value, "...") {
					ArgsTruncated = true
					value = strings.TrimSuffix(value, "...")
				}
				args := strings.Split(value, " ")
				switch key {
				case "Args":
					c.Args = args
					c.ArgsTruncated = ArgsTruncated
				case "ParentArgs":
					c.Parent.Args = args
					c.Parent.ArgsTruncated = ArgsTruncated
				}
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
