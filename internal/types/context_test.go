package types

import (
	"reflect"
	"testing"
)

func TestPacketContext_FromPacketComments(t *testing.T) {
	type args struct {
		comments []string
	}
	tests := []struct {
		name string
		args args
		want PacketContext
	}{
		{
			name: "empty comments",
			args: args{comments: []string{}},
			want: PacketContext{},
		},
		{
			name: "process information",
			args: args{
				comments: []string{
					"PID: 1234",
					"TID: 5678",
					"ThreadName: worker",
					"UserId: 1000",
					"Command: /bin/bash",
					"Args: -c sleep 10",
					"ParentPID: 100",
					"ParentCommand: systemd",
					"ParentArgs: --user",
				},
			},
			want: PacketContext{
				Process: Process{
					ProcessBase: ProcessBase{
						Pid:    1234,
						Tid:    5678,
						TName:  "worker",
						UserId: 1000,
						Cmd:    "/bin/bash",
						Args:   []string{"-c", "sleep", "10"},
					},
					Parent: ProcessBase{
						Pid:  100,
						Cmd:  "systemd",
						Args: []string{"--user"},
					},
				},
			},
		},
		{
			name: "container information",
			args: args{
				comments: []string{
					"ContainerName: nginx",
					"ContainerId: abc123",
					"ContainerImage: nginx:1.19",
					`ContainerLabels: {"app":"web","env":"prod"}`,
				},
			},
			want: PacketContext{
				Container: Container{
					Name:   "nginx",
					Id:     "abc123",
					Image:  "nginx:1.19",
					Labels: map[string]string{"app": "web", "env": "prod"},
				},
			},
		},
		{
			name: "pod information",
			args: args{
				comments: []string{
					"PodName: web-pod",
					"PodNamespace: default",
					"PodUID: def456",
					`PodLabels: {"app":"web"}`,
					`PodAnnotations: {"sidecar.istio.io/inject":"true"}`,
				},
			},
			want: PacketContext{
				Pod: Pod{
					Name:        "web-pod",
					Namespace:   "default",
					Uid:         "def456",
					Labels:      map[string]string{"app": "web"},
					Annotations: map[string]string{"sidecar.istio.io/inject": "true"},
				},
			},
		},
		{
			name: "truncated commands",
			args: args{
				comments: []string{
					"Command: /usr/bin/python3...",
					"Args: app.py --config config.yaml...",
					"ParentCommand: docker-compose...",
					"ParentArgs: up -d...",
				},
			},
			want: PacketContext{
				Process: Process{
					ProcessBase: ProcessBase{
						Cmd:           "/usr/bin/python3",
						CmdTruncated:  true,
						Args:          []string{"app.py", "--config", "config.yaml"},
						ArgsTruncated: true,
					},
					Parent: ProcessBase{
						Cmd:           "docker-compose",
						CmdTruncated:  true,
						Args:          []string{"up", "-d"},
						ArgsTruncated: true,
					},
				},
			},
		},
		{
			name: "invalid comment format",
			args: args{
				comments: []string{
					"Invalid comment",
					"PID",
					": 1234",
					"Command:",
				},
			},
			want: PacketContext{},
		},
		{
			name: "mix of valid and invalid comments",
			args: args{
				comments: []string{
					"PID: 1234",
					"Invalid: : comment :",
					"ContainerName: nginx",
					"Random text",
					"PodName: web-pod",
				},
			},
			want: PacketContext{
				Process: Process{
					ProcessBase: ProcessBase{
						Pid: 1234,
					},
				},
				Container: Container{
					Name: "nginx",
				},
				Pod: Pod{
					Name: "web-pod",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &PacketContext{}
			c.FromPacketComments(tt.args.comments)
			if got := *c; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromPacketComments(%v), got %v, want %v", tt.args.comments, got, tt.want)
			}
		})
	}
}
