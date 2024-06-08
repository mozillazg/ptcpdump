package docker

import "testing"

func Test_getDockerContainerId(t *testing.T) {
	type args struct {
		id string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "match",
			args: args{
				id: "docker-40fad6778feaab1bd6ed7bfa0d43a2d5338267204f30cd8203e4d06de871c577.scope",
			},
			want: "40fad6778feaab1bd6ed7bfa0d43a2d5338267204f30cd8203e4d06de871c577",
		},
		{
			name: "not match",
			args: args{
				id: "foobar",
			},
			want: "foobar",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getDockerContainerId(tt.args.id); got != tt.want {
				t.Errorf("getDockerContainerId() = %v, want %v", got, tt.want)
			}
		})
	}
}
