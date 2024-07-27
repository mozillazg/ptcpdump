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
			name: "test",
			args: args{
				comments: []string{},
			},
			want: PacketContext{
				Process: Process{
					Parent: ProcessBase{
						Pid:           0,
						Cmd:           "",
						CmdTruncated:  false,
						Args:          nil,
						ArgsTruncated: false,
					},
					ProcessBase: ProcessBase{
						Pid:           0,
						Cmd:           "",
						CmdTruncated:  false,
						Args:          nil,
						ArgsTruncated: false,
					},
				},
				Container: Container{
					Id:          "",
					Name:        "",
					Labels:      nil,
					Image:       "",
					ImageDigest: "",
				},
				Pod: Pod{
					Name:        "",
					Namespace:   "",
					Uid:         "",
					Labels:      nil,
					Annotations: nil,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &PacketContext{}
			c.FromPacketComments(tt.args.comments)
			if got := *c; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromPacketComments(%v), got%v, want %v", tt.args.comments, got, tt.want)
			}
		})
	}
}
