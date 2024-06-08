package utils

import "testing"

func Test_getNamespaceId(t *testing.T) {
	type args struct {
		raw string
	}
	tests := []struct {
		name string
		args args
		want int64
	}{
		{
			name: "success",
			args: args{
				raw: "mnt:[4026531841]",
			},
			want: 4026531841,
		},
		{
			name: "fail",
			args: args{
				raw: "xxx",
			},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getNamespaceId(tt.args.raw); got != tt.want {
				t.Errorf("getNamespaceId() = %v, want %v", got, tt.want)
			}
		})
	}
}
