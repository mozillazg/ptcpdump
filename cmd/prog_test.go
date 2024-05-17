package cmd

import (
	"reflect"
	"testing"
)

func Test_getProgArgs(t *testing.T) {
	type args struct {
		rawArgs []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "normal",
			args: args{
				rawArgs: []string{"--foo", "bar", "--", "/foo", "--foobar", "test"},
			},
			want: []string{"/foo", "--foobar", "test"},
		},
		{
			name: "normal",
			args: args{
				rawArgs: []string{"--foo", "bar", "--", "/foo", "--foobar", "test"},
			},
			want: []string{"/foo", "--foobar", "test"},
		},
		{
			name: "no ---",
			args: args{
				rawArgs: []string{"--foo", "bar", "/foo", "--foobar", "test"},
			},
			want: nil,
		},
		{
			name: "no sub program",
			args: args{
				rawArgs: []string{"--foo", "bar", "--"},
			},
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getSubProgArgs(tt.args.rawArgs); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getSubProgArgs() = %v, want %v", got, tt.want)
			}
		})
	}
}
