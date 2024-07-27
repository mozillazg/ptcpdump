package utils

import (
	"reflect"
	"testing"
)

func TestGetUniqInts(t *testing.T) {
	type args struct {
		items []int
	}
	tests := []struct {
		name string
		args args
		want []int
	}{
		{
			name: "nil",
			args: args{
				items: nil,
			},
			want: nil,
		},
		{
			name: "empty",
			args: args{
				items: []int{},
			},
			want: nil,
		},
		{
			name: "remove dup",
			args: args{
				items: []int{1, 2, 3, 2, 5, 3, 1},
			},
			want: []int{1, 2, 3, 5},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetUniqInts(tt.args.items); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetUniqInts() = %v, want %v", got, tt.want)
			}
		})
	}
}
