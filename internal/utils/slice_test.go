package utils

import (
	"github.com/stretchr/testify/assert"
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

func Test_TidyCliMultipleVals(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			input:    []string{"abc", "abc,efg", "foo"},
			expected: []string{"abc", "efg", "foo"},
		},
		{
			input:    []string{"x,y,z", "x", "y"},
			expected: []string{"x", "y", "z"},
		},
		{
			input:    []string{"a,b", "b,c", "c,a"},
			expected: []string{"a", "b", "c"},
		},
		{
			input:    []string{"a", "b,a", "c", "b"},
			expected: []string{"a", "b", "c"},
		},
		{
			input:    []string{"  a  ", "b, a  ", "c"},
			expected: []string{"a", "b", "c"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TidyCliMultipleVals(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}
