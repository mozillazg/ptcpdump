package utils

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestUnwrapErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{
			name: "no wrapping",
			err:  errors.New("error"),
			want: errors.New("error"),
		},
		{
			name: "single wrapping",
			err:  fmt.Errorf("wrapped: %w", errors.New("error")),
			want: errors.New("error"),
		},
		{
			name: "multiple wrapping",
			err:  fmt.Errorf("wrapped: %w", fmt.Errorf("wrapped again: %w", errors.New("error"))),
			want: errors.New("error"),
		},
		{
			name: "nil error",
			err:  nil,
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := UnwrapErr(tt.err)
			if tt.want == nil {
				if got != nil {
					t.Errorf("UnwrapErr() = %v, want %v", got, tt.want)
				}
			} else {
				if got.Error() != tt.want.Error() {
					t.Errorf("UnwrapErr() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestRunClosers(t *testing.T) {
	var closed []int
	closer := func(i int) func() {
		return func() {
			closed = append(closed, i)
		}
	}

	tests := []struct {
		name  string
		funcs []func()
		want  []int
	}{
		{
			name:  "no closers",
			funcs: nil,
			want:  nil,
		},
		{
			name:  "single closer",
			funcs: []func(){closer(1)},
			want:  []int{1},
		},
		{
			name:  "multiple closers",
			funcs: []func(){closer(1), closer(2), closer(3)},
			want:  []int{3, 2, 1},
		},
		{
			name:  "nil closer in list",
			funcs: []func(){closer(1), nil, closer(2)},
			want:  []int{2, 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			closed = nil
			RunClosers(tt.funcs)
			if !reflect.DeepEqual(closed, tt.want) {
				t.Errorf("RunClosers() closed = %v, want %v", closed, tt.want)
			}
		})
	}
}
