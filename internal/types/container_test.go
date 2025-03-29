package types

import (
	"reflect"
	"testing"
)

func TestIsNullContainer(t *testing.T) {
	tests := []struct {
		name string
		c    *Container
		want bool
	}{
		{
			name: "nil container",
			c:    nil,
			want: true,
		},
		{
			name: "empty container",
			c:    &Container{},
			want: true,
		},
		{
			name: "non-empty container",
			c:    &Container{Id: "123"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.IsNull(); got != tt.want {
				t.Errorf("IsNull() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTidyNameContainer(t *testing.T) {
	tests := []struct {
		name string
		c    Container
		want string
	}{
		{
			name: "name with leading slash",
			c:    Container{Name: "/container"},
			want: "container",
		},
		{
			name: "name without leading slash",
			c:    Container{Name: "container"},
			want: "container",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.TidyName(); got != tt.want {
				t.Errorf("TidyName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatLabelsContainer(t *testing.T) {
	tests := []struct {
		name string
		c    Container
		want string
	}{
		{
			name: "empty labels",
			c:    Container{Labels: map[string]string{}},
			want: "{}",
		},
		{
			name: "non-empty labels",
			c:    Container{Labels: map[string]string{"key": "value"}},
			want: `{"key":"value"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.FormatLabels(); got != tt.want {
				t.Errorf("FormatLabels() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsSandboxContainer(t *testing.T) {
	tests := []struct {
		name string
		c    Container
		want bool
	}{
		{
			name: "empty labels",
			c:    Container{Labels: map[string]string{}},
			want: false,
		},
		{
			name: "sandbox label with cri-containerd",
			c:    Container{Labels: map[string]string{"io.cri-containerd.kind": "sandbox"}},
			want: true,
		},
		{
			name: "sandbox label with kubernetes docker type",
			c:    Container{Labels: map[string]string{"io.kubernetes.docker.type": "sandbox"}},
			want: true,
		},
		{
			name: "sandbox label with kubernetes podsandbox",
			c:    Container{Labels: map[string]string{"io.kubernetes.docker.type": "podsandbox"}},
			want: true,
		},
		{
			name: "multiple labels with sandbox",
			c: Container{Labels: map[string]string{
				"io.kubernetes.docker.type": "sandbox",
				"other":                     "value",
			}},
			want: true,
		},
		{
			name: "wrong value for sandbox label",
			c:    Container{Labels: map[string]string{"io.cri-containerd.kind": "container"}},
			want: false,
		},
		{
			name: "non-sandbox labels",
			c:    Container{Labels: map[string]string{"key": "value"}},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.IsSandbox(); got != tt.want {
				t.Errorf("IsSandbox() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPodContainer(t *testing.T) {
	tests := []struct {
		name string
		c    Container
		want Pod
	}{
		{
			name: "cached pod",
			c:    Container{p: Pod{Name: "test-pod"}},
			want: Pod{Name: "test-pod"},
		},
		{
			name: "pod from container labels",
			c: Container{Labels: map[string]string{
				"io.kubernetes.pod.name":      "test-pod",
				"io.kubernetes.pod.namespace": "test-ns",
				"io.kubernetes.pod.uid":       "123",
			}},
			want: Pod{
				Name:      "test-pod",
				Namespace: "test-ns",
				Uid:       "123",
			},
		},
		{
			name: "empty container",
			c:    Container{},
			want: Pod{},
		},
		{
			name: "partial pod labels",
			c: Container{Labels: map[string]string{
				"io.kubernetes.pod.name": "test-pod",
			}},
			want: Pod{
				Name: "test-pod",
			},
		},
		{
			name: "pod with irrelevant labels",
			c: Container{Labels: map[string]string{
				"some.label": "value",
			}},
			want: Pod{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.Pod(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Pod() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEmptyNSContainer(t *testing.T) {
	tests := []struct {
		name string
		c    Container
		want bool
	}{
		{
			name: "all namespaces empty",
			c:    Container{},
			want: true,
		},
		{
			name: "non-empty pid namespace",
			c:    Container{PidNamespace: 1},
			want: false,
		},
		{
			name: "non-empty mount namespace",
			c:    Container{MountNamespace: 1},
			want: false,
		},
		{
			name: "non-empty network namespace",
			c:    Container{NetworkNamespace: 1},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.EmptyNS(); got != tt.want {
				t.Errorf("EmptyNS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseContainerLabels(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want map[string]string
	}{
		{
			name: "empty string",
			s:    "",
			want: map[string]string{},
		},
		{
			name: "valid json string",
			s:    `{"key":"value"}`,
			want: map[string]string{"key": "value"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseContainerLabels(tt.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseContainerLabels() = %v, want %v", got, tt.want)
			}
		})
	}
}
