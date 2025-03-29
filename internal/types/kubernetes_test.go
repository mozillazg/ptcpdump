package types

import (
	"reflect"
	"testing"
)

func TestLoadFromContainerWithEmptyLabels(t *testing.T) {
	c := Container{Labels: map[string]string{}}
	p := Pod{}
	p.LoadFromContainer(c)
	if p.Name != "" || p.Namespace != "" || p.Uid != "" {
		t.Errorf("LoadFromContainer() with empty labels = %v, %v, %v; want empty strings", p.Name, p.Namespace, p.Uid)
	}
}

func TestLoadFromContainerWithValidLabels(t *testing.T) {
	c := Container{Labels: map[string]string{
		ContainerLabelKeyPodName:      "test-pod",
		ContainerLabelKeyPodNamespace: "test-ns",
		ContainerLabelKeyPodUid:       "123",
	}}
	p := Pod{}
	p.LoadFromContainer(c)
	if p.Name != "test-pod" || p.Namespace != "test-ns" || p.Uid != "123" {
		t.Errorf("LoadFromContainer() = %v, %v, %v; want test-pod, test-ns, 123", p.Name, p.Namespace, p.Uid)
	}
}

func TestFormatLabelsWithEmptyLabels(t *testing.T) {
	p := Pod{Labels: map[string]string{}}
	got := p.FormatLabels()
	want := "{}"
	if got != want {
		t.Errorf("FormatLabels() = %v, want %v", got, want)
	}
}

func TestFormatLabelsWithNonEmptyLabels(t *testing.T) {
	p := Pod{Labels: map[string]string{"key": "value"}}
	got := p.FormatLabels()
	want := `{"key":"value"}`
	if got != want {
		t.Errorf("FormatLabels() = %v, want %v", got, want)
	}
}

func TestParsePodLabelsWithEmptyString(t *testing.T) {
	s := ""
	got := ParsePodLabels(s)
	want := map[string]string{}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParsePodLabels() = %v, want %v", got, want)
	}
}

func TestParsePodLabelsWithValidJsonString(t *testing.T) {
	s := `{"key":"value"}`
	got := ParsePodLabels(s)
	want := map[string]string{"key": "value"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParsePodLabels() = %v, want %v", got, want)
	}
}

func TestFormatAnnotationsWithEmptyAnnotations(t *testing.T) {
	p := Pod{Annotations: map[string]string{}}
	got := p.FormatAnnotations()
	want := "{}"
	if got != want {
		t.Errorf("FormatAnnotations() = %v, want %v", got, want)
	}
}

func TestFormatAnnotationsWithNonEmptyAnnotations(t *testing.T) {
	p := Pod{Annotations: map[string]string{"key": "value"}}
	got := p.FormatAnnotations()
	want := `{"key":"value"}`
	if got != want {
		t.Errorf("FormatAnnotations() = %v, want %v", got, want)
	}
}

func TestParsePodAnnotationsWithEmptyString(t *testing.T) {
	s := ""
	got := ParsePodAnnotations(s)
	want := map[string]string{}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParsePodAnnotations() = %v, want %v", got, want)
	}
}

func TestParsePodAnnotationsWithValidJsonString(t *testing.T) {
	s := `{"key":"value"}`
	got := ParsePodAnnotations(s)
	want := map[string]string{"key": "value"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParsePodAnnotations() = %v, want %v", got, want)
	}
}
