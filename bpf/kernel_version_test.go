package bpf

import (
	"testing"
)

func TestValidateKernelVersion(t *testing.T) {
	// This test will always pass on the current kernel (6.11.0-1018-azure)
	// since it's >= 5.0.0, but it validates that the function works
	err := ValidateKernelVersion()
	if err != nil {
		t.Errorf("ValidateKernelVersion() failed on kernel 6.11+: %v", err)
	}
}

func TestKernelVersionUtils(t *testing.T) {
	// Test kernelVersion function
	version := kernelVersion(5, 0, 0)
	expected := uint32((5 << 16) + (0 << 8) + 0)
	if version != expected {
		t.Errorf("kernelVersion(5, 0, 0) = %d, want %d", version, expected)
	}

	// Test kernelVersionEqOrGreaterThan - should return true for 5.0.0
	// since we're running on 6.11.0
	if !kernelVersionEqOrGreaterThan(5, 0, 0) {
		t.Error("kernelVersionEqOrGreaterThan(5, 0, 0) should return true on kernel 6.11+")
	}

	// Test with a very high version - should return false
	if kernelVersionEqOrGreaterThan(99, 0, 0) {
		t.Error("kernelVersionEqOrGreaterThan(99, 0, 0) should return false")
	}
}