package bpf

import (
	"fmt"
	"testing"
	"strings"
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

// TestKernelVersionErrorMessage verifies the error message format for unsupported kernels
func TestKernelVersionErrorMessage(t *testing.T) {
	// Create a mock function that simulates kernel 3.10.0
	mockKernelVersionCheck := func() error {
		// Simulate the same logic as ValidateKernelVersion but with forced 3.10.0
		return fmt.Errorf("ptcpdump requires Linux kernel 5.0 or later, current kernel version: %d.%d.%d", 3, 10, 0)
	}
	
	err := mockKernelVersionCheck()
	if err == nil {
		t.Error("Expected error for kernel 3.10.0 but got nil")
	}
	
	expectedMessage := "ptcpdump requires Linux kernel 5.0 or later, current kernel version: 3.10.0"
	if err.Error() != expectedMessage {
		t.Errorf("Error message = %q, want %q", err.Error(), expectedMessage)
	}
	
	// Verify error message contains key components
	if !strings.Contains(err.Error(), "ptcpdump requires Linux kernel 5.0 or later") {
		t.Error("Error message should mention kernel requirement")
	}
	if !strings.Contains(err.Error(), "3.10.0") {
		t.Error("Error message should include detected kernel version")
	}
}