package types

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFlagTypeFileSize_Set(t *testing.T) {
	tests := []struct {
		name    string
		val     string
		want    uint64
		wantErr bool
	}{
		{"valid bytes", "1000", 1000 * 1000000, false},
		{"valid kilobytes", "1k", 1 * 1024, false},
		{"valid kilobytes", "1K", 1 * 1024, false},
		{"valid kilobytes with kb", "1kb", 1 * 1024, false},
		{"valid kilobytes with kb", "1KB", 1 * 1024, false},
		{"valid megabytes", "1m", 1 * 1024 * 1024, false},
		{"valid megabytes", "1M", 1 * 1024 * 1024, false},
		{"valid megabytes with mb", "1mb", 1 * 1024 * 1024, false},
		{"valid megabytes with mb", "1MB", 1 * 1024 * 1024, false},
		{"valid gigabytes", "1g", 1 * 1024 * 1024 * 1024, false},
		{"valid gigabytes", "1G", 1 * 1024 * 1024 * 1024, false},
		{"valid gigabytes with gb", "1gb", 1 * 1024 * 1024 * 1024, false},
		{"valid gigabytes with gb", "1GB", 1 * 1024 * 1024 * 1024, false},
		{"invalid format", "1tb", 0, true},
		{"invalid number", "abc", 0, true},
		{"empty string", "", 0, true},
		{"negative number", "-1k", 0, true},
		{"zero value", "0", 0, false},
		{"whitespace around value", " 1k ", 0, true},
		{"uppercase suffix", "1K", 1 * 1024, false},
		{"error 1", "ak", 0, true},
		{"error 2", "akb", 0, true},
		{"error 3", "am", 0, true},
		{"error 4", "amb", 0, true},
		{"error 5", "ag", 0, true},
		{"error 6", "agb", 0, true},
		{"error 7", "at", 0, true},
		{"error 8", "atb", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &FlagTypeFileSize{}
			err := s.Set(tt.val)
			if (err != nil) != tt.wantErr {
				t.Errorf("Set() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if s.n != tt.want {
				t.Errorf("Set() = %v, want %v", s.n, tt.want)
			}
			if s.Bytes() != int64(tt.want) {
				t.Errorf("Bytes() = %v, want %v", s.Bytes(), tt.want)
			}
			assert.Equal(t, s.Type(), "fileSize")
			assert.Equal(t, s.String(), s.val)
		})
	}
}
