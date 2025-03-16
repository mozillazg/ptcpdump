package utils

import (
	"bytes"
	"github.com/mozillazg/ptcpdump/internal/types"
	"io"
	"testing"
)

func TestDetectPcapDataType(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    types.PcapDataType
		wantErr bool
	}{
		{
			name:    "valid pcap microsecond",
			data:    []byte{0xd4, 0xc3, 0xb2, 0xa1},
			want:    types.PcapDataTypePcap,
			wantErr: false,
		},
		{
			name:    "valid pcap nanosecond",
			data:    []byte{0x4d, 0x3c, 0xb2, 0xa1},
			want:    types.PcapDataTypePcap,
			wantErr: false,
		},
		{
			name:    "valid pcapng",
			data:    []byte{0x0a, 0x0d, 0x0d, 0x0a},
			want:    types.PcapDataTypePcapNg,
			wantErr: false,
		},
		{
			name:    "invalid magic number",
			data:    []byte{0x00, 0x00, 0x00, 0x00},
			want:    "",
			wantErr: false,
		},
		{
			name:    "error reading data",
			data:    nil,
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := types.NewReadBuffer(io.NopCloser(bytes.NewBuffer(tt.data)))
			got, err := DetectPcapDataType(r)
			if (err != nil) != tt.wantErr {
				t.Errorf("DetectPcapDataType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("DetectPcapDataType() = %v, want %v", got, tt.want)
			}
		})
	}
}
