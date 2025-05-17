package event

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"testing"
)

func Test_noL2Data(t *testing.T) {
	type args struct {
		payload []byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "payload less than 14 bytes",
			args: args{payload: []byte{0x01, 0x02, 0x03}},
			want: true,
		},
		{
			name: "ipv4",
			args: args{payload: []byte{
				69, 0, 0, 40, 48, 213, 0, 0, 127, 6, 92, 229, 1, 1, 1, 1, 172, 17, 0, 3,
				0, 80, 156, 28, 73, 124, 126, 149, 187, 87, 75, 201, 80, 25, 250, 239, 155, 38, 0, 0,
			}},
			want: true,
		},
		{
			name: "valid ethernet frame",
			args: args{payload: func() []byte {
				eth := &layers.Ethernet{
					SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
					DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
					EthernetType: layers.EthernetTypeIPv4,
				}
				buf := gopacket.NewSerializeBuffer()
				_ = eth.SerializeTo(buf, gopacket.SerializeOptions{})
				return buf.Bytes()
			}(),
			},
			want: false,
		},
		{
			name: "14 bytes but not ethernet",
			args: args{payload: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}},
			want: true,
		},
		{
			name: "empty payload",
			args: args{payload: []byte{}},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := noL2Data(tt.args.payload); got != tt.want {
				t.Errorf("noL2Data() = %v, want %v", got, tt.want)
			}
		})
	}
}
