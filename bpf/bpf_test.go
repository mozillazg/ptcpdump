package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
)

// Test htons converts host order to network (big endian) correctly.
func Test_htons(t *testing.T) {
	tests := []struct {
		name string
		in   uint16
		want uint16
	}{
		{name: "zero", in: 0x0000, want: 0x0000},
		{name: "identity for symmetric", in: 0x0101, want: 0x0101},
		{name: "swap bytes", in: 0x1234, want: 0x3412},
		{name: "max", in: 0xFFFF, want: 0xFFFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := htons(tt.in); got != tt.want {
				t.Fatalf("htons(%#04x) = %#04x, want %#04x", tt.in, got, tt.want)
			}
		})
	}
}

// Test Options builder helpers mutate the receiver as expected.
func TestOptionsBuilders(t *testing.T) {
	var opts Options

	opts.WithPids([]uint{0, 1, 2})
	if got, want := len(opts.pids), 2; got != want {
		t.Fatalf("WithPids len(pids) = %d, want %d", got, want)
	}
	if opts.haveFilter != 1 {
		t.Fatalf("WithPids: haveFilter = %d, want 1", opts.haveFilter)
	}

	opts.WithUids([]uint{1000, 1001})
	if got, want := len(opts.uids), 2; got != want {
		t.Fatalf("WithUids len(uids) = %d, want %d", got, want)
	}

	opts.WithComm("cmd")
	if opts.filterComm != 1 {
		t.Fatalf("WithComm: filterComm = %d, want 1", opts.filterComm)
	}
	if opts.comm[0] != 'c' || opts.comm[1] != 'm' || opts.comm[2] != 'd' {
		t.Fatalf("WithComm: unexpected comm contents: %v", opts.comm)
	}

	opts.WithFollowFork(true)
	if !opts.attachForks() {
		t.Fatalf("WithFollowFork(true): attachForks() = false, want true")
	}
	opts.WithFollowFork(false)
	if opts.attachForks() {
		t.Fatalf("WithFollowFork(false): attachForks() = true, want false")
	}

	opts.WithPidNsIds([]uint32{0, 10})
	if got, want := len(opts.pidnsIds), 1; got != want {
		t.Fatalf("WithPidNsIds len(pidnsIds) = %d, want %d", got, want)
	}

	opts.WithMntNsIds([]uint32{0, 20})
	if got, want := len(opts.mntnsIds), 1; got != want {
		t.Fatalf("WithMntNsIds len(mntnsIds) = %d, want %d", got, want)
	}

	opts.WithNetNsIds([]uint32{0, 30})
	if got, want := len(opts.netnsIds), 1; got != want {
		t.Fatalf("WithNetNsIds len(netnsIds) = %d, want %d", got, want)
	}

	opts.WithIfindexes([]uint32{0, 5})
	if got, want := len(opts.ifindexes), 1; got != want {
		t.Fatalf("WithIfindexes len(ifindexes) = %d, want %d", got, want)
	}

	opts.WithPcapFilter("  tcp port 80  ")
	if opts.pcapFilter != "tcp port 80" {
		t.Fatalf("WithPcapFilter: pcapFilter = %q, want %q", opts.pcapFilter, "tcp port 80")
	}

	opts.WithMaxPayloadSize(4096)
	if opts.maxPayloadSize != 4096 {
		t.Fatalf("WithMaxPayloadSize: maxPayloadSize = %d, want 4096", opts.maxPayloadSize)
	}

	opts.WithDisableReverseMatch(true)
	if !opts.disableReverseMatch {
		t.Fatalf("WithDisableReverseMatch: disableReverseMatch = false, want true")
	}

	opts.WithHookMount(true)
	if !opts.hookMount {
		t.Fatalf("WithHookMount: hookMount = false, want true")
	}

	opts.WithHookNetDev(true)
	if !opts.hookNetDev {
		t.Fatalf("WithHookNetDev: hookNetDev = false, want true")
	}
}

// Helper that writes any value as little-endian bytes.
func writeLE(t *testing.T, v interface{}) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, v); err != nil {
		t.Fatalf("binary.Write failed: %v", err)
	}
	return buf.Bytes()
}

func Test_parsePacketEvent_OK(t *testing.T) {
	var base BpfPacketEventT
	base.Meta.PayloadLen = 4
	base.Meta.PacketSize = 4
	base.Meta.Ifindex = 2

	raw := writeLE(t, &base)
	payload := []byte{1, 2, 3, 4}
	raw = append(raw, payload...)

	got, err := parsePacketEvent(raw)
	if err != nil {
		t.Fatalf("parsePacketEvent returned error: %v", err)
	}
	if got.Meta.Ifindex != base.Meta.Ifindex {
		t.Fatalf("Ifindex = %d, want %d", got.Meta.Ifindex, base.Meta.Ifindex)
	}
	if got.Meta.PayloadLen != base.Meta.PayloadLen {
		t.Fatalf("PayloadLen = %d, want %d", got.Meta.PayloadLen, base.Meta.PayloadLen)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Fatalf("Payload = %v, want %v", got.Payload, payload)
	}
}

func Test_parsePacketEvent_Truncated(t *testing.T) {
	// Too few bytes to decode should result in an error.
	_, err := parsePacketEvent([]byte{0x01})
	if err == nil {
		t.Fatalf("parsePacketEvent on truncated buffer returned nil error")
	}
}

func Test_parseExecEvent_OK(t *testing.T) {
	var in BpfExecEventT
	in.Meta.Pid = 1234
	in.Meta.Uid = 1000
	in.ArgsSize = 42

	raw := writeLE(t, &in)
	got, err := parseExecEvent(raw)
	if err != nil {
		t.Fatalf("parseExecEvent returned error: %v", err)
	}
	if got.Meta.Pid != in.Meta.Pid || got.Meta.Uid != in.Meta.Uid || got.ArgsSize != in.ArgsSize {
		t.Fatalf("parseExecEvent returned %+v, want %+v", got, in)
	}
}

func Test_parseExitEvent_OK(t *testing.T) {
	in := BpfExitEventT{Pid: 4321}
	raw := writeLE(t, &in)

	got, err := parseExitEvent(raw)
	if err != nil {
		t.Fatalf("parseExitEvent returned error: %v", err)
	}
	if got.Pid != in.Pid {
		t.Fatalf("Pid = %d, want %d", got.Pid, in.Pid)
	}
}

func Test_parseNewNetDeviceEvent_OK(t *testing.T) {
	in := BpfNewNetdeviceEventT{
		Dev: BpfNetdeviceT{
			NetnsId: 10,
			Ifindex: 5,
		},
	}
	raw := writeLE(t, &in)

	got, err := parseNewNetDeviceEvent(raw)
	if err != nil {
		t.Fatalf("parseNewNetDeviceEvent returned error: %v", err)
	}
	if got.Dev.NetnsId != in.Dev.NetnsId || got.Dev.Ifindex != in.Dev.Ifindex {
		t.Fatalf("parseNewNetDeviceEvent returned %+v, want %+v", got, in)
	}
}

func Test_parseNetDeviceChangeEvent_OK(t *testing.T) {
	in := BpfNetdeviceChangeEventT{
		OldDevice: BpfNetdeviceT{NetnsId: 1, Ifindex: 2},
		NewDevice: BpfNetdeviceT{NetnsId: 3, Ifindex: 4},
	}
	raw := writeLE(t, &in)

	got, err := parseNetDeviceChangeEvent(raw)
	if err != nil {
		t.Fatalf("parseNetDeviceChangeEvent returned error: %v", err)
	}
	if got.OldDevice.Ifindex != in.OldDevice.Ifindex || got.NewDevice.Ifindex != in.NewDevice.Ifindex {
		t.Fatalf("parseNetDeviceChangeEvent returned %+v, want %+v", got, in)
	}
}

func Test_parseMountEvent_OK(t *testing.T) {
	var in BpfMountEventT
	in.Fs[0] = 'x'
	raw := writeLE(t, &in)

	got, err := parseMountEvent(raw)
	if err != nil {
		t.Fatalf("parseMountEvent returned error: %v", err)
	}
	if got.Fs[0] != in.Fs[0] {
		t.Fatalf("Fs[0] = %q, want %q", got.Fs[0], in.Fs[0])
	}
}

func Test_parseGoKeyLogEvent_OK(t *testing.T) {
	var in BpfGoKeylogEventT
	in.LabelLen = 4
	raw := writeLE(t, &in)

	got, err := parseGoKeyLogEvent(raw)
	if err != nil {
		t.Fatalf("parseGoKeyLogEvent returned error: %v", err)
	}
	if got.LabelLen != in.LabelLen {
		t.Fatalf("LabelLen = %d, want %d", got.LabelLen, in.LabelLen)
	}
}

func Test_isCanIgnoreEventErr(t *testing.T) {
	if isCanIgnoreEventErr(nil) {
		t.Fatalf("isCanIgnoreEventErr(nil) = true, want false")
	}
	if !isCanIgnoreEventErr(io.EOF) {
		t.Fatalf("isCanIgnoreEventErr(io.EOF) = false, want true")
	}
	if !isCanIgnoreEventErr(io.ErrUnexpectedEOF) {
		t.Fatalf("isCanIgnoreEventErr(io.ErrUnexpectedEOF) = false, want true")
	}

	// Non-ignored error.
	if isCanIgnoreEventErr(errors.New("something else")) {
		t.Fatalf("isCanIgnoreEventErr(non-ignored) = true, want false")
	}
}

func Test_isReaderClosedErr(t *testing.T) {
	if isReaderClosedErr(nil) {
		t.Fatalf("isReaderClosedErr(nil) = true, want false")
	}
	if !isReaderClosedErr(perf.ErrClosed) {
		t.Fatalf("isReaderClosedErr(perf.ErrClosed) = false, want true")
	}
	if !isReaderClosedErr(ringbuf.ErrClosed) {
		t.Fatalf("isReaderClosedErr(ringbuf.ErrClosed) = false, want true")
	}
	if isReaderClosedErr(errors.New("other")) {
		t.Fatalf("isReaderClosedErr(non-closed) = true, want false")
	}
}


