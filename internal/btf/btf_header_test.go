package btf

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	ebpfbtf "github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
)

const (
	btfMagic          = 0xeb9f
	btfHeaderLen      = 24
	btfLayoutFieldLen = 8
)

// buildBTFSpec builds a minimal BTF blob which contains only one "int" type.
//
// hdrExtra is appended to the fixed 24 bytes header, it's used to simulate
// the extra header fields (layout_off/layout_len) added by kernel 7.1+.
// layout is the raw layout section at the end of the blob.
func buildBTFSpec(t *testing.T, hdrExtra []byte, layout []byte) []byte {
	t.Helper()

	typ := make([]byte, 12)
	binary.LittleEndian.PutUint32(typ[0:], 1)     // name_off: "int"
	binary.LittleEndian.PutUint32(typ[4:], 1<<24) // info: BTF_KIND_INT
	binary.LittleEndian.PutUint32(typ[8:], 4)     // size: 4
	types := append(typ, 0, 0, 0, 0)              // int encoding
	strs := []byte("\x00int\x00")

	header := make([]byte, btfHeaderLen)
	binary.LittleEndian.PutUint16(header[0:], btfMagic)
	header[2] = 1 // version
	header[3] = 0 // flags
	binary.LittleEndian.PutUint32(header[4:], uint32(btfHeaderLen+len(hdrExtra)))
	binary.LittleEndian.PutUint32(header[8:], 0)                   // type_off
	binary.LittleEndian.PutUint32(header[12:], uint32(len(types))) // type_len
	binary.LittleEndian.PutUint32(header[16:], uint32(len(types))) // str_off
	binary.LittleEndian.PutUint32(header[20:], uint32(len(strs)))  // str_len

	data := append(header, hdrExtra...)
	data = append(data, types...)
	data = append(data, strs...)
	data = append(data, layout...)

	return data
}

func TestLoadSpecBTFHeader(t *testing.T) {
	// layout_off/layout_len added by kernel 7.1+, they are relative to the
	// end of the header: len(types) + len(strs) = 16 + 5.
	layoutOff := uint32(16 + 5)
	layoutFields := make([]byte, btfLayoutFieldLen)
	binary.LittleEndian.PutUint32(layoutFields[0:], layoutOff)
	binary.LittleEndian.PutUint32(layoutFields[4:], 8)
	layout := []byte{1, 0, 0, 0, 1, 0, 0, 0}

	tests := []struct {
		name     string
		hdrExtra []byte
		layout   []byte
		wantErr  bool
	}{
		{
			name: "legacy header without layout fields",
		},
		{
			name:     "header with layout fields",
			hdrExtra: layoutFields,
			layout:   layout,
		},
		{
			name:     "header with non-zero trailer",
			hdrExtra: append(append([]byte{}, layoutFields...), 1, 2, 3, 4, 5, 6, 7, 8),
			layout:   layout,
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vmlinux.btf")
			if err := os.WriteFile(path, buildBTFSpec(t, tt.hdrExtra, tt.layout), 0644); err != nil {
				t.Fatal(err)
			}

			spec, _, err := loadSpec(path)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			if !assert.NoError(t, err) {
				return
			}

			typ, err := spec.TypeByID(1)
			if !assert.NoError(t, err) {
				return
			}
			i, ok := typ.(*ebpfbtf.Int)
			assert.True(t, ok)
			if ok {
				assert.Equal(t, "int", i.Name)
			}
		})
	}
}
