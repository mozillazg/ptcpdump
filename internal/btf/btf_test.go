package btf

import (
	"context"
	"io"
	"net/http"
	"path"
	"strings"
	"testing"

	ebpfbtf "github.com/cilium/ebpf/btf"
	"github.com/mozillazg/ptcpdump/internal/host"
	"github.com/stretchr/testify/assert"
)

func Test_loadSpecFromBTFHub(t *testing.T) {
	saveDir := t.TempDir()
	dummySpec := &ebpfbtf.Spec{}

	origHTTPGet := httpGetFunc
	origDecompress := decompressXzReaderFunc
	origLoadSpec := loadSpecFunc
	httpGetFunc = func(ctx context.Context, url string) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("stub")),
		}, nil
	}
	decompressXzReaderFunc = func(src io.Reader) ([]byte, error) {
		return []byte("stub"), nil
	}
	loadSpecFunc = func(p string) (*ebpfbtf.Spec, string, error) {
		return dummySpec, p, nil
	}
	t.Cleanup(func() {
		httpGetFunc = origHTTPGet
		decompressXzReaderFunc = origDecompress
		loadSpecFunc = origLoadSpec
	})

	type args struct {
		arch          string
		release       host.Release
		kernelVersion string
	}
	tests := []struct {
		name     string
		args     args
		wantFile string
	}{
		{
			name: "x86_64",
			args: args{
				arch: "x86_64",
				release: host.Release{
					Id:        "centos",
					VersionId: "8",
				},
				kernelVersion: "4.18.0-147.8.1.el8_1.x86_64",
			},
			wantFile: path.Join(saveDir, "4.18.0-147.8.1.el8_1.x86_64.btf"),
		},
		{
			name: "arm64",
			args: args{
				arch: "arm64",
				release: host.Release{
					Id:        "centos",
					VersionId: "8",
				},
				kernelVersion: "4.18.0-147.8.1.el8_1.aarch64",
			},
			wantFile: path.Join(saveDir, "4.18.0-147.8.1.el8_1.aarch64.btf"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, p, err := loadSpecFromBTFHub(tt.args.arch, tt.args.release, tt.args.kernelVersion, saveDir)
			assert.NoError(t, err)
			assert.NotNil(t, spec)
			assert.Equal(t, tt.wantFile, p)
			assert.FileExists(t, tt.wantFile)
		})
	}
}

func Test_loadSpecFromOpenanolis(t *testing.T) {
	saveDir := t.TempDir()
	dummySpec := &ebpfbtf.Spec{}

	origHTTPGet := httpGetFunc
	origLoadSpec := loadSpecFunc
	httpGetFunc = func(ctx context.Context, url string) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("stub")),
		}, nil
	}
	loadSpecFunc = func(p string) (*ebpfbtf.Spec, string, error) {
		return dummySpec, p, nil
	}
	t.Cleanup(func() {
		httpGetFunc = origHTTPGet
		loadSpecFunc = origLoadSpec
	})

	type args struct {
		arch          string
		release       host.Release
		kernelVersion string
	}
	tests := []struct {
		name     string
		args     args
		wantFile string
	}{
		{
			name: "x86_64",
			args: args{
				arch: "x86_64",
				release: host.Release{
					Id:        "centos",
					VersionId: "8",
				},
				kernelVersion: "4.18.0-147.8.1.el8_1.x86_64",
			},
			wantFile: path.Join(saveDir, "vmlinux-4.18.0-147.8.1.el8_1.x86_64"),
		},
		{
			name: "arm64",
			args: args{
				arch: "arm64",
				release: host.Release{
					Id:        "centos",
					VersionId: "8",
				},
				kernelVersion: "4.18.0-147.8.1.el8_1.aarch64",
			},
			wantFile: path.Join(saveDir, "vmlinux-4.18.0-147.8.1.el8_1.aarch64"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, p, err := loadSpecFromOpenanolis(tt.args.arch, tt.args.release, tt.args.kernelVersion, saveDir)
			assert.NoError(t, err)
			assert.NotNil(t, spec)
			assert.Equal(t, tt.wantFile, p)
			assert.FileExists(t, tt.wantFile)
		})
	}
}
