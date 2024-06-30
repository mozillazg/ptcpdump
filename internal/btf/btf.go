package btf

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/cilium/ebpf/btf"
	"github.com/mholt/archiver/v4"
	"github.com/mozillazg/ptcpdump/internal/host"
	"github.com/mozillazg/ptcpdump/internal/log"
)

const (
	candidatePath = "/var/lib/ptcpdump/btf/vmlinux"

	// https://github.com/aquasecurity/btfhub-archive/raw/main/centos/7/x86_64/4.19.113-300.el7.x86_64.btf.tar.xz
	btfHubURL = "https://github.com/aquasecurity/btfhub-archive/raw/main/%s/%s/%s/%s.%s.btf.tar.xz"

	// https://mirrors.openanolis.cn/coolbpf/btf/x86_64/vmlinux-4.19.91-21.al7.x86_64
	openanolisURL = "https://mirrors.openanolis.cn/coolbpf/btf/%s/vmlinux-%s.%s"
)

const (
	MirrorBTFHub = iota
	MirrorOpenanolis
)

func GetBTFSpec(path string) (*btf.Spec, error) {
	if path != "" {
		spec, err := btf.LoadSpec(path)
		if err == nil {
			log.Debugf("use btf from %s", path)
			return spec, nil
		}
		return nil, fmt.Errorf("load btf from %s: %w", path, err)
	}

	spec, err := btf.LoadKernelSpec()
	if err == nil {
		log.Debug("use btf from default location")
		return spec, nil
	}

	spec, err = loadSpecFromCandidateLocations()
	if err == nil {
		return spec, nil
	}

	spec, err = loadSpecFromRemote()
	if err != nil {
		return nil, err
	}
	return spec, nil
}

func loadSpecFromRemote() (*btf.Spec, error) {
	kernelVersion, err := host.GetKernelVersion()
	if err != nil {
		return nil, fmt.Errorf("get kernel version: %w", err)
	}
	release, err := host.GetRelease()
	if err != nil {
		return nil, fmt.Errorf("get os release: %w", err)
	}
	saveDir := filepath.Dir(candidatePath)
	if err := os.MkdirAll(saveDir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", saveDir, err)
	}

	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}

	spec, err := loadSpecFromOpenanolis(arch, *release, kernelVersion, saveDir)
	if err != nil {
		log.Debugf("load BTF specs from Openanolis: %s", err)
	}
	if spec != nil {
		return spec, nil
	}

	spec, err = loadSpecFromBTFHub(arch, *release, kernelVersion, saveDir)
	if err != nil {
		log.Debugf("load BTF specs from BTFHub: %s", err)
	}
	return spec, err
}

func loadSpecFromBTFHub(arch string, release host.Release, kernelVersion, saveDir string) (*btf.Spec, error) {
	path := filepath.Join(saveDir, fmt.Sprintf("%s.%s.btf", kernelVersion, arch))
	if exist, err := fileExist(path); err != nil {
		return nil, err
	} else if exist {
		return btf.LoadSpec(path)
	}

	downloadUrl := fmt.Sprintf(btfHubURL, release.Id, release.VersionId, arch, kernelVersion, arch)
	resp, err := httpGet(context.TODO(), downloadUrl)
	if err != nil {
		return nil, fmt.Errorf("download BTF specs from %s: %w", downloadUrl, err)
	}
	defer resp.Body.Close()

	xz := archiver.Xz{}
	r, err := xz.OpenReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("download BTF specs from %s: %w", downloadUrl, err)
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("download BTF specs from %s: %w", downloadUrl, err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return nil, fmt.Errorf("save data to %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return nil, fmt.Errorf("rename %s to %s: %w", tmpPath, path, err)
	}

	return btf.LoadSpec(path)
}

func loadSpecFromOpenanolis(arch string, _ host.Release, kernelVersion, saveDir string) (*btf.Spec, error) {
	if arch == "arm64" {
		arch = "aarch64"
	}
	path := filepath.Join(saveDir, fmt.Sprintf("vmlinux-%s.%s ", kernelVersion, arch))
	if exist, err := fileExist(path); err != nil {
		return nil, err
	} else if exist {
		return btf.LoadSpec(path)
	}

	downloadUrl := fmt.Sprintf(openanolisURL, arch, kernelVersion, arch)
	resp, err := httpGet(context.TODO(), downloadUrl)
	if err != nil {
		return nil, fmt.Errorf("download BTF specs from %s: %w", downloadUrl, err)
	}
	defer resp.Body.Close()

	tmpPath := path + ".tmp"
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("download BTF specs from %s: %w", downloadUrl, err)
	}
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return nil, fmt.Errorf("save data to %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return nil, fmt.Errorf("rename %s to %s: %w", tmpPath, path, err)
	}

	return btf.LoadSpec(path)
}

func httpGet(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	return resp, err
}

func fileExist(path string) (bool, error) {
	_, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return false, fmt.Errorf("stat file %s: %w", path, err)
		}
		return false, nil
	}
	return true, nil
}

func loadSpecFromCandidateLocations() (*btf.Spec, error) {
	path := candidatePath
	spec, err := btf.LoadSpec(path)
	if err == nil {
		log.Debugf("use btf from %s", path)
		return spec, nil
	}
	log.Debugf("load btf from %s failed: %s", path, err)

	kernelVersion, err := host.GetKernelVersion()
	if err != nil {
		return nil, fmt.Errorf("get kernel version: %w", err)
	}
	path = fmt.Sprintf("%s-%s", candidatePath, kernelVersion)
	spec, err = btf.LoadSpec(path)
	if err == nil {
		log.Debugf("use btf from %s", path)
		return spec, nil
	}
	log.Debugf("load btf from %s failed: %s", path, err)

	return nil, err
}
