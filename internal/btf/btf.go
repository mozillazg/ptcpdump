package btf

import (
	"context"
	"debug/elf"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/cilium/ebpf/btf"
	"github.com/mozillazg/ptcpdump/internal/host"
	"github.com/mozillazg/ptcpdump/internal/log"
)

const (
	DefaultPath   = "/sys/kernel/btf/vmlinux"
	candidatePath = "/var/lib/ptcpdump/btf/vmlinux"

	// https://github.com/aquasecurity/btfhub-archive/raw/main/centos/7/x86_64/4.19.113-300.el7.x86_64.btf.tar.xz
	btfHubURL = "https://github.com/aquasecurity/btfhub-archive/raw/main/%s/%s/%s/%s.btf.tar.xz"

	// https://mirrors.openanolis.cn/coolbpf/btf/x86_64/vmlinux-4.19.91-21.al7.x86_64
	openAnolisURL = "https://mirrors.openanolis.cn/coolbpf/btf/%s/vmlinux-%s"
)

const (
	MirrorBTFHub = iota
	MirrorOpenAnolis
)

func LoadBTFSpec(path string) (*btf.Spec, string, error) {
	if path != "" {
		spec, path, err := loadSpec(path)
		if err == nil {
			log.Infof("use BTF specs from %s", path)
			return spec, path, nil
		}
		return nil, path, fmt.Errorf("load BTF specs from %s: %w", path, err)
	}

	spec, err := btf.LoadKernelSpec()
	if err == nil {
		log.Info("use BTF specs from default locations")
		return spec, DefaultPath, nil
	}

	spec, path, err = loadSpecFromCandidateLocations()
	if err == nil {
		return spec, path, nil
	}

	log.Warnf("could not load BTF specs from local: %s, try to load from remote", err)
	spec, path, err = loadSpecFromRemote()
	if err != nil {
		log.Warnf("load BTF specs from remote failed: %s", err)
		return nil, path, err
	}
	return spec, path, nil
}

func loadSpecFromRemote() (*btf.Spec, string, error) {
	kernelVersion, err := host.GetKernelVersion()
	if err != nil {
		return nil, "", fmt.Errorf("get kernel version: %w", err)
	}
	release, err := host.GetRelease()
	if err != nil {
		return nil, "", fmt.Errorf("get os release: %w", err)
	}
	saveDir := filepath.Dir(candidatePath)
	if err := os.MkdirAll(saveDir, 0755); err != nil {
		return nil, "", fmt.Errorf("mkdir %s: %w", saveDir, err)
	}

	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}

	spec, path, err := loadSpecFromOpenanolis(arch, *release, kernelVersion, saveDir)
	if err != nil {
		log.Errorf("load BTF specs from OpenAnolis failed: %s", err)
	}
	if spec != nil {
		log.Infof("use BTF specs from %s", path)
		return spec, path, nil
	}

	spec, path, err = loadSpecFromBTFHub(arch, *release, kernelVersion, saveDir)
	if err != nil {
		log.Errorf("load BTF specs from BTFHub failed: %s", err)
	}
	return spec, path, err
}

func loadSpecFromBTFHub(arch string, release host.Release, kernelVersion,
	saveDir string) (*btf.Spec, string, error) {
	log.Info("try to load BTF specs from BTFHub")

	path := filepath.Join(saveDir, fmt.Sprintf("%s.btf", kernelVersion))
	if exist, err := fileExist(path); err != nil {
		return nil, path, err
	} else if exist {
		return loadSpec(path)
	}

	downloadUrl := fmt.Sprintf(btfHubURL, release.Id, release.VersionId, arch, kernelVersion)
	log.Infof("try to download BTF specs from %s and uncompress it to %s", downloadUrl, path)

	resp, err := httpGet(context.TODO(), downloadUrl)
	if err != nil {
		return nil, path, fmt.Errorf("download BTF specs from %s: %w", downloadUrl, err)
	}
	defer resp.Body.Close()

	data, err := decompressXzReader(resp.Body)
	if err != nil {
		return nil, path, fmt.Errorf("download BTF specs from %s: %w", downloadUrl, err)
	}
	if err := saveDataToFile(data, path); err != nil {
		return nil, path, err
	}

	return loadSpec(path)
}

func loadSpecFromOpenanolis(arch string, _ host.Release, kernelVersion,
	saveDir string) (*btf.Spec, string, error) {
	log.Info("try to load BTF specs from OpenAnolis mirror")
	if arch == "arm64" {
		arch = "aarch64"
	}
	path := filepath.Join(saveDir, fmt.Sprintf("vmlinux-%s", kernelVersion))
	if exist, err := fileExist(path); err != nil {
		return nil, path, err
	} else if exist {
		return loadSpec(path)
	}

	downloadUrl := fmt.Sprintf(openAnolisURL, arch, kernelVersion)
	log.Infof("try to download BTF specs from %s and save it to %s", downloadUrl, path)

	resp, err := httpGet(context.TODO(), downloadUrl)
	if err != nil {
		return nil, path, fmt.Errorf("download BTF specs from %s: %w", downloadUrl, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, path, fmt.Errorf("download BTF specs from %s: %w", downloadUrl, err)
	}
	if err := saveDataToFile(data, path); err != nil {
		return nil, path, err
	}

	return loadSpec(path)
}

func httpGet(ctx context.Context, url string) (*http.Response, error) {
	// TODO: add timeout
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status code is not 200: %d", resp.StatusCode)
	}
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

func loadSpecFromCandidateLocations() (*btf.Spec, string, error) {
	path := candidatePath
	log.Infof("try to load BTF specs from %s", path)

	spec, path, err := loadSpec(path)
	if err == nil {
		log.Infof("use BTF specs from %s", path)
		return spec, path, nil
	}
	log.Infof("load BTF specs from %s failed: %s", path, err)

	kernelVersion, err := host.GetKernelVersion()
	if err != nil {
		return nil, path, fmt.Errorf("get kernel version: %w", err)
	}
	path = fmt.Sprintf("%s-%s", candidatePath, kernelVersion)

	return loadSpec(path)
}

func loadSpec(path string) (*btf.Spec, string, error) {
	spec, err := btf.LoadSpec(path)
	if err == nil {
		log.Infof("use BTF specs from %s", path)
		return spec, path, nil
	}
	if spec, err := loadSpecFromELF(path); err == nil {
		return spec, path, nil
	}
	log.Warnf("load BTF specs from %s failed: %s", path, err)
	return nil, path, err
}

func loadSpecFromELF(path string) (spec *btf.Spec, err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		err = fmt.Errorf("reading ELF file panicked: %s", r)
	}()

	file, err := elf.Open(path)
	if err != nil {
		return nil, err
	}

	var (
		btfSection *elf.Section
	)

	for _, sec := range file.Sections {
		switch sec.Name {
		case ".BTF", ".btf":
			btfSection = sec
		default:
		}
	}

	if btfSection == nil {
		return nil, fmt.Errorf("btf: %w", btf.ErrNotFound)
	}

	if btfSection.ReaderAt == nil {
		return nil, fmt.Errorf("compressed BTF is not supported")
	}

	spec, err = btf.LoadSpecFromReader(btfSection.ReaderAt)
	return spec, err
}
