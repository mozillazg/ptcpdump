package utils

import (
	"errors"
	"fmt"
	"os"
	"regexp"
)

const (
	pathProcMounts         = "/proc/mounts"
	defaultCgroupV2RootDir = "/sys/fs/cgroup"
)

var reCgroup2Mount = regexp.MustCompile(`(?m)^cgroup2\s(/\S+)\scgroup2\s`)

func GetCgroupV2RootDir() (string, error) {
	p, err := getCgroupV2RootDir(pathProcMounts)
	if err != nil {
		st, errv2 := os.Stat(defaultCgroupV2RootDir)
		if errv2 == nil && st.IsDir() {
			return defaultCgroupV2RootDir, nil
		}
	}
	return p, err
}

func getCgroupV2RootDir(pathProcMounts string) (string, error) {
	data, err := os.ReadFile(pathProcMounts)
	if err != nil {
		return "", fmt.Errorf("read file %s: %w", pathProcMounts, err)
	}
	items := reCgroup2Mount.FindStringSubmatch(string(data))
	if len(items) < 2 {
		return "", errors.New("cgroupv2 is not mounted")
	}
	return items[1], nil
}
