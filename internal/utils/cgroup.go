package utils

import (
	"errors"
	"fmt"
	"os"
	"regexp"
)

var PathProcMounts = "/proc/mounts"
var reCgroup2Mount = regexp.MustCompile(`(?m)^cgroup2\s(/\S+)\scgroup2\s`)

func GetCgroupV2RootDir() (string, error) {
	return getCgroupV2RootDir(PathProcMounts)
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
