package host

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/mozillazg/ptcpdump/internal/log"
	"golang.org/x/sys/unix"
)

const EtcOsRelease string = "/etc/os-release"
const UsrLibOsRelease string = "/usr/lib/os-release"

var osReleaseFiles = []string{
	"/etc/os-release",
	"/usr/lib/os-release",
}

type Release struct {
	Id        string
	VersionId string
}

func GetRelease() (*Release, error) {
	var errors []error
	for _, path := range osReleaseFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			log.Infof("read file %s failed: %s", path, err)
			errors = append(errors, err)
			continue
		}

		var release Release
		for _, line := range strings.Split(string(data), "\n") {
			line := strings.TrimSpace(line)
			parts := strings.Split(line, "=")
			if len(parts) < 2 {
				continue
			}
			key, value := parts[0], parts[1]
			key = strings.TrimSpace(key)
			switch key {
			case "ID":
				release.Id = strings.TrimSpace(value)
				break
			case "VERSION_ID":
				release.VersionId = strings.TrimSpace(value)
				break
			}
		}
		if release.Id != "" {
			return &release, nil
		}
	}

	if len(errors) != 0 {
		return nil, fmt.Errorf("%v", errors)
	}

	return nil, fmt.Errorf("can't get release info from %v", osReleaseFiles)
}

var kernelVersionInfo struct {
	once    sync.Once
	version string
	err     error
}

func GetKernelVersion() (string, error) {
	kernelVersionInfo.once.Do(func() {

		var uname unix.Utsname
		err := unix.Uname(&uname)
		if err != nil {
			kernelVersionInfo.err = fmt.Errorf(": %w", err)
		} else {
			kernelVersionInfo.version = strings.TrimSpace(unix.ByteSliceToString(uname.Release[:]))
		}
	})

	return kernelVersionInfo.version, kernelVersionInfo.err
}

var bootTimeInfo struct {
	once sync.Once
	ts   int64
	err  error
}

func GetBootTimeNs() (int64, error) {
	bootTimeInfo.once.Do(func() {
		var ts unix.Timespec
		err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
		if err != nil {
			bootTimeInfo.err = fmt.Errorf("could not get time: %w", err)
		} else {

			bootTimeInfo.ts = unix.TimespecToNsec(ts)
		}
	})

	return bootTimeInfo.ts, bootTimeInfo.err
}
