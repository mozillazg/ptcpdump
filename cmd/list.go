package cmd

import (
	"fmt"
	"github.com/mozillazg/ptcpdump/internal/dev"
	"sort"
	"strings"
)

func listInterfaces() error {
	devices, err := dev.GetDevices(nil)
	if err != nil {
		return err
	}
	var devs []dev.Device
	for _, d := range devices {
		devs = append(devs, d)
	}
	sort.Slice(devs, func(i, j int) bool {
		return devs[i].Ifindex < devs[j].Ifindex
	})

	outputs := []string{}
	for _, d := range devs {
		outputs = append(outputs, fmt.Sprintf("%d.%s", d.Ifindex, d.Name))
	}
	fmt.Printf("%s\n", strings.Join(outputs, "\n"))
	return nil
}
