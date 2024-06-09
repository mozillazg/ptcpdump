package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mozillazg/ptcpdump/internal/dev"
)

func listInterfaces() error {
	devices, err := dev.GetDevices(nil)
	if err != nil {
		return err
	}
	var interfaces []dev.Device
	for _, d := range devices {
		interfaces = append(interfaces, d)
	}
	sort.Slice(interfaces, func(i, j int) bool {
		return interfaces[i].Ifindex < interfaces[j].Ifindex
	})

	outputs := []string{}
	for _, d := range interfaces {
		outputs = append(outputs, fmt.Sprintf("%d.%s", d.Ifindex, d.Name))
	}

	fmt.Printf("%s\n", strings.Join(outputs, "\n"))
	return nil
}
