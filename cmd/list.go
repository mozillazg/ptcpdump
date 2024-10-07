package cmd

import (
	"fmt"
	"strings"
)

func listInterfaces(opts Options) error {
	opts.ifaces = nil
	devices, err := opts.GetDevices()
	if err != nil {
		return err
	}
	interfaces := devices.Devs()

	outputs := []string{}
	for _, d := range interfaces {
		outputs = append(outputs, fmt.Sprintf("%d.%s, netns %d", d.Ifindex, d.Name, d.NetNs.Inode()))
	}

	fmt.Printf("%s\n", strings.Join(outputs, "\n"))
	return nil
}
