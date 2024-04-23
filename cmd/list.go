package cmd

import (
	"fmt"
	"github.com/mozillazg/ptcpdump/internal/dev"
	"sort"
	"strings"
)

func listInterfaces() error {
	devices, err := dev.GetDevices("any")
	if err != nil {
		return err
	}
	outputs := []string{}
	for _, d := range devices {
		outputs = append(outputs, fmt.Sprintf("%d.%s", d.Ifindex, d.Name))
	}
	sort.Strings(outputs)
	fmt.Printf("%s\n", strings.Join(outputs, "\n"))
	return nil
}
