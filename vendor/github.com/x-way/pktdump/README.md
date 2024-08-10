# pktdump
[![CircleCI](https://circleci.com/gh/x-way/pktdump/tree/master.svg?style=svg)](https://circleci.com/gh/x-way/pktdump/tree/master)
[![GoDoc](https://godoc.org/github.com/x-way/pktdump?status.svg)](https://godoc.org/github.com/x-way/pktdump)
[![Go Report Card](https://goreportcard.com/badge/github.com/x-way/pktdump)](https://goreportcard.com/report/github.com/x-way/pktdump)
[![Codecov](https://codecov.io/gh/x-way/pktdump/branch/master/graph/badge.svg)](https://codecov.io/gh/x-way/pktdump/)

Format gopacket.Packet network packets similar to the tcpdump CLI output

## example

```
package pktdump_test

import (
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/x-way/pktdump"
)

func ExampleFormat() {
	raw := []byte{0x45, 0x00, 0x00, 0x42, 0x9a, 0x66, 0x00, 0x00, 0x40, 0x11, 0xce, 0xc0, 0xc0, 0xa8, 0x48, 0x32, 0xc0, 0xa8, 0x48, 0x01, 0xfb, 0x6a, 0x00, 0x35, 0x00, 0x2e, 0x02, 0xeb, 0x29, 0x84, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x73, 0x69, 0x67, 0x69, 0x6e, 0x74, 0x02, 0x63, 0x68, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	packet := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)

	fmt.Println(pktdump.Format(packet))
}
```
This would produce the following result
```
IP 192.168.72.50.64362 > 192.168.72.1.53: 10628+ [1au] A CH? sigint.ch. (38)
```
