# ptcpdump

<div id="top"></div>

[![amd64-e2e](https://img.shields.io/github/actions/workflow/status/mozillazg/ptcpdump/test.yml?label=x86_64%20(amd64)%20e2e)](https://github.com/mozillazg/ptcpdump/actions/workflows/test.yml)
[![arm64-e2e](https://img.shields.io/circleci/build/gh/mozillazg/ptcpdump/master?label=aarch64%20(arm64)%20e2e)](https://app.circleci.com/pipelines/github/mozillazg/ptcpdump?branch=master)


ptcpdump is the tcpdump(8) implementation using eBPF, with an extra feature:
it adds process info as packet comments for each Packet when possible.
Inspired by [jschwinger233/skbdump](https://github.com/jschwinger233/skbdump).

![](./docs/wireshark.png)

Table of Contents
=================

* [Features](#features)
* [Installation](#installation)
   * [Requirements](#requirements)
* [Usage](#usage)
   * [Example commands](#example-commands)
   * [Example output](#example-output)
   * [Flags](#flags)
* [Compare with tcpdump](#compare-with-tcpdump)
* [Build](#build)


## Features

* Process-aware
  * Aware of the process information associated with the packets.
  * Supports filtering packets by process ID and process name.
* Container-aware and Kubernetes-aware
  * Aware of the container and pod information associated with the packets.
  * Supports multiple container runtimes: Docker Engine and containerd
* Supports using pcap-filter(7) syntax for filtering packets.
* Directly applies filters in the kernel space.
* Supports saving captured packets in the PcapNG format for offline analysis with third-party tools such as Wireshark.
* Supports reading packets from pcapng file.


## Installation

Please download the latest binary in the [releases](https://github.com/mozillazg/ptcpdump/releases).

### Requirements

Linux kernel version >= 5.2.

<p align="right"><a href="#top">🔝</a></p>


## Usage

### Example commands

```
sudo ptcpdump -i any tcp
sudo ptcpdump -i eth0 -i lo
sudo ptcpdump -i eth0 --pid 1234 port 80 and host 10.10.1.1
sudo ptcpdump -i any --pname curl
sudo ptcpdump -i any -- curl ubuntu.com
sudo ptcpdump -i any -w demo.pcapng
sudo ptcpdump -i any -w - port 80 | tcpdump -n -r -
sudo ptcpdump -i any -w - port 80 | tshark -r -
ptcpdump -r demo.pcapng
```

<p align="right"><a href="#top">🔝</a></p>


### Example output


Default:

```
09:32:09.718892 vethee2a302f In IP 10.244.0.2.33426 > 139.178.84.217.80: Flags [S], seq 4113492822, win 64240, length 0, Process [/usr/bin/wget.3553008], Container [test], Pod [test.default]
09:32:09.718941 eth0 Out IP 172.19.0.2.33426 > 139.178.84.217.80: Flags [S], seq 4113492822, win 64240, length 0, Process [/usr/bin/wget.3553008], Container [test], Pod [test.default]
```

With `-v`:

```
09:32:44.613707 vethee2a302f In IP (tos 0x0, ttl 64, id 45068, offset 0, flags [DF], proto TCP (6), length 60)
    10.244.0.2.60142 > 139.178.84.217.80: Flags [S], cksum 0xebaf, seq 1553234662, win 64240, options [mss 1460,sackOK,TS val 55511585 ecr 0,nop,wscale 7], length 0
    Process (pid 3558755, cmd /usr/bin/wget, args wget kernel.org)
    Container (name test, id 22786d2c79f70dbed0003c80915276943695a5674e589e72f45ea9469427bc70, image docker.io/library/alpine:3.18, labels {"io.cri-containerd.kind":"container","io.kubernetes.container.name":"test","io.kubernetes.pod.name":"test","io.kubernetes.pod.namespace":"default","io.kubernetes.pod.uid":"9e4bc54b-de48-4b1c-8b9e-54709f67ed0c"})
    Pod (name test, namespace default, UID 9e4bc54b-de48-4b1c-8b9e-54709f67ed0c, labels {"run":"test"}, annotations {"kubernetes.io/config.seen":"2024-06-15T02:43:38.519669660Z","kubernetes.io/config.source":"api"})
09:32:44.613758 eth0 Out IP (tos 0x0, ttl 63, id 45068, offset 0, flags [DF], proto TCP (6), length 60)
    172.19.0.2.60142 > 139.178.84.217.80: Flags [S], cksum 0x8ccf, seq 1553234662, win 64240, options [mss 1460,sackOK,TS val 55511585 ecr 0,nop,wscale 7], length 0
    Process (pid 3558755, cmd /usr/bin/wget, args wget kernel.org)
    Container (name test, id 22786d2c79f70dbed0003c80915276943695a5674e589e72f45ea9469427bc70, image docker.io/library/alpine:3.18, labels {"io.cri-containerd.kind":"container","io.kubernetes.container.name":"test","io.kubernetes.pod.name":"test","io.kubernetes.pod.namespace":"default","io.kubernetes.pod.uid":"9e4bc54b-de48-4b1c-8b9e-54709f67ed0c"})
    Pod (name test, namespace default, UID 9e4bc54b-de48-4b1c-8b9e-54709f67ed0c, labels {"run":"test"}, annotations {"kubernetes.io/config.seen":"2024-06-15T02:43:38.519669660Z","kubernetes.io/config.source":"api"})
```

<p align="right"><a href="#top">🔝</a></p>


### Flags


```
Usage:
  ptcpdump [flags] [expression] [-- command [args]]

Examples:
  sudo ptcpdump -i any tcp
  sudo ptcpdump -i eth0 -i lo
  sudo ptcpdump -i eth0 --pid 1234 port 80 and host 10.10.1.1
  sudo ptcpdump -i any --pname curl
  sudo ptcpdump -i any -- curl ubuntu.com
  sudo ptcpdump -i any -w ptcpdump.pcapng
  sudo ptcpdump -i any -w - port 80 | tcpdump -n -r -
  sudo ptcpdump -i any -w - port 80 | tshark -r -
  ptcpdump -r ptcpdump.pcapng

Expression: see "man 7 pcap-filter"

Flags:
  --container-id string      Filter by container id (only TCP and UDP packets are supported)
  -Q, --direction string     Choose send/receive direction for which packets should be captured. Possible values are 'in', 'out' and 'inout' (default "inout")
  -f, --follow-forks         Trace child processes as they are created by currently traced processes when filter by process
  -h, --help                 help for ptcpdump
  -i, --interface strings    Interfaces to capture (default [lo])
      --list-interfaces      Print the list of the network interfaces available on the system
      --oneline              Print parsed packet output in a single line
      --pid uint             Filter by process ID (only TCP and UDP packets are supported)
      --pname string         Filter by process name (only TCP and UDP packets are supported)
      --print                Print parsed packet output, even if the raw packets are being saved to a file with the -w flag
  -r, --read-file string     Read packets from file (which was created with the -w option). e.g. ptcpdump.pcapng
  -c, --receive-count uint   Exit after receiving count packets
  -v, --verbose count        When parsing and printing, produce (slightly more) verbose output
      --version              Print the ptcpdump and libpcap version strings and exit
  -w, --write-file string    Write the raw packets to file rather than parsing and printing them out. They can later be printed with the -r option. Standard output is used if file is '-'. e.g. ptcpdump.pcapng
```

<p align="right"><a href="#top">🔝</a></p>


## Compare with tcpdump

| Options                                           | tcpdump | ptcpdump                 |
|---------------------------------------------------|---------|--------------------------|
| *expression*                                      | ✅       | ✅                        |
| -i *interface*, --interface=*interface*           | ✅       | ✅                        |
| -w *x.pcapng*                                     | ✅       | ✅ (with process info)    |
| -w *x.pcap*                                       | ✅       | ✅ (without process info) |
| -w *-*                                            | ✅       | ✅                        |
| -r *x.pcapng*, -r *x.pcap*                        | ✅       | ✅                        |
| -r *-*                                            | ✅       |                          |
| --pid *process_id*                                |         | ✅                        |
| --pname *process_name*                            |         | ✅                        |
| --container-id *container_id*                     |         | ✅                        |
| -f, --follow-forks                                |         | ✅                        |
| -- *command [args]*                               |         | ✅                        |
| --oneline                                       |         | ✅                        |
| --print                                           | ✅       | ✅                        |
| -c *count*                                        | ✅       | ✅                        |
| -Q *direction*, --direction=*direction*           | ✅       | ✅                        |
| -D, --list-interfaces                             | ✅       | ✅                        |
| -A                                                | ✅       |                          |
| -B *bufer_size*, --buffer-size=*buffer_size*      | ✅       |                          |
| --count                                           | ✅       | ✅                       |
| -C *file_size                                     | ✅       |                          |
| -d                                                | ✅       |                          |
| -dd                                               | ✅       |                          |
| -ddd                                              | ✅       |                          |
| -e                                                | ✅       |                          |
| -f                                                | ✅       | ⛔                        |
| -F *file*                                         | ✅       |                          |
| -G *rotate_seconds*                               | ✅       |                          |
| -h, --help                                        | ✅       | ✅                        |
| --version                                         | ✅       | ✅                        |
| -H                                                | ✅       |                          |
| -l, --monitor-mode                                | ✅       |                          |
| --immediate-mode                                  | ✅       |                          |
| -j *tstamp_type*, --time-stamp-type=*tstamp_type* | ✅       |                          |
| -J, --list-time-stamp-types                       | ✅       |                          |
| --time-stamp-precision=*tstamp_precision*         | ✅       |                          |
| --micro                                           | ✅       |                          |
| --nano                                            | ✅       |                          |
| -K, --dont-verify-checksums                       | ✅       |                          |
| -l                                                | ✅       |                          |
| -L, --list-data-link-types                        | ✅       |                          |
| -m *module*                                       | ✅       |                          |
| -M *secret*                                       | ✅       |                          |
| -n                                                | ✅       | ✅                       |
| -N                                                | ✅       |                          |
| -#, --number                                      | ✅       | ✅                       |
| -O, --no-optimize                                 | ✅       |                          |
| -p, --no-promiscuous-mode                         | ✅       | ⛔                        |
| -S, --absolute-tcp-sequence-numbers               | ✅       |                          |
| -s *snaplen*, --snapshot-length=*snaplen*         | ✅       |                          |
| -T *type*                                         | ✅       |                          |
| -t                                                | ✅       | ✅                       |
| -tt                                               | ✅       |                          |
| -ttt                                              | ✅       |                          |
| -tttt                                             | ✅       |                          |
| -u                                                | ✅       |                          |
| -U, --packet-buffered                             | ✅       |                          |
| -v                                                | ✅       | ✅                       |
| -vv                                               | ✅       |                          |
| -vvv                                              | ✅       |                          |
| -V *file*                                         | ✅       |                          |
| -W *filecont*                                     | ✅       |                          |
| -x                                                | ✅       |                          |
| -xx                                               | ✅       |                          |
| -X                                                | ✅       |                          |
| -XX                                               | ✅       |                          |
| -y *datalinktype*, --linktype=*datalinktype*      | ✅       |                          |
| -z *postrotate-command*                           | ✅       |                          |
| -Z *user*, --relinquish-privileges=*user*         | ✅       |                          |

<p align="right"><a href="#top">🔝</a></p>


## Build

1. Build eBPF programs:

    ```
    make build-bpf
    ```

2. Build ptcpdump:

    ```
    make build
    ```

<p align="right"><a href="#top">🔝</a></p>
