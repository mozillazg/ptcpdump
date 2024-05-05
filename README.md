# ptcpdump

[![Test](https://github.com/mozillazg/ptcpdump/actions/workflows/test.yml/badge.svg)](https://github.com/mozillazg/ptcpdump/actions/workflows/test.yml)

ptcpdump is the tcpdump(8) implementation using eBPF, with an extra feature:
it adds process info as packet comments for each Packet.

![](./docs/wireshark.png)

Table of Contents
=================

* [Features](#features)
* [Installation](#installation)
  * [Requirements](#requirements)
* [Usage](#usage)
  * [Example output](#example-output)
* [Compare with tcpdump](#compare-with-tcpdump)


## Features

* Aware of the process information associated with the packets.
* Supports using pcap-filter(7) syntax for filtering packets.
* Supports filtering packets by process ID and process name.
* Directly applies filters in the kernel space.
* Supports saving captured packets in the PcapNG format for offline analysis with third-party tools such as Wireshark.
* Supports reading packets from pcapng file.


## Installation

Please download the latest binary in the [releases](https://github.com/mozillazg/ptcpdump/releases).

### Requirements

Linux kernel version must be larger than 5.1.


## Usage

```
Usage:
  ptcpdump [flags] [expression]

Examples:
  ptcpdump -i any

  ptcpdump -i eth0 --pid 1234 port 80 and host 10.10.1.1

  ptcpdump -i any --pname curl

  ptcpdump -i any -w ptcpdump.pcapng

  ptcpdump -r ptcpdump.pcapng

Expression: see "man 7 pcap-filter"

Flags:
  -Q, --direction string     Choose send/receive direction for which packets should be captured. Possible values are 'in', 'out' and 'inout' (default "inout")
  -f, --follow-forks         Include child processes when filter by process
  -h, --help                 help for ptcpdump
  -i, --interface strings    Interfaces to capture (default [lo])
      --list-interfaces      Print the list of the network interfaces available on the system
      --pid uint             Filter by process ID
      --pname string         Filter by process name
      --print                Print parsed packet output, even if the raw packets are being saved to a file with the -w flag
  -r, --read-file string     Read packets from file (which was created with the -w option). e.g. ptcpdump.pcapng
  -c, --receive-count uint   Exit after receiving count packets
      --version              Print the ptcpdump and libpcap version strings and exit
  -w, --write-file string    Write the raw packets to file rather than parsing and printing them out. They can later be printed with the -r option. e.g. ptcpdump.pcapng
```


### Example output

```
18:05:35.441022 wlp4s0 In IP (tos 0x4, ttl 51, id 0, offset 0, flags [DF], ip_proto TCP (6), length 60)
    185.125.190.29.80 > 192.168.1.50.41966: Flags [S.], cksum 0x68fd, seq 3647722906, ack 1664327469, win 65160, options [mss 1452,sackOK,TS val 1103153989 ecr 3934018003,nop,wscale 7], length 0
    Process (pid 892817, cmd /usr/bin/curl, args curl ubuntu.com)
18:05:35.441298 wlp4s0 Out IP (tos 0x0, ttl 64, id 19415, offset 0, flags [DF], ip_proto TCP (6), length 126)
    192.168.1.50.41966 > 185.125.190.29.80: Flags [P.], cksum 0x39e6, seq 1664327469:1664327543, ack 3647722907, win 502, options [nop,nop,TS val 3934018248 ecr 1103153989], length 74
    Process (pid 892817, cmd /usr/bin/curl, args curl ubuntu.com)
```

## Compare with tcpdump

| Options| tcpdump | ptcpdump|
|--------|--------|--------|
| *expression* | ✅  | ✅  |
| -i *interface* | ✅ | ✅ |
| -w *x.pcapng* |  ✅ | ✅ |
| -w *x.pcap* |  ✅ | |
| -r *x.pcapng* |  ✅ | ✅ |
| -r *x.pcap* |  ✅ | |
| --pid *process_id* | | ✅ |
| --pname *process_name* | | ✅ |
| -f | | ✅ |
| --follow-forks | | ✅ |
| --print | ✅ | ✅ |
| -c *count* | ✅ | ✅ |
| -Q *direction* | ✅ | ✅ |
| --direction=*direction* | ✅ | ✅ |
|--list-interfaces | ✅ | ✅ |
|-A | ✅ | |
| -B *bufer_size* | ✅ | |
| --buffer-size=*buffer_size* | ✅ | |
|--count | ✅ | |
| -C *file_size | ✅ | |
| -d | ✅ | |
| -dd | ✅ | |
| -ddd | ✅ | |
| -D | ✅ | |
| -e | ✅ | |
| -f | ✅ | |
| -F *file* | ✅ | |
| -G *rotate_seconds* | ✅ | |
| -h | ✅ | ✅ |
| --help | ✅ | ✅ |
| --version | ✅ | ✅ |
| -H | ✅ | |
| --interface=*interface* | ✅ | ✅ |
| -l | ✅ | |
| --monitor-mode | ✅ | |
| --immediate-mode | ✅ | |
| -j *tstamp_type* | ✅ | |
| --time-stamp-type=*tstamp_type* | ✅ | |
| -J | ✅ | |
| --list-time-stamp-types | ✅ | |
| --time-stamp-precision=*tstamp_precision* | ✅ | |
| --micro | ✅ | |
| --nano | ✅ | |
| -K | ✅ | |
| --dont-verify-checksums | ✅ | |
| -l | ✅ | |
| -L | ✅ | |
| --list-data-link-types | ✅ | |
| -m *module* | ✅ | |
| -M *secret* | ✅ | |
| -n | ✅ | |
| -N | ✅ | |
| -# | ✅ | |
| --number | ✅ | |
| -O | ✅ | |
| --no-optimize | ✅ | |
| -p | ✅ | |
| --no-promiscuous-mode | ✅ | |
| -S | ✅ | |
| --absolute-tcp-sequence-numbers | ✅ | |
| -s *snaplen* | ✅ | |
| --snapshot-length=*snaplen*  | ✅ | |
| -T *type* | ✅ | |
| -t | ✅ | |
| -tt | ✅ | |
| -ttt | ✅ | |
| -tttt | ✅ | |
| -u | ✅ | |
| -U | ✅ | |
| --packet-buffered | ✅ | |
| -v | ✅ | |
| -vv | ✅ | |
| -vvv | ✅ | |
| -V *file* | ✅ | |
| -W *filecont* | ✅ | |
| -x | ✅ | |
| -xx | ✅ | |
| -X | ✅ | |
| -XX | ✅ | |
| -y *datalinktype* | ✅ | |
| --linktype=*datalinktype* | ✅ | |
| -z *postrotate-command* | ✅ | |
| -Z *user* | ✅ | |
| --relinquish-privileges=*user* | ✅ | |
