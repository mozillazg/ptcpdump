---
title: "Loopback ICMP Smoke Test"
weight: 10
---

## Case

Validate that ptcpdump can capture traffic on the local loopback device and annotate ping packets with process information. This mirrors the quick verification flow from the README's example commands and the `test_default.sh` smoke test.

## Command

```bash
sudo ptcpdump -i lo -c 2 -v --print -w /tmp/ptcpdump_default.pcapng 'icmp and host 127.0.0.1'
```

Ping `127.0.0.1` in another terminal while the capture runs. The log will include 
the ICMP echo request paired with the `ping` process metadata, 
and the `pcapng` output can be inspected later via tcpdump or Wireshark.

## Output Example

```
14:45:14.492769 lo Out IP (tos 0x0, ttl 64, id 6805, offset 0, flags [DF], proto ICMPv4 (1), length 84)
    127.0.0.1 > 127.0.0.1: ICMP echo request, id 56170, seq 1, length 64
    Process (pid 252778, cmd /usr/bin/ping, args ping -c 2 127.0.0.1)
    User (uid 1000)
    ParentProc (pid 101064, cmd /usr/bin/bash, args /bin/bash -i)
14:45:14.492822 lo In IP (tos 0x0, ttl 64, id 6805, offset 0, flags [DF], proto ICMPv4 (1), length 84)
    127.0.0.1 > 127.0.0.1: ICMP echo request, id 56170, seq 1, length 64
```
