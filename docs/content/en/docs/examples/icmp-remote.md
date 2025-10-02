---
title: "Capture Remote ICMP"
weight: 150
---

## Case

- Watch outbound and inbound ICMP echo traffic to external hosts, as covered by `test_icmp.sh`.
- Demonstrate how ptcpdump annotates payloads with both command path and arguments when using `ping`.
- Diagnose network reachability issues to external hosts by observing ICMP echo requests and replies.
- Verify that a host can successfully communicate with a remote server at the network layer.
- Troubleshoot firewall rules that might be blocking ICMP traffic to or from external destinations.

## Command

```bash
sudo ptcpdump -i any 'icmp and host 1.1.1.1'
```

Run `ping -w 10 -c 2 1.1.1.1` while the capture is active. Expect to see echo 
requests with the `ping` command recorded, plus a pcapng file you can 
replay to confirm the metadata persists.

## Output Example

```
14:27:04.544875 ens33 ping.242851 Out IP 10.0.2.15 > 1.1.1.1: ICMP echo request, id 46243, seq 1, length 64, ParentProc [bash.101064]
14:27:04.750660 ens33 In IP 1.1.1.1 > 10.0.2.15: ICMP echo reply, id 46243, seq 1, length 64
```
