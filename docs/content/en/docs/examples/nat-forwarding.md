---
title: "Inspect NATed Container Traffic"
weight: 200
---

## Case

- Observe how container traffic traverses NAT on the host bridge, reflecting the checks in `test_nat.sh`.
- Validate packet rewriting through `docker0` or other bridges.
- Verify that NAT rules are correctly translating container IP addresses for external communication.
- Troubleshoot connectivity issues where containers cannot reach external services due to incorrect NAT configurations.
- Monitor the source IP addresses of outbound traffic from containers after NAT translation.

## Command

```bash
sudo ptcpdump -i any 'host 1.1.1.1'
```

While ptcpdump runs, launch a container that reaches out—e.g., 
`docker run --rm alpine:3.18 wget --timeout=10 1.1.1.1`. 
The capture shows SYN packets on `docker0` annotated with 
the container's `wget` command and highlights the NATed source address. 
Replaying the pcap confirms host and container perspectives.
