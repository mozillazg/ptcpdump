---
title: "Backend Matrix Coverage"
weight: 260
---

## Case

- Understand how ptcpdump behaves across the supported eBPF backends—`tc`, `cgroup-skb`, `tp-btf`, and `socket-filter`—mirroring the GitHub Actions matrix.
- Validate compatibility against various kernels.
- Determine which eBPF backend is the most performant for a specific workload on your system.
- Troubleshoot capture issues that may be specific to a certain kernel version or eBPF backend.
- Select the most appropriate backend for your environment based on kernel version and required features.

## Command

Each backend is exercised with the same suite of smoke tests:

```bash
sudo ptcpdump -i any --backend tc -c 2
sudo ptcpdump -i any --backend cgroup-skb -c 2
sudo ptcpdump -i any --backend tp-btf -c 2
sudo ptcpdump -i any --backend socket-filter -c 2
```

Pair these with representative scenarios, such as the loopback ICMP or curl SYN captures.
In CI, little-vm-helper provisions kernels ranging from 4.19 to bpf-next; 
consult `.github/workflows/test.yml` to see which tests run on which backend. 
This reference page ties the matrix back to actionable commands.
For more details on each backend, see the [Backend Guide](../backends/).