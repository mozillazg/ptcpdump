---
title: "Socket Filter"
weight: 30
---

## Overview

- eBPF program type: `BPF_PROG_TYPE_SOCKET_FILTER`
- Captures L2 headers ✅
- Cross-network namespaces ❌
- Kernel support: Linux 5.4+
- cgroup v2 recommended for richer metadata

## When to Use

Choose the socket filter backend when you want tcpdump-like semantics without configuring `tc`, or when running on kernels where socket filtering offers better stability. It attaches to classic socket hooks, delivering Ethernet headers along with ptcpdump's process awareness.

## Example Command

```bash
sudo ptcpdump -i any --backend socket-filter host 1.1.1.1
```

Initiate `curl http://1.1.1.1` to reproduce the README sample, verifying that SYN/ACK packets and process context appear just like the stock tcpdump output.
