---
title: "Tracepoint BTF (tp-btf)"
weight: 40
---

## Overview

- eBPF program type: `BPF_PROG_TYPE_TRACING`
- Captures L2 headers ✅
- Cross-network namespaces ✅
- Kernel support: Linux 5.5+
- Benefits from cgroup v2 for consistent metadata

## When to Use

`tp-btf` taps tracepoints with BTF typing, giving you cross-namespace visibility similar to `cgroup-skb` while still exposing layer-two headers. It's well-suited for newer kernels and complex environments where you need broad coverage without sacrificing packet detail.

## Example Command

```bash
sudo ptcpdump -i any --backend tp-btf host 1.1.1.1
```

As the README demonstrates, running `curl http://1.1.1.1` displays the full handshake with process annotations, letting you validate tracepoint-based captures.
