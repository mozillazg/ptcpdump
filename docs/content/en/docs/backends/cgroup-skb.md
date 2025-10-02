---
title: "cgroup-skb"
weight: 20
---

## Overview

- eBPF program type: `BPF_PROG_TYPE_CGROUP_SKB`
- Captures L2 headers ❌
- Cross-network namespaces ✅
- Kernel support: Linux 5.2+
- Requires cgroup v2 (as enforced in CI)

## When to Use

Select `cgroup-skb` if you need visibility across namespaces or per-cgroup policy enforcement. It attaches to socket-level hooks, so layer-two framing is absent, but you still get process, thread, and container metadata. Ideal for container platforms using unified cgroup hierarchies.

## Example Command

```bash
sudo ptcpdump -i any --backend cgroup-skb host 1.1.1.1
```

While you curl `1.1.1.1`, the capture annotates packets with both process and thread identifiers, mirroring the detailed output in the README comparison.
