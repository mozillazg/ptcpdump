---
title: "Traffic Control (tc)"
weight: 10
---

## Overview

- eBPF program type: `BPF_PROG_TYPE_SCHED_CLS`
- Captures L2 headers ✅
- Cross-network namespaces ❌
- Kernel support: Linux 5.2+
- Default backend when `--backend` is omitted

## When to Use

Pick `tc` for general-purpose captures on the host. It gives you Ethernet frames plus process metadata with minimal configuration. Because it attaches to `tc` hooks, it works well for inspecting standard interfaces where namespace hopping is not required.

## Example Command

```bash
sudo ptcpdump -i any --backend tc host 1.1.1.1
```

Run a quick `curl http://1.1.1.1` to see the SYN/ACK handshake annotated with the launching process, matching the output showcased in the README.
