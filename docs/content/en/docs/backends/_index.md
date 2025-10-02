---
title: "Backend Guide"
weight: 25
---

Understand the capture backends supported by ptcpdump. Each section summarizes the underlying eBPF program type, highlights when to pick the backend, and shows a ready-to-run command lifted from the README examples.

## Backend Profiles

- [Traffic Control (`tc`)](tc/)
- [cgroup-skb](cgroup-skb/)
- [Socket Filter](socket-filter/)
- [Tracepoint BTF (`tp-btf`)](tp-btf/)
