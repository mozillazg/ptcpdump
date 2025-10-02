---
title: "Troubleshooting"
weight: 30
---

Diagnose the most common setup issues when running ptcpdump.

## Kernel and Permission Checks {#kernel-and-permission-checks}

- Verify your kernel version: `uname -r` should report 5.2 or newer.
- Ensure BPF/BTF support is enabled:
  ```bash
  zgrep CONFIG_BPF /proc/config.gz
  zgrep CONFIG_DEBUG_INFO_BTF /proc/config.gz
  ```
- Mount `debugfs` if `/sys/kernel/debug` is empty:
  ```bash
  sudo mount -t debugfs none /sys/kernel/debug
  ```
- Run ptcpdump with root privileges or grant `CAP_BPF` and `CAP_NET_ADMIN` to the binary:
  ```bash
  sudo setcap cap_bpf,cap_net_admin=eip /usr/local/bin/ptcpdump
  ```

If you need the full kernel option matrix for the tc, cgroup, or socket filter backends, refer to the README's
[requirements table](https://github.com/mozillazg/ptcpdump?tab=readme-ov-file#requirements).

## Missing Metadata

If packets lack process or container details:

- Confirm the workload runs on the same host namespace where ptcpdump executes.
- Include `--context=process,parentproc,container,pod` to request all metadata blocks.
- Ensure container runtimes expose metadata (Docker/containerd supported).
- Capture the correct interfaces (use `ptcpdump -D` to list interfaces).

## Permission Denied Errors

`operation not permitted` typically indicates missing capabilities. Double-check that `setcap` succeeded or run ptcpdump with `sudo`.

## Build Issues

When compiling from source:

- Install build dependencies (`clang`, `llvm`, `bison`, `flex`, `libelf`, `make`, `gcc`, `autoconf`, Go 1.23+).
- Use `make build-bpf` if you modified the eBPF programs.
- Prefer `make build-via-docker` if your host lacks the required toolchain.

If a build step fails, rerun with `V=1` (e.g., `make V=1 build`) for verbose logs.
