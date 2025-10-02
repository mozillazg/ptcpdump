---
title: "Installation"
weight: 5
---

Choose the best way to install ptcpdump for your environment. If you want a guided walkthrough plus a first capture, head to the [Quickstart](quickstart/).

## Prebuilt Binaries

Download static builds for x86_64 or arm64 from the [GitHub releases page](https://github.com/mozillazg/ptcpdump/releases):


## Build from Source

Install build prerequisites (Go 1.23+, clang/llvm, bison, flex, gcc, make, autoconf, libelf). On Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y build-essential clang llvm bison flex \
    make autoconf libelf-dev
```

Clone the repository and produce a static binary:

```bash
git clone https://github.com/mozillazg/ptcpdump.git
cd ptcpdump
make build
sudo cp ptcpdump /usr/local/bin/
```

If you modify the eBPF programs, regenerate bytecode before building:

```bash
make build-bpf
make build
```

Use the Docker-based builder when the local toolchain is unavailable:

```bash
make build-via-docker
```

## Runtime Requirements

- Linux kernel 5.2 or newer with BPF and BTF enabled.
- `debugfs` mounted at `/sys/kernel/debug` (mount with `sudo mount -t debugfs none /sys/kernel/debug`).
- Root privileges or the `CAP_BPF` and `CAP_NET_ADMIN` capabilities (`sudo setcap cap_bpf,cap_net_admin=eip /usr/local/bin/ptcpdump`).

See the [Troubleshooting guide](troubleshooting/) for the complete kernel option matrix and additional help.
