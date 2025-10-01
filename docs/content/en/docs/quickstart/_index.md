---
title: "Quickstart"
weight: 10
---

Get up and running with ptcpdump in a few minutes. This guide covers installation and a first capture that highlights process-aware metadata.

## 1. Check Requirements

- Linux kernel 5.2 or newer with BPF and BTF enabled.
- `debugfs` mounted at `/sys/kernel/debug` (mount with `sudo mount -t debugfs none /sys/kernel/debug` if needed).
- Root privileges or the `CAP_BPF` and `CAP_NET_ADMIN` capabilities to load eBPF programs (run commands with `sudo`).

For a complete list of kernel configuration options, see the [Troubleshooting](../troubleshooting/#kernel-and-permission-checks) guide.

## 2. Install ptcpdump

### Download a Release

```bash
curl -sSL https://github.com/mozillazg/ptcpdump/releases/latest/download/ptcpdump-$(uname -m).tar.gz \
  | sudo tar -xz -C /usr/local/bin ptcpdump
sudo chmod +x /usr/local/bin/ptcpdump
```

Replace `$(uname -m)` with `x86_64` or `arm64` if you prefer an explicit architecture.

### Build from Source (optional)

```bash
git clone https://github.com/mozillazg/ptcpdump.git
cd ptcpdump
make build
sudo cp dist/ptcpdump /usr/local/bin/
```

The `make build` target compiles libpcap and produces a static binary inside `dist/`.

## 3. Run Your First Capture

```bash
sudo ptcpdump -i any --pname curl -c 10
```

This command captures up to 10 packets from any interface and limits the context to the `curl` process. You should see output similar to:

```
eth0 curl.205562 Out IP 10.0.2.15.39984 > 139.178.84.217.80: Flags [P.], ... ParentProc [bash.180205]
```

To save a capture with embedded metadata for Wireshark, run:

```bash
sudo ptcpdump -i any -w demo.pcapng
```

## What Next?

- Learn more filters and workflow tips in the [Usage Guide](../usage/).
- Troubleshoot kernel or permission issues via the [Troubleshooting](../troubleshooting/) reference.
- Review the [GitHub README](https://github.com/mozillazg/ptcpdump#installation) for advanced build modes and feature comparisons.
- Explore the sample capture files bundled in the repository (`demo.pcapng`, `gotls.pcapng`).
