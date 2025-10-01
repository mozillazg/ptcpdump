---
title: "安装"
weight: 5
---

根据自己的环境选择合适的安装方式。若希望按照步骤完成并进行第一次抓包，请前往[快速上手](quickstart/)。

## 预编译二进制

在 [GitHub Releases](https://github.com/mozillazg/ptcpdump/releases) 页面获取适用于 x86_64 或 arm64 的静态版本：

```bash
curl -sSL https://github.com/mozillazg/ptcpdump/releases/latest/download/ptcpdump-$(uname -m).tar.gz \
  | sudo tar -xz -C /usr/local/bin ptcpdump
sudo chmod +x /usr/local/bin/ptcpdump
```

## 从源码构建

安装构建依赖（Go 1.23+、clang/llvm、bison、flex、gcc、make、autoconf、libelf）。在 Debian/Ubuntu 上：

```bash
sudo apt-get update
sudo apt-get install -y build-essential clang llvm bison flex \
    make autoconf libelf-dev
```

克隆仓库并生成静态二进制：

```bash
git clone https://github.com/mozillazg/ptcpdump.git
cd ptcpdump
make build
sudo cp dist/ptcpdump /usr/local/bin/
```

如果修改过 eBPF 代码，请先重新生成字节码：

```bash
make build-bpf
make build
```

当本地缺少工具链时，可使用 Docker 构建：

```bash
make build-via-docker
```

## 运行时要求

- Linux 内核版本 ≥ 5.2，并启用 BPF/BTF。
- `/sys/kernel/debug` 挂载了 `debugfs`（可执行 `sudo mount -t debugfs none /sys/kernel/debug`）。
- 使用 root 权限或为 ptcpdump 授予 `CAP_BPF`、`CAP_NET_ADMIN` 能力（`sudo setcap cap_bpf,cap_net_admin=eip /usr/local/bin/ptcpdump`）。

更多内核选项及常见问题请参见[故障排查](troubleshooting/)。
