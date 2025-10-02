---
title: "故障排查"
weight: 30
---

帮助你快速定位运行 ptcpdump 时最常见的问题。

## 内核与权限检查 {#kernel-and-permission-checks}

- 查看内核版本：`uname -r` 应为 5.2 及以上。
- 确认已启用 BPF/BTF 支持：
  ```bash
  zgrep CONFIG_BPF /proc/config.gz
  zgrep CONFIG_DEBUG_INFO_BTF /proc/config.gz
  ```
- 如果 `/sys/kernel/debug` 为空，请挂载 `debugfs`：
  ```bash
  sudo mount -t debugfs none /sys/kernel/debug
  ```
- 以 root 权限运行，或为二进制授予 `CAP_BPF` 与 `CAP_NET_ADMIN`：
  ```bash
  sudo setcap cap_bpf,cap_net_admin=eip /usr/local/bin/ptcpdump
  ```

如需 tc/cgroup/socket 等后端的完整内核配置表，请参考 README 中的
[“Requirements”](https://github.com/mozillazg/ptcpdump?tab=readme-ov-file#requirements) 小节。

## 缺失元数据

若输出中看不到进程或容器信息：

- 确认被监控进程与 ptcpdump 运行在同一主机命名空间。
- 通过 `--context=process,parentproc,container,pod` 请求全部元数据。
- 确保容器运行时（Docker/containerd）能够提供相关标签。
- 选择正确的网卡进行抓取，可用 `ptcpdump -D` 查看列表。

## 权限不足错误

出现 `operation not permitted` 时，通常代表缺少权限。请再次确认已使用 `sudo` 或成功执行 `setcap`。

## 构建问题

从源码编译时：

- 安装构建依赖（`clang`、`llvm`、`bison`、`flex`、`libelf`、`make`、`gcc`、`autoconf`、Go 1.23+）。
- 若修改了 eBPF 代码，需要执行 `make build-bpf`。
- 如果本机缺少工具链，可使用 `make build-via-docker`。

构建失败时，可追加 `V=1`（如 `make V=1 build`）以输出详细日志。
