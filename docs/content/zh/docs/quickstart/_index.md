---
title: "快速上手"
weight: 10
---

几分钟内完成 ptcpdump 的安装与首个抓包。本指南包含安装方式和展示进程感知特性的第一个示例。

## 1. 检查环境要求

- Linux 内核版本 5.2 或更高，并开启 BPF 与 BTF。
- 已在 `/sys/kernel/debug` 挂载 `debugfs`（如目录为空，可执行 `sudo mount -t debugfs none /sys/kernel/debug`）。
- 以 root 身份运行，或为二进制授予 `CAP_BPF` 与 `CAP_NET_ADMIN` 能力（使用 `sudo` 执行命令即可）。

完整的内核配置列表见 [故障排查](../troubleshooting/#kernel-and-permission-checks)。

## 2. 安装 ptcpdump

### 下载发布版

在 [GitHub Releases](https://github.com/mozillazg/ptcpdump/releases) 页面获取适用于 x86_64 或 arm64 的静态版本：


### 从源码构建（可选）

```bash
git clone https://github.com/mozillazg/ptcpdump.git
cd ptcpdump
make build
sudo cp ptcpdump /usr/local/bin/
```

`make build` 会先编译 libpcap，并在当前目录生成静态链接的可执行文件。

## 3. 运行首个抓包

```bash
sudo ptcpdump -i any --pname curl -c 10
```

以上命令会在任意网卡上抓取 10 个数据包，并将上下文限定为 `curl` 进程。输出示例：

```
eth0 curl.205562 Out IP 10.0.2.15.39984 > 139.178.84.217.80: Flags [P.], ... ParentProc [bash.180205]
```

若需保存包含元数据的 PcapNG 供 Wireshark 分析，可执行：

```bash
sudo ptcpdump -i any -w demo.pcapng
```

## 下一步

- 在[使用指南](../usage/)了解更多过滤器与工作流技巧。
- 参考[故障排查](../troubleshooting/)解决内核或权限相关问题。
- 查阅 [GitHub README](https://github.com/mozillazg/ptcpdump#installation) 获取高级构建方式与功能对比。
- 试用仓库内附带的示例抓包文件（`demo.pcapng`、`gotls.pcapng`）。
