---
title: "安装"
weight: 1
---

你可以在 [releases page](https://github.com/mozillazg/ptcpdump/releases) 下载以静态链接方式编译的适用于 x86_64 和 arm64 架构的二进制文件。

### Requirements

`ptcpdump` 只支持 Linux 系统，并且系统的内核版本最好 >= 5.2 (内核需要启用 BPF 和 BTF 支持）。

对于内核版本介于 4.18 ~ 5.2 之间的系统，如果系统中未提供程序依赖的内核 BTF 文件的话，
`ptcpdump` 将自动尝试从 [龙蜥 BTF 目录](https://mirrors.openanolis.cn/coolbpf/btf/) 和 [BTFhub](https://github.com/aquasecurity/btfhub-archive) 
下载当前系统内核版本对应的 BTF 文件。
