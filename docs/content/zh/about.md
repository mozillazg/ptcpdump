---
title: "关于 ptcpdump"
---

## ptcpdump 是什么？

**ptcpdump** 是一个使用 eBPF 技术实现的、兼容 tcpdump 的网络抓包工具。它的核心特性是能够在捕获数据包的同时，自动关联上对应的进程、容器以及 Kubernetes Pod 的元数据。这极大地丰富了抓包信息，让您能轻松地识别出特定网络流量的来源应用。

## 项目灵感

本项目的灵感来源于 [jschwinger233/skbdump](https://github.com/jschwinger233/skbdump)。

## 开源协议

`ptcpdump` 是一个基于 **MIT 许可证** 的开源软件。

## 如何贡献

欢迎任何形式的贡献！您可以在我们的 [GitHub 仓库](https://github.com/mozillazg/ptcpdump) 提交 Issue 或 Pull Request。
