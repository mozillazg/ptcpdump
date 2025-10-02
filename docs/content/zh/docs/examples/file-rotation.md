---
title: "按大小轮换捕获文件"
weight: 210
---

## 使用场景

- 保持滚动捕获受大小限制，与 `test_rotate_filesize.sh` 匹配。
- 在流式传输大文件时，您可以自动轮换 pcap 文件并安全地存档。
- 防止单个捕获文件增长过大而变得难以管理。
- 通过将网络捕获分解为更小、更易于管理的数据块，方便传输和分析。
- 实现持续网络监控，并自动存档捕获数据。

## 命令

```bash
sudo ptcpdump -i any -C 1kb -w /tmp/ptcpdump_rotate.pcap 'port 8087 and host 127.0.0.1'
```

提供一个相当大的响应（例如，通过 `nc -l -p 8087` 管道传输 100 MiB 的 `dd`）并使用 `curl --retry 2 --retry-all-errors http://127.0.0.1:8087` 获取它。一旦文件超过 1 KiB，ptcpdump 就会轮换文件。该测试验证是否生成了多个文件，以及每个文件是否都可以使用 `ptcpdump -r` 读回。