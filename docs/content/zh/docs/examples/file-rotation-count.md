---
title: "按文件计数限制轮换"
weight: 220
---

## 使用场景

- 限制保留的轮换文件数量，如 `test_rotate_filesize_with_count.sh` 中所示。
- 当您需要一个近期流量的滑动窗口时，这是理想的选择。
- 在长时间连续捕获流量时有效管理磁盘空间。
- 确保仅保留最新的网络活动以供分析。
- 为网络取证实现滚动缓冲区，自动丢弃较旧的捕获。

## 命令

```bash
sudo ptcpdump -i any -C 1kb -W 3 -w /tmp/ptcpdump_rotate_count.pcap 'port 8087 and host 127.0.0.1'
```

生成持续的流量（同样，通过 `nc` 和 `curl` 进行大量传输），ptcpdump 仅保留最新的三个文件。自动化测试可确保仅剩下三个文件，并且每个文件之后都可以读取。