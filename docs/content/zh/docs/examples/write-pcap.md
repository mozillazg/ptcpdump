---
title: "写入 PcapNG 以供日后使用"
weight: 120
---

## 使用场景

- 根据 `test_write_pcap.sh` 中的断言，将数据包捕获到磁盘并使用 ptcpdump 或 tcpdump 进行重放。
- 将网络流量存档以进行长期存储、合规性或事后取证分析。
- 与安全团队或开发人员共享捕获的网络数据以进行协作故障排除。
- 在受控环境中重放网络场景以测试入侵检测系统或网络性能。

## 命令

```bash
sudo ptcpdump -i any -c 1 --print -w /tmp/ptcpdump_write.pcapng 'dst host 1.1.1.1 and tcp[tcpflags] = tcp-syn'
sudo tcpdump -n -r /tmp/ptcpdump_write.pcapng
sudo ptcpdump -r /tmp/ptcpdump_write.pcapng
```

启动捕获，发出 `curl -m 10 1.1.1.1`，并使用这两种工具检查存储的文件。该测试可确保 SYN 出现在每次回读中，并且 ptcpdump 写入的文件 tcpdump 可以理解。