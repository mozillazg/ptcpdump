---
title: "检查 ARP 探测"
weight: 140
---

## 使用场景

- 根据 `test_arp.sh` 捕获 ARP 发现流量以确认第二层可见性。
- 在实验环境中诊断地址解析问题或验证邻居发现。
- 监控网络分段上的 ARP 风暴或过多的 ARP 请求。
- 验证特定主机是否响应 ARP 请求。
- 调试主机无法正确将 IP 解析为 MAC 地址的网络连接问题。

## 命令

```bash
sudo ptcpdump -i any 'arp host 1.1.1.1'
```

并行运行 `arping -w 10 -c 2 1.1.1.1`。ptcpdump 会记录 ARP 请求（“who-has 1.1.1.1”）并将其存储在 pcapng 文件中，tcpdump 稍后可以重放该文件，这与自动化测试相呼应。

## 输出示例

```
14:15:25.031043 ens33 Out ARP, Request who-has 1.1.1.1 tell 10.0.2.15, length 28
14:15:26.036061 ens33 Out ARP, Request who-has 1.1.1.1 tell 10.0.2.15, length 28
```