---
title: "捕获远程 ICMP"
weight: 150
---

## 使用场景

- 观察到外部主机的出站和入站 ICMP 回显流量，如 `test_icmp.sh` 所涵盖。
- 演示 ptcpdump 在使用 `ping` 时如何使用命令路径和参数注释有效负载。
- 通过观察 ICMP 回显请求和回复来诊断到外部主机的网络可达性问题。
- 验证主机是否可以在网络层与远程服务器成功通信。
- 对可能阻止往返外部目标的 ICMP 流量的防火墙规则进行故障排除。

## 命令

```bash
sudo ptcpdump -i any 'icmp and host 1.1.1.1'
```

在捕获处于活动状态时运行 `ping -w 10 -c 2 1.1.1.1`。期望看到记录了 `ping` 命令的回显请求，以及一个可以重放以确认元数据持久存在的 pcapng 文件。

## 输出示例

```
14:27:04.544875 ens33 ping.242851 Out IP 10.0.2.15 > 1.1.1.1: ICMP echo request, id 46243, seq 1, length 64, ParentProc [bash.101064]
14:27:04.750660 ens33 In IP 1.1.1.1 > 10.0.2.15: ICMP echo reply, id 46243, seq 1, length 64
```