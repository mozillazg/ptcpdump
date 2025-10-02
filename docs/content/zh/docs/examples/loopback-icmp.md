---
title: "环回 ICMP 烟雾测试"
weight: 10
---

## 使用场景

验证 ptcpdump 是否可以捕获本地环回设备上的流量，并使用进程信息注释 ping 数据包。这反映了 README 示例命令和 `test_default.sh` 烟雾测试中的快速验证流程。

## 命令

```bash
sudo ptcpdump -i lo -c 2 -v --print -w /tmp/ptcpdump_default.pcapng 'icmp and host 127.0.0.1'
```

在捕获运行时，在另一个终端中 ping `127.0.0.1`。日志将包括与 `ping` 进程元数据配对的 ICMP 回显请求，并且稍后可以通过 tcpdump 或 Wireshark 检查 `pcapng` 输出。

## 输出示例

```
14:45:14.492769 lo Out IP (tos 0x0, ttl 64, id 6805, offset 0, flags [DF], proto ICMPv4 (1), length 84)
    127.0.0.1 > 127.0.0.1: ICMP echo request, id 56170, seq 1, length 64
    Process (pid 252778, cmd /usr/bin/ping, args ping -c 2 127.0.0.1)
    User (uid 1000)
    ParentProc (pid 101064, cmd /usr/bin/bash, args /bin/bash -i)
14:45:14.492822 lo In IP (tos 0x0, ttl 64, id 6805, offset 0, flags [DF], proto ICMPv4 (1), length 84)
    127.0.0.1 > 127.0.0.1: ICMP echo request, id 56170, seq 1, length 64
```