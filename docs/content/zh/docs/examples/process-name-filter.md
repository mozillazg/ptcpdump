---
title: "按进程名称筛选"
weight: 90
---

## 使用场景

- 将捕获限制为特定的可执行文件，与 `test_pname_filter.sh` 中强制执行的保护措施相呼应。
- 当有多个流处于活动状态，但您只关心某个二进制文件（例如 `curl`）时，请使用此功能。
- 监控特定应用程序在多个实例或部署中的网络活动。
- 确定特定服务或守护进程是否正在建立意外的网络连接。
- 在不需要 PID 的情况下调试已知应用程序的网络相关问题。

## 命令

```bash
sudo ptcpdump -i any -c 6 -v --pname curl -f
```

启动捕获，然后运行 `curl -m 10 1.1.1.1`。ptcpdump 仅打印由 curl 生成的数据包，标记 SYN 和 ACK 数据包，同时忽略不相关的流量。生成的 `pcapng` 文件会保留筛选后的子集以供日后查看。


## 输出示例

```
15:05:13.000236 ens33 Out IP (tos 0x0, ttl 64, id 37131, offset 0, flags [DF], proto TCP (6), length 60)
    10.0.2.15.46712 > 1.1.1.1.80: Flags [S], cksum 0xe3f, seq 723251949, win 64240, options [mss 1460,sackOK,TS val 2313940516 ecr 0,nop,wscale 7], length 0
    Process (pid 254600, cmd /usr/bin/curl, args curl -m 10 1.1.1.1)
    User (uid 1000)
    ParentProc (pid 217538, cmd /usr/bin/bash, args /bin/bash -i)
15:05:13.167214 ens33 In IP (tos 0x0, ttl 128, id 12503, offset 0, flags [none], proto TCP (6), length 44)
    1.1.1.1.80 > 10.0.2.15.46712: Flags [S.], cksum 0xd44c, seq 1738571349, ack 723251950, win 64240, options [mss 1460], length 0
    Process (pid 254600, cmd /usr/bin/curl, args curl -m 10 1.1.1.1)
    User (uid 1000)
    ParentProc (pid 217538, cmd /usr/bin/bash, args /bin/bash -i)
```