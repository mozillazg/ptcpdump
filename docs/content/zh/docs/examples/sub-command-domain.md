---
title: "针对域启动 Curl"
weight: 190
---

## 使用场景

- 生成一个解析主机名的命令并监控其流量，与 `test_sub_curl_domain_program.sh` 相呼应。
- 演示在 ptcpdump 处理进程归属的同时捕获外部域的 DNS 解析的 HTTP 请求。
- 验证特定应用程序是否正确解析域名并连接到预期的 IP 地址。
- 通过观察整个 DNS 查找和连接过程来排查应用程序的 DNS 解析失败问题。
- 监控由特定命令或脚本发起的到外部域的出站连接。

## 命令

```bash
sudo ptcpdump -i any -v -- curl -m 10 https://ubuntu.com
```

ptcpdump 调用 curl，捕获 HTTP 交换（包括朝向解析的 IP 的 SYN 数据包），并记录显示完整命令行 `curl -m 10 ubuntu.com` 的元数据。这对于捕获短暂运行而不会错过初始握手非常有用。


## 输出示例

```
15:08:28.079227 lo Out IP (tos 0x0, ttl 64, id 13848, offset 0, flags [DF], proto UDP (17), length 67)
    127.0.0.1.37308 > 127.0.0.53.53: 20673+ [1au] A? ubuntu.com. (39)
    Process (pid 254949, cmd /usr/bin/curl, args curl -m 10 https://ubuntu.com)
    User (uid 0)
    ParentProc (pid 254941, cmd ptcpdump, args ptcpdump -- curl -m 10 https://ubuntu.com)
15:08:28.110391 lo Out IP (tos 0x0, ttl 1, id 47265, offset 0, flags [DF], proto UDP (17), length 115)
    127.0.0.53.53 > 127.0.0.1.37308: 20673 3/0/1 A 185.125.190.29, A 185.125.190.20, A 185.125.190.21 (87)
    Process (pid 254949, cmd /usr/bin/curl, args curl -m 10 https://ubuntu.com)
    User (uid 0)
    ParentProc (pid 254941, cmd ptcpdump, args ptcpdump -- curl -m 10 https://ubuntu.com)
...
15:08:28.110417 lo In IP (tos 0x0, ttl 1, id 47265, offset 0, flags [DF], proto UDP (17), length 115)
    127.0.0.53.53 > 127.0.0.1.37308: 20673 3/0/1 A 185.125.190.29, A 185.125.190.20, A 185.125.190.21 (87)
    Process (pid 254949, cmd /usr/bin/curl, args curl -m 10 https://ubuntu.com)
    User (uid 0)
    ParentProc (pid 254941, cmd ptcpdump, args ptcpdump -- curl -m 10 https://ubuntu.com)
...
15:08:28.440246 ens33 Out IP (tos 0x0, ttl 64, id 18470, offset 0, flags [DF], proto TCP (6), length 60)
    10.0.2.15.33824 > 185.125.190.29.443: Flags [S], cksum 0x83d8, seq 1966522591, win 64240, options [mss 1460,sackOK,TS val 2720366192 ecr 0,nop,wscale 7], length 0
    Process (pid 254949, cmd /usr/bin/curl, args curl -m 10 https://ubuntu.com)
    User (uid 0)
    ParentProc (pid 254941, cmd ptcpdump, args ptcpdump -- curl -m 10 https://ubuntu.com)
```