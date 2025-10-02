---
title: "按进程 ID 过滤"
weight: 100
---

## 使用场景

- 跟踪与特定 PID 相关的​​数据包，反映了 `test_pid_filter.sh` 中的保障措施。
- 当同一程序的多个实例同时存在并且您只想获取来自特定进程的流量时非常有用。
- 当同一应用程序的多个实例正在运行时，隔离由特定进程生成的网络流量。
- 调试特定进程的网络通信，而不会被不相关的系统流量所淹没。
- 监控由其 PID 识别的可疑进程的网络活动。

## 命令

```bash
sudo ptcpdump -i any --pid $(pgrep -n python3) -f
```

开始捕获，记下您所针对的 PID（如果需要，请将子 shell 替换为您自己的 PID 列表），并发出 `import http.client; http.client.HTTPConnection('1.1.1.1', 80).request("GET", '/')`。ptcpdump 会为该确切的 PID 发出 SYN/ACK 对，并将它们与命令路径元数据一起写入 pcap 以进行后期分析。

## 输出示例

```
15:02:57.041920 ens33 python3.12.254006 Out IP 10.0.2.15.46112 > 1.1.1.1.80: Flags [S], seq 1607118109, win 64240, options [mss 1460,sackOK,TS val 2313804558 ecr 0,nop,wscale 7], length 0, ParentProc [bash.241382]
15:02:57.250542 ens33 python3.12.254006 In IP 1.1.1.1.80 > 10.0.2.15.46112: Flags [S.], seq 1199640697, ack 1607118110, win 64240, options [mss 1460], length 0, ParentProc [bash.241382]
15:02:57.250733 ens33 python3.12.254006 Out IP 10.0.2.15.46112 > 1.1.1.1.80: Flags [.], seq 1607118110, ack 1199640698, win 64240, length 0, ParentProc [bash.241382]
15:02:57.250945 ens33 python3.12.254006 Out IP 10.0.2.15.46112 > 1.1.1.1.80: Flags [P.], seq 1607118110:1607118170, ack 1199640698, win 64240, length 60: HTTP: GET / HTTP/1.1, ParentProc [bash.241382]
```