---
title: "查找出站 HTTP 调用者"
weight: 35
---

## 使用场景

- 精确查明哪些进程发起到特定站点的 HTTP 连接。
- 快速发现尝试访问端口 80 上的 `serverfault.com` 的意外客户端。
- 识别向外部域发出未经授权的 HTTP 请求的应用程序或服务。
- 通过观察 HTTP 请求和响应流来排查与 Web 服务的连接问题。
- 通过跟踪到可疑目标地址的出站 HTTP 连接来监控数据泄露企图。

## 命令

```bash
sudo ptcpdump -i any -c 5 'port 80 and host serverfault.com'
```

运行捕获并重现您关心的流量。ptcpdump 会打印数据包以及负责的进程（如果存在，还包括容器/pod），从而揭示触发了出站 HTTP 请求的二进制文件和命令行。

## 输出示例

```
14:48:46.096204 ens33 curl.253100 Out IP 10.0.2.15.57132 > 172.64.148.218.80: Flags [S], seq 1685848518, win 64240, options [mss 1460,sackOK,TS val 3711113013 ecr 0,nop,wscale 7], length 0, ParentProc [bash.101064]
14:48:46.283661 ens33 curl.253100 In IP 172.64.148.218.80 > 10.0.2.15.57132: Flags [S.], seq 1647926, ack 1685848519, win 64240, options [mss 1460], length 0, ParentProc [bash.101064]
14:48:46.283726 ens33 curl.253100 Out IP 10.0.2.15.57132 > 172.64.148.218.80: Flags [.], seq 1685848519, ack 1647927, win 64240, length 0, ParentProc [bash.101064]
14:48:46.283901 ens33 curl.253100 Out IP 10.0.2.15.57132 > 172.64.148.218.80: Flags [P.], seq 1685848519:1685848598, ack 1647927, win 64240, length 79: HTTP: HEAD / HTTP/1.1, ParentProc [bash.101064]
14:48:46.284120 ens33 curl.253100 In IP 172.64.148.218.80 > 10.0.2.15.57132: Flags [.], seq 1647927, ack 1685848598, win 64240, length 0, ParentProc [bash.101064]
```