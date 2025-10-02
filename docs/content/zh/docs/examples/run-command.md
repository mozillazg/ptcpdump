---
title: "启动并跟踪 Curl 运行"
weight: 30
---

## 使用场景

- 当您需要从一个短暂的程序中抓取数据包时，让 ptcpdump 生成它，这样就不会有流量溜走。
- `test_sub_program.sh` 脚本直接从 README 中关于使用 `--` 的指南中实践了这种模式。
- 捕获快速退出的短暂脚本或命令的网络流量，确保不会丢失任何数据包。
- 从程序一开始就调试其网络交互，包括初始连接尝试。
- 在需要验证程序网络行为的集成测试中自动进行网络捕获。

## 命令

```bash
sudo ptcpdump -i any -c 10 -- curl -m 10 http://1.1.1.1
```

ptcpdump 会代表您启动 `curl`，用启动的命令标记每个数据包，并在十个数据包后自动停止。调整过滤器或计数以匹配您的工作负载。


## 输出示例

```
15:07:08.407094 ens33 curl.254838 Out IP 10.0.2.15.38924 > 1.1.1.1.80: Flags [S], seq 361565032, win 64240, options [mss 1460,sackOK,TS val 2314055923 ecr 0,nop,wscale 7], length 0, ParentProc [ptcpdump.254829]
15:07:08.570968 ens33 curl.254838 In IP 1.1.1.1.80 > 10.0.2.15.38924: Flags [S.], seq 739065025, ack 361565033, win 64240, options [mss 1460], length 0, ParentProc [ptcpdump.254829]
15:07:08.571075 ens33 curl.254838 Out IP 10.0.2.15.38924 > 1.1.1.1.80: Flags [.], seq 361565033, ack 739065026, win 64240, length 0, ParentProc [ptcpdump.254829]
15:07:08.571178 ens33 curl.254838 Out IP 10.0.2.15.38924 > 1.1.1.1.80: Flags [P.], seq 361565033:361565103, ack 739065026, win 64240, length 70: HTTP: GET / HTTP/1.1, ParentProc [ptcpdump.254829]
15:07:08.571380 ens33 curl.254838 In IP 1.1.1.1.80 > 10.0.2.15.38924: Flags [.], seq 739065026, ack 361565103, win 64240, length 0, ParentProc [ptcpdump.254829]
<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>cloudflare</center>
</body>
</html>
15:07:08.734100 ens33 curl.254838 In IP 1.1.1.1.80 > 10.0.2.15.38924: Flags [P.], seq 739065026:739065412, ack 361565103, win 64240, length 386: HTTP: HTTP/1.1 301 Moved Permanently, ParentProc [ptcpdump.254829]
```