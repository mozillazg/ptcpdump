---
title: "将捕获流式传输到标准输出"
weight: 130
---

## 使用场景

- 通过将捕获写入标准输出，将实时数据包直接输入另一个工具，这是由 `test_write_stdout.sh` 验证的工作流。
- 当您希望 tcpdump、tshark 或自定义解析器在不使用临时文件的情况下使用数据包时，这是完美的选择。
- 将 ptcpdump 与其他命令行工具集成，以进行网络流量的实时分析或过滤。
- 使用自定义脚本或解析器处理实时网络数据，而无需写入磁盘的开销。
- 将网络捕获直接转发到远程分析服务器或 SIEM 系统。

## 命令

```bash
sudo ptcpdump -i any -c 1 -w - 'dst host 1.1.1.1 and tcp[tcpflags] = tcp-syn' | tcpdump -c 1 -n -r -
```

在管道运行时，执行 `curl -m 10 1.1.1.1`。tcpdump 直接从标准输入读取数据包，而 ptcpdump 仍会将带注释的输出打印到控制台。该测试可确保 SYN 在往返过程中幸免于难。