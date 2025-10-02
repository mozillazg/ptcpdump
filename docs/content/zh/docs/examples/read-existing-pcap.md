---
title: "读取现有的 PcapNG"
weight: 110
---

## 使用场景

- 打开由其他工具生成的捕获文件，并使用 ptcpdump 的解码功能对其进行丰富，就像 `test_read_pcap.sh` 验证的那样。
- 使用增强的上下文（例如始发进程信息）重新检查历史网络数据。
- 与同事共享网络捕获，然后他们可以使用 ptcpdump 更深入地了解流量。

## 命令

```bash
sudo ptcpdump -i any -c 1 -w /tmp/ptcpdump_read.pcapng 'dst host 1.1.1.1 and tcp[tcpflags] = tcp-syn'
sudo ptcpdump -r /tmp/ptcpdump_read.pcapng
```

第一个命令使用 ptcpdump 捕获一个 SYN；第二个命令通过 ptcpdump 重放该文件，以熟悉的格式呈现相同的数据包。测试套件可确保输出符合预期，包括 SYN 标志检查。