---
title: "使用指南"
weight: 20
---

了解如何捕获数据、过滤流量，以及如何使用 ptcpdump 提供的进程元数据。

## 基本运行

列出可用网卡并启动一次抓包：

```bash
sudo ptcpdump -D
sudo ptcpdump -i eth0 -c 20
```

ptcpdump 支持与 tcpdump 相同的过滤语法，例如：

```bash
sudo ptcpdump -i any 'tcp port 443 and host 139.178.84.217'
```

## 常见示例

```bash
sudo ptcpdump -i eth0 tcp
sudo ptcpdump -i eth0 -A -s 0 -n -v 'tcp and port 80 and host 10.10.1.1'
sudo ptcpdump -i any -s 0 -n -v -C 100MB -W 3 -w test.pcapng 'tcp and port 80 and host 10.10.1.1'
sudo ptcpdump -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0'
```

更多模式：

```bash
sudo ptcpdump -i eth0 -i lo
sudo ptcpdump -i any --uid 1000
sudo ptcpdump -i any -w - port 80 | tcpdump -n -r -
sudo ptcpdump -i lo --netns /run/netns/foo --netns /run/netns/bar
```

## 进程与容器过滤

利用额外的上下文字段聚焦特定工作负载：

```bash
sudo ptcpdump -i any --pid 1234 --pid 5678
sudo ptcpdump -i any --pname curl
sudo ptcpdump -i any --container-id 36f0310403b1
sudo ptcpdump -i any --pod-name web.default
```

也可以直接让 ptcpdump 启动目标程序：

```bash
sudo ptcpdump -i any -- curl https://example.com
```

## 丰富的元数据输出

开启详细模式即可看到完整的进程/容器/Pod 信息：

```
13:44:41.529003 eth0 In IP (tos 0x4, ttl 45, id 45428, offset 0, flags [DF], proto TCP (6), length 52)
    139.178.84.217.443 > 172.19.0.2.42606: Flags [.], cksum 0x5284, seq 3173118145, ack 1385712707, win 118, options [nop,nop,TS val 134560683 ecr 1627716996], length 0
    Process (pid 553587, cmd /usr/bin/wget, args wget kernel.org)
    ParentProc (pid 553296, cmd /bin/sh, args sh)
    Container (name test, id d9028334..., image docker.io/library/alpine:3.18)
    Pod (name test, namespace default, UID 9e4bc54b..., labels {"run":"test"})
```

如需减少输出，可通过 `--context` 指定需要的元数据：

```bash
sudo ptcpdump -i any -v --context=process --context=container
```

## 保存抓包

以 PcapNG 格式写入文件，并保留嵌入的元数据：

```bash
sudo ptcpdump -i any -w demo.pcapng
```

还可以将数据通过管道交给其他工具：

```bash
sudo ptcpdump -i any -w - 'tcp port 80' | tcpdump -n -r -
sudo ptcpdump -i any -w - 'tcp port 80' | tshark -r -
```

## 搭配 Wireshark

在 Wireshark 中打开生成的 PcapNG 文件，可查看每个数据包的额外上下文。

![Wireshark Screenshot](/images/wireshark.png)


## 轮转与输出控制

- 限制抓包数量：`-c 100`
- 同时抓取多个网卡：`-i eth0 -i lo`
- 轮转输出文件：`-C 100 -W 3 -w capture.pcapng`
- 输出 ASCII 载荷：`-A` 或 `-X`

如需完整的参数列表，可查看 `ptcpdump --help`，或访问 [README 参数矩阵](https://github.com/mozillazg/ptcpdump#flags)。
