---
title: "检查 NAT 容器流量"
weight: 200
---

## 使用场景

- 观察容器流量如何通过主机桥上的 NAT，反映了 `test_nat.sh` 中的检查。
- 通过 `docker0` 或其他网桥验证数据包重写。
- 验证 NAT 规则是否正确转换容器 IP 地址以进行外部通信。
- 对由于 NAT 配置不正确导致容器无法访问外部服务的连接问题进行故障排除。
- 监控 NAT 转换后来自容器的出站流量的源 IP 地址。

## 命令

```bash
sudo ptcpdump -i any 'host 1.1.1.1'
```

在 ptcpdump 运行时，启动一个向外访问的容器，例如 `docker run --rm alpine:3.18 wget --timeout=10 1.1.1.1`。捕获的 `docker0` 上的 SYN 数据包会带有容器的 `wget` 命令注释，并突出显示经过 NAT 的源地址。重放 pcap 文件可以确认主机和容器的视角。