---
title: "跨多个网络命名空间捕获"
weight: 170
---

## 使用场景

- 监控在静态网络命名空间之间流动的流量，同时跟踪两个端点。
- 与 `test_netns.sh` 对齐，其中 ptcpdump 监视通过 veth 对链接的两个命名空间之间的流量。
- 调试在不同网络命名空间中运行的应用程序之间的通信问题。
- 在涉及多个命名空间的复杂网络设置中验证网络隔离和路由配置。
- 在每个虚拟机或容器可能驻留在其自己的网络命名空间中的虚拟化环境中监控流量。

## 命令

```bash
sudo bash -c '
  ip netns add netns10
  ip netns add netns11
  ip link add veth10 type veth peer name veth11
  ip link set veth10 netns netns10
  ip link set veth11 netns netns11
  ip -n netns10 addr add 192.168.64.1/24 dev veth10
  ip -n netns11 addr add 192.168.64.2/24 dev veth11
  ip -n netns10 link set veth10 up
  ip -n netns11 link set veth11 up
  timeout 30s ptcpdump -i any --netns netns10 --netns netns11 -c 4 \
    "icmp and host 192.168.64.2" &
  sleep 20
  ip netns exec netns10 ping -c 2 192.168.64.2
  wait
'
```

ptcpdump 记录命名空间到命名空间流量的两个方向，并保存您可以重放的捕获。之后包括一个清理步骤以删除命名空间和 veth。