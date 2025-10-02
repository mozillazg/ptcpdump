---
title: "跟踪 TUN 接口上的流量"
weight: 160
---

## 使用场景

- 检查用户空间 TUN 设备内部的数据包，遵循 `test_tun.sh` 中更丰富的场景。
- 验证依赖于注入接口的 VPN 或覆盖设置。
- 通过检查流经 TUN 设备的流量来调试 VPN 或覆盖网络配置。
- 验证隧道中数据包的正确封装和解封装。
- 分析创建和利用 TUN 接口进行专门网络的应用程序的网络行为。

## 命令

```bash
sudo bash -c '
  ip netns add tun_test_ns
  ip netns exec tun_test_ns ip tuntap add dev tun0 mode tun
  ip netns exec tun_test_ns ip addr add 10.8.0.1 peer 10.8.0.2 dev tun0
  ip netns exec tun_test_ns ip link set tun0 up
  timeout 60s ptcpdump -i any -c 4 --netns tun_test_ns -v \
    "icmp and host 10.8.0.2" &
  sleep 20
  ip netns exec tun_test_ns ping -c 3 10.8.0.2 || true
  wait
'
```

命名空间创建反映了自动化测试：ptcpdump 在 `tun_test_ns` 内部侦听，捕获朝向对等地址的 ICMP 尝试，并将结果保存到磁盘以供查看。运行后清理命名空间 (`ip netns del tun_test_ns`)。