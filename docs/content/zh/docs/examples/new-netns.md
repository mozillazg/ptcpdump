---
title: "在新网络命名空间中抓取数据包"
weight: 60
---

## 使用场景

- 捕获在动态创建的网络命名空间内始发的流量——这对于调试隔离的测试环境非常有用。
- `test_netns_newly_exec.sh` 脚本预配了两个命名空间，并通过它们运行 curl，同时 ptcpdump 会进行跟踪。
- 调试为特定任务创建临时的、隔离的网络环境的应用程序。
- 分析利用新网络命名空间的沙盒进程或容器的网络行为。
- 验证新预配的网络命名空间的网络配置和隔离。

## 命令

```bash
sudo ptcpdump -i any --netns newly -- bash testdata/create_netns.sh netns30 veth30 netns31 veth31
```

从存储库根目录运行此命令，以便 `testdata/` 下的辅助脚本可用，或者换成您自己的设置逻辑。ptcpdump 会随着命名空间的出现和消失而保持同步，并使用始发接口注释数据包。将 `--netns` 与其他过滤器（如特定子网）结合使用，以仅关注您关心的流。