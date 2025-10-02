---
title: "按 Kubernetes Pod 过滤流量"
weight: 50
---

## 使用场景

- 通过将捕获固定到其 Pod 身份来调试单个 Kubernetes 工作负载。
- 通过 CI 管道工作流确认 ptcpdump 的集群感知能力。
- 隔离和分析在多服务 pod 中运行的特定微服务的网络流量。
- 验证 pod 是否仅与其预期的服务和外部端点通信。
- 对影响特定 Kubernetes pod 的网络性能问题进行故障排除。

## 命令

```bash
sudo ptcpdump -i any -v --pod-name test-ptcpdump.test-ns 'host 1.1.1.1'
```

确保 Pod 正在运行并发出网络请求（例如，一个 `wget` `1.1.1.1` 的容器）。捕获内容包括每个数据包旁边的 Pod 名称和命名空间，有助于即使在共享节点上也能区分流量。使用 README 中显示的 `<name>.<namespace>` 格式换成您自己的 Pod 名称。

## 输出示例

```
16:40:51.611855 vethf7fbf633 Out IP (tos 0x0, ttl 126, id 2681, offset 0, flags [none], proto TCP (6), length 44)
    1.1.1.1.80 > 10.244.0.6.60648: Flags [S.], cksum 0x9794, seq 2068807368, ack 3339143741, win 64240, options [mss 1460], length 0
    Process (pid 252148, cmd /usr/bin/wget, args wget -T 10 1.1.1.1)
    User (uid 0)
    ParentProc (pid 252127, cmd /bin/sh, args sh -c wget -T 10 1.1.1.1 || true)
    Container (name test, id 9ae7b846aee3bc959d4fefdb1aedb3eef42a8f5c6ce10d456e916159c966a874, image docker.io/library/alpine:3.18, labels {"io.cri-containerd.kind":"container","io.kubernetes.container.name":"test","io.kubernetes.pod.name":"test-ptcpdump","io.kubernetes.pod.namespace":"test-ns","io.kubernetes.pod.uid":"165311bb-64fd-4906-9ff6-3a40f6ea2efd"})
    Pod (name test-ptcpdump, namespace test-ns, UID 165311bb-64fd-4906-9ff6-3a40f6ea2efd, labels {"run":"test"}, annotations {"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"labels\":{\"run\":\"test\"},\"name\":\"test-ptcpdump\",\"namespace\":\"test-ns\"},\"spec\":{\"containers\":[{\"args\":[\"sh\",\"-c\",\"wget -T 10 1.1.1.1 || true\"],\"image\":\"alpine:3.18\",\"name\":\"test\"}]}}","kubernetes.io/config.seen":"2025-10-02T06:40:50.421577416Z","kubernetes.io/config.source":"api"})
```