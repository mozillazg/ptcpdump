---
title: "Kubernetes 集成捕获"
weight: 250
---

## 使用场景

- 总结基于 Kind 的端到端套件（`run_test_k8s.sh` 加上 pod/容器过滤器）。
- 捕获 pod 流量，按容器 ID 过滤，并验证多容器 pod。
- 在 Kubernetes 集群中调试网络策略和服务网格配置。
- 监控 pod 间通信以识别瓶颈或未经授权的数据流。
- 对在 Kubernetes pod 中运行的应用程序的 DNS 解析或外部服务连接问题进行故障排除。

## 命令

```bash
sudo ptcpdump -i any -v 'host 1.1.1.1'
```

在您的集群中：

```bash
kubectl create ns test-ns
kubectl -n test-ns apply -f testdata/test_k8s.yaml
kubectl -n test-ns wait --for=condition=Ready pod/test-ptcpdump
```

通过以下方式捕获重点流量：

```bash
sudo ptcpdump -i any --pod-name test-ptcpdump.test-ns 'host 1.1.1.1'
sudo ptcpdump -i any --container-id <id> 'host 1.1.1.1'
```

这些命令与 CI 覆盖范围相匹配，确保文档重点介绍由 `run_test_k8s_filter_by_pod_2.sh` 验证的 pod 范围捕获、容器名称过滤器和多容器行为。

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