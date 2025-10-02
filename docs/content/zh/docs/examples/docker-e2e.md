---
title: "Docker 集成捕获"
weight: 230
---

## 使用场景

- 复制在 CI 中运行的端到端容器场景（`test_docker.sh` 和相关的过滤器脚本）。
- 捕获出站流量，然后通过 ID 或名称深入研究特定于容器的过滤器。
- 调试 Docker 容器之间或容器与外部服务之间的网络连接问题。
- 监控特定 Docker 容器生成的网络流量，以确保合规性或检测异常。
- 验证应用于 Docker 容器的网络配置和防火墙规则。

## 命令

```bash
sudo ptcpdump -i any -v 'host 1.1.1.1'
```

在捕获运行时，启动示例工作负载：

```bash
docker run --rm busybox:1 sh -c 'wget -T 10 1.1.1.1'
docker run --rm alpine:3.18 sh -c 'wget -T 5 1.1.1.1'
```

ptcpdump 为每个流标记容器 ID 和参数（例如，`wget -T 10`）。要专注于特定的工作负载，请添加过滤器：

```bash
sudo ptcpdump -i any --container-id <id> 'host 1.1.1.1'
sudo ptcpdump -i any --container-name <name> 'host 1.1.1.1'
```

这些命令反映了 CI 脚本，确保文档提供了真实的 Docker 故障排除步骤。

## 输出示例

```
$ sudo ptcpdump -i any -v 'host 1.1.1.1'
14:21:19.932603 veth4c1652a Out IP (tos 0x0, ttl 64, id 47726, offset 0, flags [DF], proto TCP (6), length 60)
    172.17.0.3.37144 > 1.1.1.1.80: Flags [S], cksum 0xae44, seq 92667574, win 64240, options [mss 1460,sackOK,TS val 4280046680 ecr 0,nop,wscale 7], length 0
    Process (pid 241879, cmd /usr/bin/wget, args wget -T 10 1.1.1.1)
    User (uid 0)
    ParentProc (pid 241858, cmd /usr/bin/containerd-shim-runc-v2, args /usr/bin/containerd-shim-runc-v2 -namespace moby -id 78f1713c7d0f329f35b4c1ab5ef189d47a1c16e40fdff3317943b4fb3b0f2890 -address /run/containerd/containerd.sock)
    Container (name , id 78f1713c7d0f329f35b4c1ab5ef189d47a1c16e40fdff3317943b4fb3b0f2890, image , labels {"com.docker/engine.bundle.path":"/var/run/docker/containerd/78f1713c7d0f329f35b4c1ab5ef189d47a1c16e40fdff3317943b4fb3b0f2890"})
14:21:19.932626 vethf95de12 In IP (tos 0x0, ttl 64, id 47726, offset 0, flags [DF], proto TCP (6), length 60)
    172.17.0.3.37144 > 1.1.1.1.80: Flags [S], cksum 0xae44, seq 92667574, win 64240, options [mss 1460,sackOK,TS val 4280046680 ecr 0,nop,wscale 7], length 0
    Process (pid 241879, cmd /usr/bin/wget, args wget -T 10 1.1.1.1)
    User (uid 0)
    ParentProc (pid 241858, cmd /usr/bin/containerd-shim-runc-v2, args /usr/bin/containerd-shim-runc-v2 -namespace moby -id 78f1713c7d0f329f35b4c1ab5ef189d47a1c16e40fdff3317943b4fb3b0f2890 -address /run/containerd/containerd.sock)
    Container (name , id 78f1713c7d0f329f35b4c1ab5ef189d47a1c16e40fdff3317943b4fb3b0f2890, image , labels {"com.docker/engine.bundle.path":"/var/run/docker/containerd/78f1713c7d0f329f35b4c1ab5ef189d47a1c16e40fdff3317943b4fb3b0f2890"})
14:21:19.932627 docker0 In IP (tos 0x0, ttl 64, id 47726, offset 0, flags [DF], proto TCP (6), length 60)
    172.17.0.3.37144 > 1.1.1.1.80: Flags [S], cksum 0xae44, seq 92667574, win 64240, options [mss 1460,sackOK,TS val 4280046680 ecr 0,nop,wscale 7], length 0
    Process (pid 241879, cmd /usr/bin/wget, args wget -T 10 1.1.1.1)
    User (uid 0)
    ParentProc (pid 241858, cmd /usr/bin/containerd-shim-runc-v2, args /usr/bin/containerd-shim-runc-v2 -namespace moby -id 78f1713c7d0f329f35b4c1ab5ef189d47a1c16e40fdff3317943b4fb3b0f2890 -address /run/containerd/containerd.sock)
    Container (name , id 78f1713c7d0f329f35b4c1ab5ef189d47a1c16e40fdff3317943b4fb3b0f2890, image , labels {"com.docker/engine.bundle.path":"/var/run/docker/containerd/78f1713c7d0f329f35b4c1ab5ef189d47a1c16e40fdff3317943b4fb3b0f2890"})
14:21:19.932671 ens33 Out IP (tos 0x0, ttl 63, id 47726, offset 0, flags [DF], proto TCP (6), length 60)
    10.0.2.15.37144 > 1.1.1.1.80: Flags [S], cksum 0xe3f, seq 92667574, win 64240, options [mss 1460,sackOK,TS val 4280046680 ecr 0,nop,wscale 7], length 0
```