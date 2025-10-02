---
title: "Containerd 集成捕获"
weight: 240
---

## 使用场景

- 镜像 CI 工作流，用于验证 containerd 环境（`test_containerd.sh` 及其过滤器变体）。
- 捕获出站请求，并按 nerdctl 提供的容器 ID 和名称进行过滤。
- 通过捕获特定容器的流量来调试其网络问题。
- 验证网络策略是否正确应用于容器。
- 监控容器流量以识别意外或恶意活动。

## 命令

```bash
sudo ptcpdump -i any -v 'host 1.1.1.1'
```

使用 nerdctl 生成流量：

```bash
docker run --rm alpine:3.18 sh -c 'wget -T 10 1.1.1.1'
```

ptcpdump 使用 containerd 公开的容器元数据为数据包添加注释。
通过以下方式专注于单个工作负载：

```bash
sudo ptcpdump -i any --container-id <id> 'host 1.1.1.1'
sudo ptcpdump -i any --container-name <name> 'host 1.1.1.1'
```

这些步骤复制了自动化测试中的覆盖范围，并可作为调试基于 containerd 的集群时的参考。

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