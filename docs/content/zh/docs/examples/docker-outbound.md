---
title: "观察容器的出站连接"
weight: 40
---

## 使用场景

- 观察来自多个容器的出站连接，并在捕获中保留它们的身份。
- 审计哪些容器正在进行外部网络调用以及调用目标。
- 识别可能表示安全漏洞或配置错误的意外出站连接。
- 验证容器是否仅与经批准的外部服务通信。

## 命令

```bash
sudo ptcpdump -i any -v 'host 1.1.1.1'
```

在启动容器之前开始捕获（例如，使用 `docker run busybox:1 wget -T 10 1.1.1.1`）。日志输出会显示每个数据包的 PID、容器 ID 和命令参数（例如 `wget`），从而可以轻松审计是哪个容器发起了流量。使用 `--container-id` 或 `--container-name` 来专注于特定的工作负载。

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