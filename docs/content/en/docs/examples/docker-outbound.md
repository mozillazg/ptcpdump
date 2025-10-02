---
title: "Watch Containers Reach Out"
weight: 40
---

## Case

- Observe outbound connections from multiple containers and keep their identities in the capture.
- Audit which containers are making external network calls and to what destinations.
- Identify unexpected outbound connections that might indicate a security compromise or misconfiguration.
- Verify that containers are only communicating with approved external services.

## Command

```bash
sudo ptcpdump -i any -v 'host 1.1.1.1'
```

Start the capture before launching your containers (for example with `docker run busybox:1 wget -T 10 1.1.1.1`). The log output shows the PID, container ID, and command arguments (such as `wget`) for each packet, making it easy to audit which container initiated the traffic. Use `--container-id` or `--container-name` to focus on a specific workload.

## Output Example

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
