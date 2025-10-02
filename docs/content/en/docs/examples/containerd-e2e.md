---
title: "Containerd Integration Capture"
weight: 240
---

## Case

- Mirror the CI workflows that validate containerd environments (`test_containerd.sh` and its filter variants).
- Capture outbound requests and filter by container IDs and names provided by nerdctl.
- Debug networking issues for a specific container by capturing its traffic.
- Verify network policies are being correctly applied to containers.
- Monitor container traffic to identify unexpected or malicious activity.

## Command

```bash
sudo ptcpdump -i any -v 'host 1.1.1.1'
```

Generate traffic using nerdctl:

```bash
docker run --rm alpine:3.18 sh -c 'wget -T 10 1.1.1.1'
```

ptcpdump annotates packets with the container metadata exposed by containerd. 
Focus on individual workloads via:

```bash
sudo ptcpdump -i any --container-id <id> 'host 1.1.1.1'
sudo ptcpdump -i any --container-name <name> 'host 1.1.1.1'
```

These steps replicate the coverage in the automated tests and serve as a 
reference when debugging containerd-based clusters.

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
