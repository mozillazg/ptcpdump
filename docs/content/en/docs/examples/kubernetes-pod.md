---
title: "Filter Traffic by Kubernetes Pod"
weight: 50
---

## Case

- Debug a single Kubernetes workload by pinning the capture to its Pod identity.
- Confirm ptcpdump's cluster awareness through CI pipeline workflows.
- Isolate and analyze network traffic for a specific microservice running within a multi-service pod.
- Verify that a pod is only communicating with its intended services and external endpoints.
- Troubleshoot network performance issues affecting a particular Kubernetes pod.

## Command

```bash
sudo ptcpdump -i any -v --pod-name test-ptcpdump.test-ns 'host 1.1.1.1'
```

Make sure the Pod is running and issuing network requests
(for example, a container that `wget`s `1.1.1.1`). The capture includes the 
Pod name and namespace next to each packet, helping differentiate 
traffic even on shared nodes. Swap in your own Pod name 
using the `<name>.<namespace>` format shown in the README.

## Output Example

```
16:40:51.611855 vethf7fbf633 Out IP (tos 0x0, ttl 126, id 2681, offset 0, flags [none], proto TCP (6), length 44)
    1.1.1.1.80 > 10.244.0.6.60648: Flags [S.], cksum 0x9794, seq 2068807368, ack 3339143741, win 64240, options [mss 1460], length 0
    Process (pid 252148, cmd /usr/bin/wget, args wget -T 10 1.1.1.1)
    User (uid 0)
    ParentProc (pid 252127, cmd /bin/sh, args sh -c wget -T 10 1.1.1.1 || true)
    Container (name test, id 9ae7b846aee3bc959d4fefdb1aedb3eef42a8f5c6ce10d456e916159c966a874, image docker.io/library/alpine:3.18, labels {"io.cri-containerd.kind":"container","io.kubernetes.container.name":"test","io.kubernetes.pod.name":"test-ptcpdump","io.kubernetes.pod.namespace":"test-ns","io.kubernetes.pod.uid":"165311bb-64fd-4906-9ff6-3a40f6ea2efd"})
    Pod (name test-ptcpdump, namespace test-ns, UID 165311bb-64fd-4906-9ff6-3a40f6ea2efd, labels {"run":"test"}, annotations {"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"labels\":{\"run\":\"test\"},\"name\":\"test-ptcpdump\",\"namespace\":\"test-ns\"},\"spec\":{\"containers\":[{\"args\":[\"sh\",\"-c\",\"wget -T 10 1.1.1.1 || true\"],\"image\":\"alpine:3.18\",\"name\":\"test\"}]}}\n","kubernetes.io/config.seen":"2025-10-02T06:40:50.421577416Z","kubernetes.io/config.source":"api"})
```
