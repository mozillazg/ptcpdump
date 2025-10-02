---
title: "Kubernetes Integration Capture"
weight: 250
---

## Case

- Summarize the Kind-based end-to-end suite (`run_test_k8s.sh` plus pod/container filters).
- Capture pod traffic, filter by container ID, and validate multi-container pods.
- Debug network policies and service mesh configurations within a Kubernetes cluster.
- Monitor inter-pod communication to identify bottlenecks or unauthorized data flows.
- Troubleshoot DNS resolution or external service connectivity issues for applications running in Kubernetes pods.

## Command

```bash
sudo ptcpdump -i any -v 'host 1.1.1.1'
```

Within your cluster:

```bash
kubectl create ns test-ns
kubectl -n test-ns apply -f testdata/test_k8s.yaml
kubectl -n test-ns wait --for=condition=Ready pod/test-ptcpdump
```

Capture focused traffic via:

```bash
sudo ptcpdump -i any --pod-name test-ptcpdump.test-ns 'host 1.1.1.1'
sudo ptcpdump -i any --container-id <id> 'host 1.1.1.1'
```

These commands match the CI coverage, ensuring the docs highlight pod-scoped captures, 
container-name filters, and multi-container behavior validated by `run_test_k8s_filter_by_pod_2.sh`.

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
