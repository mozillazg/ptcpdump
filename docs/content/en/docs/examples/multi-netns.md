---
title: "Capture Across Multiple NetNS"
weight: 170
---

## Case

- Monitor traffic that flows between static network namespaces while tracking both endpoints.
- Align with `test_netns.sh`, where ptcpdump watches traffic between two namespaces linked via a veth pair.
- Debug communication issues between applications running in different network namespaces.
- Verify network isolation and routing configurations in complex network setups involving multiple namespaces.
- Monitor traffic flow in virtualized environments where each virtual machine or container might reside in its own network namespace.

## Command

```bash
sudo bash -c '
  ip netns add netns10
  ip netns add netns11
  ip link add veth10 type veth peer name veth11
  ip link set veth10 netns netns10
  ip link set veth11 netns netns11
  ip -n netns10 addr add 192.168.64.1/24 dev veth10
  ip -n netns11 addr add 192.168.64.2/24 dev veth11
  ip -n netns10 link set veth10 up
  ip -n netns11 link set veth11 up
  timeout 30s ptcpdump -i any --netns netns10 --netns netns11 -c 4 \
    "icmp and host 192.168.64.2" &
  sleep 20
  ip netns exec netns10 ping -c 2 192.168.64.2
  wait
'
```

ptcpdump records both directions of the namespace-to-namespace traffic and 
saves a capture you can replay. Include a cleanup step afterward to 
delete the namespaces and veths.
