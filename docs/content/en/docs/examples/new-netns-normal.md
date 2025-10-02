---
title: "Detect Newly Created NetNS"
weight: 180
---

## Case

- Follow namespaces that appear after the capture starts, just like `test_netns_newly_normal.sh`.
- Handy for integration tests where ephemeral namespaces are created dynamically.
- Monitor network activity in dynamically created environments, such as CI/CD pipelines or ephemeral test setups.
- Track network communication of applications that create isolated network namespaces for security or resource management.
- Debug network issues in container orchestration systems where new network namespaces are frequently provisioned.

## Command

```bash
sudo ptcpdump -i any  --netns newly 'icmp'
```

Start ptcpdump first, then add namespaces and generate traffic—for example 
using the helper from `test_netns_newly_normal.sh` that creates 
veth pairs and pings between `192.168.64.1` and `192.168.64.2`. 
ptcpdump automatically attaches to the new namespaces and records 
the bidirectional ICMP exchanges.
