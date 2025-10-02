---
title: "Grab Packets in a Fresh Network Namespace"
weight: 60
---

## Case

- Capture traffic that originates inside network namespaces created on the fly—useful for debugging isolated test environments.
- The `test_netns_newly_exec.sh` script provisions two namespaces and runs curl through them while ptcpdump follows along.
- Debug applications that create temporary, isolated network environments for specific tasks.
- Analyze network behavior of sandboxed processes or containers that utilize fresh network namespaces.
- Verify the network configuration and isolation of newly provisioned network namespaces.

## Command

```bash
sudo ptcpdump -i any --netns newly -- bash testdata/create_netns.sh netns30 veth30 netns31 veth31
```

Run this from the repository root so the helper script under `testdata/` is available, 
or swap in your own setup logic. ptcpdump keeps up with the namespaces as they appear 
and disappear, annotating packets with the originating interface. 
Combine `--netns` with additional filters (like specific subnets) 
to focus on just the flows you care about.
