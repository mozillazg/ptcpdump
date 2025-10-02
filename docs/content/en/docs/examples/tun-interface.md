---
title: "Trace Traffic on a TUN Interface"
weight: 160
---

## Case

- Inspect packets inside a userspace TUN device, following the richer scenario in `test_tun.sh`.
- Validate VPN or overlay setups that rely on injected interfaces.
- Debug VPN or overlay network configurations by inspecting traffic flowing through the TUN device.
- Verify the correct encapsulation and decapsulation of packets in a tunnel.
- Analyze the network behavior of applications that create and utilize TUN interfaces for specialized networking.

## Command

```bash
sudo bash -c '
  ip netns add tun_test_ns
  ip netns exec tun_test_ns ip tuntap add dev tun0 mode tun
  ip netns exec tun_test_ns ip addr add 10.8.0.1 peer 10.8.0.2 dev tun0
  ip netns exec tun_test_ns ip link set tun0 up
  timeout 60s ptcpdump -i any -c 4 --netns tun_test_ns -v \
    "icmp and host 10.8.0.2" &
  sleep 20
  ip netns exec tun_test_ns ping -c 3 10.8.0.2 || true
  wait
'
```

The namespace creation mirrors the automated test: ptcpdump listens inside `tun_test_ns`,
captures the ICMP attempts toward the peer address, and saves the results to disk 
for review. Clean up the namespace after the run (`ip netns del tun_test_ns`).
