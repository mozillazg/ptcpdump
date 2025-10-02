---
title: "Inspect ARP Probes"
weight: 140
---

## Case

- Capture ARP discovery traffic to confirm layer 2 visibility, following `test_arp.sh`.
- Diagnose address resolution issues or validating neighbor discovery in lab setups.
- Monitor for ARP storms or excessive ARP requests on a network segment.
- Verify that a specific host is (or is not) responding to ARP requests.
- Debug network connectivity issues where a host may not be resolving an IP to a MAC address correctly.

## Command

```bash
sudo ptcpdump -i any 'arp host 1.1.1.1'
```

Run `arping -w 10 -c 2 1.1.1.1` in parallel. ptcpdump records the 
ARP requests ("who-has 1.1.1.1") and stores them in a pcapng that 
tcpdump can replay later, mirroring the automated test.

## Output Example

```
14:15:25.031043 ens33 Out ARP, Request who-has 1.1.1.1 tell 10.0.2.15, length 28
14:15:26.036061 ens33 Out ARP, Request who-has 1.1.1.1 tell 10.0.2.15, length 28
```
