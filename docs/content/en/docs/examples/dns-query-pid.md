---
title: "Identify DNS Query Processes"
weight: 45
---

## Case

- Discover which processes send DNS traffic to a given resolver.
- Trace outbound requests by combining port and host filters.
- Identify which application is responsible for high volumes of DNS traffic.
- Detect malware or other unwanted software that is making DNS queries.
- Troubleshoot DNS resolution issues by identifying which process is sending queries to a misconfigured or unresponsive DNS server.

## Command

```bash
sudo ptcpdump -i any 'port 53 and host 1.1.1.1'
```

Run the capture during DNS lookups. ptcpdump annotates each packet with the PID 
and command line responsible for the query, making it easy to pinpoint unexpected 
resolvers or misconfigured services.

## Output Example

```
14:25:26.218806 ens33 dig.242610 Out IP 10.0.2.15.38641 > 1.1.1.1.53: 42024+ [1au] A? kernel.org. (51), ParentProc [bash.101064]
14:25:26.387748 ens33 dig.242610 In IP 1.1.1.1.53 > 10.0.2.15.38641: 42024 1/0/1 A 139.178.84.217 (55), ParentProc [bash.101064]
```
