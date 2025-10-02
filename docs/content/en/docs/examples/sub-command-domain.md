---
title: "Launch Curl Against a Domain"
weight: 190
---

## Case

- Spawn a command that resolves hostnames and monitor its traffic, echoing `test_sub_curl_domain_program.sh`.
- Demonstrate capturing DNS-resolved HTTP requests for external domains while ptcpdump handles process attribution.
- Verify that a specific application correctly resolves domain names and connects to the intended IP addresses.
- Troubleshoot DNS resolution failures for applications by observing the entire DNS lookup and connection process.
- Monitor outbound connections to external domains initiated by a specific command or script.

## Command

```bash
sudo ptcpdump -i any -v -- curl -m 10 https://ubuntu.com
```

ptcpdump invokes curl, captures the HTTP exchange (including SYN packets toward the 
resolved IP), and records metadata showing the full command line 
`curl -m 10 ubuntu.com`. Useful for capturing short-lived runs without 
missing the initial handshake.


## Output Example

```
15:08:28.079227 lo Out IP (tos 0x0, ttl 64, id 13848, offset 0, flags [DF], proto UDP (17), length 67)
    127.0.0.1.37308 > 127.0.0.53.53: 20673+ [1au] A? ubuntu.com. (39)
    Process (pid 254949, cmd /usr/bin/curl, args curl -m 10 https://ubuntu.com)
    User (uid 0)
    ParentProc (pid 254941, cmd ptcpdump, args ptcpdump -- curl -m 10 https://ubuntu.com)
15:08:28.110391 lo Out IP (tos 0x0, ttl 1, id 47265, offset 0, flags [DF], proto UDP (17), length 115)
    127.0.0.53.53 > 127.0.0.1.37308: 20673 3/0/1 A 185.125.190.29, A 185.125.190.20, A 185.125.190.21 (87)
    Process (pid 254949, cmd /usr/bin/curl, args curl -m 10 https://ubuntu.com)
    User (uid 0)
    ParentProc (pid 254941, cmd ptcpdump, args ptcpdump -- curl -m 10 https://ubuntu.com)
...
15:08:28.110417 lo In IP (tos 0x0, ttl 1, id 47265, offset 0, flags [DF], proto UDP (17), length 115)
    127.0.0.53.53 > 127.0.0.1.37308: 20673 3/0/1 A 185.125.190.29, A 185.125.190.20, A 185.125.190.21 (87)
    Process (pid 254949, cmd /usr/bin/curl, args curl -m 10 https://ubuntu.com)
    User (uid 0)
    ParentProc (pid 254941, cmd ptcpdump, args ptcpdump -- curl -m 10 https://ubuntu.com)
...
15:08:28.440246 ens33 Out IP (tos 0x0, ttl 64, id 18470, offset 0, flags [DF], proto TCP (6), length 60)
    10.0.2.15.33824 > 185.125.190.29.443: Flags [S], cksum 0x83d8, seq 1966522591, win 64240, options [mss 1460,sackOK,TS val 2720366192 ecr 0,nop,wscale 7], length 0
    Process (pid 254949, cmd /usr/bin/curl, args curl -m 10 https://ubuntu.com)
    User (uid 0)
    ParentProc (pid 254941, cmd ptcpdump, args ptcpdump -- curl -m 10 https://ubuntu.com)
```
