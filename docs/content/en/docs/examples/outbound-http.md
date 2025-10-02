---
title: "Find Outbound HTTP Callers"
weight: 35
---

## Case

- Pinpoint which processes initiate HTTP connections to a specific site.
- Quickly spot unexpected clients attempting to reach `serverfault.com` on port 80.
- Identify applications or services making unauthorized HTTP requests to external domains.
- Troubleshoot connectivity issues to web services by observing the HTTP request and response flow.
- Monitor for data exfiltration attempts by tracking outbound HTTP connections to suspicious destinations.

## Command

```bash
sudo ptcpdump -i any -c 5 'port 80 and host serverfault.com'
```

Run the capture and reproduce the traffic you care about. ptcpdump prints 
the packets along with the responsible process (and container/pod if present), 
revealing the binary and command line that triggered the outbound HTTP request.

## Output Example

```
14:48:46.096204 ens33 curl.253100 Out IP 10.0.2.15.57132 > 172.64.148.218.80: Flags [S], seq 1685848518, win 64240, options [mss 1460,sackOK,TS val 3711113013 ecr 0,nop,wscale 7], length 0, ParentProc [bash.101064]
14:48:46.283661 ens33 curl.253100 In IP 172.64.148.218.80 > 10.0.2.15.57132: Flags [S.], seq 1647926, ack 1685848519, win 64240, options [mss 1460], length 0, ParentProc [bash.101064]
14:48:46.283726 ens33 curl.253100 Out IP 10.0.2.15.57132 > 172.64.148.218.80: Flags [.], seq 1685848519, ack 1647927, win 64240, length 0, ParentProc [bash.101064]
14:48:46.283901 ens33 curl.253100 Out IP 10.0.2.15.57132 > 172.64.148.218.80: Flags [P.], seq 1685848519:1685848598, ack 1647927, win 64240, length 79: HTTP: HEAD / HTTP/1.1, ParentProc [bash.101064]
14:48:46.284120 ens33 curl.253100 In IP 172.64.148.218.80 > 10.0.2.15.57132: Flags [.], seq 1647927, ack 1685848598, win 64240, length 0, ParentProc [bash.101064]
```
