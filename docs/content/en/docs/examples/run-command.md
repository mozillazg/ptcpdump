---
title: "Launch and Trace a Curl Run"
weight: 30
---

## Case

- When you need to grab packets from a short-lived program, let ptcpdump spawn it so no traffic slips away.
- The `test_sub_program.sh` script exercises this pattern directly from the README guidance about using `--`.
- Capture network traffic of a short-lived script or command that exits quickly, ensuring no packets are missed.
- Debug network interactions of a specific program from its very inception, including initial connection attempts.
- Automate network capture for integration tests where a program's network behavior needs to be verified.

## Command

```bash
sudo ptcpdump -i any -c 10 -- curl -m 10 http://1.1.1.1
```

ptcpdump starts `curl` on your behalf, tags every packet with the launched command, 
and stops automatically after ten packets. Adjust the filter or count to match 
your workload.


## Output Example

```
15:07:08.407094 ens33 curl.254838 Out IP 10.0.2.15.38924 > 1.1.1.1.80: Flags [S], seq 361565032, win 64240, options [mss 1460,sackOK,TS val 2314055923 ecr 0,nop,wscale 7], length 0, ParentProc [ptcpdump.254829]
15:07:08.570968 ens33 curl.254838 In IP 1.1.1.1.80 > 10.0.2.15.38924: Flags [S.], seq 739065025, ack 361565033, win 64240, options [mss 1460], length 0, ParentProc [ptcpdump.254829]
15:07:08.571075 ens33 curl.254838 Out IP 10.0.2.15.38924 > 1.1.1.1.80: Flags [.], seq 361565033, ack 739065026, win 64240, length 0, ParentProc [ptcpdump.254829]
15:07:08.571178 ens33 curl.254838 Out IP 10.0.2.15.38924 > 1.1.1.1.80: Flags [P.], seq 361565033:361565103, ack 739065026, win 64240, length 70: HTTP: GET / HTTP/1.1, ParentProc [ptcpdump.254829]
15:07:08.571380 ens33 curl.254838 In IP 1.1.1.1.80 > 10.0.2.15.38924: Flags [.], seq 739065026, ack 361565103, win 64240, length 0, ParentProc [ptcpdump.254829]
<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>cloudflare</center>
</body>
</html>
15:07:08.734100 ens33 curl.254838 In IP 1.1.1.1.80 > 10.0.2.15.38924: Flags [P.], seq 739065026:739065412, ack 361565103, win 64240, length 386: HTTP: HTTP/1.1 301 Moved Permanently, ParentProc [ptcpdump.254829]
```
