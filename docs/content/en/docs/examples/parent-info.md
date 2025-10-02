---
title: "Parent Process Insight"
weight: 80
---

## Case

- Expose the parent command responsible for network activity while capturing traffic to a remote host.
- Mirror the assertions in `test_parent_info.sh`, which ensures parent metadata propagates alongside child process details.
- Trace network activity back to its originating script or higher-level process, not just the immediate child process.
- Identify the full execution chain of a network request for security auditing or compliance purposes.
- Debug complex application behaviors where child processes inherit network capabilities from their parents.

## Command

```bash
sudo ptcpdump -i any 'dst host 1.1.1.1'
```

Kick off `curl -m 10 1.1.1.1` from a shell. The resulting output includes both the
`curl` process and its launching parent (e.g., the shell script), 
allowing you to tie packets to higher-level workflow controllers. 
Replaying the saved capture with `ptcpdump -r` keeps the parent metadata intact.


## Output Example

```
14:50:19.032537 ens33 curl.253365 Out IP 10.0.2.15.49650 > 1.1.1.1.80: Flags [S], seq 1688479772, win 64240, options [mss 1460,sackOK,TS val 2313046548 ecr 0,nop,wscale 7], length 0, ParentProc [bash.217538]
```
