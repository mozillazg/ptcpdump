---
title: "Write a PcapNG for Later"
weight: 120
---

## Case

- Capture packets to disk and replay them with either ptcpdump or tcpdump, per the assertions in `test_write_pcap.sh`.
- Archive network traffic for long-term storage, compliance, or post-incident forensic analysis.
- Share captured network data with security teams or developers for collaborative troubleshooting.
- Replay network scenarios in a controlled environment for testing intrusion detection systems or network performance.

## Command

```bash
sudo ptcpdump -i any -c 1 --print -w /tmp/ptcpdump_write.pcapng 'dst host 1.1.1.1 and tcp[tcpflags] = tcp-syn'
sudo tcpdump -n -r /tmp/ptcpdump_write.pcapng
sudo ptcpdump -r /tmp/ptcpdump_write.pcapng
```

Kick off the capture, issue `curl -m 10 1.1.1.1`, and inspect the stored file 
with both tools. The test makes sure the SYN appears in each readback and 
that ptcpdump writes a file tcpdump understands.
