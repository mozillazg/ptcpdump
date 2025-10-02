---
title: "Read an Existing PcapNG"
weight: 110
---

## Case

- Open captures produced by other tools and enrich them with ptcpdump's decoding, just as `test_read_pcap.sh` validates.
- Re-examine historical network data with enhanced context, such as the originating process information.
- Share network captures with colleagues who can then use ptcpdump to gain deeper insights into the traffic.

## Command

```bash
sudo ptcpdump -i any -c 1 -w /tmp/ptcpdump_read.pcapng 'dst host 1.1.1.1 and tcp[tcpflags] = tcp-syn'
sudo ptcpdump -r /tmp/ptcpdump_read.pcapng
```

The first command captures a SYN with ptcpdump; the second replays the file through ptcpdump, 
rendering the same packet with familiar formatting. The test suite ensures the output matches expectations, 
including the SYN flag check.
