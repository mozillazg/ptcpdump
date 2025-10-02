---
title: "Rotate with File Count Limit"
weight: 220
---

## Case

- Limit how many rotated files are retained, as demonstrated in `test_rotate_filesize_with_count.sh`.
- Ideal when you want a sliding window of recent traffic.
- Manage disk space efficiently when continuously capturing traffic over long periods.
- Ensure that only the most recent network activity is preserved for analysis.
- Implement a rolling buffer for network forensics, automatically discarding older captures.

## Command

```bash
sudo ptcpdump -i any -C 1kb -W 3 -w /tmp/ptcpdump_rotate_count.pcap 'port 8087 and host 127.0.0.1'
```

Generate sustained traffic (again, a large transfer via `nc` plus `curl`) 
and ptcpdump keeps only the most recent three files. The automated test 
ensures exactly three files remain and that each is readable afterwards.
