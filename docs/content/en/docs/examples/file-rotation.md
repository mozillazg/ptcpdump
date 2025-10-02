---
title: "Rotate Capture Files by Size"
weight: 210
---

## Case

- Keep rolling captures bounded by size, matching `test_rotate_filesize.sh`.
- When streaming large transfers you can rotate pcaps automatically and archive them safely.
- Prevent single capture files from growing excessively large and becoming unmanageable.
- Facilitate easier transfer and analysis of network captures by breaking them into smaller, more manageable chunks.
- Implement continuous network monitoring with automatic archiving of capture data.

## Command

```bash
sudo ptcpdump -i any -C 1kb -w /tmp/ptcpdump_rotate.pcap 'port 8087 and host 127.0.0.1'
```

Serve a sizable response (for example, `dd` piping 100 MiB through `nc -l -p 8087`) 
and fetch it with `curl --retry 2 --retry-all-errors http://127.0.0.1:8087`. 
ptcpdump rotates files once they exceed 1 KiB. The test verifies multiple 
files are produced and that each can be read back with `ptcpdump -r`.
