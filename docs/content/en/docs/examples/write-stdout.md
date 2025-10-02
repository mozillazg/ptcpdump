---
title: "Stream Capture to Stdout"
weight: 130
---

## Case

- Feed live packets directly into another tool by writing captures to stdout, the workflow validated by `test_write_stdout.sh`.
- Perfect when you want tcpdump, tshark, or a custom parser to consume packets without temporary files.
- Integrate ptcpdump with other command-line tools for real-time analysis or filtering of network traffic.
- Process live network data with custom scripts or parsers without the overhead of writing to disk.
- Forward network captures directly to a remote analysis server or SIEM system.

## Command

```bash
sudo ptcpdump -i any -c 1 -w - 'dst host 1.1.1.1 and tcp[tcpflags] = tcp-syn' | tcpdump -c 1 -n -r -
```

While the pipeline runs, execute `curl -m 10 1.1.1.1`. tcpdump reads the packets 
straight from stdin, and ptcpdump still prints annotated output to the console. 
The test ensures the SYN survives the round trip.
