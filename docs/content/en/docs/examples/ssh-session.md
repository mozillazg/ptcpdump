---
title: "Attach to an Existing SSH Session"
weight: 20
---

## Case

- Capture packets that belong to an already-active SSH session to audit long-running connections.
- Follow the `test_exist_connection.sh` integration test, highlighting how ptcpdump annotates server-side daemons such as `sshd`.
- Monitor an active SSH session for suspicious activity or unauthorized data transfer.
- Debug network performance issues affecting an ongoing SSH connection.
- Audit user activity within an SSH session for security compliance or forensic analysis.

## Command

```bash
sudo ptcpdump -i any -c 10 'port 22'
```

Run the command from the host that terminates SSH connections. While ptcpdump 
listens, reuse an open session or generate traffic (e.g., run a few shell commands). 
The capture shows both directions of TCP packets and includes the `sshd` command path 
in the metadata column.
