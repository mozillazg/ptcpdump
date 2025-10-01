---
title: "Installation"
weight: 1
---

You can download the statically linked executable for x86_64 and arm64 from the [releases page](https://github.com/mozillazg/ptcpdump/releases).

### Requirements

Linux kernel >= 5.2 (compiled with BPF and BTF support).

`ptcpdump` optionally requires debugfs. It has to be mounted in /sys/kernel/debug.
In case the folder is empty, it can be mounted with:

    mount -t debugfs none /sys/kernel/debug
