---
title: "Usage"
weight: 2
---

### Example commands

Filter like tcpdump:

    sudo ptcpdump -i eth0 tcp
    sudo ptcpdump -i eth0 -A -s 0 -n -v tcp and port 80 and host 10.10.1.1
    sudo ptcpdump -i any -s 0 -n -v -C 100MB -W 3 -w test.pcapng 'tcp and port 80 and host 10.10.1.1'
    sudo ptcpdump -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0'

Multiple interfaces:

    sudo ptcpdump -i eth0 -i lo

Filter by process or user:

    sudo ptcpdump -i any --pid 1234 --pid 233 -f
    sudo ptcpdump -i any --pname curl
    sudo ptcpdump -i any --uid 1000

Capture by process via run target program:

    sudo ptcpdump -i any -- curl ubuntu.com

Filter by container or pod:

    sudo ptcpdump -i any --container-id 36f0310403b1
    sudo ptcpdump -i any --container-name test
    sudo ptcpdump -i any --pod-name test.default

Save data in PcapNG format:

    sudo ptcpdump -i any -w demo.pcapng
    sudo ptcpdump -i any -w - port 80 | tcpdump -n -r -
    sudo ptcpdump -i any -w - port 80 | tshark -r -


Capturing interfaces in other network namespaces:

    sudo ptcpdump -i lo --netns /run/netns/foo --netns /run/netns/bar
    sudo ptcpdump -i any --netns /run/netns/foobar
    sudo ptcpdump -i any --netns /proc/26/ns/net
