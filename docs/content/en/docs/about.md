---
title: "Overview"
weight: 2
---

## What is ptcpdump?

**ptcpdump** is a tcpdump-compatible packet analyzer powered by eBPF. Its key feature is the ability to automatically annotate packets with process, container, and Kubernetes pod metadata where detectable. This enriches the packet capture, making it easier to understand which application is responsible for specific network traffic.

![Wireshark Screenshot](/images/wireshark.png)

## Inspiration

This project was inspired by [jschwinger233/skbdump](https://github.com/jschwinger233/skbdump).

## License

`ptcpdump` is open source software licensed under the **MIT License**.

## Contributing

Contributions are welcome! Please feel free to open an issue or submit a pull request on our [GitHub repository](https://github.com/mozillazg/ptcpdump).
