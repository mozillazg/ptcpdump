---
title: "ptcpdump: An eBPF-based Packet Analyzer"
linkTitle: "Home"
layout: "landing"
description: "A tcpdump-compatible analyzer that enriches every packet with process context, powered by eBPF."
---

{{< blocks/cover title="Welcome to ptcpdump!" image_anchor="top" height="min" >}}
<div class="mx-auto">
	<a class="btn btn-lg btn-primary mr-3 mb-4" href="{{< relref "/docs/" >}}">
		Get Started <i class="fas fa-arrow-alt-circle-right ml-2"></i>
	</a>
	<a class="btn btn-lg btn-secondary mr-3 mb-4" href="https://github.com/mozillazg/ptcpdump">
		View on GitHub <i class="fab fa-github ml-2 "></i>
	</a>
	<p class="lead mt-5">Process-aware, eBPF-based tcpdump</p>
</div>

{{< blocks/link-down color="info" >}}
{{< /blocks/cover >}}


{{% blocks/section color="light" type="row" %}}


{{% blocks/feature icon="fa-solid fa-sitemap" title="Process/Container Aware" %}}
Capture packets with full process, container, and Kubernetes pod context.
{{% /blocks/feature %}}

{{% blocks/feature icon="fa-solid fa-filter" title="tcpdump Compatible" %}}
Use the same flags and filter syntax you already know, like `-i`, `-w`, `-A`, and `pcap-filter(7)`.
{{% /blocks/feature %}}

{{% blocks/feature icon="fa-regular fa-handshake" title="PcapNG with Metadata" %}}
Save captures in PcapNG format with embedded metadata, ready for deep analysis in Wireshark.
{{% /blocks/feature %}}

{{% /blocks/section %}}
