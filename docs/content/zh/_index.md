---
title: "ptcpdump: 基于 eBPF 的网络抓包工具"
linkTitle: "首页"
layout: "landing"
description: "一个兼容 tcpdump 的分析器，通过 eBPF 为每个数据包注入进程上下文。"
---

{{< blocks/cover title="欢迎使用 ptcpdump!" image_anchor="top" height="min" >}}
<div class="mx-auto">
	<a class="btn btn-lg btn-primary mr-3 mb-4" href="{{< relref "/docs/" >}}">
		开始使用 <i class="fas fa-arrow-alt-circle-right ml-2"></i>
	</a>
	<a class="btn btn-lg btn-secondary mr-3 mb-4" href="https://github.com/mozillazg/ptcpdump">
		查看 GitHub <i class="fab fa-github ml-2 "></i>
	</a>
	<p class="lead mt-5">进程感知，基于 eBPF 的 tcpdump</p>
</div>
{{< blocks/link-down color="info" >}}
{{< /blocks/cover >}}


{{% blocks/section color="light" type="row" %}}


{{% blocks/feature icon="fa-solid fa-sitemap" title="进程/容器感知" %}}
捕获带有完整进程、容器和 Kubernetes Pod 上下文的数据包。
{{% /blocks/feature %}}

{{% blocks/feature icon="fa-solid fa-filter" title="兼容 tcpdump" %}}
使用您所熟悉的标志和过滤语法，例如 `-i`、`-w`、`-A` 和 `pcap-filter(7)`。
{{% /blocks/feature %}}

{{% blocks/feature icon="fa-regular fa-handshake" title="带元数据的 PcapNG" %}}
将捕获的数据以 PcapNG 格式保存，其中嵌入了元数据，可直接在 Wireshark 中进行深入分析。
{{% /blocks/feature %}}


{{% /blocks/section %}}
