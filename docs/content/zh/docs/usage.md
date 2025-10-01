---
title: "用法"
weight: 2
---

### 示例命令

支持 tcpdump 支持的包过滤语法以及常用命令行参数：

```
sudo ptcpdump -i eth0 tcp
sudo ptcpdump -i eth0 -A -s 0 -n -v tcp and port 80 and host 10.10.1.1
sudo ptcpdump -i any -s 0 -n -v -C 100MB -W 3 -w test.pcapng 'tcp and port 80 and host 10.10.1.1'
sudo ptcpdump -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0'
```

对多个网络接口进行抓包：

```
sudo ptcpdump -i eth0 -i lo
```

按进程过滤：

```
sudo ptcpdump -i any --pid 1234 --pid 233 -f
sudo ptcpdump -i any --pname curl
```

通过执行目标程序的方式进行抓包：

```
sudo ptcpdump -i any -- curl ubuntu.com
```

按容器过滤：

```
sudo ptcpdump -i any --container-id 36f0310403b1
sudo ptcpdump -i any --container-name test
```

按 Pod 过滤

```
sudo ptcpdump -i any --pod-name test.default
```

以 PcapNG 格式保存捕获的流量:

```
sudo ptcpdump -i any -w demo.pcapng
sudo ptcpdump -i any -w - port 80 | tcpdump -n -r -
sudo ptcpdump -i any -w - port 80 | tshark -r -
```

支持对其他网络命名空间下的网络接口进行抓包:

```
sudo ptcpdump -i lo --netns /run/netns/foo --netns /run/netns/bar
sudo ptcpdump -i any --netns /run/netns/foobar
sudo ptcpdump -i any --netns /proc/26/ns/net
```
