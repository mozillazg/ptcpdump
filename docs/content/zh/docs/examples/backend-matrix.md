---
title: "后端矩阵覆盖范围"
weight: 260
---

## 使用场景

- 了解 ptcpdump 在所支持的 eBPF 后端（`tc`、`cgroup-skb`、`tp-btf` 和 `socket-filter`）中的行为，与 GitHub Actions 矩阵保持一致。
- 验证与各种内核的兼容性。
- 确定哪个 eBPF 后端在您的系统上针对特定工作负载性能最佳。
- 对可能特定于某个内核版本或 eBPF 后端的捕获问题进行故障排除。
- 根据内核版本和所需功能，为您的环境选择最合适的后端。

## 命令

每个后端都使用相同的烟雾测试套件进行测试：

```bash
sudo ptcpdump -i any --backend tc -c 2
sudo ptcpdump -i any --backend cgroup-skb -c 2
sudo ptcpdump -i any --backend tp-btf -c 2
sudo ptcpdump -i any --backend socket-filter -c 2
```

将这些与代表性场景（例如环回 ICMP 或 curl SYN 捕获）配对。
在 CI 中，little-vm-helper 会提供从 4.19 到 bpf-next 的内核；
请查阅 `.github/workflows/test.yml` 以查看哪个测试在哪个后端上运行。
此参考页面将矩阵与可操作的命令联系起来。
有关每个后端的更多详细信息，请参阅[后端指南](../backends/)。
