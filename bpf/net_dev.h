#ifndef __PTCPDUMP_NET_DEV_H__
#define __PTCPDUMP_NET_DEV_H__

#include "compat.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define IFNAMSIZ 16
#define FS_NAME_LEN 8
#define PATH_MAX 4096

struct netdevice_buf_t {
    u64 dev;
    u64 net;
};

struct netdevice_t {
    u32 netns_id;
    u32 ifindex;
    char name[IFNAMSIZ];
};

struct new_netdevice_event_t {
    struct netdevice_t dev;
};

struct mount_event_t {
    char fs[FS_NAME_LEN];
    char src[PATH_MAX];
    char dest[PATH_MAX];
};

struct netdevice_change_event_t {
    struct netdevice_t old_device;
    struct netdevice_t new_device;
};

const struct mount_event_t *unused12 __attribute__((unused));
const struct netdevice_change_event_t *unused13 __attribute__((unused));
const struct new_netdevice_event_t *unused14 __attribute__((unused));

#ifdef ENABLE_NET_DEV_W

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100);
    __type(key, u64);
    __type(value, struct netdevice_buf_t);
} ptcpdump_netdevice_bufs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100);
    __type(key, u64);
    __type(value, struct netdevice_t);
} ptcpdump_tid_netdevice_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} ptcpdump_new_netdevice_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} ptcpdump_netdevice_change_events SEC(".maps");

struct enter_mount_buf_t {
    u64 fs;
    u64 src;
    u64 dest;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100);
    __type(key, u64);
    __type(value, struct enter_mount_buf_t);
} ptcpdump_enter_mount_bufs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct mount_event_t);
} ptcpdump_mount_event_stack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} ptcpdump_mount_events SEC(".maps");

const struct new_netdevice_event_t *unused10 __attribute__((unused));
const struct netdevice_change_event_t *unused11 __attribute__((unused));

SEC("tracepoint/syscalls/sys_enter_mount")
int ptcpdump_tracepoint__syscalls__sys_enter_mount(struct trace_event_raw_sys_enter *ctx) {
    u64 tid = bpf_get_current_pid_tgid();
    struct enter_mount_buf_t val = {0};
    val.src = (u64)BPF_CORE_READ(ctx, args[0]);
    val.dest = (u64)BPF_CORE_READ(ctx, args[1]);
    val.fs = (u64)BPF_CORE_READ(ctx, args[2]);
    bpf_map_update_elem(&ptcpdump_enter_mount_bufs, &tid, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mount")
int ptcpdump_tracepoint__syscalls__sys_exit_mount(struct trace_event_raw_sys_exit *ctx) {
    if (ctx->ret != 0) {
        goto out;
    }

    u64 tid = bpf_get_current_pid_tgid();
    struct enter_mount_buf_t *buf;
    buf = bpf_map_lookup_elem(&ptcpdump_enter_mount_bufs, &tid);
    if (!buf) {
        goto out;
    }
    bpf_map_delete_elem(&ptcpdump_enter_mount_bufs, &tid);

    struct mount_event_t *event;
#ifdef LEGACY_KERNEL
    u32 u32_zero = 0;
#endif
    event = bpf_map_lookup_elem(&ptcpdump_mount_event_stack, &u32_zero);
    if (!event) {
        debug_log("[ptcpdump] loopup ptcpdump_mount_event_stack failed\n");
        goto out;
    }

    bpf_probe_read_user_str(&event->src, sizeof(event->src), (void *)buf->src);
    bpf_probe_read_user_str(&event->dest, sizeof(event->dest), (void *)buf->dest);
    bpf_probe_read_user_str(&event->fs, sizeof(event->fs), (void *)buf->fs);

    //    debug_log("new mount, src: %s, dest: %s, fs: %s\n", event->src, event->dest, event->fs);
    int event_ret = bpf_perf_event_output(ctx, &ptcpdump_mount_events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    if (event_ret != 0) {
        debug_log("[ptcpdump] bpf_perf_event_output ptcpdump_mount_events failed: %d\n", event_ret);
    }

out:
    return 0;
}

SEC("kprobe/register_netdevice")
int BPF_KPROBE(ptcpdump_kprobe__register_netdevice, struct net_device *dev) {
    u64 tid = bpf_get_current_pid_tgid();
    struct netdevice_buf_t val = {0};
    val.dev = (u64)dev;
    bpf_map_update_elem(&ptcpdump_netdevice_bufs, &tid, &val, BPF_ANY);

    return 0;
}

static __always_inline void parse_net_device(struct net_device *dev, struct netdevice_t *target) {
    BPF_CORE_READ_INTO(&target->ifindex, dev, ifindex);
    BPF_CORE_READ_STR_INTO(&target->name, dev, name);
    possible_net_t nd_net = BPF_CORE_READ(dev, nd_net);
    BPF_CORE_READ_INTO(&target->netns_id, &nd_net, net, ns.inum);
}

SEC("kretprobe/register_netdevice")
int BPF_KRETPROBE(ptcpdump_kretprobe__register_netdevice, long ret) {
    if (ret != 0) {
        goto out;
    }

    u64 tid = bpf_get_current_pid_tgid();
    struct netdevice_buf_t *buf;
    buf = bpf_map_lookup_elem(&ptcpdump_netdevice_bufs, &tid);
    if (!buf) {
        goto out;
    }
    bpf_map_delete_elem(&ptcpdump_netdevice_bufs, &tid);
    struct net_device *dev = (struct net_device *)buf->dev;

    struct new_netdevice_event_t event = {0};
    struct netdevice_t device = {0};
    parse_net_device(dev, &device);
    event.dev = device;
    //    debug_log("new device: ifindex: %d, name: %s, netns_id: %lu\n", device.ifindex, device.name, device.netns_id);

    int event_ret =
        bpf_perf_event_output(ctx, &ptcpdump_new_netdevice_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    if (event_ret != 0) {
        debug_log("[ptcpdump] bpf_perf_event_output new_device_events failed: %d\n", event_ret);
    }

out:
    return 0;
}

static __always_inline void handle_dev_get_by_index_ret(struct net_device *dev) {
    u64 tid = bpf_get_current_pid_tgid();
    struct netdevice_t device = {0};
    parse_net_device(dev, &device);
    bpf_map_update_elem(&ptcpdump_tid_netdevice_map, &tid, &device, BPF_ANY);
    //    debug_log("get device: ifindex: %d, name: %s, netns_id: %lu\n", device.ifindex, device.name, device.netns_id);
}

SEC("kretprobe/dev_get_by_index")
int BPF_KRETPROBE(ptcpdump_kretprobe__dev_get_by_index_legacy, struct net_device *dev) {
    if (!dev) {
        goto out;
    }

    handle_dev_get_by_index_ret(dev);

out:
    return 0;
}

SEC("kretprobe/__dev_get_by_index")
int BPF_KRETPROBE(ptcpdump_kretprobe__dev_get_by_index, struct net_device *dev) {
    if (!dev) {
        goto out;
    }

    handle_dev_get_by_index_ret(dev);

out:
    return 0;
}

static __always_inline void handle_dev_change_net_namespace(struct net_device *dev, struct net *net) {
    u64 tid = bpf_get_current_pid_tgid();
    struct netdevice_buf_t buf = {0};
    buf.dev = (u64)dev;
    buf.net = (u64)net;
    bpf_map_update_elem(&ptcpdump_netdevice_bufs, &tid, &buf, BPF_ANY);
}

SEC("kprobe/dev_change_net_namespace")
int BPF_KPROBE(ptcpdump_kprobe__dev_change_net_namespace_legacy, struct net_device *dev, struct net *net) {
    handle_dev_change_net_namespace(dev, net);
    return 0;
}

SEC("kprobe/__dev_change_net_namespace")
int BPF_KPROBE(ptcpdump_kprobe__dev_change_net_namespace, struct net_device *dev, struct net *net) {
    handle_dev_change_net_namespace(dev, net);
    return 0;
}

static __always_inline void clone_netdevice(struct netdevice_t *origin, struct netdevice_t *target) {
    target->ifindex = origin->ifindex;
    target->netns_id = origin->netns_id;
    __builtin_memcpy(&target->name, &origin->name, sizeof(origin->name));
}

static __always_inline void handle_dev_change_net_namespace_ret(void *ctx) {
    u64 tid = bpf_get_current_pid_tgid();
    struct netdevice_buf_t *buf;
    buf = bpf_map_lookup_elem(&ptcpdump_netdevice_bufs, &tid);
    if (!buf) {
        goto out;
    }
    struct netdevice_t *old_device;
    old_device = bpf_map_lookup_elem(&ptcpdump_tid_netdevice_map, &tid);
    if (!old_device) {
        goto out;
    }
    bpf_map_delete_elem(&ptcpdump_tid_netdevice_map, &tid);

    struct net_device *new_device_buf = (struct net_device *)buf->dev;
    struct netdevice_t new_device = {0};
    parse_net_device(new_device_buf, &new_device);

    //    debug_log("device (ifindex: %d, netns_id: %lu) change netns to %lu\n", old_device->ifindex,
    //    old_device->netns_id,
    //              new_device.netns_id);
    //    debug_log("device (ifindex: %d, netns_id: %lu) change ifindex to %lu\n", old_device->ifindex,
    //    old_device->netns_id,
    //              new_device.ifindex);

    struct netdevice_change_event_t event = {0};
    clone_netdevice(old_device, &event.old_device);
    clone_netdevice(&new_device, &event.new_device);
    int event_ret =
        bpf_perf_event_output(ctx, &ptcpdump_netdevice_change_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    if (event_ret != 0) {
        debug_log("[ptcpdump] bpf_perf_event_output ptcpdump_netdevice_change_events failed: %d\n", event_ret);
    }

out:
    return;
}

SEC("kretprobe/dev_change_net_namespace")
int BPF_KRETPROBE(ptcpdump_kretprobe__dev_change_net_namespace_legacy, long ret) {
    if (ret != 0) {
        goto out;
    }

    handle_dev_change_net_namespace_ret(ctx);

out:
    return 0;
}

SEC("kretprobe/__dev_change_net_namespace")
int BPF_KRETPROBE(ptcpdump_kretprobe__dev_change_net_namespace, long ret) {
    if (ret != 0) {
        goto out;
    }

    handle_dev_change_net_namespace_ret(ctx);

out:
    return 0;
}

#endif /* ENABLE_NET_DEV_W */

#endif /* __PTCPDUMP_NET_DEV_H__ */
