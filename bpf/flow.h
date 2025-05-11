#ifndef __PTCPDUMP_FLOW__
#define __PTCPDUMP_FLOW__

#include "compat.h"
#include "custom.h"
#include "gotls.h"
#include "helpers.h"
#include "nat.h"
#include "net.h"
#include "net_dev.h"
#include "process.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define TTY_NAME_LEN 64

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, struct process_meta_t);
} ptcpdump_sock_cookie_pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_pid_key_t);
    __type(value, struct process_meta_t);
} ptcpdump_flow_pid_map SEC(".maps");

#ifndef NO_CGROUP_PROG
static __always_inline int store_socket_cookie_process_info(u64 cookie, bool overwrite) {
    if (cookie <= 0) {
        goto out;
    }
    if (!overwrite) {
        if (bpf_map_lookup_elem(&ptcpdump_sock_cookie_pid_map, &cookie)) {
            goto out;
        }
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (is_kernel_thread(task)) {
        goto out;
    }
    if (parent_process_filter(task) < 0) {
        if (process_filter(task) < 0) {
            goto out;
        }
    }
    // debug_log("sock_create\n");

    struct process_meta_t meta = {0};
    fill_process_meta(task, &meta);
    u64 flags = overwrite ? BPF_ANY : BPF_NOEXIST;

    int ret = bpf_map_update_elem(&ptcpdump_sock_cookie_pid_map, &cookie, &meta, flags);
    if (ret != 0) {
        // debug_log("[ptcpdump] bpf_map_update_elem ptcpdump_sock_cookie_pid_map failed: %d\n", ret);
        goto out;
    } else {
        return 1;
    }

out:
    return 0;
}

static __always_inline int store_cgroup_socket_cookie(void *ctx, bool overwrite) {
    if (!bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_socket_cookie)) {
        goto out;
    }
    u64 cookie = bpf_get_socket_cookie(ctx);
    if (cookie <= 0) {
        // debug_log("[ptcpdump] sock_create: bpf_get_socket_cookie failed\n");
        goto out;
    }

    return store_socket_cookie_process_info(cookie, overwrite);

out:
    return 0;
}

SEC("cgroup/sock_create")
int ptcpdump_cgroup__sock_create(void *ctx) {
    if (store_cgroup_socket_cookie(ctx, true) > 0) {
        //        u32 pid = bpf_get_current_pid_tgid() >> 32;
        //        debug_log("[ptcpdump] saved cookie from cgroup/sock_create, pid: %lld\n", pid);
    }

    return 1;
}

SEC("cgroup/post_bind4")
int ptcpdump_cgroup__post_bind4(void *ctx) {
    if (store_cgroup_socket_cookie(ctx, false) > 0) {
        //        u32 pid = bpf_get_current_pid_tgid() >> 32;
        //        debug_log("[ptcpdump] saved cookie from cgroup/post_bind4, pid: %lld\n", pid);
    }

    return 1;
}

SEC("cgroup/post_bind6")
int ptcpdump_cgroup__post_bind6(void *ctx) {
    if (store_cgroup_socket_cookie(ctx, false) > 0) {
        //        u32 pid = bpf_get_current_pid_tgid() >> 32;
        //        debug_log("[ptcpdump] saved cookie from cgroup/post_bind6, pid: %lld\n", pid);
    }

    return 1;
}

SEC("cgroup/connect4")
int ptcpdump_cgroup__connect4(void *ctx) {
    if (store_cgroup_socket_cookie(ctx, false) > 0) {
        //        u32 pid = bpf_get_current_pid_tgid() >> 32;
        //        debug_log("[ptcpdump] saved cookie from cgroup/connect4, pid: %lld\n", pid);
    }

    return 1;
}

SEC("cgroup/connect6")
int ptcpdump_cgroup__connect6(void *ctx) {
    if (store_cgroup_socket_cookie(ctx, false) > 0) {
        //        u32 pid = bpf_get_current_pid_tgid() >> 32;
        //        debug_log("[ptcpdump] saved cookie from cgroup/connect6, pid: %lld\n", pid);
    }

    return 1;
}

SEC("cgroup/sendmsg4")
int ptcpdump_cgroup__sendmsg4(void *ctx) {
    if (store_cgroup_socket_cookie(ctx, false) > 0) {
        //        u32 pid = bpf_get_current_pid_tgid() >> 32;
        //        debug_log("[ptcpdump] saved cookie from cgroup/sendmsg4, pid: %lld\n", pid);
    }

    return 1;
}

SEC("cgroup/sendmsg6")
int ptcpdump_cgroup__sendmsg6(void *ctx) {
    if (store_cgroup_socket_cookie(ctx, false) > 0) {
        //        u32 pid = bpf_get_current_pid_tgid() >> 32;
        //        debug_log("[ptcpdump] saved cookie from cgroup/sendmsg6, pid: %lld\n", pid);
    }

    return 1;
}

SEC("cgroup/recvmsg4")
int ptcpdump_cgroup__recvmsg4(void *ctx) {
    if (store_cgroup_socket_cookie(ctx, false) > 0) {
        //        u32 pid = bpf_get_current_pid_tgid() >> 32;
        //        debug_log("[ptcpdump] saved cookie from cgroup/recvmsg4, pid: %lld\n", pid);
    }

    return 1;
}

SEC("cgroup/recvmsg6")
int ptcpdump_cgroup__recvmsg6(void *ctx) {
    if (store_cgroup_socket_cookie(ctx, false) > 0) {
        //        u32 pid = bpf_get_current_pid_tgid() >> 32;
        //        debug_log("[ptcpdump] saved cookie from cgroup/recvmsg6, pid: %lld\n", pid);
    }

    return 1;
}

SEC("cgroup/sock_release")
int ptcpdump_cgroup__sock_release(void *ctx) {
    if (!bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_socket_cookie)) {
        goto out;
    }
    u64 cookie = bpf_get_socket_cookie(ctx);
    if (cookie <= 0) {
        goto out;
    }

    bpf_map_delete_elem(&ptcpdump_sock_cookie_pid_map, &cookie);
out:
    return 1;
}
#endif /* NO_CGROUP_PROG */

static __always_inline int handle_sock(struct sock *sk, bool overwrite) {
    struct flow_pid_key_t key = {0};
    struct process_meta_t value = {0};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 cookie = BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);

    if (is_kernel_thread(task)) {
        goto out;
    }
    if (parent_process_filter(task) < 0) {
        if (process_filter(task) < 0) {
            goto out;
        }
    }
    // debug_log("flow match\n");

    fill_sk_meta(sk, &key);

    if (!overwrite) {
        if (bpf_map_lookup_elem(&ptcpdump_flow_pid_map, &key)) {
            goto out;
        }
    }

    fill_process_meta(task, &value);
    if (cookie > 0) {
        bpf_map_update_elem(&ptcpdump_sock_cookie_pid_map, &cookie, &value, BPF_NOEXIST);
    }

    if (key.sport == 0) {
        goto out;
    }

    // debug_log("[ptcpdump] flow key: %pI4 %d\n", &key.saddr[0], key.sport);
    u64 flags = overwrite ? BPF_ANY : BPF_NOEXIST;

    int ret = bpf_map_update_elem(&ptcpdump_flow_pid_map, &key, &value, flags);
    if (ret != 0) {
        // debug_log("bpf_map_update_elem ptcpdump_flow_pid_map failed: %d\n", ret);
    } else {
        return 1;
    }

out:
    return 0;
}

SEC("kprobe/security_sk_classify_flow")
int BPF_KPROBE(ptcpdump_kprobe__security_sk_classify_flow, struct sock *sk) {
    handle_sock(sk, true);
    return 0;
}

#ifndef NO_TRACING
SEC("fentry/security_sk_classify_flow")
int BPF_PROG(ptcpdump_fentry__security_sk_classify_flow, struct sock *sk) {
    handle_sock(sk, true);
    return 0;
}
#endif

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(ptcpdump_kprobe__tcp_sendmsg, struct sock *sk) {
    handle_sock(sk, false);
    return 0;
}

#ifndef NO_TRACING
SEC("fentry/tcp_sendmsg")
int BPF_PROG(ptcpdump_fentry__tcp_sendmsg, struct sock *sk) {
    handle_sock(sk, false);
    return 0;
}
#endif

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(ptcpdump_kprobe__udp_sendmsg, struct sock *sk) {
    handle_sock(sk, false);
    return 0;
}

#ifndef NO_TRACING
SEC("fentry/udp_sendmsg")
int BPF_PROG(ptcpdump_fentry__udp_sendmsg, struct sock *sk) {
    handle_sock(sk, false);
    return 0;
}
#endif

SEC("kprobe/udp_send_skb")
int BPF_KPROBE(ptcpdump_kprobe__udp_send_skb, struct sk_buff *skb) {
    struct sock *sk = BPF_CORE_READ(skb, sk);
    handle_sock(sk, false);
    return 0;
}

#ifndef NO_TRACING
SEC("fentry/udp_send_skb")
int BPF_PROG(ptcpdump_fentry__udp_send_skb, struct sk_buff *skb) {
    struct sock *sk = BPF_CORE_READ(skb, sk);
    handle_sock(sk, false);
    return 0;
}
#endif

SEC("kprobe/__kfree_skb")
int BPF_KPROBE(ptcpdump_kprobe__kfree_skb, struct sk_buff *skb) {
    u64 cookie = BPF_CORE_READ(skb, sk, __sk_common.skc_cookie.counter);
    if (cookie > 0) {
        bpf_map_delete_elem(&ptcpdump_sock_cookie_pid_map, &cookie);
    }
    return 0;
}

#ifndef NO_TRACING
SEC("fentry/__kfree_skb")
int BPF_PROG(ptcpdump_fentry__kfree_skb, struct sk_buff *skb) {
    u64 cookie = BPF_CORE_READ(skb, sk, __sk_common.skc_cookie.counter);
    if (cookie > 0) {
        bpf_map_delete_elem(&ptcpdump_sock_cookie_pid_map, &cookie);
    }
    return 0;
}
#endif

#endif /* __PTCPDUMP_FLOW__ */
