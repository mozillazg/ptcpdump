// go:build ignore
//  +build ignore

#include "custom.h"
#include "gotls.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EEXIST 17 /* File exists */
#define TASK_COMM_LEN 16
#define TTY_NAME_LEN 64
#define ETH_HLEN 14       /* Total octets in header.	 */
#define ETH_P_IP 0x0800   /* Internet Protocol packet	*/
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook		*/
#define IPPROTO_ICMP 1    /* Internet Control Message Protocol	*/
#define IPPROTO_ICMPV6 58 /* ICMPv6			*/
#define IPPROTO_TCP 6     /* Transmission Control Protocol	*/
#define IPPROTO_UDP 17    /* User Datagram Protocol		*/
#define IPPROTO_SCTP 132  /* Stream Control Transport Protocol	*/
#define TC_ACT_UNSPEC (-1)
#define AF_INET 2
#define AF_INET6 10
#define INGRESS_PACKET 0
#define EGRESS_PACKET 1
#define EXEC_FILENAME_LEN 512
#define EXEC_ARGS_LEN 4096

char _license[] SEC("license") = "Dual MIT/GPL";

struct gconfig_t {
    u8 have_filter;
    u8 filter_follow_forks;
    char filter_comm[TASK_COMM_LEN];
    u8 filter_comm_enable;
    u32 max_payload_size;
};

#ifndef LEGACY_KERNEL
static volatile const struct gconfig_t g = {0};
static const u8 u8_zero = 0;
static const u32 u32_zero = 0;
#endif

struct l2_t {
    u16 h_protocol;
};

struct l3_t {
    u8 protocol;
    u64 saddr[2];
    u64 daddr[2];
};

struct l4_t {
    u16 sport;
    u16 dport;
};

struct nat_flow_t {
    u64 saddr[2];
    u64 daddr[2];
    u16 sport;
    u16 dport;
};

struct packet_meta_t {
    u32 ifindex;

    struct l2_t l2;
    struct l3_t l3;
    struct l4_t l4;

    u32 offset;
};

struct flow_pid_key_t {
    u64 saddr[2];
    u16 sport;
};

struct process_meta_t {
    u32 ppid;
    u32 pid;
    u32 pidns_id;
    u32 mntns_id;
    u32 netns_id;
    char cgroup_name[128];
};

struct packet_event_meta_t {
    u64 timestamp;
    u8 packet_type;
    u32 ifindex;
    u64 payload_len;
    u64 packet_size;

    struct process_meta_t process;
};

struct packet_event_t {
    struct packet_event_meta_t meta;
};

struct exec_event_t {
    struct process_meta_t meta;

    u8 filename_truncated;
    u8 args_truncated;
    unsigned int args_size;
    char filename[EXEC_FILENAME_LEN];
    char args[EXEC_ARGS_LEN];
};

struct exit_event_t {
    u32 pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct gconfig_t);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, u8);
} filter_mntns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, u8);
} filter_pidns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, u8);
} filter_netns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct exec_event_t);
} exec_event_stack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} exec_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} exit_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct nat_flow_t);
    __type(value, struct nat_flow_t);
} nat_flow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_pid_key_t);
    __type(value, struct process_meta_t);
} flow_pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, struct process_meta_t);
} sock_cookie_pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct packet_event_t);
} packet_event_stack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} packet_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, u32);
    __type(value, u8);
} filter_pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} filter_by_kernel_count SEC(".maps");

// force emitting struct into the ELF.
// the `-type` flag of bpf2go need this
// avoid "Error: collect C types: type name XXX: not found"
const struct packet_event_t *unused1 __attribute__((unused));
const struct exec_event_t *unused2 __attribute__((unused));
const struct flow_pid_key_t *unused3 __attribute__((unused));
const struct process_meta_t *unused4 __attribute__((unused));
const struct exit_event_t *unused5 __attribute__((unused));
const struct gconfig_t *unused6 __attribute__((unused));

#ifdef LEGACY_KERNEL
#define debug_log(fmt, ...)                                                                                            \
    ({                                                                                                                 \
        char ____fmt[] = fmt;                                                                                          \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                                                     \
    })
#define GET_CONFIG()                                                                                                   \
    struct gconfig_t g = {0};                                                                                          \
    u32 configk = 0;                                                                                                   \
    struct gconfig_t *configv = bpf_map_lookup_elem(&config_map, &configk);                                            \
    if (configv) {                                                                                                     \
        g = *configv;                                                                                                  \
    }
#else

#define debug_log(fmt, ...) ({ bpf_printk(fmt, ##__VA_ARGS__); })
#define GET_CONFIG()
#endif

static __always_inline int parse_skb_l2(struct __sk_buff *skb, struct l2_t *l2, u32 *offset) {
    if (bpf_skb_load_bytes(skb, *offset + offsetof(struct ethhdr, h_proto), &l2->h_protocol, sizeof(l2->h_protocol)) <
        0) {
        // debug_log("parse_skb_l2 1 failed:\n");
        return -1;
    }
    l2->h_protocol = bpf_ntohs(l2->h_protocol);
    *offset += sizeof(struct ethhdr);
    return 0;
}

static __always_inline int parse_skb_l3(struct __sk_buff *skb, u16 protocol, struct l3_t *l3, u32 *offset) {
    switch (protocol) {
    case ETH_P_IP: {
        struct iphdr ip_hdr;
        if (bpf_skb_load_bytes(skb, *offset, &ip_hdr, sizeof(struct iphdr)) < 0) {
            // debug_log("parse_skb_l3 1 failed:\n");
            return -1;
        }
        l3->protocol = ip_hdr.protocol;
        l3->saddr[0] = ip_hdr.saddr;
        l3->daddr[0] = ip_hdr.daddr;
        *offset += sizeof(struct iphdr);
        return 0;
    }
    case ETH_P_IPV6: {
        struct ipv6hdr ip_hdr;
        if (bpf_skb_load_bytes(skb, *offset, &ip_hdr, sizeof(struct ipv6hdr)) < 0) {
            // debug_log("parse_skb_l3 2 failed:\n");
            return -1;
        }
        l3->protocol = ip_hdr.nexthdr;
        if (bpf_skb_load_bytes(skb, *offset + offsetof(struct ipv6hdr, saddr), &l3->saddr, sizeof(l3->saddr)) < 0) {
            // debug_log("parse_skb_l3 3 failed:\n");
            return -1;
        }
        if (bpf_skb_load_bytes(skb, *offset + offsetof(struct ipv6hdr, daddr), &l3->daddr, sizeof(l3->daddr)) < 0) {
            // debug_log("parse_skb_l3 4 failed:\n");
            return -1;
        }
        *offset += sizeof(struct ipv6hdr);
        return 0;
    }
    default: {
        return 0;
    }
    }

    return 0;
}

static __always_inline int parse_skb_l4(struct __sk_buff *skb, u8 protocol, struct l4_t *l4, u32 *offset) {
    switch (protocol) {
        //    case IPPROTO_ICMP: {
        //        l4->sport = 0;
        //        l4->dport = 0;
        //        *offset += sizeof(struct icmphdr);
        //        return 0;
        //     }
        //    case IPPROTO_ICMPV6: {
        //        l4->sport = 0;
        //        l4->dport = 0;
        //        *offset += sizeof(struct icmp6hdr);
        //        return 0;
        //     }
    case IPPROTO_TCP: {
        struct tcphdr tcp_hdr;
        if (bpf_skb_load_bytes(skb, *offset, &tcp_hdr, sizeof(struct tcphdr)) < 0) {
            // debug_log("parse_skb_l4 1 failed:\n");
            return -1;
        }
        l4->sport = bpf_ntohs(tcp_hdr.source);
        l4->dport = bpf_ntohs(tcp_hdr.dest);
        *offset += sizeof(struct tcphdr);
    }
        return 0;
    case IPPROTO_UDP: {
        struct udphdr udp_hdr;
        if (bpf_skb_load_bytes(skb, *offset, &udp_hdr, sizeof(struct udphdr)) < 0) {
            // debug_log("parse_skb_l4 2 failed:\n");
            return -1;
        }
        l4->sport = bpf_ntohs(udp_hdr.source);
        l4->dport = bpf_ntohs(udp_hdr.dest);
        *offset += sizeof(struct udphdr);
        return 0;
    }
    case IPPROTO_SCTP: {
        struct sctphdr sctp_hdr;
        if (bpf_skb_load_bytes(skb, *offset, &sctp_hdr, sizeof(struct sctphdr)) < 0) {
            // debug_log("parse_skb_l4 3 failed:\n");
            return -1;
        }
        l4->sport = bpf_ntohs(sctp_hdr.source);
        l4->dport = bpf_ntohs(sctp_hdr.dest);
        *offset += sizeof(struct sctphdr);
        return 0;
    }
    default: {
        return 0;
    }
    }

    return 0;
}

static __always_inline int parse_skb_meta(struct __sk_buff *skb, struct packet_meta_t *meta) {
    meta->ifindex = skb->ifindex;

    if (parse_skb_l2(skb, &meta->l2, &meta->offset) < 0) {
        return -1;
    }

    if (parse_skb_l3(skb, meta->l2.h_protocol, &meta->l3, &meta->offset) < 0) {
        return -1;
    }

    if (parse_skb_l4(skb, meta->l3.protocol, &meta->l4, &meta->offset) < 0) {
        return -1;
    }
    return 0;
}

static __always_inline void fill_process_meta(struct task_struct *task, struct process_meta_t *meta) {
    BPF_CORE_READ_INTO(&meta->pidns_id, task, nsproxy, pid_ns_for_children, ns.inum);
    BPF_CORE_READ_INTO(&meta->mntns_id, task, nsproxy, mnt_ns, ns.inum);
    BPF_CORE_READ_INTO(&meta->netns_id, task, nsproxy, net_ns, ns.inum);
    BPF_CORE_READ_INTO(&meta->pid, task, tgid);
    BPF_CORE_READ_INTO(&meta->ppid, task, real_parent, tgid);

    const char *cname = BPF_CORE_READ(task, cgroups, subsys[0], cgroup, kn, name);
    bpf_core_read_str(&meta->cgroup_name, sizeof(meta->cgroup_name), cname);
}

static __always_inline void fill_sk_meta(struct sock *sk, struct flow_pid_key_t *meta) {
    BPF_CORE_READ_INTO(&meta->sport, sk, __sk_common.skc_num);
    u32 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    switch (family) {
    case AF_INET: {
        bpf_probe_read(&meta->saddr, sizeof(sk->__sk_common.skc_rcv_saddr), &sk->__sk_common.skc_rcv_saddr);
        break;
    }
    case AF_INET6: {
        bpf_probe_read(&meta->saddr, sizeof(sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32),
                       &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        break;
    }
    default: {
        break;
    }
    }
}

static __always_inline void *bpf_map_lookup_or_try_init(void *map, const void *key, const void *init) {
    void *value;
    value = bpf_map_lookup_elem(map, key);
    if (value) {
        return value;
    }

    int err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
    if (err && err != -EEXIST)
        return 0;

    return bpf_map_lookup_elem(map, key);
}

static __always_inline int str_cmp(const char *a, const volatile char *b, int len) {
#pragma unroll
    for (int i = 0; i < len; i++) {
        if (a[i] != b[i])
            return -1;
        if (a[i] == '\0')
            break;
    }
    return 0;
}

static __always_inline bool have_pid_filter_rules() {
    GET_CONFIG()

    return g.have_filter > 0;
}

static __always_inline int filter_pid(u32 pid) {
    if (bpf_map_lookup_elem(&filter_pid_map, &pid)) {
        return 0;
    }
    return -1;
}

static __always_inline int filter_mntns(u32 ns) {
    if (bpf_map_lookup_elem(&filter_mntns_map, &ns)) {
        return 0;
    }
    return -1;
}

static __always_inline int filter_pidns(u32 ns) {
    if (bpf_map_lookup_elem(&filter_pidns_map, &ns)) {
        return 0;
    }
    return -1;
}

static __always_inline int filter_netns(u32 ns) {
    if (bpf_map_lookup_elem(&filter_netns_map, &ns)) {
        return 0;
    }
    return -1;
}

static __always_inline int process_filter(struct task_struct *task) {
    // no filter rules
    if (!have_pid_filter_rules()) {
        // debug_log("no filter\n");
        return 0;
    }

    u32 pid = BPF_CORE_READ(task, tgid);
    if (filter_pid(pid) == 0) {
        // debug_log("match filter\n");
        return 0;
    }

    GET_CONFIG()
#ifdef LEGACY_KERNEL
    u8 u8_zero = 0;
#endif

    bool should_filter = false;
    u32 mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    u32 netns_id = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
    u32 pidns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    if ((filter_pidns(pidns_id) == 0) || (filter_mntns(mntns_id) == 0) || (filter_netns(netns_id) == 0)) {
        // debug_log("%u %u %u\n", mntns_id, netns_id, pidns_id);
        should_filter = true;
    }

    if (!should_filter) {
        if (g.filter_comm_enable == 1) {
            char comm[TASK_COMM_LEN];
            __builtin_memset(&comm, 0, sizeof(comm));
            BPF_CORE_READ_STR_INTO(&comm, task, comm);
            if (str_cmp(comm, g.filter_comm, TASK_COMM_LEN) == 0) {
                should_filter = true;
            }
        }
    }

    if (should_filter) {
        bpf_map_update_elem(&filter_pid_map, &pid, &u8_zero, BPF_NOEXIST);
        return 0;
    }

    // debug_log("process_filter not match, pid: %u, filter_pid: %u", pid, g.filter_pid);

    return -1;
}

static __always_inline int parent_process_filter(struct task_struct *current) {
    // no filter rules
    if (!have_pid_filter_rules()) {
        // debug_log("no filter\n");
        return 0;
    }

    GET_CONFIG()
#ifdef LEGACY_KERNEL
    u8 u8_zero = 0;
#endif

    if (g.filter_follow_forks != 1) {
        return -1;
    }
    struct task_struct *parent = BPF_CORE_READ(current, real_parent);
    if (!parent) {
        return -1;
    }
    if (process_filter(parent) == 0) {
        u32 child_pid = BPF_CORE_READ(current, tgid);
        bpf_map_update_elem(&filter_pid_map, &child_pid, &u8_zero, BPF_NOEXIST);
        return 0;
    }

    return -1;
}

static __always_inline void handle_fork(struct bpf_raw_tracepoint_args *ctx) {
    GET_CONFIG()
#ifdef LEGACY_KERNEL
    u8 u8_zero = 0;
#endif

    if (g.filter_follow_forks != 1) {
        return;
    }

    // args: struct task_struct *parent, struct task_struct *child
    struct task_struct *parent = (struct task_struct *)BPF_CORE_READ(ctx, args[0]);
    struct task_struct *child = (struct task_struct *)BPF_CORE_READ(ctx, args[1]);
    u32 child_pid = BPF_CORE_READ(child, tgid);

    if (process_filter(parent) == 0) {
        bpf_map_update_elem(&filter_pid_map, &child_pid, &u8_zero, BPF_NOEXIST);
        return;
    }
    if (process_filter(child) == 0) {
        return;
    }
    return;
}

SEC("raw_tracepoint/sched_process_fork")
int raw_tracepoint__sched_process_fork(struct bpf_raw_tracepoint_args *ctx) {
    handle_fork(ctx);
    return 0;
}

#ifndef LEGACY_KERNEL
SEC("cgroup/sock_create")
int cgroup__sock_create(void *ctx) {
    if (!bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_socket_cookie)) {
        return 1;
    }
    u64 cookie = bpf_get_socket_cookie(ctx);
    if (cookie <= 0) {
        // debug_log("[ptcpdump] sock_create: bpf_get_socket_cookie failed\n");
        return 1;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (parent_process_filter(task) < 0) {
        if (process_filter(task) < 0) {
            return 1;
        }
    }
    // debug_log("sock_create\n");

    struct process_meta_t meta = {0};
    fill_process_meta(task, &meta);

    int ret = bpf_map_update_elem(&sock_cookie_pid_map, &cookie, &meta, BPF_ANY);
    if (ret != 0) {
        // debug_log("[ptcpdump] bpf_map_update_elem sock_cookie_pid_map failed: %d\n", ret);
    }

    return 1;
}
#endif

#ifndef LEGACY_KERNEL
SEC("cgroup/sock_release")
int cgroup__sock_release(void *ctx) {
    if (!bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_socket_cookie)) {
        return 1;
    }
    u64 cookie = bpf_get_socket_cookie(ctx);
    if (cookie <= 0) {
        return 1;
    }

    bpf_map_delete_elem(&sock_cookie_pid_map, &cookie);
    return 1;
}
#endif

SEC("kprobe/security_sk_classify_flow")
int BPF_KPROBE(kprobe__security_sk_classify_flow, struct sock *sk) {
    struct flow_pid_key_t key = {0};
    struct process_meta_t value = {0};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    if (parent_process_filter(task) < 0) {
        if (process_filter(task) < 0) {
            return 0;
        }
    }
    // debug_log("flow match\n");

    fill_sk_meta(sk, &key);
    fill_process_meta(task, &value);

    if (key.sport == 0) {
        return 0;
    }

    // debug_log("[ptcpdump] flow key: %pI4 %d\n", &key.saddr[0], key.sport);

    int ret = bpf_map_update_elem(&flow_pid_map, &key, &value, BPF_ANY);
    if (ret != 0) {
        // debug_log("bpf_map_update_elem flow_pid_map failed: %d\n", ret);
    }
    return 0;
}

static __always_inline void handle_sendmsg(struct sock *sk) {
    struct flow_pid_key_t key = {0};
    struct process_meta_t value = {0};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    if (parent_process_filter(task) < 0) {
        if (process_filter(task) < 0) {
            return;
        }
    }
    // debug_log("sendmsg match\n");

    fill_sk_meta(sk, &key);
    if (bpf_map_lookup_elem(&flow_pid_map, &key)) {
        return;
    }

    fill_process_meta(task, &value);
    if (key.sport == 0) {
        return;
    }
    // debug_log("[ptcpdump][sendmsg] flow key: %pI4 %d\n", &key.saddr[0], key.sport);
    int ret = bpf_map_update_elem(&flow_pid_map, &key, &value, BPF_NOEXIST);
    if (ret != 0) {
        // debug_log("[handle_tcp_sendmsg] bpf_map_update_elem flow_pid_map failed: %d\n", ret);
    }
    return;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe__tcp_sendmsg, struct sock *sk) {
    handle_sendmsg(sk);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe__udp_sendmsg, struct sock *sk) {
    handle_sendmsg(sk);
    return 0;
}

SEC("kprobe/udp_send_skb")
int BPF_KPROBE(kprobe__udp_send_skb, struct sk_buff *skb) {
    struct sock *sk = BPF_CORE_READ(skb, sk);
    handle_sendmsg(sk);
    return 0;
}

static __noinline bool pcap_filter(void *_skb, void *__skb, void *___skb, void *data, void *data_end) {
    return data != data_end && _skb == __skb && __skb == ___skb;
}

static __always_inline void parse_conntrack_tuple(struct nf_conntrack_tuple *tuple, struct nat_flow_t *flow) {
    BPF_CORE_READ_INTO(&flow->saddr, tuple, src.u3.all);
    BPF_CORE_READ_INTO(&flow->daddr, tuple, dst.u3.all);

    flow->sport = bpf_ntohs(tuple->src.u.all);
    flow->dport = bpf_ntohs(tuple->dst.u.all);
}

static __always_inline void reverse_flow(struct nat_flow_t *orig_flow, struct nat_flow_t *new_flow) {
    new_flow->saddr[0] = orig_flow->daddr[0];
    new_flow->saddr[1] = orig_flow->daddr[1];

    new_flow->daddr[0] = orig_flow->saddr[0];
    new_flow->daddr[1] = orig_flow->saddr[1];

    new_flow->sport = orig_flow->dport;
    new_flow->dport = orig_flow->sport;
}

static __always_inline void handle_nat(struct nf_conn *ct) {
    struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];

    if (bpf_core_field_exists(ct->tuplehash)) {
        BPF_CORE_READ_INTO(&tuplehash, ct, tuplehash);
    } else {
        struct nf_conn___older_52 *nf_conn_old = (void *)ct;
        if (bpf_core_field_exists(nf_conn_old->tuplehash)) {
            BPF_CORE_READ_INTO(&tuplehash, nf_conn_old, tuplehash);
        } else {
            return;
        }
    }

    struct nf_conntrack_tuple *orig_tuple = &tuplehash[IP_CT_DIR_ORIGINAL].tuple;
    struct nf_conntrack_tuple *reply_tuple = &tuplehash[IP_CT_DIR_REPLY].tuple;

    struct nat_flow_t orig = {0};
    struct nat_flow_t reply = {0};
    parse_conntrack_tuple(orig_tuple, &orig);
    parse_conntrack_tuple(reply_tuple, &reply);

    struct nat_flow_t reversed_orig = {0};
    reverse_flow(&orig, &reversed_orig);
    // debug_log("[ptcpdump] nat flow %pI4:%d %pI4:%d ->\n",
    // 		&reply.saddr[0], reply.sport,
    // 	       	&reply.daddr[0], reply.dport);
    // debug_log("[ptcpdump]                               -> %pI4:%d %pI4:%d\n",
    // 		&reversed_orig.saddr[0], reversed_orig.sport,
    // 		&reversed_orig.saddr[0], reversed_orig.dport);
    bpf_map_update_elem(&nat_flow_map, &reply, &reversed_orig, BPF_ANY);

    struct nat_flow_t reversed_reply = {0};
    reverse_flow(&reply, &reversed_reply);
    // debug_log("[ptcpdump] nat flow %pI4:%d %pI4:%d ->\n",
    // 		&reversed_reply.saddr[0], reversed_reply.sport,
    // 	       	&reversed_reply.daddr[0], reversed_reply.dport);
    // debug_log("[ptcpdump]                               -> %pI4:%d %pI4:%d\n",
    // 		&orig.saddr[0], orig.sport,
    // 		&orig.saddr[0], orig.dport);
    bpf_map_update_elem(&nat_flow_map, &reversed_reply, &orig, BPF_ANY);
}

SEC("kprobe/nf_nat_packet")
int BPF_KPROBE(kprobe__nf_nat_packet, struct nf_conn *ct) {
    handle_nat(ct);
    return 0;
}

SEC("kprobe/nf_nat_manip_pkt")
int BPF_KPROBE(kprobe__nf_nat_manip_pkt, void *_, struct nf_conn *ct) {
    handle_nat(ct);
    return 0;
}

static __always_inline void clone_flow(struct nat_flow_t *orig, struct nat_flow_t *new_flow) {
    new_flow->saddr[0] = orig->saddr[0];
    new_flow->saddr[1] = orig->saddr[1];

    new_flow->daddr[0] = orig->daddr[0];
    new_flow->daddr[1] = orig->daddr[1];

    new_flow->sport = orig->sport;
    new_flow->dport = orig->dport;
}

static __always_inline void route_packet(struct packet_meta_t *packet_meta, struct nat_flow_t *flow) {
    flow->saddr[0] = packet_meta->l3.saddr[0];
    flow->saddr[1] = packet_meta->l3.saddr[1];

    flow->daddr[0] = packet_meta->l3.daddr[0];
    flow->daddr[1] = packet_meta->l3.daddr[1];

    flow->sport = packet_meta->l4.sport;
    flow->dport = packet_meta->l4.dport;

    struct nat_flow_t tmp_flow = *flow;
#pragma unroll
    for (int i = 0; i < 10; i++) {
        struct nat_flow_t *translated_flow = bpf_map_lookup_elem(&nat_flow_map, &tmp_flow);
        if (translated_flow == NULL) {
            // debug_log("[ptcpdump]: no router %pI4:%d %pI4:%d\n",
            // 		&tmp_flow.saddr[0], tmp_flow.sport, &tmp_flow.daddr[0],
            // tmp_flow.dport);
            break;
        }

        // debug_log("[ptcpdump] route: %pI4 %pI4 => %pI4 %pI4\n",
        // 		&tmp_flow.saddr[0], &tmp_flow.daddr[0],
        // 		&translated_flow->saddr[0], &translated_flow->daddr[0]);
        clone_flow(translated_flow, flow);
        clone_flow(translated_flow, &tmp_flow);
    }

    return;
}

static __always_inline void clone_process_meta(struct process_meta_t *origin, struct process_meta_t *target) {
    target->ppid = origin->ppid;
    target->pid = origin->pid;
    target->mntns_id = origin->mntns_id;
    target->netns_id = origin->netns_id;
    target->pidns_id = origin->pidns_id;
    __builtin_memcpy(&target->cgroup_name, &origin->cgroup_name, sizeof(origin->cgroup_name));
}

static __always_inline int get_pid_meta(struct __sk_buff *skb, struct process_meta_t *pid_meta, bool egress) {
#ifndef LEGACY_KERNEL
    if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_socket_cookie)) {
        u64 cookie = bpf_get_socket_cookie(skb);
        if (cookie > 0) {
            struct process_meta_t *value = bpf_map_lookup_elem(&sock_cookie_pid_map, &cookie);
            if (value) {
                clone_process_meta(value, pid_meta);
                return 0;
            }
        } else {
            if (egress) {
                // debug_log("[ptcpdump] tc egress: bpf_get_socket_cookie failed\n");
            } else {
                // debug_log("[ptcpdump] tc ingress: bpf_get_socket_cookie failed\n");
            }
        }
    }
#endif

    struct packet_meta_t packet_meta = {0};
    int ret = parse_skb_meta(skb, &packet_meta);
    if (ret < 0) {
        // debug_log("parse skb meta failed\n");
        return -1;
    }
    struct nat_flow_t flow = {0};
    route_packet(&packet_meta, &flow);

    bool have_pid_filter = have_pid_filter_rules();
    struct flow_pid_key_t key = {0};

#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (egress) {
            key.saddr[0] = flow.saddr[0];
            key.saddr[1] = flow.saddr[1];
            key.sport = flow.sport;
        } else {
            key.saddr[0] = flow.daddr[0];
            key.saddr[1] = flow.daddr[1];
            key.sport = flow.dport;
        }

        if (have_pid_filter && flow.sport == 0 && flow.dport == 0) {
            // debug_log("tc, sport is zero\n");
            // debug_log("[tc] %pI4 %d sport is zero\n", &key.saddr[0], key.sport);
            return -1;
        }

        // debug_log("tc, try to get pid\n");
        // debug_log("[tc] check %pI4 %d\n", &key.saddr[0], key.sport);
        if (key.sport > 0) {
            // debug_log("[tc] check %pI4 %d\n", &key.saddr[0], key.sport);
            struct process_meta_t *value = bpf_map_lookup_elem(&flow_pid_map, &key);
            if (value) {
                // debug_log("[tc] got %pI4 %d -> %pI4\n", &flow.saddr[0],
                // flow.sport, &flow.daddr[0]);
                clone_process_meta(value, pid_meta);
                return 0;
            } else if (have_pid_filter) {
                // debug_log("tc, flow_pid_map is empty\n");
                // debug_log("[tc] %pI4 %d bpf_map_lookup_elem flow_pid_map is empty\n", &key.saddr[0], key.sport);
            }
        }
        egress = !egress;
    }

    if (have_pid_filter) {
        // debug_log("[tc] check %pI4 %d -> %pI4\n", &flow.saddr[0], flow.sport, &flow.daddr[0]);
        // debug_log("tc, not found pid from flow_pid_map");
        return -1;
    }

    return 0;
}

static __always_inline void handle_tc(struct __sk_buff *skb, bool egress) {
    bpf_skb_pull_data(skb, 0);

    if (!pcap_filter((void *)skb, (void *)skb, (void *)skb, (void *)(long)skb->data, (void *)(long)skb->data_end)) {
        return;
    }
#ifdef LEGACY_KERNEL
    u32 u32_zero = 0;
#endif

    struct packet_event_t *event;
    event = bpf_map_lookup_elem(&packet_event_stack, &u32_zero);
    if (!event) {
        // debug_log("[ptcpdump] packet_event_stack failed\n");
        return;
    }
    __builtin_memset(&event->meta, 0, sizeof(event->meta));
    __builtin_memset(&event->meta.process, 0, sizeof(event->meta.process));
    __builtin_memset(&event->meta.process.cgroup_name, 0, sizeof(event->meta.process.cgroup_name));

    if (get_pid_meta(skb, &event->meta.process, egress) < 0) {
        // debug_log("tc, not found pid\n");
        return;
    };
    // if (process_meta_filter(&event->meta.process) < 0) {
    //     // debug_log("tc, not match filter\n");
    //     return;
    // };

    u32 *count;
    count = bpf_map_lookup_or_try_init(&filter_by_kernel_count, &u32_zero, &u32_zero);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    if (egress) {
        event->meta.packet_type = EGRESS_PACKET;
    } else {
        event->meta.packet_type = INGRESS_PACKET;
    }
    event->meta.timestamp = bpf_ktime_get_ns();
    event->meta.ifindex = skb->ifindex;

    GET_CONFIG()

    u64 payload_len = (u64)skb->len;
    event->meta.packet_size = payload_len;
    if (g.max_payload_size > 0) {
        payload_len = payload_len < g.max_payload_size ? payload_len : g.max_payload_size;
    }
    event->meta.payload_len = payload_len;

    int event_ret = bpf_perf_event_output(skb, &packet_events, BPF_F_CURRENT_CPU | (payload_len << 32), event,
                                          sizeof(struct packet_event_t));
    if (event_ret != 0) {
        // debug_log("[ptcpdump] bpf_perf_event_output exec_events failed: %d\n", event_ret);
    }

    return;
}

static __always_inline void handle_exec(struct bpf_raw_tracepoint_args *ctx) {
    // args: struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm
    struct task_struct *task = (struct task_struct *)BPF_CORE_READ(ctx, args[0]);
    //    if (process_filter(task) < 0) {
    //        return;
    //    }

    struct exec_event_t *event;
#ifdef LEGACY_KERNEL
    u32 u32_zero = 0;
#endif
    event = bpf_map_lookup_elem(&exec_event_stack, &u32_zero);
    if (!event) {
        // debug_log("[ptcpdump] exec_event_stack failed\n");
        return;
    }
    __builtin_memset(&event->meta, 0, sizeof(event->meta));

    fill_process_meta(task, &event->meta);

    struct linux_binprm *bprm = (struct linux_binprm *)BPF_CORE_READ(ctx, args[2]);
    const char *filename_p = BPF_CORE_READ(bprm, filename);
    int f_ret = bpf_probe_read_str(&event->filename, sizeof(event->filename), filename_p);
    if (f_ret < 0) {
        // debug_log("[ptcpdump] read exec filename failed: %d\n", f_ret);
    }
    if (f_ret == EXEC_FILENAME_LEN) {
        event->filename_truncated = 1;
    }

    void *arg_start = (void *)BPF_CORE_READ(task, mm, arg_start);
    void *arg_end = (void *)BPF_CORE_READ(task, mm, arg_end);
    unsigned long arg_length = arg_end - arg_start;
    if (arg_length > EXEC_ARGS_LEN) {
        arg_length = EXEC_ARGS_LEN;
        event->args_truncated = 1;
    }
    int arg_ret = bpf_probe_read(&event->args, arg_length, arg_start);
    if (arg_ret < 0) {
        // debug_log("[ptcpdump] read exec args failed: %d\n", arg_ret);
    } else {
        event->args_size = arg_length;
    }

    int event_ret = bpf_perf_event_output(ctx, &exec_events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    if (event_ret != 0) {
        // debug_log("[ptcpdump] bpf_perf_event_output exec_events failed: %d\n", event_ret);
    }
    return;
}

static __always_inline void handle_exit(struct bpf_raw_tracepoint_args *ctx) {
    // args: struct task_struct *p
    struct task_struct *task = (struct task_struct *)BPF_CORE_READ(ctx, args[0]);

    atomic_t live = BPF_CORE_READ(task, signal, live);
    if (live.counter > 0) {
        return;
    }

    u32 pid = BPF_CORE_READ(task, tgid);
    if (bpf_map_lookup_elem(&filter_pid_map, &pid)) {
        bpf_map_delete_elem(&filter_pid_map, &pid);
    }

    struct exit_event_t event = {
        .pid = pid,
    };
    int event_ret = bpf_perf_event_output(ctx, &exit_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    if (event_ret != 0) {
        // debug_log("[ptcpdump] bpf_perf_event_output exit_events failed: %d\n", event_ret);
    }

    return;
}

SEC("raw_tracepoint/sched_process_exec")
int raw_tracepoint__sched_process_exec(struct bpf_raw_tracepoint_args *ctx) {
    handle_exec(ctx);
    return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int raw_tracepoint__sched_process_exit(struct bpf_raw_tracepoint_args *ctx) {
    handle_exit(ctx);
    return 0;
}

SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    handle_tc(skb, false);
    return TC_ACT_UNSPEC;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
    handle_tc(skb, true);
    return TC_ACT_UNSPEC;
}

SEC("uprobe/go:crypto/tls.(*Config).writeKeyLog")
int uprobe__go_builtin__tls__write_key_log(struct pt_regs *ctx) {
    struct go_keylog_buf_t buf = {0};
    u32 smp_id = bpf_get_smp_processor_id();

    read_go_arg_into(&buf.label_len_ptr, ctx, 3);
    read_go_arg_into(&buf.random_len_ptr, ctx, 5);
    read_go_arg_into(&buf.secret_len_ptr, ctx, 8);

    read_go_arg_into(&buf.label_ptr, ctx, 2);
    read_go_arg_into(&buf.random_ptr, ctx, 4);
    read_go_arg_into(&buf.secret_ptr, ctx, 7);

    bpf_map_update_elem(&go_keylog_buf_storage, &smp_id, &buf, BPF_ANY);

    return 0;
}

SEC("uprobe/go:crypto/tls.(*Config).writeKeyLog/ret")
int uprobe__go_builtin__tls__write_key_log__ret(struct pt_regs *ctx) {
    struct go_keylog_buf_t *buf;
    struct go_keylog_event_t event = {0};
    int ret;

    u32 smp_id = bpf_get_smp_processor_id();
    buf = bpf_map_lookup_elem(&go_keylog_buf_storage, &smp_id);
    if (!buf) {
        //        debug_log("no buf");
        return 0;
    }

    bpf_probe_read_kernel(&event.label_len, sizeof(event.label_len), &(buf->label_len_ptr));
    bpf_probe_read_kernel(&event.client_random_len, sizeof(event.client_random_len), &(buf->random_len_ptr));
    bpf_probe_read_kernel(&event.secret_len, sizeof(event.secret_len), &(buf->secret_len_ptr));
    if (event.label_len == 0 && event.client_random_len == 0 && event.secret_len == 0) {
        //                debug_log("go tls read filed, label_len: %d, client_random_len: %d, secret_len: %d",
        //                            event.label_len, event.client_random_len, event.secret_len );
        return 0;
    }

    ret = bpf_probe_read_user(&event.label, sizeof(event.label), (void *)(buf->label_ptr));
    if (ret < 0) {
        //        debug_log("go labels, ret: %d", ret);
    }
    ret = bpf_probe_read_user(&event.client_random, sizeof(event.client_random), (void *)(buf->random_ptr));
    if (ret < 0) {
        //        debug_log("go random, ret: %d", ret);
    }
    ret = bpf_probe_read_user(&event.secret, sizeof(event.secret), (void *)(buf->secret_ptr));
    if (ret < 0) {
        //        debug_log("go secret, ret: %d", ret);
    }
    //        debug_log("go label_len: %d, client_random_len: %d, secret_len: %d", event.label_len,
    //                event.client_random_len, event.secret_len);
    //    debug_log("go label: %x, client_random: %x, secret: %x", event.label,
    //                event.client_random, event.secret);
    ret = bpf_perf_event_output(ctx, &go_keylog_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    if (ret < 0) {
        //                debug_log("go tls: per event failed, %d", ret);
    }
    return 0;
}
