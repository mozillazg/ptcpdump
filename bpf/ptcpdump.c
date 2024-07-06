// go:build ignore
//  +build ignore

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
#define TC_ACT_UNSPEC -1
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define AF_INET 2
#define AF_INET6 10
#define INGRESS_PACKET 0
#define EGRESS_PACKET 1
#define EXEC_FILENAME_LEN 512
#define EXEC_ARGS_LEN 4096

char _license[] SEC("license") = "Dual MIT/GPL";

struct gconfig_t {
    u32 filter_pid;
    u8 filter_follow_forks;
    char filter_comm[TASK_COMM_LEN];
    u8 filter_comm_enable;
    u32 filter_mntns_id;
    u32 filter_netns_id;
    u32 filter_pidns_id;
    u32 max_payload_size;
};

#ifdef NO_CONST
#else
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
    u32 pid;
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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u8);
    __type(value, struct gconfig_t);
} config_map SEC(".maps");

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

#ifdef NO_CONST
#define GET_CONFIG()                                                                                                   \
    struct gconfig_t g = {0};                                                                                          \
    u8 configk = 0;                                                                                                    \
    struct gconfig_t *configv = bpf_map_lookup_elem(&config_map, &configk);                                            \
    if (configv) {                                                                                                     \
        g = *configv;                                                                                                  \
    }
#else
#define GET_CONFIG()
#endif

static __always_inline int parse_skb_l2(struct __sk_buff *skb, struct l2_t *l2, u32 *offset) {
    if (bpf_skb_load_bytes(skb, *offset + offsetof(struct ethhdr, h_proto), &l2->h_protocol, sizeof(l2->h_protocol)) <
        0) {
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
            return -1;
        }
        l3->protocol = ip_hdr.nexthdr;
        if (bpf_skb_load_bytes(skb, *offset + offsetof(struct ipv6hdr, saddr), &l3->saddr, sizeof(l3->saddr)) < 0) {
            return -1;
        }
        if (bpf_skb_load_bytes(skb, *offset + offsetof(struct ipv6hdr, daddr), &l3->daddr, sizeof(l3->daddr)) < 0) {
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
    BPF_CORE_READ_INTO(&meta->mntns_id, task, nsproxy, mnt_ns, ns.inum);
    BPF_CORE_READ_INTO(&meta->netns_id, task, nsproxy, net_ns, ns.inum);
    BPF_CORE_READ_INTO(&meta->pid, task, tgid);

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

    return g.filter_pid > 0 || g.filter_comm_enable == 1 || g.filter_mntns_id > 0 || g.filter_netns_id > 0 ||
           g.filter_pidns_id > 0;
}

static __always_inline int process_filter(struct task_struct *task) {
    // no filter rules
    if (!have_pid_filter_rules()) {
        // bpf_printk("no filter");
        return 0;
    }

    u32 pid = BPF_CORE_READ(task, tgid);
    if (bpf_map_lookup_elem(&filter_pid_map, &pid)) {
        // bpf_printk("match filter");
        return 0;
    }

    GET_CONFIG()
#ifdef NO_CONST
    u8 u8_zero = 0;
#endif

    bool should_filter = false;
    if (g.filter_pid > 0 && pid == g.filter_pid) {
        // bpf_printk("filter_id");
        should_filter = true;
    }

    if (!should_filter) {
        u32 mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
        u32 netns_id = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
        u32 pidns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
        if ((mntns_id > 0 && mntns_id == g.filter_mntns_id) || (netns_id > 0 && netns_id == g.filter_netns_id) ||
            (pidns_id > 0 && pidns_id == g.filter_pidns_id)) {
            // bpf_printk("%u %u %u", mntns_id, netns_id, pidns_id);
            should_filter = true;
        }
    }

    if (!should_filter) {
        if (g.filter_comm_enable == 1) {
            char comm[TASK_COMM_LEN];
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

    return -1;
}

static __always_inline int parent_process_filter(struct task_struct *current) {
    // no filter rules
    if (!have_pid_filter_rules()) {
        // bpf_printk("no filter");
        return 0;
    }

    GET_CONFIG()
#ifdef NO_CONST
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
#ifdef NO_CONST
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

#ifndef NO_CONST
SEC("cgroup/sock_create")
int cgroup__sock_create(void *ctx) {
    u64 cookie = bpf_get_socket_cookie(ctx);
    if (cookie <= 0) {
        // bpf_printk("[ptcpdump] sock_create: bpf_get_socket_cookie failed");
        return 1;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (parent_process_filter(task) < 0) {
        if (process_filter(task) < 0) {
            return 1;
        }
    }
    // bpf_printk("sock_create");

    struct process_meta_t meta = {0};
    fill_process_meta(task, &meta);

    int ret = bpf_map_update_elem(&sock_cookie_pid_map, &cookie, &meta, BPF_ANY);
    if (ret != 0) {
        // bpf_printk("[ptcpdump] bpf_map_update_elem sock_cookie_pid_map failed: %d", ret);
    }

    return 1;
}
#endif

#ifndef NO_CONST
SEC("cgroup/sock_release")
int cgroup__sock_release(void *ctx) {
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
    // bpf_printk("flow match");

    fill_sk_meta(sk, &key);
    fill_process_meta(task, &value);

    if (key.sport == 0) {
        return 0;
    }

    // bpf_printk("[ptcpdump] flow key: %pI4 %d", &key.saddr[0], key.sport);

    int ret = bpf_map_update_elem(&flow_pid_map, &key, &value, BPF_ANY);
    if (ret != 0) {
        // bpf_printk("bpf_map_update_elem flow_pid_map failed: %d", ret);
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
    // bpf_printk("sendmsg match");

    fill_sk_meta(sk, &key);
    if (bpf_map_lookup_elem(&flow_pid_map, &key)) {
        return;
    }

    fill_process_meta(task, &value);
    if (key.sport == 0) {
        return;
    }
    // bpf_printk("[ptcpdump][sendmsg] flow key: %pI4 %d", &key.saddr[0], key.sport);
    int ret = bpf_map_update_elem(&flow_pid_map, &key, &value, BPF_NOEXIST);
    if (ret != 0) {
        // bpf_printk("[handle_tcp_sendmsg] bpf_map_update_elem flow_pid_map failed: %d", ret);
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

// https://elixir.bootlin.com/linux/v5.2.21/source/include/net/netfilter/nf_conntrack.h
struct nf_conn__older_52 {
    struct nf_conntrack ct_general;
    spinlock_t	lock;
    u16		__cpu;
    struct nf_conntrack_zone zone;
    struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];
} __attribute__((preserve_access_index));

static __always_inline void handle_nat(struct nf_conn *ct) {
    struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];

    struct nf_conn__older_52 *nf_conn_old = (void *) ct;
    if (bpf_core_field_exists(nf_conn_old->__cpu)) {
         BPF_CORE_READ_INTO(&tuplehash, nf_conn_old, tuplehash);
    } else {
         BPF_CORE_READ_INTO(&tuplehash, ct, tuplehash);
    }

    struct nf_conntrack_tuple *orig_tuple = &tuplehash[IP_CT_DIR_ORIGINAL].tuple;
    struct nf_conntrack_tuple *reply_tuple = &tuplehash[IP_CT_DIR_REPLY].tuple;

    struct nat_flow_t orig = {0};
    struct nat_flow_t reply = {0};
    parse_conntrack_tuple(orig_tuple, &orig);
    parse_conntrack_tuple(reply_tuple, &reply);

    struct nat_flow_t reversed_orig = {0};
    reverse_flow(&orig, &reversed_orig);
    // bpf_printk("[ptcpdump] nat flow %pI4:%d %pI4:%d ->",
    // 		&reply.saddr[0], reply.sport,
    // 	       	&reply.daddr[0], reply.dport);
    // bpf_printk("[ptcpdump]                               -> %pI4:%d %pI4:%d",
    // 		&reversed_orig.saddr[0], reversed_orig.sport,
    // 		&reversed_orig.saddr[0], reversed_orig.dport);
    bpf_map_update_elem(&nat_flow_map, &reply, &reversed_orig, BPF_ANY);

    struct nat_flow_t reversed_reply = {0};
    reverse_flow(&reply, &reversed_reply);
    // bpf_printk("[ptcpdump] nat flow %pI4:%d %pI4:%d ->",
    // 		&reversed_reply.saddr[0], reversed_reply.sport,
    // 	       	&reversed_reply.daddr[0], reversed_reply.dport);
    // bpf_printk("[ptcpdump]                               -> %pI4:%d %pI4:%d",
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
            // bpf_printk("[ptcpdump]: no router %pI4:%d %pI4:%d",
            // 		&tmp_flow.saddr[0], tmp_flow.sport, &tmp_flow.daddr[0],
            // tmp_flow.dport);
            break;
        }

        // bpf_printk("[ptcpdump] route: %pI4 %pI4 => %pI4 %pI4",
        // 		&tmp_flow.saddr[0], &tmp_flow.daddr[0],
        // 		&translated_flow->saddr[0], &translated_flow->daddr[0]);
        clone_flow(translated_flow, flow);
        clone_flow(translated_flow, &tmp_flow);
    }

    return;
}

static __always_inline int get_pid_meta(struct __sk_buff *skb, struct process_meta_t *pid_meta, bool egress) {
#ifdef NO_CONST
#else
    u64 cookie = bpf_get_socket_cookie(skb);
    if (cookie > 0) {
        struct process_meta_t *value = bpf_map_lookup_elem(&sock_cookie_pid_map, &cookie);
        if (value) {
            pid_meta->pid = value->pid;
            pid_meta->mntns_id = value->mntns_id;
            pid_meta->netns_id = value->netns_id;
            __builtin_memcpy(&pid_meta->cgroup_name, &value->cgroup_name, sizeof(value->cgroup_name));
            return 0;
        }
    } else {
        if (egress) {
            //            bpf_printk("[ptcpdump] tc egress: bpf_get_socket_cookie failed");
        } else {
            //            bpf_printk("[ptcpdump] tc ingress: bpf_get_socket_cookie failed");
        }
    }
#endif

    struct packet_meta_t packet_meta = {0};
    int ret = parse_skb_meta(skb, &packet_meta);
    if (ret < 0) {
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

        if (have_pid_filter && key.sport == 0) {
            return -1;
        }

        if (key.sport > 0) {
            // bpf_printk("[tc] check %pI4 %d", &key.saddr[0], key.sport);
            struct process_meta_t *value = bpf_map_lookup_elem(&flow_pid_map, &key);
            if (value) {
                // bpf_printk("[tc] got %pI4 %d -> %pI4", &flow.saddr[0],
                // flow.sport, &flow.daddr[0]);
                pid_meta->pid = value->pid;
                pid_meta->mntns_id = value->mntns_id;
                pid_meta->netns_id = value->netns_id;
                __builtin_memcpy(&pid_meta->cgroup_name, &value->cgroup_name, sizeof(value->cgroup_name));

                break;
            } else if (have_pid_filter) {
                /* bpf_printk("[tc] %pI4 %d bpf_map_lookup_elem is empty",
                 * &key.saddr[0], key.sport); */
                return -1;
            }
        }
        egress = !egress;
    }

    return 0;
}

static __always_inline void handle_tc(struct __sk_buff *skb, bool egress) {
    bpf_skb_pull_data(skb, 0);

    if (!pcap_filter((void *)skb, (void *)skb, (void *)skb, (void *)(long)skb->data, (void *)(long)skb->data_end)) {
        return;
    }

    struct process_meta_t pid_meta = {0};
    if (get_pid_meta(skb, &pid_meta, egress) < 0) {
        return;
    };

    u32 *count;
#ifdef NO_CONST
    u32 u32_zero = 0;
#endif
    count = bpf_map_lookup_or_try_init(&filter_by_kernel_count, &u32_zero, &u32_zero);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    struct packet_event_t *event;
    event = bpf_map_lookup_elem(&packet_event_stack, &u32_zero);
    if (!event) {
        // bpf_printk("[ptcpdump] packet_event_stack failed");
        return;
    }
    /* __builtin_memset(&event->payload, 0, sizeof(event->payload)); */
    __builtin_memset(&event->meta, 0, sizeof(event->meta));

    if (egress) {
        event->meta.packet_type = EGRESS_PACKET;
    } else {
        event->meta.packet_type = INGRESS_PACKET;
    }
    event->meta.timestamp = bpf_ktime_get_ns();
    event->meta.ifindex = skb->ifindex;
    if (pid_meta.pid > 0) {
        event->meta.process.pid = pid_meta.pid;
        event->meta.process.mntns_id = pid_meta.mntns_id;
        event->meta.process.netns_id = pid_meta.netns_id;
        __builtin_memcpy(&event->meta.process.cgroup_name, &pid_meta.cgroup_name, sizeof(pid_meta.cgroup_name));
        /* __builtin_memcpy(&event->meta.comm, &pid_meta->comm, sizeof(pid_meta->comm)); */
    }

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
        // bpf_printk("[ptcpdump] bpf_perf_event_output exec_events failed: %d", event_ret);
    }

    return;
}

static __always_inline void handle_exec(struct bpf_raw_tracepoint_args *ctx) {
    // args: struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm
    struct task_struct *task = (struct task_struct *)BPF_CORE_READ(ctx, args[0]);
    if (process_filter(task) < 0) {
        return;
    }

    struct exec_event_t *event;
#ifdef NO_CONST
    u32 u32_zero = 0;
#endif
    event = bpf_map_lookup_elem(&exec_event_stack, &u32_zero);
    if (!event) {
        // bpf_printk("[ptcpdump] exec_event_stack failed");
        return;
    }
    __builtin_memset(&event->meta, 0, sizeof(event->meta));

    fill_process_meta(task, &event->meta);

    struct linux_binprm *bprm = (struct linux_binprm *)BPF_CORE_READ(ctx, args[2]);
    const char *filename_p = BPF_CORE_READ(bprm, filename);
    int f_ret = bpf_probe_read_str(&event->filename, sizeof(event->filename), filename_p);
    if (f_ret < 0) {
        // bpf_printk("[ptcpdump] read exec filename failed: %d", f_ret);
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
        // bpf_printk("[ptcpdump] read exec args failed: %d", arg_ret);
    } else {
        event->args_size = arg_length;
    }

    int event_ret = bpf_perf_event_output(ctx, &exec_events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    if (event_ret != 0) {
        // bpf_printk("[ptcpdump] bpf_perf_event_output exec_events failed: %d", event_ret);
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
        // bpf_printk("[ptcpdump] bpf_perf_event_output exit_events failed: %d", event_ret);
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
    return TC_ACT_OK;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
    handle_tc(skb, true);
    return TC_ACT_OK;
}
