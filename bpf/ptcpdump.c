//go:build ignore
// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define TTY_NAME_LEN 64
#define ETH_HLEN 14 /* Total octets in header.	 */
#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/
#define IPPROTO_ICMP  1		/* Internet Control Message Protocol	*/
#define IPPROTO_ICMPV6		58	/* ICMPv6			*/
#define IPPROTO_TCP  6		/* Transmission Control Protocol	*/
#define IPPROTO_UDP  17		/* User Datagram Protocol		*/
#define IPPROTO_SCTP  132		/* Stream Control Transport Protocol	*/
#define TC_ACT_UNSPEC -1
#define TC_ACT_OK      0
#define TC_ACT_SHOT    2
#define AF_INET    2
#define AF_INET6   10
#define MAX_PAYLOAD_SIZE 1500
#define INGRESS_PACKET 0
#define EGRESS_PACKET 1
#define EXEC_FILENAME_LEN 512
#define EXEC_ARGS_LEN 4096

static volatile const u32 filter_pid = 0;
static volatile const u8 filter_follow_forks = 0;
volatile const char filter_comm[TASK_COMM_LEN];
static const u8 u8_zero = 0;
static const u32 u32_zero = 0;

char _license[] SEC("license") = "Dual MIT/GPL";

struct l2_t {
    u16 h_protocol;
};

struct l3_t {
    u8 ip_version;
    u8 protocol;
    u32 saddr[4];
    u32 daddr[4];
};

struct l4_t {
    u64 flags;
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
    u32 saddr[4];
    u16 sport;
};

struct flow_pid_value_t {
    u32 pid;

    char comm[TASK_COMM_LEN];
    char tty_name[TTY_NAME_LEN];
};

struct packet_event_meta_t {
    u64 timestamp;
    u8 packet_type;
    u32 ifindex;
    u32 pid;
    u64 payload_len;
    u64 packet_size;
    char comm[TASK_COMM_LEN];
};

struct packet_event_t {
    struct packet_event_meta_t meta;
    u8 payload[MAX_PAYLOAD_SIZE];
};

struct exec_event_t {
    u32 pid;
    u8 filename_truncated;
    u8 args_truncated;
    unsigned int args_size;
    char filename[EXEC_FILENAME_LEN];
    char args[EXEC_ARGS_LEN];
};

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
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_pid_key_t);
    __type(value, struct flow_pid_value_t);
} flow_pid_map SEC(".maps");

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

// force emitting struct into the ELF.
// the `-type` flag of bpf2go need this
// avoid "Error: collect C types: type name XXX: not found"
const struct packet_event_t *unused1 __attribute__((unused));
const struct exec_event_t *unused2 __attribute__((unused));


static __always_inline int parse_skb_l2(struct __sk_buff *skb, struct l2_t *l2, u32 *offset) {
    if (bpf_skb_load_bytes(skb, *offset + offsetof(struct ethhdr, h_proto), &l2->h_protocol, sizeof(l2->h_protocol)) < 0 ) {
        return -1;
    }
    l2->h_protocol = bpf_ntohs(l2->h_protocol);
    *offset += sizeof(struct ethhdr);
    return 0;
};

static __always_inline int parse_skb_l3(struct __sk_buff *skb, u16 protocol, struct l3_t *l3, u32 *offset) {
    switch (protocol) {
    case ETH_P_IP: {
        l3->ip_version = 4;
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
        l3->ip_version = 6;
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
};

static __always_inline int parse_skb_l4(struct __sk_buff *skb, u8 protocol, struct l4_t *l4, u32 *offset) {
    switch (protocol) {
    case IPPROTO_ICMP: {
        l4->sport = 0;
        l4->dport = 0;
        if (bpf_skb_load_bytes(skb, *offset + offsetof(struct icmphdr, type), &l4->flags, sizeof(u8)) < 0) {
            return -1;
        }
        *offset += sizeof(struct icmphdr);
        return 0;
     }
    case IPPROTO_ICMPV6: {
        l4->sport = 0;
        l4->dport = 0;
        if (bpf_skb_load_bytes(skb, *offset + offsetof(struct icmp6hdr, icmp6_type), &l4->flags, sizeof(u8)) < 0) {
            return -1;
        }
        *offset += sizeof(struct icmp6hdr);
        return 0;
     }
    case IPPROTO_TCP: {
        struct tcphdr tcp_hdr;
        if (bpf_skb_load_bytes(skb, *offset, &tcp_hdr, sizeof(struct tcphdr)) < 0) {
            return -1;
        }
        l4->sport = bpf_ntohs(tcp_hdr.source);
        l4->dport = bpf_ntohs(tcp_hdr.dest);
        l4->flags = tcp_hdr.fin + (tcp_hdr.syn << 1) + (tcp_hdr.rst << 2) + (tcp_hdr.psh << 3) + (tcp_hdr.ack << 4) + (tcp_hdr.urg << 5) + (tcp_hdr.ece << 6) + (tcp_hdr.cwr << 7);
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
};

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
};

static __always_inline void fill_process_meta(struct task_struct *task, struct flow_pid_value_t *meta) {
    struct tty_struct *tty = (struct tty_struct *)BPF_CORE_READ(task, signal, tty);
    BPF_CORE_READ_STR_INTO(&meta->tty_name, tty, name);
    BPF_CORE_READ_STR_INTO(&meta->comm, task, comm);
    BPF_CORE_READ_INTO(&meta->pid, task, tgid);
};

static __always_inline void fill_sk_meta(struct sock *sk, struct flow_pid_key_t *meta) {
    BPF_CORE_READ_INTO(&meta->sport, sk, __sk_common.skc_num);
    u32 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    switch (family) {
    case AF_INET: {
        BPF_CORE_READ_INTO(&meta->saddr[0], sk, __sk_common.skc_rcv_saddr);
        break;
      }
    case AF_INET6: {
        BPF_CORE_READ_INTO(&meta->saddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        break;
      }
    default: {
        break;
      }
    }
};

static __always_inline bool str_cmp(const char *a, const volatile char *b, int len)
{
#pragma unroll
    for (int i = 0; i < len; i++) {
        if (a[i] != b[i])
            return -1;
        if (a[i] == '\0')
            break;
    }
    return 0;
}

static __always_inline int str_len(const volatile char *s, int max_len)
{
#pragma unroll
    for (int i = 0; i < max_len; i++) {
        if (s[i] == '\0')
            return i;
    }
    if (s[max_len - 1] != '\0')
        return max_len;
    return 0;
}

static __always_inline int process_filter(struct task_struct *task) {
    u32 pid = BPF_CORE_READ(task, tgid);
    if (bpf_map_lookup_elem(&filter_pid_map, &pid)) {
        return 0;
    }

    bool should_filter = false;
    if (filter_pid != 0) {
        if (pid != filter_pid) {
            return -1;
        }
        should_filter = true;
    }

    if (!should_filter) {
        if (str_len(filter_comm, TASK_COMM_LEN) > 1) {
            char comm[TASK_COMM_LEN];
            BPF_CORE_READ_STR_INTO(&comm, task, comm);
            if (str_cmp(comm, filter_comm, TASK_COMM_LEN) != 0) {
                return -1;
            }
            should_filter = true;
        }
    }

    if (should_filter) {
        bpf_map_update_elem(&filter_pid_map, &pid, &u8_zero, BPF_NOEXIST);
    }

    return 0;
}

static __always_inline void handle_fork(struct trace_event_raw_sys_exit *ctx) {
    if (filter_follow_forks != 1) {
        return;
    }
    u32 child_pid = BPF_CORE_READ(ctx, ret);
    if (child_pid <= 0) {
        return;
    }

    bool should_filter = false;
    struct task_struct *task =  (struct task_struct*)bpf_get_current_task();
    if (process_filter(task) == 0) {
        should_filter = true;
//        bpf_printk("handle fork: parent");
    }

    if (!should_filter) {
        if (filter_pid > 0 && child_pid == filter_pid) {
            should_filter = true;
        }
    }
    if (should_filter) {
        bpf_map_update_elem(&filter_pid_map, &child_pid, &u8_zero, BPF_NOEXIST);
//        bpf_printk("handle fork: %d", child_pid);
    }
    return;
}

SEC("tracepoint/syscalls/sys_exit_fork")
int tracepoint__syscalls__sys_exit_fork(struct trace_event_raw_sys_exit *ctx) {
    handle_fork(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_vfork")
int tracepoint__syscalls__sys_exit_vfork(struct trace_event_raw_sys_exit *ctx) {
    handle_fork(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone")
int tracepoint__syscalls__sys_exit_clone(struct trace_event_raw_sys_exit *ctx) {
    handle_fork(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone3")
int tracepoint__syscalls__sys_exit_clone3(struct trace_event_raw_sys_exit *ctx) {
    handle_fork(ctx);
    return 0;
}

SEC("kprobe/security_sk_classify_flow")
int BPF_KPROBE(kprobe__security_sk_classify_flow, struct sock *sk) {
    struct flow_pid_key_t key = {0};
    struct flow_pid_value_t value = {0};
    struct task_struct *task =  (struct task_struct*)bpf_get_current_task();

    if (process_filter(task) < 0) {
        return 0;
    }

    fill_sk_meta(sk, &key);
    fill_process_meta(task, &value);

    if (key.sport == 0) {
        return 0;
    }

    /* bpf_printk("(%s) %pI4 %d", value.comm, &key.saddr[0], key.sport); */

    int ret = bpf_map_update_elem(&flow_pid_map, &key, &value, BPF_ANY);
    if (ret != 0) {
        bpf_printk("bpf_map_update_elem flow_pid_map failed: %d", ret);
    }
    return 0;
};

static __noinline bool pcap_filter(void *_skb, void *__skb, void *___skb, void *data, void* data_end) {
	return data != data_end && _skb == __skb && __skb == ___skb;
};

static __always_inline void handle_tc(struct __sk_buff *skb, bool egress) {
    bpf_skb_pull_data(skb, 0);

    if (!pcap_filter((void *)skb, (void *)skb, (void *)skb, (void *)(long)skb->data, (void *)(long)skb->data_end)) {
        return;
    }

    struct packet_meta_t packet_meta = {0};
    int ret = parse_skb_meta(skb, &packet_meta);
    if (ret < 0) {
        return;
    }


    struct flow_pid_key_t key = {0};
    if (egress) {
        key.saddr[0] = packet_meta.l3.saddr[0];
        key.saddr[1] = packet_meta.l3.saddr[1];
        key.saddr[2] = packet_meta.l3.saddr[2];
        key.saddr[3] = packet_meta.l3.saddr[3];
        key.sport = packet_meta.l4.sport;
    } else {
        key.saddr[0] = packet_meta.l3.daddr[0];
        key.saddr[1] = packet_meta.l3.daddr[1];
        key.saddr[2] = packet_meta.l3.daddr[2];
        key.saddr[3] = packet_meta.l3.daddr[3];
        key.sport = packet_meta.l4.dport;
    }

    if (key.sport == 0) {
        return;
    }


    /* bpf_printk("[tc] %pI4 %d", &key.saddr[0], key.sport); */

    struct flow_pid_value_t *value = bpf_map_lookup_elem(&flow_pid_map, &key);
    if (value) {
//        bpf_printk("[tc] (%s) %pI4 %d", value->comm, &key.saddr[0], key.sport);
    } else {
        /* bpf_printk("[tc] %pI4 %d bpf_map_lookup_elem is empty", &key.saddr[0], key.sport); */
        return;
    }

    struct packet_event_t *event;
    event = bpf_map_lookup_elem(&packet_event_stack, &u32_zero);
    if (!event) {
        bpf_printk("[ptcpdump] packet_event_stack failed");
        return;
    }
//    __builtin_memset(event, 0, sizeof(*event));

    if (egress) {
        event->meta.packet_type = EGRESS_PACKET;
    } else {
        event->meta.packet_type = INGRESS_PACKET;
    }
    event->meta.timestamp = bpf_ktime_get_ns();
    event->meta.ifindex = packet_meta.ifindex;
    event->meta.pid = value->pid;
    __builtin_memcpy(&event->meta.comm, &value->comm, sizeof(value->comm));

    u64 payload_len = (u64)skb->len;
    event->meta.packet_size = payload_len;
    payload_len = payload_len < MAX_PAYLOAD_SIZE ? payload_len : MAX_PAYLOAD_SIZE;
    event->meta.payload_len = payload_len;

    bpf_perf_event_output(skb, &packet_events, BPF_F_CURRENT_CPU | (payload_len <<32),
                          event, offsetof(struct packet_event_t, payload));

    return;
}

static __always_inline void handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (process_filter(task) < 0) {
        return;
    }

    struct exec_event_t *event;
    event = bpf_map_lookup_elem(&exec_event_stack, &u32_zero);
    if (!event) {
        bpf_printk("[ptcpdump] exec_event_stack failed");
        return;
    }

    event->pid = bpf_get_current_pid_tgid() >> 32;

    unsigned int filename_loc = BPF_CORE_READ(ctx, __data_loc_filename) & 0xFFFF;
    int f_ret = bpf_probe_read_str(&event->filename, sizeof(event->filename), (void *)ctx + filename_loc);
    if (f_ret < 0 ) {
        bpf_printk("[ptcpdump] read exec filename failed: %d", f_ret);
    }
    if (f_ret == EXEC_FILENAME_LEN) {
        event->filename_truncated = 1;
//        char tmp[EXEC_FILENAME_LEN+1];
//        if (bpf_probe_read_str(&tmp, sizeof(tmp), (void *)ctx + filename_loc) > EXEC_FILENAME_LEN) {
//            event->filename_truncated = 1;
//        }
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
        bpf_printk("[ptcpdump] read exec args failed: %d", arg_ret);
    } else {
        event->args_size = arg_length;
    }

    int event_ret = bpf_perf_event_output(ctx, &exec_events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    if (event_ret != 0) {
        bpf_printk("[ptcpdump] bpf_perf_event_output exec_events failed: %d", event_ret);
    }
    return;
}

SEC("tracepoint/sched/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    handle_exec(ctx);
    return 0;
}

SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    handle_tc(skb, false);
    return TC_ACT_OK;
};

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
    handle_tc(skb, true);
    return TC_ACT_OK;
};
