#ifndef __PTCPDUMP_NET_H__
#define __PTCPDUMP_NET_H__

#include "common.h"
#include "compat.h"
#include "process.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_HLEN 14       /* Total octets in header.	 */
#define ETH_P_IP 0x0800   /* Internet Protocol packet	*/
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook		*/
#define IPPROTO_ICMP 1    /* Internet Control Message Protocol	*/
#define IPPROTO_ICMPV6 58 /* ICMPv6			*/
#define IPPROTO_TCP 6     /* Transmission Control Protocol	*/
#define IPPROTO_UDP 17    /* User Datagram Protocol		*/
#define IPPROTO_SCTP 132  /* Stream Control Transport Protocol	*/
#define AF_INET 2
#define AF_INET6 10

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
        // some systems do not have struct sctphdr. e.g. openwrt
        if (!bpf_core_type_exists(struct sctphdr)) {
            return 0;
        }
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

static __always_inline int parse_skb_meta(struct __sk_buff *skb, bool l2_skb, struct packet_meta_t *meta) {
    meta->ifindex = skb->ifindex;

    if (l2_skb) {
        if (parse_skb_l2(skb, &meta->l2, &meta->offset) < 0) {
            return -1;
        }
    }

    if (parse_skb_l3(skb, meta->l2.h_protocol, &meta->l3, &meta->offset) < 0) {
        return -1;
    }

    if (parse_skb_l4(skb, meta->l3.protocol, &meta->l4, &meta->offset) < 0) {
        return -1;
    }
    return 0;
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

static __always_inline void save_flow_from_sock(struct task_struct *task, struct sock *sk) {
    struct flow_pid_key_t key = {0};
    struct process_meta_t value = {0};

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

#ifndef NO_TRACING

extern void socket_file_ops __ksym;

SEC("iter/task_file")
int iter__task_file(struct bpf_iter__task_file *ctx) {
    struct file *file = ctx->file;
    struct task_struct *task = ctx->task;

    if (!file || !task) {
        goto out;
    }

    struct socket *socket = NULL;
    if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_sock_from_file)) {
        socket = bpf_sock_from_file(file);
    } else {
        if (file->f_op != &socket_file_ops) {
            goto out;
        }
        socket = (struct socket *)file->private_data;
    }
    if (!socket) {
        goto out;
    }

    struct sock *sk = BPF_CORE_READ(socket, sk);
    save_flow_from_sock(task, sk);

out:
    return 0;
}
#endif

#endif /* __PTCPDUMP_NET_H__ */
