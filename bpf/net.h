#ifndef __PTCPDUMP_NET_H__
#define __PTCPDUMP_NET_H__

#include "bpf_ipv6.h"
#include "compat.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_HLEN 14         /* Total octets in header.	 */
#define ETH_P_IP 0x0800     /* Internet Protocol packet	*/
#define ETH_P_IPV6 0x86DD   /* IPv6 over bluebook		*/
#define ETH_P_8021Q 0x8100  /* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD 0x88A8 /* 802.1ad Service VLAN		*/
#define IPPROTO_ICMP 1      /* Internet Control Message Protocol	*/
#define IPPROTO_ICMPV6 58   /* ICMPv6			*/
#define IPPROTO_TCP 6       /* Transmission Control Protocol	*/
#define IPPROTO_UDP 17      /* User Datagram Protocol		*/
#define IPPROTO_SCTP 132    /* Stream Control Transport Protocol	*/
#define AF_INET 2
#define AF_INET6 10

struct l2_t {
    u16 h_protocol; /* next layer protocol */
};

struct l3_t {
    u8 protocol; /* next layer protocol */
    u64 saddr[2];
    u64 daddr[2];
};

struct l4_t {
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

const struct flow_pid_key_t *unused3 __attribute__((unused));

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

        u8 ip_ihl = 0;
        u32 ip_hdr_len = 0;
        // support ip options
        if (bpf_skb_load_bytes(skb, *offset, &ip_ihl, sizeof(ip_ihl)) == 0) {
            ip_hdr_len = (ip_ihl & 0x0f) * 4;
        }
        if (ip_hdr_len < sizeof(struct iphdr)) {
            //            debug_log("[ptcpdump] invalid ip header length: %d, use default %d\n", ip_hdr_len,
            //            sizeof(struct iphdr));
            ip_hdr_len = sizeof(struct iphdr);
        }

        //        debug_log("source_ip: %pI4, dest_ip: %pI4\n", &l3->saddr[0], &l3->daddr[0]);

        *offset += ip_hdr_len;
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
            //             debug_log("parse_skb_l4 1 failed:\n");
            return -1;
        }
        l4->sport = bpf_ntohs(tcp_hdr.source);
        l4->dport = bpf_ntohs(tcp_hdr.dest);

        //        debug_log("parse_skb_l4 1 success: %d -> %d\n", l4->sport, l4->dport);

        *offset += sizeof(struct tcphdr);
        return 0;
    }
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
#ifdef SUPPORT_SCTP
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
#endif /* SUPPORT_SCTP */
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

#define is_unset(x) ((x) == (typeof(x))~0U)

static __always_inline bool is_valid_mac(u16 mac) { return !is_unset(mac); }

static __always_inline bool is_valid_network(u16 network) { return network && !is_unset(network); }

static __always_inline bool has_valid_mac_data(const struct sk_buff *skb) {
    u16 mac = BPF_CORE_READ(skb, mac_header);
    u16 network = BPF_CORE_READ(skb, network_header);

    return is_valid_mac(mac) && BPF_CORE_READ(skb, dev, hard_header_len) && mac < network &&
           !(is_valid_network(network) && network == mac && BPF_CORE_READ(skb, mac_len) == 0);
}

static __always_inline int parse_skb_buff_meta(struct sk_buff *skb, struct packet_meta_t *meta) {
    meta->ifindex = BPF_CORE_READ(skb, dev, ifindex);

    void *skb_head = BPF_CORE_READ(skb, head);
    u16 l2_offset = BPF_CORE_READ(skb, mac_header);
    u16 l3_offset = BPF_CORE_READ(skb, network_header);
    u16 l4_offset = BPF_CORE_READ(skb, transport_header);
    u16 protocol = BPF_CORE_READ(skb, protocol);

    if (has_valid_mac_data(skb)) {
        struct ethhdr *eth_hdr = (struct ethhdr *)(skb_head + l2_offset);
        meta->l2.h_protocol = bpf_ntohs(BPF_CORE_READ(eth_hdr, h_proto));
    }
    if (!meta->l2.h_protocol) {
        meta->l2.h_protocol = bpf_ntohs(BPF_CORE_READ(skb, protocol));
    }
    if (protocol == bpf_ntohs(ETH_P_8021Q) || protocol == bpf_ntohs(ETH_P_8021AD)) {
        //        debug_log("[ptcpdump][tp-btf] parse_skb_buff_meta: vlan header\n");
        l3_offset += sizeof(struct vlan_hdr);
        struct iphdr *ip_hdr = (struct iphdr *)(skb_head + l3_offset);
        u8 ip_ver = BPF_CORE_READ_BITFIELD_PROBED(ip_hdr, version);
        if (ip_ver == 4) {
            meta->l2.h_protocol = ETH_P_IP;
        } else if (ip_ver == 6) {
            meta->l2.h_protocol = ETH_P_IPV6;
        }
    }

    //    debug_log("[ptcpdump][tp-btf] meta->l2.h_protocol: %d, %d, %d, %d\n", meta->l2.h_protocol,
    //              BPF_CORE_READ(skb, mac_header), BPF_CORE_READ(skb, network_header), BPF_CORE_READ(skb,
    //              transport_header));
    switch (meta->l2.h_protocol) {
    case ETH_P_IP: {
        struct iphdr *ip_hdr = (struct iphdr *)(skb_head + l3_offset);
        meta->l3.protocol = BPF_CORE_READ(ip_hdr, protocol);
        meta->l3.saddr[0] = BPF_CORE_READ(ip_hdr, saddr);
        meta->l3.daddr[0] = BPF_CORE_READ(ip_hdr, daddr);
        l4_offset = l3_offset + BPF_CORE_READ_BITFIELD_PROBED(ip_hdr, ihl) * 4;
        break;
    }
    case ETH_P_IPV6: {
        struct ipv6hdr *ip_hdr = (struct ipv6hdr *)(skb_head + l3_offset);
        meta->l3.protocol = BPF_CORE_READ(ip_hdr, nexthdr);
        BPF_CORE_READ_INTO(&meta->l3.saddr, ip_hdr, saddr);
        BPF_CORE_READ_INTO(&meta->l3.daddr, ip_hdr, daddr);
        l4_offset = l3_offset + ipv6_hdrlen(ip_hdr);
        break;
    }
    }

    //    debug_log("[ptcpdump][tp-btf] meta->l3.protocol: %pI4 %d\n", &meta->l3.saddr[0], meta->l3.protocol);
    switch (meta->l3.protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp_hdr = (struct tcphdr *)(skb_head + l4_offset);
        meta->l4.sport = bpf_ntohs(BPF_CORE_READ(tcp_hdr, source));
        meta->l4.dport = bpf_ntohs(BPF_CORE_READ(tcp_hdr, dest));
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *udp_hdr = (struct udphdr *)(skb_head + l4_offset);
        meta->l4.sport = bpf_ntohs(BPF_CORE_READ(udp_hdr, source));
        meta->l4.dport = bpf_ntohs(BPF_CORE_READ(udp_hdr, dest));
        break;
    }
#ifdef SUPPORT_SCTP
    case IPPROTO_SCTP: {
        // some systems do not have struct sctphdr. e.g. openwrt
        if (!bpf_core_type_exists(struct sctphdr)) {
            break;
        }
        struct sctphdr *sctp_hdr = (struct sctphdr *)(skb_head + l4_offset);
        meta->l4.sport = bpf_ntohs(BPF_CORE_READ(sctp_hdr, source));
        meta->l4.dport = bpf_ntohs(BPF_CORE_READ(sctp_hdr, dest));
        break;
    }
#endif /* SUPPORT_SCTP */
    default: {
        //        debug_log("[ptcpdump][tp-btf] parse_skb_buff_meta: unknown l4 protocol %d\n", meta->l3.protocol);
        meta->l3.protocol = BPF_CORE_READ(skb, sk, sk_protocol);
        meta->l4.sport = BPF_CORE_READ(skb, sk, __sk_common.skc_num);
        meta->l4.dport = bpf_ntohs(BPF_CORE_READ(skb, sk, __sk_common.skc_dport));
        u32 family = BPF_CORE_READ(skb, sk, __sk_common.skc_family);
        switch (family) {
        case AF_INET: {
            meta->l3.saddr[0] = BPF_CORE_READ(skb, sk, __sk_common.skc_rcv_saddr);
            meta->l3.daddr[0] = BPF_CORE_READ(skb, sk, __sk_common.skc_daddr);
            break;
        }
        case AF_INET6: {
            BPF_CORE_READ_INTO(&meta->l3.saddr, skb, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
            BPF_CORE_READ_INTO(&meta->l3.daddr, skb, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
            break;
        }
        }

        //        debug_log("[ptcpdump][tp-btf] addr %pI4 %pI4\n", &meta->l3.saddr[0], &meta->l3.daddr[0]);
        //        debug_log("[ptcpdump][tp-btf] port %d %d\n", meta->l4.sport, meta->l4.dport);
        break;
    }
    }

    //    debug_log("[ptcpdump][tp-btf] meta->l4.sport: %d, %d\n", meta->l4.sport, meta->l4.dport);
    return 0;
}

static __always_inline u32 get_netns_id_from_skb(struct sk_buff *skb) {
    u32 netns = BPF_CORE_READ(skb, dev, nd_net.net, ns.inum);
    if (!netns) {
        netns = BPF_CORE_READ(skb, sk, __sk_common.skc_net.net, ns.inum);
    }
    return netns;
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

#endif /* __PTCPDUMP_NET_H__ */
