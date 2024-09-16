#ifndef __PTCPDUMP_CUSTOM_H__
#define __PTCPDUMP_CUSTOM_H__

#include "vmlinux.h"

struct nf_conntrack_tuple___custom {
    struct nf_conntrack_man src;
    struct {
        union nf_inet_addr u3;
        union {
            __be16 all;
            struct {
                __be16 port;
            } tcp;
            struct {
                __be16 port;
            } udp;
            struct {
                u_int8_t type;
                u_int8_t code;
            } icmp;
            struct {
                __be16 port;
            } dccp;
            struct {
                __be16 port;
            } sctp;
            struct {
                __be16 key;
            } gre;
        } u;
        u_int8_t protonum;
        u_int8_t dir;
    } dst;
} __attribute__((preserve_access_index));

struct nf_conntrack_tuple_hash___custom {
    struct hlist_nulls_node hnnode;
    struct nf_conntrack_tuple___custom tuple;
} __attribute__((preserve_access_index));

// https://elixir.bootlin.com/linux/v5.2.21/source/include/net/netfilter/nf_conntrack.h
struct nf_conn___older_52 {
    struct nf_conntrack ct_general;
    spinlock_t lock;
    u16 ___cpu;
    struct nf_conntrack_zone zone;
    struct nf_conntrack_tuple_hash___custom tuplehash[IP_CT_DIR_MAX];
} __attribute__((preserve_access_index));

#endif /* __PTCPDUMP_CUSTOM_H__ */
