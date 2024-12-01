#ifndef __PTCPDUMP_NAT_H__
#define __PTCPDUMP_NAT_H__

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct nat_flow_t {
    u64 saddr[2];
    u64 daddr[2];
    u16 sport;
    u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct nat_flow_t);
    __type(value, struct nat_flow_t);
} nat_flow_map SEC(".maps");

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

#ifndef NO_TRACING
SEC("fentry/nf_nat_packet")
int BPF_PROG(fentry__nf_nat_packet, struct nf_conn *ct) {
    handle_nat(ct);
    return 0;
}
#endif

SEC("kprobe/nf_nat_manip_pkt")
int BPF_KPROBE(kprobe__nf_nat_manip_pkt, void *_, struct nf_conn *ct) {
    handle_nat(ct);
    return 0;
}

#ifndef NO_TRACING
SEC("fentry/nf_nat_manip_pkt")
int BPF_PROG(fentry__nf_nat_manip_pkt, void *_, struct nf_conn *ct) {
    handle_nat(ct);
    return 0;
}
#endif

static __always_inline void clone_flow(struct nat_flow_t *orig, struct nat_flow_t *new_flow) {
    new_flow->saddr[0] = orig->saddr[0];
    new_flow->saddr[1] = orig->saddr[1];

    new_flow->daddr[0] = orig->daddr[0];
    new_flow->daddr[1] = orig->daddr[1];

    new_flow->sport = orig->sport;
    new_flow->dport = orig->dport;
}

#endif /* __PTCPDUMP_NAT_H__ */
