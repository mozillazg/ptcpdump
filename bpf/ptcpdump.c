// go:build ignore
//  +build ignore

#include "compat.h"
#include "custom.h"
#include "flow.h"
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
#define TC_ACT_UNSPEC (-1)
#define TCX_NEXT (-1)
#define PACKET_HOST 0      /* To us		*/
#define PACKET_BROADCAST 1 /* To all		*/
#define PACKET_MULTICAST 2 /* To group		*/
#define PACKET_OTHERHOST 3 /* To someone else 	*/
#define PACKET_OUTGOING 4  /* Outgoing of any type */
#define PACKET_LOOPBACK 5  /* MC/BRD frame looped back */
#define INGRESS_PACKET 1
#define EGRESS_PACKET 2
#define L2_LAYER 2
#define L3_LAYER 3
#define IFNAMESIZ 16

char _license[] SEC("license") = "Dual MIT/GPL";

struct packet_event_meta_t {
    u64 timestamp;
    u8 packet_type;
    u8 first_layer;
    u16 l3_protocol;
    u32 netns_id;
    u32 ifindex;
    unsigned char ifname[IFNAMESIZ];
    u64 payload_len;
    u64 packet_size;

    struct process_meta_t process;
};

struct packet_event_t {
    struct packet_event_meta_t meta;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, u32);
    __type(value, u8);
} ptcpdump_filter_ifindex_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct packet_event_t);
} ptcpdump_packet_event_stack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} ptcpdump_packet_events SEC(".maps");

struct skb_data_t {
    u8 data[1 << 18];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 25);
} ptcpdump_packet_events_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} ptcpdump_filter_by_kernel_count SEC(".maps");

// force emitting struct into the ELF.
// the `-type` flag of bpf2go need this
// avoid "Error: collect C types: type name XXX: not found"
const struct packet_event_t *unused1 __attribute__((unused));
const struct gconfig_t *unused6 __attribute__((unused));

static __noinline bool pcap_filter(void *_skb, void *__skb, void *___skb, void *data, void *data_end) {
    return data != data_end && _skb == __skb && __skb == ___skb;
}

static __noinline bool pcap_filter_l3(void *_skb, void *__skb, void *___skb, void *data, void *data_end) {
    return data != data_end && _skb == __skb && __skb == ___skb;
}

static __always_inline void fallback_pid_meta(struct process_meta_t *meta) {
    // The bpf_get_current_task() fallback is disabled. It is unsafe without a reliable
    // way to detect the interrupt context (e.g., bpf_in_interrupt()). In such a context,
    // it would return an unrelated task and cause incorrect PID association.
    return;
}

static __always_inline int fill_packet_event_meta(struct __sk_buff *skb, bool cgroup_skb,
                                                  struct packet_event_meta_t *event_meta, bool egress) {
    struct process_meta_t *pid_meta = &event_meta->process;

    if (cgroup_skb && egress) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        if (task && !is_kernel_thread(task)) {
            if (parent_process_filter(task) < 0) {
                if (process_filter(task) < 0) {
                    goto outer;
                }
            }
            event_meta->l3_protocol = bpf_ntohs(skb->protocol);
            fill_process_meta_with_thread(task, pid_meta);
            if (pid_meta->pid > 0) {
                // debug_log("[ptcpdump][cgroup_sk] get_current_task success\n");
                return 0;
            }
        }
    outer:
        (void)0;
        // debug_log("[ptcpdump][cgroup_sk] get_current_task failed\n");
    }

    bool have_pid_filter = have_pid_filter_rules();
    struct packet_meta_t packet_meta = {0};
    if (cgroup_skb) {
        packet_meta.l2.h_protocol = bpf_ntohs(skb->protocol);
    }
    int ret = parse_skb_meta(skb, !cgroup_skb, &packet_meta);
    event_meta->l3_protocol = packet_meta.l2.h_protocol;
    //     debug_log("l3_protocol: %d\n", event_meta->l3_protocol);
    if (ret < 0) {
        //         debug_log("[ptcpdump] parse skb meta failed\n");
        if (have_pid_filter) {
            return -1;
        }
        return 0;
    }

#ifndef LEGACY_KERNEL
    if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_socket_cookie)) {
        u64 cookie = bpf_get_socket_cookie(skb);
        if (cookie > 0) {
            if (egress) {
                // debug_log("[ptcpdump] tc egress: bpf_get_socket_cookie success\n");
            } else {
                // debug_log("[ptcpdump] tc ingress: bpf_get_socket_cookie success\n");
            }
            struct process_meta_t *value = bpf_map_lookup_elem(&ptcpdump_sock_cookie_pid_map, &cookie);
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

    struct nat_flow_t flow = {0};
    GET_CONFIG()
    struct flow_pid_key_t key = {0};
    bool reverse = false;

#ifdef SUPPORT_NAT
    struct nat_flow_t tmp_flow = flow;
#endif

#pragma unroll
    for (int j = 0; j < 2; j++) {
        if (j == 1) {
            if (g.disable_reverse_match) {
                break;
            }
            reverse = true;
        }
        flow.saddr[0] = packet_meta.l3.saddr[0];
        flow.saddr[1] = packet_meta.l3.saddr[1];

        flow.daddr[0] = packet_meta.l3.daddr[0];
        flow.daddr[1] = packet_meta.l3.daddr[1];

        flow.sport = packet_meta.l4.sport;
        flow.dport = packet_meta.l4.dport;

#pragma unroll
        for (int i = 0; i < 10; i++) {
            if (!reverse) {
                key.saddr[0] = flow.saddr[0];
                key.saddr[1] = flow.saddr[1];
                key.sport = flow.sport;
            } else {
                key.saddr[0] = flow.daddr[0];
                key.saddr[1] = flow.daddr[1];
                key.sport = flow.dport;
            }

            if (have_pid_filter && flow.sport == 0 && flow.dport == 0) {
                // debug_log("[ptcpdump][tc], sport is zero\n");
                // debug_log("[ptcpdump][tc] %pI4 %d sport is zero\n", &key.saddr[0], key.sport);
                return -1;
            }

            // debug_log("tc, try to get pid\n");
            //            debug_log("[ptcpdump][tc] %d, %d check %pI4 %d\n", j, i, &key.saddr[0], key.sport);
            if (key.sport > 0) {
                //                debug_log("[tc] check %pI4 %d\n", &key.saddr[0], key.sport);
                struct process_meta_t *value = bpf_map_lookup_elem(&ptcpdump_flow_pid_map, &key);
                if (value) {
                    // debug_log("[ptcpdump][tc] got %pI4 %d -> %pI4\n", &flow.saddr[0],
                    // flow.sport, &flow.daddr[0]);
                    clone_process_meta(value, pid_meta);
                    return 0;
                } else if (have_pid_filter) {
                    // debug_log("[ptcpdump][tc], ptcpdump_flow_pid_map is empty\n");
                    // debug_log("[ptcpdump][tc] %pI4 %d bpf_map_lookup_elem ptcpdump_flow_pid_map is empty\n",
                    // &key.saddr[0], key.sport);
                }
            }

#ifdef SUPPORT_NAT
            struct nat_flow_t *translated_flow = bpf_map_lookup_elem(&ptcpdump_nat_flow_map, &tmp_flow);
            if (translated_flow == NULL) {
                // debug_log("[ptcpdump][tc]: no router %pI4:%d %pI4:%d\n",
                // 		&tmp_flow.saddr[0], tmp_flow.sport, &tmp_flow.daddr[0],
                // tmp_flow.dport);
                break;
            }

            // debug_log("[ptcpdump][tc] route: %pI4 %pI4 => %pI4 %pI4\n",
            // 		&tmp_flow.saddr[0], &tmp_flow.daddr[0],
            // 		&translated_flow->saddr[0], &translated_flow->daddr[0]);
            clone_flow(translated_flow, &flow);
            clone_flow(translated_flow, &tmp_flow);
#else
            break;
#endif /* SUPPORT_NAT */
        }
    }

    fallback_pid_meta(pid_meta);
    //    debug_log("fallback pid: %d\n", pid_meta->pid);
    if (pid_meta->pid > 0) {
        return 0;
    }

    if (have_pid_filter) {
        // debug_log("[tc] check %pI4 %d -> %pI4\n", &flow.saddr[0], flow.sport, &flow.daddr[0]);
        // debug_log("tc, not found pid from ptcpdump_flow_pid_map");
        return -1;
    }
    return 0;
}

static __always_inline void handle_skb(bool cgroup_skb, struct __sk_buff *skb, bool egress, void *data, void *data_end,
                                       bool l2) {

    if (l2) {
        if (!pcap_filter((void *)skb, (void *)skb, (void *)skb, data, data_end)) {
            return;
        }
    } else {
        if (!pcap_filter_l3((void *)skb, (void *)skb, (void *)skb, data, data_end)) {
            return;
        }
    }

#ifdef LEGACY_KERNEL
    u32 u32_zero = 0;
#endif
    GET_CONFIG()

    void *ringbuf = NULL;
    struct packet_event_t *event;
    bool use_ringbuf = false;

    if (g.use_ringbuf_submit_skb && ringbuf_available()) {
        ringbuf = bpf_ringbuf_reserve(&ptcpdump_packet_events_ringbuf, sizeof(*event) + g.max_payload_size, 0);
        if (!ringbuf) {
            return;
        }
        event = (struct packet_event_t *)ringbuf;
        use_ringbuf = true;
    } else {
        event = bpf_map_lookup_elem(&ptcpdump_packet_event_stack, &u32_zero);
    }

    if (!event) {
        // debug_log("[ptcpdump] ptcpdump_packet_event_stack failed\n");
        return;
    }

    __builtin_memset(&event->meta, 0, sizeof(event->meta));
    __builtin_memset(&event->meta.process, 0, sizeof(event->meta.process));
    __builtin_memset(&event->meta.process.cgroup_name, 0, sizeof(event->meta.process.cgroup_name));

    if (fill_packet_event_meta(skb, cgroup_skb, &event->meta, egress) < 0) {
        // debug_log("tc, not found pid\n");
        if (use_ringbuf) {
            bpf_ringbuf_discard(ringbuf, 0);
        }
        return;
    };
    // if (process_meta_filter(&event->meta.process) < 0) {
    //     // debug_log("tc, not match filter\n");
    //     return;
    // };

    u32 *count;
    count = bpf_map_lookup_or_try_init(&ptcpdump_filter_by_kernel_count, &u32_zero, &u32_zero);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    if (egress) {
        event->meta.packet_type = EGRESS_PACKET;
    } else {
        event->meta.packet_type = INGRESS_PACKET;
    }
    if (cgroup_skb || !l2) {
        event->meta.first_layer = L3_LAYER;
    } else {
        event->meta.first_layer = L2_LAYER;
    }
    event->meta.timestamp = bpf_ktime_get_ns();
    event->meta.ifindex = skb->ifindex;

    u64 payload_len = (u64)skb->len;
    event->meta.packet_size = payload_len;
    if (g.max_payload_size > 0) {
        payload_len = payload_len < g.max_payload_size ? payload_len : g.max_payload_size;
    }
    event->meta.payload_len = payload_len;

    if (use_ringbuf) {
        if (payload_len > 0) {
            struct skb_data_t *skb_data = (struct skb_data_t *)(event + 1);
            bpf_skb_load_bytes(skb, 0, &skb_data->data, payload_len);
        }
        bpf_ringbuf_submit(ringbuf, 0);
    } else {
        int event_ret = bpf_perf_event_output(skb, &ptcpdump_packet_events, BPF_F_CURRENT_CPU | (payload_len << 32),
                                              event, sizeof(struct packet_event_t));
        if (event_ret != 0) {
            // debug_log("[ptcpdump] bpf_perf_event_output exec_events failed: %d\n", event_ret);
        }
    }

    return;
}

__always_inline void handle_tc_ingress(struct __sk_buff *skb, bool l2) {
    bpf_skb_pull_data(skb, 0);
    handle_skb(false, skb, false, (void *)(long)skb->data, (void *)(long)skb->data_end, l2);
}

SEC("tc")
int ptcpdump_tc_ingress_l2(struct __sk_buff *skb) {
    handle_tc_ingress(skb, true);
    return TC_ACT_UNSPEC;
}
SEC("tc")
int ptcpdump_tc_ingress_l3(struct __sk_buff *skb) {
    handle_tc_ingress(skb, false);
    return TC_ACT_UNSPEC;
}

#ifndef NO_TCX
__always_inline void handle_tcx_ingress(struct __sk_buff *skb, bool l2) {
    bpf_skb_pull_data(skb, 0);
    handle_skb(false, skb, false, (void *)(long)skb->data, (void *)(long)skb->data_end, l2);
}
SEC("tcx/ingress")
int ptcpdump_tcx_ingress_l2(struct __sk_buff *skb) {
    handle_tcx_ingress(skb, true);
    return TCX_NEXT;
}
SEC("tcx/ingress")
int ptcpdump_tcx_ingress_l3(struct __sk_buff *skb) {
    handle_tcx_ingress(skb, false);
    return TCX_NEXT;
}
#endif

__always_inline void handle_tc_egress(struct __sk_buff *skb, bool l2) {
    bpf_skb_pull_data(skb, 0);
    handle_skb(false, skb, true, (void *)(long)skb->data, (void *)(long)skb->data_end, l2);
}

SEC("tc")
int ptcpdump_tc_egress_l2(struct __sk_buff *skb) {
    handle_tc_egress(skb, true);
    return TC_ACT_UNSPEC;
}
SEC("tc")
int ptcpdump_tc_egress_l3(struct __sk_buff *skb) {
    handle_tc_egress(skb, false);
    return TC_ACT_UNSPEC;
}

#ifndef NO_TCX
__always_inline void handle_tcx_egress(struct __sk_buff *skb, bool l2) {
    bpf_skb_pull_data(skb, 0);
    handle_skb(false, skb, true, (void *)(long)skb->data, (void *)(long)skb->data_end, l2);
}

SEC("tcx/egress")
int ptcpdump_tcx_egress_l2(struct __sk_buff *skb) {
    handle_tcx_egress(skb, true);
    return TCX_NEXT;
}

SEC("tcx/egress")
int ptcpdump_tcx_egress_l3(struct __sk_buff *skb) {
    handle_tcx_egress(skb, false);
    return TCX_NEXT;
}
#endif

__always_inline void handle_socket_filter__ingress(struct __sk_buff *skb, bool l2) {
    char dummy[1];
    if (skb->pkt_type == PACKET_HOST) {
        bpf_skb_load_bytes(skb, 0, &dummy, sizeof(dummy));
        handle_skb(false, skb, false, (void *)(long)skb, dummy, l2);
    }
}

SEC("socket")
int ptcpdump_socket_filter__ingress_l2(struct __sk_buff *skb) {
    handle_socket_filter__ingress(skb, true);
    return 0;
}

SEC("socket")
int ptcpdump_socket_filter__ingress_l3(struct __sk_buff *skb) {
    handle_socket_filter__ingress(skb, false);
    return 0;
}

__always_inline void handle_socket_filter__egress(struct __sk_buff *skb, bool l2) {
    char dummy[1];

    if (skb->pkt_type == PACKET_OUTGOING) {
        ;
        bpf_skb_load_bytes(skb, 0, &dummy, sizeof(dummy));
        handle_skb(false, skb, true, (void *)(long)skb, dummy, l2);
    }
}

SEC("socket")
int ptcpdump_socket_filter__egress_l2(struct __sk_buff *skb) {
    handle_socket_filter__egress(skb, true);
    return 0;
}

SEC("socket")
int ptcpdump_socket_filter__egress_l3(struct __sk_buff *skb) {
    handle_socket_filter__egress(skb, false);
    return 0;
}

#ifndef NO_CGROUP_PROG
static __always_inline void handle_cgroup_skb(struct __sk_buff *skb, bool egress) {
    GET_CONFIG()

    if (g.filter_ifindex_enable) {
        u32 ifindex = skb->ifindex;
        if (!bpf_map_lookup_elem(&ptcpdump_filter_ifindex_map, &ifindex)) {
            return;
        }
    }

    handle_skb(true, skb, egress, (void *)(long)skb->data, (void *)(long)skb->data_end, false);
}

SEC("cgroup_skb/ingress")
int ptcpdump_cgroup_skb__ingress(struct __sk_buff *skb) {
    handle_cgroup_skb(skb, false);
    return 1;
}

SEC("cgroup_skb/egress")
int ptcpdump_cgroup_skb__egress(struct __sk_buff *skb) {
    handle_cgroup_skb(skb, true);
    return 1;
}
#endif /* NO_CGROUP_PROG */

#ifndef NO_TRACING

static __always_inline int fill_packet_event_meta_from_sk_buff(struct sk_buff *skb,
                                                               struct packet_event_meta_t *event_meta, bool egress) {
    bool have_pid_filter = have_pid_filter_rules();
    struct process_meta_t *pid_meta = &event_meta->process;
    struct packet_meta_t packet_meta = {0};
    int ret = parse_skb_buff_meta(skb, &packet_meta);
    if (ret < 0) {
        // debug_log("[ptcpdump] parse skb meta failed\n");
        if (have_pid_filter) {
            return -1;
        }
        return 0;
    }
    event_meta->l3_protocol = packet_meta.l2.h_protocol;
    // debug_log("l3_protocol: %d\n", event_meta->l3_protocol);
    event_meta->ifindex = packet_meta.ifindex;
    BPF_CORE_READ_STR_INTO(&event_meta->ifname, skb, dev, name);
    event_meta->netns_id = get_netns_id_from_skb(skb);

    u64 cookie = BPF_CORE_READ(skb, sk, __sk_common.skc_cookie.counter);
    if (cookie > 0) {
        if (egress) {
            //             debug_log("[ptcpdump] tp-btf egress: get socket cookie success\n");
        } else {
            //             debug_log("[ptcpdump] tp-btf ingress: get socket cookie success\n");
        }
        struct process_meta_t *value = bpf_map_lookup_elem(&ptcpdump_sock_cookie_pid_map, &cookie);
        if (value) {
            clone_process_meta(value, pid_meta);
            return 0;
        }
    } else {
        if (egress) {
            // debug_log("[ptcpdump] tp-btf egress: bpf_get_socket_cookie failed\n");
        } else {
            // debug_log("[ptcpdump] tp-btf ingress: bpf_get_socket_cookie failed\n");
        }
    }

    struct nat_flow_t flow = {0};
    GET_CONFIG()
    struct flow_pid_key_t key = {0};
    bool reverse = false;

#ifdef SUPPORT_NAT
    struct nat_flow_t tmp_flow = flow;
#endif

#pragma unroll
    for (int j = 0; j < 2; j++) {
        if (j == 1) {
            if (g.disable_reverse_match) {
                break;
            }
            reverse = true;
        }
        flow.saddr[0] = packet_meta.l3.saddr[0];
        flow.saddr[1] = packet_meta.l3.saddr[1];

        flow.daddr[0] = packet_meta.l3.daddr[0];
        flow.daddr[1] = packet_meta.l3.daddr[1];

        flow.sport = packet_meta.l4.sport;
        flow.dport = packet_meta.l4.dport;

#pragma unroll
        for (int i = 0; i < 10; i++) {
            if (!reverse) {
                key.saddr[0] = flow.saddr[0];
                key.saddr[1] = flow.saddr[1];
                key.sport = flow.sport;
            } else {
                key.saddr[0] = flow.daddr[0];
                key.saddr[1] = flow.daddr[1];
                key.sport = flow.dport;
            }

            if (have_pid_filter && flow.sport == 0 && flow.dport == 0) {
                // debug_log("[ptcpdump][tp-btf], sport is zero\n");
                // debug_log("[ptcpdump][tp-btf] %pI4 %d sport is zero\n", &key.saddr[0], key.sport);
                return -1;
            }

            // debug_log("tc, try to get pid\n");
            //            debug_log("[ptcpdump][tp-btf] %d, %d check %pI4 %d\n", j, i, &key.saddr[0], key.sport);
            if (key.sport > 0) {
                //                debug_log("[tc] check %pI4 %d\n", &key.saddr[0], key.sport);
                struct process_meta_t *value = bpf_map_lookup_elem(&ptcpdump_flow_pid_map, &key);
                if (value) {
                    // debug_log("[ptcpdump][tp-btf] got %pI4 %d -> %pI4\n", &flow.saddr[0],
                    // flow.sport, &flow.daddr[0]);
                    clone_process_meta(value, pid_meta);
                    return 0;
                } else if (have_pid_filter) {
                    // debug_log("[ptcpdump][tp-btf], ptcpdump_flow_pid_map is empty\n");
                    // debug_log("[ptcpdump][tp-btf] %pI4 %d bpf_map_lookup_elem ptcpdump_flow_pid_map is empty\n",
                    // &key.saddr[0], key.sport);
                }
            }

#ifdef SUPPORT_NAT
            struct nat_flow_t *translated_flow = bpf_map_lookup_elem(&ptcpdump_nat_flow_map, &tmp_flow);
            if (translated_flow == NULL) {
                // debug_log("[ptcpdump][tp-btf]: no router %pI4:%d %pI4:%d\n",
                // 		&tmp_flow.saddr[0], tmp_flow.sport, &tmp_flow.daddr[0],
                // tmp_flow.dport);
                break;
            }

            // debug_log("[ptcpdump][tp-btf] route: %pI4 %pI4 => %pI4 %pI4\n",
            // 		&tmp_flow.saddr[0], &tmp_flow.daddr[0],
            // 		&translated_flow->saddr[0], &translated_flow->daddr[0]);
            clone_flow(translated_flow, &flow);
            clone_flow(translated_flow, &tmp_flow);
#else
            break;
#endif /* SUPPORT_NAT */
        }
    }

    fallback_pid_meta(pid_meta);
    //    debug_log("fallback pid: %d\n", pid_meta->pid);
    if (pid_meta->pid > 0) {
        return 0;
    }

    if (have_pid_filter) {
        // debug_log("[tc] check %pI4 %d -> %pI4\n", &flow.saddr[0], flow.sport, &flow.daddr[0]);
        // debug_log("tc, not found pid from ptcpdump_flow_pid_map");
        return -1;
    }
    return 0;
}

static __always_inline void handle_skb_buff(struct sk_buff *skb, bool egress) {
    GET_CONFIG()
    if (g.filter_ifindex_enable) {
        u32 ifindex = BPF_CORE_READ(skb, dev, ifindex);
        if (!bpf_map_lookup_elem(&ptcpdump_filter_ifindex_map, &ifindex)) {
            return;
        }
    }

    void *skb_head = BPF_CORE_READ(skb, head);
#if !defined(bpf_target_arm)
    void *data_end = skb_head + BPF_CORE_READ(skb, tail);
#else
    void *data_end = BPF_CORE_READ(skb, tail);
#endif

    u16 mac_header = BPF_CORE_READ(skb, mac_header);
    u16 network_header = BPF_CORE_READ(skb, network_header);
    bool has_l2 = has_valid_mac_data(skb);

    void *data = skb_head + mac_header;
    if (pcap_filter((void *)skb, (void *)skb, (void *)skb, data, data_end)) {
        goto filter_ok;
    }
    data = skb_head + network_header;
    if (!pcap_filter_l3((void *)skb, (void *)skb, (void *)skb, data, data_end)) {
        return;
    }

filter_ok:

//    debug_log("[ptcpdump][tp-btf] mac_header: %d, network_header: %d, has_l2: %d", mac_header, network_header,
//    has_l2);
#ifdef LEGACY_KERNEL
    u32 u32_zero = 0;
#endif
    GET_CONFIG()

    struct packet_event_t *event;
    event = bpf_map_lookup_elem(&ptcpdump_packet_event_stack, &u32_zero);
    if (!event) {
        // debug_log("[ptcpdump] ptcpdump_packet_event_stack failed\n");
        return;
    }

    __builtin_memset(&event->meta, 0, sizeof(event->meta));
    __builtin_memset(&event->meta.ifname, 0, sizeof(event->meta.ifname));
    __builtin_memset(&event->meta.process, 0, sizeof(event->meta.process));
    __builtin_memset(&event->meta.process.cgroup_name, 0, sizeof(event->meta.process.cgroup_name));

    if (fill_packet_event_meta_from_sk_buff(skb, &event->meta, egress) < 0) {
        // debug_log("tc, not found pid\n");
        return;
    };

    u32 *count;
    count = bpf_map_lookup_or_try_init(&ptcpdump_filter_by_kernel_count, &u32_zero, &u32_zero);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    if (egress) {
        event->meta.packet_type = EGRESS_PACKET;
    } else {
        event->meta.packet_type = INGRESS_PACKET;
    }
    event->meta.timestamp = bpf_ktime_get_ns();
    event->meta.first_layer = has_l2 ? L2_LAYER : L3_LAYER;

    u64 payload_len = (u64)skb->len;
    event->meta.packet_size = payload_len;
    if (g.max_payload_size > 0) {
        payload_len = payload_len < g.max_payload_size ? payload_len : g.max_payload_size;
    }
    event->meta.payload_len = payload_len;

    int event_ret = bpf_skb_output(skb, &ptcpdump_packet_events, BPF_F_CURRENT_CPU | (payload_len << 32), event,
                                   sizeof(struct packet_event_t));
    if (event_ret != 0) {
        // debug_log("[ptcpdump] bpf_perf_event_output exec_events failed: %d\n", event_ret);
    }

    return;
}

SEC("tp_btf/net_dev_queue")
int BPF_PROG(ptcpdump_tp_btf__net_dev_queue, struct sk_buff *skb) {
    handle_skb_buff(skb, true);
    return 0;
}

SEC("tp_btf/netif_receive_skb")
int BPF_PROG(ptcpdump_tp_btf__netif_receive_skb, struct sk_buff *skb) {
    handle_skb_buff(skb, false);
    return 0;
}

#endif /* NO_TRACING */
