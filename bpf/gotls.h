#ifndef __PTCPDUMP_GOTLS_H__
#define __PTCPDUMP_GOTLS_H__

#include "gotls_helpers.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// https://tlswg.org/sslkeylogfile/draft-ietf-tls-keylogfile.html#name-the-sslkeylogfile-format
#define KEYLOG_LABEL_LEN 32
#define KEYLOG_CLIENT_RANDOM_LEN 32
#define KEYLOG_SECRET_LEN 64

struct go_keylog_event_t {
    char label[KEYLOG_LABEL_LEN];
    char client_random[KEYLOG_CLIENT_RANDOM_LEN];
    char secret[KEYLOG_SECRET_LEN];
    u8 label_len;
    u8 client_random_len;
    u8 secret_len;
};

struct go_keylog_buf_t {
    u64 label_ptr;
    u64 label_len_ptr;
    u64 random_ptr;
    u64 random_len_ptr;
    u64 secret_ptr;
    u64 secret_len_ptr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, struct go_keylog_buf_t);
} go_keylog_buf_storage SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} go_keylog_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct go_keylog_event_t));
} go_keylog_event_tmp SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} go_keylog_events_ringbuf SEC(".maps");

const struct go_keylog_event_t *unused7 __attribute__((unused));

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
    struct go_keylog_event_t *event;
    int ret;
    u32 u32_zero = 0;
    bool use_ringbuf = false;

    u32 smp_id = bpf_get_smp_processor_id();
    buf = bpf_map_lookup_elem(&go_keylog_buf_storage, &smp_id);
    if (!buf) {
        //        debug_log("no buf");
        return 0;
    }

    if (ringbuf_available()) {
        event = bpf_ringbuf_reserve(&go_keylog_events_ringbuf, sizeof(*event), 0);
        use_ringbuf = true;
    } else {
        event = bpf_map_lookup_elem(&go_keylog_event_tmp, &u32_zero);
    }
    if (!event) {
        return 0;
    }

    bpf_probe_read_kernel(&event->label_len, sizeof(event->label_len), &(buf->label_len_ptr));
    bpf_probe_read_kernel(&event->client_random_len, sizeof(event->client_random_len), &(buf->random_len_ptr));
    bpf_probe_read_kernel(&event->secret_len, sizeof(event->secret_len), &(buf->secret_len_ptr));
    if (event->label_len == 0 && event->client_random_len == 0 && event->secret_len == 0) {
        //                debug_log("go tls read filed, label_len: %d, client_random_len: %d, secret_len: %d",
        //                            event->label_len, event->client_random_len, event->secret_len );
        if (use_ringbuf) {
            bpf_ringbuf_discard(event, 0);
        }
        return 0;
    }

    ret = bpf_probe_read_user(&event->label, sizeof(event->label), (void *)(buf->label_ptr));
    if (ret < 0) {
        //        debug_log("go labels, ret: %d", ret);
    }
    ret = bpf_probe_read_user(&event->client_random, sizeof(event->client_random), (void *)(buf->random_ptr));
    if (ret < 0) {
        //        debug_log("go random, ret: %d", ret);
    }
    ret = bpf_probe_read_user(&event->secret, sizeof(event->secret), (void *)(buf->secret_ptr));
    if (ret < 0) {
        //        debug_log("go secret, ret: %d", ret);
    }
    //        debug_log("go label_len: %d, client_random_len: %d, secret_len: %d", event->label_len,
    //                event->client_random_len, event->secret_len);
    //    debug_log("go label: %x, client_random: %x, secret: %x", event->label,
    //                event->client_random, event->secret);

    if (use_ringbuf) {
        bpf_ringbuf_submit(event, 0);
    } else {
        ret = bpf_perf_event_output(ctx, &go_keylog_events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    }
    if (ret < 0) {
        //                debug_log("go tls: per event failed, %d", ret);
    }
    return 0;
}

#endif /* __PTCPDUMP_GOTLS_H__ */
