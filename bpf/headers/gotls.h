#ifndef __PTCPDUMP_GOTLS_H__
#define __PTCPDUMP_GOTLS_H__

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// https://tlswg.org/sslkeylogfile/draft-ietf-tls-keylogfile.html#name-the-sslkeylogfile-format
#define KEYLOG_LABEL_LEN 32
#define KEYLOG_CLIENT_RANDOM_LEN 32
#define KEYLOG_SECRET_LEN 64

#if defined(bpf_target_x86)
#define GO_PARAM1(dst, x) BPF_CORE_READ_INTO(dst, (x), ax)
#define GO_PARAM2(dst, x) BPF_CORE_READ_INTO(dst, (x), bx)
#define GO_PARAM3(dst, x) BPF_CORE_READ_INTO(dst, (x), cx)
#define GO_PARAM4(dst, x) BPF_CORE_READ_INTO(dst, (x), di)
#define GO_PARAM5(dst, x) BPF_CORE_READ_INTO(dst, (x), si)
#define GO_PARAM6(dst, x) BPF_CORE_READ_INTO(dst, (x), r8)
#define GO_PARAM7(dst, x) BPF_CORE_READ_INTO(dst, (x), r9)
#define GO_PARAM8(dst, x) BPF_CORE_READ_INTO(dst, (x), r10)
#define GO_PARAM9(dst, x) BPF_CORE_READ_INTO(dst, (x), r11)
#elif defined(bpf_target_arm64)
#define GO_PARAM1(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), __PT_PARM1_REG)
#define GO_PARAM2(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), __PT_PARM2_REG)
#define GO_PARAM3(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), __PT_PARM3_REG)
#define GO_PARAM4(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), __PT_PARM4_REG)
#define GO_PARAM5(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), __PT_PARM5_REG)
#define GO_PARAM6(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), __PT_PARM6_REG)
#define GO_PARAM7(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), __PT_PARM7_REG)
#define GO_PARAM8(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), __PT_PARM8_REG)
#define GO_PARAM9(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), regs[8])
#endif

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

const struct go_keylog_event_t *unused7 __attribute__((unused));

static __always_inline void read_go_arg_into(u64 *dst, struct pt_regs *ctx, u8 index) {
    switch (index) {
    case 1:
        GO_PARAM1(dst, ctx);
        break;
    case 2:
        GO_PARAM2(dst, ctx);
        break;
    case 3:
        GO_PARAM3(dst, ctx);
        break;
    case 4:
        GO_PARAM4(dst, ctx);
        break;
    case 5:
        GO_PARAM5(dst, ctx);
        break;
    case 6:
        GO_PARAM6(dst, ctx);
        break;
    case 7:
        GO_PARAM7(dst, ctx);
        break;
    case 8:
        GO_PARAM8(dst, ctx);
        break;
    case 9:
        GO_PARAM9(dst, ctx);
        break;
    }
    return;
}

#endif /* __PTCPDUMP_GOTLS_H__ */
