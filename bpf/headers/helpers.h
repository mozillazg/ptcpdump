#ifndef __PTCPDUMP_HELPERS_H__
#define __PTCPDUMP_HELPERS_H__

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EEXIST 17 /* File exists */

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

#endif /* __PTCPDUMP_HELPERS_H__ */
