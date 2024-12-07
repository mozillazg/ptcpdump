#ifndef __PTCPDUMP_COMPAT_H__
#define __PTCPDUMP_COMPAT_H__

#include "vmlinux.h"

#define TASK_COMM_LEN 16

struct gconfig_t {
    u8 have_filter;
    u8 filter_follow_forks;
    char filter_comm[TASK_COMM_LEN];
    u8 filter_comm_enable;
    u8 filter_ifindex_enable;
    u32 max_payload_size;
};

#ifndef LEGACY_KERNEL
static volatile const struct gconfig_t g = {0};
static const u8 u8_zero = 0;
static const u32 u32_zero = 0;
#endif

#ifdef LEGACY_KERNEL
#define debug_log(fmt, ...)                                                                                            \
    ({                                                                                                                 \
        char ____fmt[] = fmt;                                                                                          \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                                                     \
    })
#define GET_CONFIG()                                                                                                   \
    struct gconfig_t g = {0};                                                                                          \
    u32 configk = 0;                                                                                                   \
    struct gconfig_t *configv = bpf_map_lookup_elem(&config_map, &configk);                                            \
    if (configv) {                                                                                                     \
        g = *configv;                                                                                                  \
    }
#else

#define debug_log(fmt, ...) ({ bpf_printk(fmt, ##__VA_ARGS__); })
#define GET_CONFIG()
#endif

#endif /* __PTCPDUMP_COMPAT_H__ */
