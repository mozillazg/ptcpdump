#ifndef __PTCPDUMP_COMMON_H__
#define __PTCPDUMP_COMMON_H__

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define EXEC_FILENAME_LEN 512
#define EXEC_ARGS_LEN 4096
#define MIN_CGROUP_NAME_LEN 64 + 1
#define MAX_CGROUP_NAME_LEN 128

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

struct process_meta_t {
    u32 ppid;
    u32 pid;
    u32 pidns_id;
    u32 mntns_id;
    u32 netns_id;
    u32 tid;
    u32 uid;
    u32 gid;
    char tname[TASK_COMM_LEN];
    char cgroup_name[MAX_CGROUP_NAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_pid_key_t);
    __type(value, struct process_meta_t);
} flow_pid_map SEC(".maps");

const struct flow_pid_key_t *unused3 __attribute__((unused));
const struct process_meta_t *unused4 __attribute__((unused));

#endif /* __PTCPDUMP_COMMON_H__ */
