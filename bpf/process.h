#ifndef __PTCPDUMP_PROCESS_H__
#define __PTCPDUMP_PROCESS_H__

#include "compat.h"
#include "helpers.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EXEC_FILENAME_LEN 512
#define EXEC_ARGS_LEN 4096
#define MIN_CGROUP_NAME_LEN 64 + 1
#define MAX_CGROUP_NAME_LEN 128

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

struct exec_event_t {
    struct process_meta_t meta;

    u8 filename_truncated;
    u8 args_truncated;
    unsigned int args_size;
    char filename[EXEC_FILENAME_LEN];
    char args[EXEC_ARGS_LEN];
};

struct exit_event_t {
    u32 pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct gconfig_t);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, u8);
} filter_mntns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, u8);
} filter_pidns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, u8);
} filter_netns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, u32);
    __type(value, u8);
} filter_pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct exec_event_t);
} exec_event_stack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} exec_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} exit_events SEC(".maps");

const struct exec_event_t *unused2 __attribute__((unused));
const struct process_meta_t *unused4 __attribute__((unused));
const struct exit_event_t *unused5 __attribute__((unused));

static __always_inline bool have_pid_filter_rules() {
    GET_CONFIG()

    return g.have_filter > 0;
}

static __always_inline int filter_pid(u32 pid) {
    if (bpf_map_lookup_elem(&filter_pid_map, &pid)) {
        return 0;
    }
    return -1;
}

static __always_inline int filter_mntns(u32 ns) {
    if (bpf_map_lookup_elem(&filter_mntns_map, &ns)) {
        return 0;
    }
    return -1;
}

static __always_inline int filter_pidns(u32 ns) {
    if (bpf_map_lookup_elem(&filter_pidns_map, &ns)) {
        return 0;
    }
    return -1;
}

static __always_inline int filter_netns(u32 ns) {
    if (bpf_map_lookup_elem(&filter_netns_map, &ns)) {
        return 0;
    }
    return -1;
}

static __always_inline int process_filter(struct task_struct *task) {
    // no filter rules
    if (!have_pid_filter_rules()) {
        // debug_log("no filter\n");
        return 0;
    }

    u32 pid = BPF_CORE_READ(task, tgid);
    if (filter_pid(pid) == 0) {
        // debug_log("match filter\n");
        return 0;
    }

    GET_CONFIG()
#ifdef LEGACY_KERNEL
    u8 u8_zero = 0;
#endif

    bool should_filter = false;
    u32 mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    u32 netns_id = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
    u32 pidns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    if ((filter_pidns(pidns_id) == 0) || (filter_mntns(mntns_id) == 0) || (filter_netns(netns_id) == 0)) {
        // debug_log("%u %u %u\n", mntns_id, netns_id, pidns_id);
        should_filter = true;
    }

    if (!should_filter) {
        if (g.filter_comm_enable == 1) {
            // TODO: check real process name instead of comm
            char comm[TASK_COMM_LEN];
            __builtin_memset(&comm, 0, sizeof(comm));
            BPF_CORE_READ_STR_INTO(&comm, task, comm);
            if (str_cmp(comm, g.filter_comm, TASK_COMM_LEN) == 0) {
                should_filter = true;
            }
        }
    }

    if (should_filter) {
        bpf_map_update_elem(&filter_pid_map, &pid, &u8_zero, BPF_NOEXIST);
        return 0;
    }

    // debug_log("process_filter not match, pid: %u, filter_pid: %u", pid, g.filter_pid);

    return -1;
}

static __always_inline int parent_process_filter(struct task_struct *current) {
    // no filter rules
    if (!have_pid_filter_rules()) {
        // debug_log("no filter\n");
        return 0;
    }

    GET_CONFIG()
#ifdef LEGACY_KERNEL
    u8 u8_zero = 0;
#endif

    if (g.filter_follow_forks != 1) {
        return -1;
    }
    struct task_struct *parent = BPF_CORE_READ(current, real_parent);
    if (!parent) {
        return -1;
    }
    if (process_filter(parent) == 0) {
        u32 child_pid = BPF_CORE_READ(current, tgid);
        bpf_map_update_elem(&filter_pid_map, &child_pid, &u8_zero, BPF_NOEXIST);
        return 0;
    }

    return -1;
}

static __always_inline void handle_fork(struct task_struct *parent, struct task_struct *child) {
    GET_CONFIG()
#ifdef LEGACY_KERNEL
    u8 u8_zero = 0;
#endif

    if (g.filter_follow_forks != 1) {
        return;
    }

    u32 child_pid = BPF_CORE_READ(child, tgid);

    if (process_filter(parent) == 0) {
        bpf_map_update_elem(&filter_pid_map, &child_pid, &u8_zero, BPF_NOEXIST);
        return;
    }
    if (process_filter(child) == 0) {
        return;
    }
    return;
}

SEC("raw_tracepoint/sched_process_fork")
int BPF_PROG(raw_tracepoint__sched_process_fork, struct task_struct *parent, struct task_struct *child) {
    handle_fork(parent, child);
    return 0;
}

#ifndef NO_TRACING
SEC("tp_btf/sched_process_fork")
int BPF_PROG(tp_btf__sched_process_fork, struct task_struct *parent, struct task_struct *child) {
    handle_fork(parent, child);
    return 0;
}
#endif

static __always_inline void fill_process_meta(struct task_struct *task, struct process_meta_t *meta) {
    BPF_CORE_READ_INTO(&meta->pidns_id, task, nsproxy, pid_ns_for_children, ns.inum);
    BPF_CORE_READ_INTO(&meta->mntns_id, task, nsproxy, mnt_ns, ns.inum);
    BPF_CORE_READ_INTO(&meta->netns_id, task, nsproxy, net_ns, ns.inum);
    BPF_CORE_READ_INTO(&meta->pid, task, tgid);
    BPF_CORE_READ_INTO(&meta->ppid, task, real_parent, tgid);

    u64 uid_gid = bpf_get_current_uid_gid();
    if (uid_gid > 0) {
        meta->uid = uid_gid & 0xFFFFFFFF;
        meta->gid = uid_gid >> 32;
    } else {
        BPF_CORE_READ_INTO(&meta->uid, task, cred, uid);
        BPF_CORE_READ_INTO(&meta->gid, task, cred, gid);
    }

    debug_log("uid %lld, gid %lld\n", meta->uid, meta->gid);

    const char *cname = BPF_CORE_READ(task, cgroups, subsys[0], cgroup, kn, name);
    int size = bpf_core_read_str(&meta->cgroup_name, sizeof(meta->cgroup_name), cname);
    if (size < MIN_CGROUP_NAME_LEN) {
        __builtin_memset(&meta->cgroup_name, 0, sizeof(meta->cgroup_name));
    }
}

static __always_inline void fill_process_meta_with_thread(struct task_struct *task, struct process_meta_t *meta) {
    fill_process_meta(task, meta);
    BPF_CORE_READ_INTO(&meta->tid, task, pid);
    BPF_CORE_READ_STR_INTO(&meta->tname, task, comm);
}

static __always_inline void handle_exec(void *ctx, struct task_struct *task, pid_t old_pid, struct linux_binprm *bprm) {
    //    if (process_filter(task) < 0) {
    //        return;
    //    }

    struct exec_event_t *event;
#ifdef LEGACY_KERNEL
    u32 u32_zero = 0;
#endif
    event = bpf_map_lookup_elem(&exec_event_stack, &u32_zero);
    if (!event) {
        // debug_log("[ptcpdump] exec_event_stack failed\n");
        return;
    }
    __builtin_memset(&event->meta, 0, sizeof(event->meta));

    fill_process_meta(task, &event->meta);

    const char *filename_p = BPF_CORE_READ(bprm, filename);
    int f_ret = bpf_probe_read_str(&event->filename, sizeof(event->filename), filename_p);
    if (f_ret < 0) {
        // debug_log("[ptcpdump] read exec filename failed: %d\n", f_ret);
    }
    if (f_ret == EXEC_FILENAME_LEN) {
        event->filename_truncated = 1;
    }

    void *arg_start = (void *)BPF_CORE_READ(task, mm, arg_start);
    void *arg_end = (void *)BPF_CORE_READ(task, mm, arg_end);
    unsigned long arg_length = arg_end - arg_start;
    if (arg_length > EXEC_ARGS_LEN) {
        arg_length = EXEC_ARGS_LEN;
        event->args_truncated = 1;
    }
    int arg_ret = bpf_probe_read(&event->args, arg_length, arg_start);
    if (arg_ret < 0) {
        // debug_log("[ptcpdump] read exec args failed: %d\n", arg_ret);
    } else {
        event->args_size = arg_length;
    }

    int event_ret = bpf_perf_event_output(ctx, &exec_events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    if (event_ret != 0) {
        // debug_log("[ptcpdump] bpf_perf_event_output exec_events failed: %d\n", event_ret);
    }
    return;
}

static __always_inline void handle_exit(void *ctx, struct task_struct *task) {
    atomic_t live = BPF_CORE_READ(task, signal, live);
    if (live.counter > 0) {
        return;
    }

    u32 pid = BPF_CORE_READ(task, tgid);
    if (bpf_map_lookup_elem(&filter_pid_map, &pid)) {
        bpf_map_delete_elem(&filter_pid_map, &pid);
    }

    struct exit_event_t event = {
        .pid = pid,
    };
    int event_ret = bpf_perf_event_output(ctx, &exit_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    if (event_ret != 0) {
        // debug_log("[ptcpdump] bpf_perf_event_output exit_events failed: %d\n", event_ret);
    }

    return;
}

SEC("raw_tracepoint/sched_process_exec")
int BPF_PROG(raw_tracepoint__sched_process_exec, struct task_struct *task, pid_t old_pid, struct linux_binprm *bprm) {
    handle_exec(ctx, task, old_pid, bprm);
    return 0;
}

#ifndef NO_TRACING
SEC("tp_btf/sched_process_exec")
int BPF_PROG(tp_btf__sched_process_exec, struct task_struct *task, pid_t old_pid, struct linux_binprm *bprm) {
    handle_exec(ctx, task, old_pid, bprm);
    return 0;
}
#endif

SEC("raw_tracepoint/sched_process_exit")
int BPF_PROG(raw_tracepoint__sched_process_exit, struct task_struct *task) {
    handle_exit(ctx, task);
    return 0;
}

#ifndef NO_TRACING
SEC("tp_btf/sched_process_exit")
int BPF_PROG(tp_btf__sched_process_exit, struct task_struct *task) {
    handle_exit(ctx, task);
    return 0;
}
#endif

static __always_inline void clone_process_meta(struct process_meta_t *origin, struct process_meta_t *target) {
    target->ppid = origin->ppid;
    target->pid = origin->pid;
    target->mntns_id = origin->mntns_id;
    target->netns_id = origin->netns_id;
    target->pidns_id = origin->pidns_id;
    target->uid = origin->uid;
    target->gid = origin->gid;
    __builtin_memcpy(&target->cgroup_name, &origin->cgroup_name, sizeof(origin->cgroup_name));
}

#endif /* __PTCPDUMP_PROCESS_H__ */
