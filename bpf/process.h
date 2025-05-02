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
} ptcpdump_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, u8);
} ptcpdump_filter_mntns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, u8);
} ptcpdump_filter_pidns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, u8);
} ptcpdump_filter_netns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, u32);
    __type(value, u8);
} ptcpdump_filter_pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, u8);
} ptcpdump_filter_uid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct exec_event_t);
} ptcpdump_exec_event_stack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
#ifdef LOW_MEMORY
    __uint(max_entries, 1 << 12);
#else
    __uint(max_entries, 1 << 24);
#endif
} ptcpdump_ptcpdump_exec_events_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} ptcpdump_exec_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct exit_event_t);
} ptcpdump_exit_event_tmp SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} ptcpdump_exit_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
#ifdef LOW_MEMORY
    __uint(max_entries, 1 << 12);
#else
    __uint(max_entries, 1 << 17);
#endif
} ptcpdump_exit_events_ringbuf SEC(".maps");

const struct exec_event_t *unused2 __attribute__((unused));
const struct process_meta_t *unused4 __attribute__((unused));
const struct exit_event_t *unused5 __attribute__((unused));

static __always_inline bool have_pid_filter_rules() {
    GET_CONFIG()

    return g.have_filter > 0;
}

static __always_inline int filter_pid(u32 pid) {
    if (bpf_map_lookup_elem(&ptcpdump_filter_pid_map, &pid)) {
        return 0;
    }
    return -1;
}

static __always_inline int filter_uid(u32 uid) {
    if (bpf_map_lookup_elem(&ptcpdump_filter_uid_map, &uid)) {
        return 0;
    }
    return -1;
}

static __always_inline int filter_mntns(u32 ns) {
    if (bpf_map_lookup_elem(&ptcpdump_filter_mntns_map, &ns)) {
        return 0;
    }
    return -1;
}

static __always_inline int filter_pidns(u32 ns) {
    if (bpf_map_lookup_elem(&ptcpdump_filter_pidns_map, &ns)) {
        return 0;
    }
    return -1;
}

static __always_inline int filter_netns(u32 ns) {
    if (bpf_map_lookup_elem(&ptcpdump_filter_netns_map, &ns)) {
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
    u32 uid = BPF_CORE_READ(task, cred, uid.val);
    if ((filter_pidns(pidns_id) == 0) || (filter_mntns(mntns_id) == 0) || (filter_netns(netns_id) == 0) ||
        (filter_uid(uid) == 0)) {
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
        bpf_map_update_elem(&ptcpdump_filter_pid_map, &pid, &u8_zero, BPF_NOEXIST);
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
        bpf_map_update_elem(&ptcpdump_filter_pid_map, &child_pid, &u8_zero, BPF_NOEXIST);
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
        bpf_map_update_elem(&ptcpdump_filter_pid_map, &child_pid, &u8_zero, BPF_NOEXIST);
        return;
    }
    if (process_filter(child) == 0) {
        return;
    }
    return;
}

SEC("raw_tracepoint/sched_process_fork")
int BPF_PROG(ptcpdump_raw_tracepoint__sched_process_fork, struct task_struct *parent, struct task_struct *child) {
    handle_fork(parent, child);
    return 0;
}

#ifndef NO_TRACING
SEC("tp_btf/sched_process_fork")
int BPF_PROG(ptcpdump_tp_btf__sched_process_fork, struct task_struct *parent, struct task_struct *child) {
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
    BPF_CORE_READ_INTO(&meta->uid, task, cred, uid.val);

    __builtin_memset(&meta->cgroup_name, 0, sizeof(meta->cgroup_name));
#ifdef SUPPORT_CGROUP
    if (bpf_core_field_exists(task->cgroups)) {
        const char *cname = BPF_CORE_READ(task, cgroups, subsys[0], cgroup, kn, name);
        int size = bpf_core_read_str(&meta->cgroup_name, sizeof(meta->cgroup_name), cname);
        if (size < MIN_CGROUP_NAME_LEN) {
            __builtin_memset(&meta->cgroup_name, 0, sizeof(meta->cgroup_name));
        }
    }
#endif
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
    if (is_kernel_thread(task)) {
        //        debug_log("[ptcpdump] kernel thread exec\n");
        return;
    }
    bool use_ringbuf = false;

    struct exec_event_t *event;
#ifdef LEGACY_KERNEL
    u32 u32_zero = 0;
#endif

    if (ringbuf_available()) {
        event = bpf_ringbuf_reserve(&ptcpdump_ptcpdump_exec_events_ringbuf, sizeof(*event), 0);
        use_ringbuf = true;
    } else {
        event = bpf_map_lookup_elem(&ptcpdump_exec_event_stack, &u32_zero);
    }
    if (!event) {
        //        debug_log("[ptcpdump] ptcpdump_exec_event_stack failed\n");
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

    if (use_ringbuf) {
        bpf_ringbuf_submit(event, 0);
    } else {
        int event_ret = bpf_perf_event_output(ctx, &ptcpdump_exec_events, BPF_F_CURRENT_CPU, event, sizeof(*event));
        if (event_ret != 0) {
            // debug_log("[ptcpdump] bpf_perf_event_output ptcpdump_exec_events failed: %d\n", event_ret);
        }
    }
    return;
}

static __always_inline void handle_exit(void *ctx, struct task_struct *task) {
    if (is_kernel_thread(task)) {
        //        debug_log("[ptcpdump] kernel thread exit\n");
        return;
    }
    u32 pid = BPF_CORE_READ(task, tgid);
    if (pid == 0) {
        //        debug_log("[ptcpdump] pid is 0\n");
        return;
    }
#ifdef P_EXIT_CHECK_LIVE
    atomic_t live = BPF_CORE_READ(task, signal, live);
    if (live.counter > 0) {
        //        debug_log("[ptcpdump] task is still alive\n");
        return;
    }
#else
    if (pid != BPF_CORE_READ(task, pid)) {
        //        debug_log("[ptcpdump] pid is not equal tid\n");
        return;
    }
#endif

    if (bpf_map_lookup_elem(&ptcpdump_filter_pid_map, &pid)) {
        bpf_map_delete_elem(&ptcpdump_filter_pid_map, &pid);
    }

    struct exit_event_t *event;
    bool use_ringbuf = false;
#ifdef LEGACY_KERNEL
    u32 u32_zero = 0;
#endif
    if (ringbuf_available()) {
        event = bpf_ringbuf_reserve(&ptcpdump_exit_events_ringbuf, sizeof(*event), 0);
        use_ringbuf = true;
    } else {
        event = bpf_map_lookup_elem(&ptcpdump_exit_event_tmp, &u32_zero);
    }
    if (!event) {
        //        debug_log("[ptcpdump] ptcpdump_exit_event_tmp failed\n");
        return;
    }

    event->pid = pid;

    if (use_ringbuf) {
        bpf_ringbuf_submit(event, 0);
    } else {
        int event_ret = bpf_perf_event_output(ctx, &ptcpdump_exit_events, BPF_F_CURRENT_CPU, event, sizeof(*event));
        if (event_ret != 0) {
            // debug_log("[ptcpdump] bpf_perf_event_output ptcpdump_exit_events failed: %d\n", event_ret);
        }
    }

    return;
}

SEC("tracepoint/sched/sched_process_exec")
int ptcpdump_tracepoint__sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
    pid_t old_pid = ctx->old_pid;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct linux_binprm bprm = {0};
    bprm.filename = (char *)((void *)ctx + fname_off);

    // debug_log("new exec event from tracepoint, pid: %llu\n", ctx->pid);

    handle_exec(ctx, task, old_pid, &bprm);
    return 0;
}

SEC("raw_tracepoint/sched_process_exec")
int BPF_PROG(ptcpdump_raw_tracepoint__sched_process_exec, struct task_struct *task, pid_t old_pid,
             struct linux_binprm *bprm) {
    handle_exec(ctx, task, old_pid, bprm);
    return 0;
}

#ifndef NO_TRACING
SEC("tp_btf/sched_process_exec")
int BPF_PROG(ptcpdump_tp_btf__sched_process_exec, struct task_struct *task, pid_t old_pid, struct linux_binprm *bprm) {
    handle_exec(ctx, task, old_pid, bprm);
    return 0;
}
#endif

SEC("raw_tracepoint/sched_process_exit")
int BPF_PROG(ptcpdump_raw_tracepoint__sched_process_exit, struct task_struct *task) {
    handle_exit(ctx, task);
    return 0;
}

#ifndef NO_TRACING
SEC("tp_btf/sched_process_exit")
int BPF_PROG(ptcpdump_tp_btf__sched_process_exit, struct task_struct *task) {
    handle_exit(ctx, task);
    return 0;
}
#endif

SEC("kprobe/acct_process")
int BPF_KPROBE(ptcpdump_kprobe__acct_process) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    //    debug_log("[ptcpdump] kprobe/acct_process\n");
    handle_exit(ctx, task);
    return 0;
}

SEC("kprobe/do_exit")
int BPF_KPROBE(ptcpdump_kprobe__do_exit) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    //    debug_log("[ptcpdump] kprobe/do_exit\n");
    handle_exit(ctx, task);
    return 0;
}

#ifndef NO_TRACING
SEC("fentry/acct_process")
int BPF_PROG(ptcpdump_fentry__acct_process) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    //    debug_log("[ptcpdump] fentry/acct_process\n");
    handle_exit(ctx, task);
    return 0;
}

SEC("fentry/do_exit")
int BPF_PROG(ptcpdump_fentry__do_exit) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    //    debug_log("[ptcpdump] fentry/do_exit\n");
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
    __builtin_memcpy(&target->cgroup_name, &origin->cgroup_name, sizeof(origin->cgroup_name));
}

#endif /* __PTCPDUMP_PROCESS_H__ */
