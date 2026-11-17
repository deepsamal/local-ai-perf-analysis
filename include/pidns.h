/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PIDNS_H
#define __PIDNS_H

/*
 * PID-namespace translation for BPF programs.
 *
 * BPF helpers (bpf_get_current_pid_tgid, task->pid/tgid) report ids in
 * the ROOT pid namespace. When the tracer runs inside a child namespace
 * -- every WSL2 distro does, as does any container -- those ids don't
 * exist in its /proc: symbolization fails ("/proc/448/maps: No such
 * file"), --pid never matches, and Python's /tmp/perf-<pid>.map (named
 * with the namespace pid) is never found.
 *
 * The loader passes the inode of its own pid namespace
 * (/proc/self/ns/pid). For each task we walk task->thread_pid->numbers[]
 * (one struct upid per namespace level) and return the id whose
 * namespace matches. Tasks not visible in the tracer's namespace get
 * global_id + PID_OUTSIDE_NS_BASE so they can't collide with real ids.
 * ns_inum == 0 disables translation (old behaviour).
 */

#ifdef __BPF__
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* Minimal CO-RE views; libbpf relocates offsets against kernel BTF. */
struct ns_common {
    unsigned int inum;
} __attribute__((preserve_access_index));

struct pid_namespace {
    struct ns_common ns;
} __attribute__((preserve_access_index));

struct upid {
    int nr;
    struct pid_namespace *ns;
} __attribute__((preserve_access_index));

struct pid {
    unsigned int level;
    struct upid numbers[4];   /* kernel: flexible array; we only use constant indices */
} __attribute__((preserve_access_index));

struct task_struct {
    int pid;            /* root-ns thread id */
    int tgid;           /* root-ns process id */
    unsigned int __state;
    char comm[16];
    struct pid *thread_pid;
    struct task_struct *group_leader;
    int exit_code;      /* wait status, valid from do_exit() on */
} __attribute__((preserve_access_index));

/* Up to 4 pid-namespace levels: root -> WSL distro -> container -> nested. */

static __always_inline __u32 pid_in_ns(struct pid *p, __u32 ns_inum, __u32 global_id)
{
    if (!p)
        return global_id + PID_OUTSIDE_NS_BASE;
    unsigned int level = BPF_CORE_READ(p, level);
    __u32 found = 0;
    int hit = 0;
    /* One constant index per level. A variable index (p->numbers[i]) is
     * not a CO-RE-relocatable access: on WSL2 it produced an `nr` from a
     * different level than the `ns` it was matched against. Constant
     * indices get a proper array relocation each, and libbpf accepts
     * them against the kernel's flexible numbers[] array. */
#define PIDNS_TRY(i)                                                        \
    if (!hit && (i) <= level) {                                             \
        struct pid_namespace *ns_ = BPF_CORE_READ(p, numbers[i].ns);        \
        if (ns_ && BPF_CORE_READ(ns_, ns.inum) == ns_inum) {                \
            found = (__u32)BPF_CORE_READ(p, numbers[i].nr);                 \
            hit = 1;                                                        \
        }                                                                   \
    }
    PIDNS_TRY(0)
    PIDNS_TRY(1)
    PIDNS_TRY(2)
    PIDNS_TRY(3)
#undef PIDNS_TRY
    return hit ? found : global_id + PID_OUTSIDE_NS_BASE;
}

/* Process id (tgid) and thread id of `t`, as seen from the tracer's
 * pid namespace. */
static __always_inline void task_ids_ns(struct task_struct *t, __u32 ns_inum,
                                        __u32 *tgid, __u32 *tid)
{
    __u32 g_tid  = BPF_CORE_READ(t, pid);
    __u32 g_tgid = BPF_CORE_READ(t, tgid);
    if (ns_inum == 0) {
        *tid = g_tid;
        *tgid = g_tgid;
        return;
    }
    *tid  = pid_in_ns(BPF_CORE_READ(t, thread_pid), ns_inum, g_tid);
    *tgid = pid_in_ns(BPF_CORE_READ(t, group_leader, thread_pid), ns_inum, g_tgid);
}

struct bpf_pidns_info {
    __u32 pid;
    __u32 tgid;
};

/* Current task's ids in the namespace identified by (dev, ino) of its
 * nsfs file, via the kernel helper (which only succeeds when that is the
 * task's active pid namespace). Falls back to the task_struct walk. */
static __always_inline void current_ids_ns(__u64 ns_dev, __u32 ns_inum,
                                           __u32 *tgid, __u32 *tid)
{
    if (ns_inum != 0) {
        struct bpf_pidns_info ni = {};
        if (bpf_get_ns_current_pid_tgid(ns_dev, ns_inum, &ni, sizeof(ni)) == 0) {
            *tgid = ni.tgid;
            *tid  = ni.pid;
            return;
        }
    }
    task_ids_ns((struct task_struct *)bpf_get_current_task(), ns_inum, tgid, tid);
}

/* Debug snapshot of a task's pid chain (written by --verbose runs). */
struct pidns_dbg {
    __u32 level;
    __s32 helper_rc;
    __u32 helper_pid;
    __u32 helper_tgid;
    __u32 nr[4];
    __u32 inum[4];
    __u32 tgid_nr[4];
};

static __always_inline void pidns_snapshot(struct pidns_dbg *d, __u64 ns_dev, __u32 ns_inum)
{
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct pid *p = BPF_CORE_READ(t, thread_pid);
    struct pid *gp = BPF_CORE_READ(t, group_leader, thread_pid);
    struct bpf_pidns_info ni = {};
    d->helper_rc = bpf_get_ns_current_pid_tgid(ns_dev, ns_inum, &ni, sizeof(ni));
    d->helper_pid = ni.pid;
    d->helper_tgid = ni.tgid;
    d->level = BPF_CORE_READ(p, level);
#define PIDNS_SNAP(i)                                                      \
    d->nr[i] = BPF_CORE_READ(p, numbers[i].nr);                            \
    d->tgid_nr[i] = BPF_CORE_READ(gp, numbers[i].nr);                      \
    { struct pid_namespace *n_ = BPF_CORE_READ(p, numbers[i].ns);          \
      d->inum[i] = n_ ? BPF_CORE_READ(n_, ns.inum) : 0; }
    PIDNS_SNAP(0) PIDNS_SNAP(1) PIDNS_SNAP(2) PIDNS_SNAP(3)
#undef PIDNS_SNAP
}

#endif /* __BPF__ */
#endif /* __PIDNS_H */
