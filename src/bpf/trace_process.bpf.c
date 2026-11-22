// SPDX-License-Identifier: GPL-2.0
/*
 * Subprocess tracer (roadmap Phase 2): fork / exec / exit / wait.
 *
 * Without this a code-interpreter or shell tool looks like the agent
 * doing nothing: its thread is off-CPU and the work happens in a pid
 * the tracer was never told about. Here we
 *   - record every new process forked by a traced process, with the
 *     parent's user stack (the agent code that spawned the tool);
 *   - add the child to the traced set (io_tracked) so its own network
 *     and disk activity is captured too ("follow children");
 *   - record exec (what it became) and exit (when, and with what status);
 *   - record wait4/waitid calls that reaped a child or blocked.
 *
 * Everything is tp_btf: scheduler tracepoints plus the raw sys_enter /
 * sys_exit tracepoints, which exist on every BTF kernel. (A kprobe on
 * the wait4 entry point would need an arch-specific symbol and kprobe
 * support; the syscall tracepoints sys_enter_wait4 need
 * CONFIG_FTRACE_SYSCALLS.) The price is that sys_enter runs for every
 * syscall on the machine: it returns after one integer compare unless
 * the syscall is a wait, and sys_exit returns after one array-map read
 * unless a traced wait is in flight.
 */
#include "io_common.h"

char LICENSE[] SEC("license") = "GPL";

struct linux_binprm {
    const char *filename;
} __attribute__((preserve_access_index));

#if defined(__TARGET_ARCH_arm64)
#define IO_NR_WAIT4  260
#define IO_NR_WAITID 95
#else /* x86_64 */
#define IO_NR_WAIT4  61
#define IO_NR_WAITID 247
#endif

struct wait_call {
    __u64 ts;
    __u32 pid;
    __u32 tid;
    __u32 nr;
    __s32 stack_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct wait_call);
} io_waits SEC(".maps");

/* Number of traced waits currently in flight; lets sys_exit bail early. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} io_waits_inflight SEC(".maps");

static __always_inline void fill_hdr(struct io_hdr *h, __u32 type, __u32 pid, __u32 tid)
{
    h->ts   = bpf_ktime_get_ns();
    h->type = type;
    h->pid  = pid;
    h->tid  = tid;
    h->stack_id = -1;
    bpf_get_current_comm(&h->comm, sizeof(h->comm));
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(tp_proc_fork, struct task_struct *parent, struct task_struct *child)
{
    struct io_tracer_cfg *c = io_get_cfg();
    if (!c)
        return 0;
    __u32 p_root = BPF_CORE_READ(parent, tgid);
    __u32 c_root = BPF_CORE_READ(child, tgid);
    if (p_root == c_root)
        return 0;                       /* new thread, not a new process */

    __u32 pid, tid;
    if (!io_wanted(c, &pid, &tid))      /* current == parent here */
        return 0;

    if (c->follow_children && c->target_tgid != 0) {
        __u8 one = 1;
        bpf_map_update_elem(&io_tracked, &c_root, &one, BPF_ANY);
    }

    struct io_proc_event ev;
    __builtin_memset(&ev, 0, sizeof(ev));
    fill_hdr(&ev.h, IO_PROC_FORK, pid, tid);
    ev.h.stack_id = io_stack(ctx, c);
    __u32 c_tid;
    task_ids_ns(child, c->pidns_inum, &ev.child_pid, &c_tid);
    io_emit(&ev, sizeof(ev));
    return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(tp_proc_exec, struct task_struct *p, int old_pid, struct linux_binprm *bprm)
{
    struct io_tracer_cfg *c = io_get_cfg();
    if (!c)
        return 0;
    __u32 pid, tid;
    if (!io_wanted(c, &pid, &tid))
        return 0;

    struct io_proc_event ev;
    __builtin_memset(&ev, 0, sizeof(ev));
    fill_hdr(&ev.h, IO_PROC_EXEC, pid, tid);
    const char *fn = BPF_CORE_READ(bprm, filename);
    bpf_probe_read_kernel_str(ev.filename, sizeof(ev.filename), fn);
    io_emit(&ev, sizeof(ev));
    return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(tp_proc_exit, struct task_struct *p)
{
    /* Fires per thread; the process is treated as gone when its leader
     * exits. */
    __u32 root_tid  = BPF_CORE_READ(p, pid);
    __u32 root_tgid = BPF_CORE_READ(p, tgid);
    if (root_tid != root_tgid)
        return 0;

    struct io_tracer_cfg *c = io_get_cfg();
    if (!c)
        return 0;
    __u32 pid, tid;
    if (!io_wanted(c, &pid, &tid))
        return 0;

    struct io_proc_event ev;
    __builtin_memset(&ev, 0, sizeof(ev));
    fill_hdr(&ev.h, IO_PROC_EXIT, pid, tid);
    ev.exit_code = BPF_CORE_READ(p, exit_code);
    io_emit(&ev, sizeof(ev));

    bpf_map_delete_elem(&io_tracked, &root_tgid);
    return 0;
}

SEC("tp_btf/sys_enter")
int BPF_PROG(tp_sys_enter, void *regs, long id)
{
    if (id != IO_NR_WAIT4 && id != IO_NR_WAITID)
        return 0;

    struct io_tracer_cfg *c = io_get_cfg();
    if (!c)
        return 0;
    struct wait_call w = {};
    if (!io_wanted(c, &w.pid, &w.tid))
        return 0;
    w.ts = bpf_ktime_get_ns();
    w.nr = (__u32)id;
    w.stack_id = io_stack(ctx, c);

    __u64 key = bpf_get_current_pid_tgid();
    if (bpf_map_update_elem(&io_waits, &key, &w, BPF_NOEXIST) == 0) {
        __u32 k0 = 0;
        __u64 *n = bpf_map_lookup_elem(&io_waits_inflight, &k0);
        if (n)
            __sync_fetch_and_add(n, 1);
    }
    return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(tp_sys_exit, void *regs, long ret)
{
    __u32 k0 = 0;
    __u64 *n = bpf_map_lookup_elem(&io_waits_inflight, &k0);
    if (!n || *n == 0)
        return 0;

    __u64 key = bpf_get_current_pid_tgid();
    struct wait_call *wp = bpf_map_lookup_elem(&io_waits, &key);
    if (!wp)
        return 0;
    struct wait_call w = *wp;
    bpf_map_delete_elem(&io_waits, &key);
    __sync_fetch_and_add(n, -1);

    __u64 now = bpf_ktime_get_ns();
    /* Keep waits that reaped a child or really blocked; WNOHANG polling
     * that returns 0 immediately is noise. */
    if (ret <= 0 && now - w.ts < 1000000ULL)
        return 0;

    struct io_proc_event ev;
    __builtin_memset(&ev, 0, sizeof(ev));
    ev.h.ts       = w.ts;
    ev.h.dur_ns   = now - w.ts;
    ev.h.type     = IO_PROC_WAIT;
    ev.h.pid      = w.pid;
    ev.h.tid      = w.tid;
    ev.h.stack_id = w.stack_id;
    bpf_get_current_comm(&ev.h.comm, sizeof(ev.h.comm));
    ev.ret        = ret;
    ev.syscall_nr = w.nr;
    io_emit(&ev, sizeof(ev));
    return 0;
}
