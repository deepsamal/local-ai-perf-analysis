// SPDX-License-Identifier: GPL-2.0
/*
 * CPU scheduling tracer: on-CPU / off-CPU spans + wakeups for the agent.
 *
 * Uses BTF-typed tracepoints (tp_btf) so we receive real task_struct
 * pointers and can filter on the PROCESS id (tgid). The previous
 * version used classic tracepoint args, whose prev_pid/next_pid fields
 * are kernel task ids — i.e. THREAD ids. Comparing those to a process
 * id silently dropped every worker thread (PyTorch, llama.cpp, ggml
 * all do their work off the main thread).
 *
 * Stack capture happens on the OFF event. At sched_switch time
 * `current` is still the outgoing task, so bpf_get_stackid() with
 * BPF_F_USER_STACK returns the user stack of `prev` — exactly where
 * the thread blocked. (The old code captured on the ON event, which
 * recorded prev's stack but attributed it to next.)
 *
 * Requires kernel BTF (/sys/kernel/btf/vmlinux), kernel >= 5.5.
 *
 * clang -target bpf defines __BPF__ automatically; common.h and maps.h
 * both gate BPF-only blocks on that macro.
 */
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.h"  /* stack_traces; shared with trace_cuda via reuse_fd */

char LICENSE[] SEC("license") = "GPL";

/* Minimal CO-RE view of task_struct. preserve_access_index makes libbpf
 * relocate field offsets against the running kernel's BTF, so we don't
 * need vmlinux.h.
 */
struct task_struct {
    int pid;            /* kernel task id == user-visible thread id */
    int tgid;           /* thread-group id == user-visible process id */
    unsigned int __state;
    char comm[16];
} __attribute__((preserve_access_index));

/* Pre-5.14 kernels name the field `state` (long). */
struct task_struct___pre514 {
    long state;
} __attribute__((preserve_access_index));

/* Ring buffer for CPU scheduling events. Larger than before because
 * system-wide mode (target_tgid == 0) emits two events per switch.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024); /* 4 MB */
} cpu_events SEC(".maps");

/* Counter of ring-buffer reservation failures, so user space can report
 * dropped events instead of silently under-counting.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} cpu_drops SEC(".maps");

/* Knobs, set from user space via .rodata before load. Single struct for
 * a deterministic layout (clang may reorder separate globals); the same
 * definition is mirrored in unified_trace.c.
 */
struct sched_tracer_cfg {
    __u32 target_tgid;     /* 0 = all processes */
    __u8  offcpu_stacks;   /* capture user stack on blocking switch-outs */
    __u8  _pad[3];
};
const volatile struct sched_tracer_cfg cfg = {
    .target_tgid   = 0,
    .offcpu_stacks = 1,
};

static __always_inline int wanted(__u32 tgid)
{
    return cfg.target_tgid == 0 || tgid == cfg.target_tgid;
}

static __always_inline void count_drop(void)
{
    __u32 key = 0;
    __u64 *v = bpf_map_lookup_elem(&cpu_drops, &key);
    if (v)
        (*v)++;
}

static __always_inline __u64 task_state(struct task_struct *t)
{
    if (bpf_core_field_exists(t->__state))
        return BPF_CORE_READ(t, __state);
    struct task_struct___pre514 *old = (void *)t;
    return (__u64)BPF_CORE_READ(old, state);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(trace_sched_switch, _Bool preempt,
             struct task_struct *prev, struct task_struct *next)
{
    struct cpu_sched_event *event;
    __u32 prev_tid  = BPF_CORE_READ(prev, pid);
    __u32 prev_tgid = BPF_CORE_READ(prev, tgid);
    __u32 next_tid  = BPF_CORE_READ(next, pid);
    __u32 next_tgid = BPF_CORE_READ(next, tgid);
    __u64 now = bpf_ktime_get_ns();
    __u32 cpu = bpf_get_smp_processor_id();

    /* prev going OFF CPU. tid 0 is the idle task; skip it. */
    if (prev_tid != 0 && wanted(prev_tgid)) {
        event = bpf_ringbuf_reserve(&cpu_events, sizeof(*event), 0);
        if (event) {
            __u64 st = task_state(prev);
            event->timestamp  = now;
            event->event_type = CPU_SCHED_OFF;
            event->pid        = prev_tgid;
            event->tid        = prev_tid;
            event->cpu        = cpu;
            event->prev_state = st;
            event->stack_id   = -1;
            /* Only voluntary (blocking) switches carry a useful "why am I
             * waiting" stack; st == 0 means preempted while runnable.
             * Stacks are skipped in system-wide mode to bound overhead.
             */
            if (cfg.offcpu_stacks && cfg.target_tgid != 0 && st != 0)
                event->stack_id = bpf_get_stackid(ctx, &stack_traces,
                        BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);
            BPF_CORE_READ_STR_INTO(&event->comm, prev, comm);
            bpf_ringbuf_submit(event, 0);
        } else {
            count_drop();
        }
    }

    /* next coming ON CPU. No stack: `current` is still prev here. */
    if (next_tid != 0 && wanted(next_tgid)) {
        event = bpf_ringbuf_reserve(&cpu_events, sizeof(*event), 0);
        if (event) {
            event->timestamp  = now;
            event->event_type = CPU_SCHED_ON;
            event->pid        = next_tgid;
            event->tid        = next_tid;
            event->cpu        = cpu;
            event->prev_state = 0;
            event->stack_id   = -1;
            BPF_CORE_READ_STR_INTO(&event->comm, next, comm);
            bpf_ringbuf_submit(event, 0);
        } else {
            count_drop();
        }
    }
    return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(trace_sched_wakeup, struct task_struct *p)
{
    __u32 tid  = BPF_CORE_READ(p, pid);
    __u32 tgid = BPF_CORE_READ(p, tgid);

    if (tid == 0 || !wanted(tgid))
        return 0;

    struct cpu_sched_event *event =
        bpf_ringbuf_reserve(&cpu_events, sizeof(*event), 0);
    if (!event) {
        count_drop();
        return 0;
    }
    event->timestamp  = bpf_ktime_get_ns();
    event->event_type = CPU_SCHED_WAKEUP;
    event->pid        = tgid;
    event->tid        = tid;
    event->cpu        = bpf_get_smp_processor_id();
    event->prev_state = 0;
    event->stack_id   = -1;
    BPF_CORE_READ_STR_INTO(&event->comm, p, comm);
    bpf_ringbuf_submit(event, 0);
    return 0;
}
