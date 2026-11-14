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
 * Records are built in a stack-local struct and copied with
 * bpf_ringbuf_output() rather than written in place after
 * bpf_ringbuf_reserve(). The WSL2 toolchain (Ubuntu 22.04 clang) dropped
 * every plain store into reserved ringbuf memory on the OFF path -- only
 * the comm string copy survived, so OFF records arrived all-zero. Stores
 * to a stack object passed to a helper can't be elided.
 *
 * Requires kernel BTF (/sys/kernel/btf/vmlinux) and kernel >= 5.14
 * (task_struct.__state).
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

#include "pidns.h" /* CO-RE task_struct + pid-namespace translation */

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

/* Knobs, read from the sched_cfg map below; mirrored in unified_trace.c. */
struct sched_tracer_cfg {
    __u32 target_tgid;     /* 0 = all processes; in the tracer's pid namespace */
    __u8  offcpu_stacks;   /* capture user stack on blocking switch-outs */
    __u8  _pad[3];
    __u32 pidns_inum;      /* tracer's pid-namespace inode; 0 = no translation */
    __u32 _pad2;
};
/* Config in a one-entry array map, filled by user space after load and
 * before attach. Not `const volatile` .rodata: clang 10 constant-folds
 * those struct members to their initializers (see trace_cuda.bpf.c). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sched_tracer_cfg);
} sched_cfg SEC(".maps");

static __always_inline struct sched_tracer_cfg *get_cfg(void)
{
    __u32 k = 0;
    return bpf_map_lookup_elem(&sched_cfg, &k);
}

static __always_inline int wanted(struct sched_tracer_cfg *cfgp, __u32 tgid)
{
    return cfgp->target_tgid == 0 || tgid == cfgp->target_tgid;
}

static __always_inline void count_drop(void)
{
    __u32 key = 0;
    __u64 *v = bpf_map_lookup_elem(&cpu_drops, &key);
    if (v)
        (*v)++;
}

static __always_inline void emit(struct cpu_sched_event *ev)
{
    if (bpf_ringbuf_output(&cpu_events, ev, sizeof(*ev), 0) != 0)
        count_drop();
}

SEC("tp_btf/sched_switch")
int BPF_PROG(trace_sched_switch, _Bool preempt,
             struct task_struct *prev, struct task_struct *next)
{
    struct sched_tracer_cfg *cfgp = get_cfg();
    if (!cfgp)
        return 0;
    struct cpu_sched_event ev;
    __u32 prev_tid, prev_tgid, next_tid, next_tgid;
    /* Global tid 0 is the idle task; skip it before translating. */
    int prev_idle = BPF_CORE_READ(prev, pid) == 0;
    int next_idle = BPF_CORE_READ(next, pid) == 0;
    task_ids_ns(prev, cfgp->pidns_inum, &prev_tgid, &prev_tid);
    task_ids_ns(next, cfgp->pidns_inum, &next_tgid, &next_tid);
    __u64 now = bpf_ktime_get_ns();
    __u32 cpu = bpf_get_smp_processor_id();

    /* prev going OFF CPU. */
    if (!prev_idle && wanted(cfgp, prev_tgid)) {
        __u64 st = BPF_CORE_READ(prev, __state);
        __builtin_memset(&ev, 0, sizeof(ev));
        ev.timestamp  = now;
        ev.event_type = CPU_SCHED_OFF;
        ev.pid        = prev_tgid;
        ev.tid        = prev_tid;
        ev.cpu        = cpu;
        ev.prev_state = st;
        ev.stack_id   = -1;
        /* Only voluntary (blocking) switches carry a useful "why am I
         * waiting" stack; st == 0 means preempted while runnable.
         * Stacks are skipped in system-wide mode to bound overhead.
         */
        if (cfgp->offcpu_stacks && cfgp->target_tgid != 0 && st != 0)
            ev.stack_id = bpf_get_stackid(ctx, &stack_traces,
                    BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);
        BPF_CORE_READ_STR_INTO(&ev.comm, prev, comm);
        emit(&ev);
    }

    /* next coming ON CPU. No stack: `current` is still prev here. */
    if (!next_idle && wanted(cfgp, next_tgid)) {
        __builtin_memset(&ev, 0, sizeof(ev));
        ev.timestamp  = now;
        ev.event_type = CPU_SCHED_ON;
        ev.pid        = next_tgid;
        ev.tid        = next_tid;
        ev.cpu        = cpu;
        ev.stack_id   = -1;
        BPF_CORE_READ_STR_INTO(&ev.comm, next, comm);
        emit(&ev);
    }
    return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(trace_sched_wakeup, struct task_struct *p)
{
    struct sched_tracer_cfg *cfgp = get_cfg();
    if (!cfgp)
        return 0;
    __u32 tid, tgid;
    if (BPF_CORE_READ(p, pid) == 0)
        return 0;
    task_ids_ns(p, cfgp->pidns_inum, &tgid, &tid);

    if (!wanted(cfgp, tgid))
        return 0;

    struct cpu_sched_event ev;
    __builtin_memset(&ev, 0, sizeof(ev));
    ev.timestamp  = bpf_ktime_get_ns();
    ev.event_type = CPU_SCHED_WAKEUP;
    ev.pid        = tgid;
    ev.tid        = tid;
    ev.cpu        = bpf_get_smp_processor_id();
    ev.stack_id   = -1;
    BPF_CORE_READ_STR_INTO(&ev.comm, p, comm);
    emit(&ev);
    return 0;
}
