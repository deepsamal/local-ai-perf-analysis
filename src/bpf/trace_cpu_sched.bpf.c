// SPDX-License-Identifier: GPL-2.0
/* clang -target bpf defines __BPF__ automatically; common.h and maps.h
 * both gate BPF-only blocks on that macro.
 */
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.h"  /* shared, pinned stack_traces map */

char LICENSE[] SEC("license") = "GPL";

/* Ring buffer for CPU scheduling events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024); /* 512 KB */
} cpu_events SEC(".maps");

/* stack_traces map is declared in maps.h and shared (pinned by name)
 * with trace_cuda.bpf.c so both BPF objects produce stack IDs in the
 * same address space.
 */

/* Filter: only trace specific PID (0 = trace all) */
const volatile __u32 target_pid = 0;

/* Raw tracepoint context for sched_switch */
struct sched_switch_args {
    unsigned long long pad;
    char prev_comm[16];
    int prev_pid;
    int prev_prio;
    long prev_state;
    char next_comm[16];
    int next_pid;
    int next_prio;
};

/* Raw tracepoint context for sched_wakeup */
struct sched_wakeup_args {
    unsigned long long pad;
    char comm[16];
    int pid;
    int prio;
    int success;
    int target_cpu;
};

/* Tracepoint for context switches */
SEC("tp/sched/sched_switch")
int trace_sched_switch(struct sched_switch_args *ctx)
{
    struct cpu_sched_event *event;
    __u32 prev_pid, next_pid;
    
    prev_pid = ctx->prev_pid;
    next_pid = ctx->next_pid;
    
    /* Filter by PID if specified */
    if (target_pid != 0 && prev_pid != target_pid && next_pid != target_pid)
        return 0;
    
    /* Only generate event for our target thread going off or on CPU */
    if (target_pid != 0) {
        if (prev_pid == target_pid) {
            /* Our thread is being switched off CPU */
            event = bpf_ringbuf_reserve(&cpu_events, sizeof(*event), 0);
            if (!event)
                return 0;
            
            event->timestamp = bpf_ktime_get_ns();
            event->event_type = CPU_SCHED_OFF;
            event->pid = prev_pid;
            event->tid = prev_pid;
            event->cpu = bpf_get_smp_processor_id();
            event->prev_state = ctx->prev_state;            event->stack_id = -1;  /* No stack for OFF events */            __builtin_memcpy(event->comm, ctx->prev_comm, TASK_COMM_LEN);
            
            bpf_ringbuf_submit(event, 0);
        } else if (next_pid == target_pid) {
            /* Our thread is being switched on CPU */
            event = bpf_ringbuf_reserve(&cpu_events, sizeof(*event), 0);
            if (!event)
                return 0;
            
            event->timestamp = bpf_ktime_get_ns();
            event->event_type = CPU_SCHED_ON;
            event->pid = next_pid;
            event->tid = next_pid;
            event->cpu = bpf_get_smp_processor_id();
            event->prev_state = 0;            /* Capture user-space stack trace for the thread being scheduled on */
            event->stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);            __builtin_memcpy(event->comm, ctx->next_comm, TASK_COMM_LEN);
            
            bpf_ringbuf_submit(event, 0);
        }
    } else {
        /* Trace all: generate two events */
        /* Thread going off CPU */
        event = bpf_ringbuf_reserve(&cpu_events, sizeof(*event), 0);
        if (event) {
            event->timestamp = bpf_ktime_get_ns();
            event->event_type = CPU_SCHED_OFF;
            event->pid = prev_pid;
            event->tid = prev_pid;
            event->cpu = bpf_get_smp_processor_id();
            event->prev_state = ctx->prev_state;
            event->stack_id = -1;  /* No stack for OFF events */
            __builtin_memcpy(event->comm, ctx->prev_comm, TASK_COMM_LEN);
            
            bpf_ringbuf_submit(event, 0);
        }
        
        /* Thread going on CPU */
        event = bpf_ringbuf_reserve(&cpu_events, sizeof(*event), 0);
        if (event) {
            event->timestamp = bpf_ktime_get_ns();
            event->event_type = CPU_SCHED_ON;
            event->pid = next_pid;
            event->tid = next_pid;
            event->cpu = bpf_get_smp_processor_id();
            event->prev_state = 0;
            /* Capture user-space stack trace */
            event->stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
            __builtin_memcpy(event->comm, ctx->next_comm, TASK_COMM_LEN);
            
            bpf_ringbuf_submit(event, 0);
        }
    }
    
    return 0;
}

/* Tracepoint for thread wakeups */
SEC("tp/sched/sched_wakeup")
int trace_sched_wakeup(struct sched_wakeup_args *ctx)
{
    struct cpu_sched_event *event;
    __u32 pid;
    
    pid = ctx->pid;
    
    /* Filter by PID if specified */
    if (target_pid != 0 && pid != target_pid)
        return 0;
    
    event = bpf_ringbuf_reserve(&cpu_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->event_type = CPU_SCHED_WAKEUP;
    event->pid = pid;
    event->tid = pid;
    event->cpu = bpf_get_smp_processor_id();
    event->prev_state = 0;
    event->stack_id = -1;  /* No stack for wakeup events */
    
    /* Get comm from the woken task */
    __builtin_memcpy(event->comm, ctx->comm, TASK_COMM_LEN);
    
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}
