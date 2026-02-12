// SPDX-License-Identifier: GPL-2.0
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* BPF map for communicating events to user-space */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB */
} events SEC(".maps");

/* BPF program attached to sys_enter_execve tracepoint */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx)
{
    struct exec_event *event;
    __u64 pid_tgid;
    __u32 pid, uid;

    /* Get current process info */
    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    /* Reserve space in ring buffer */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    /* Fill event data */
    event->pid = pid;
    event->ppid = 0; /* Can be enhanced to get parent PID */
    event->uid = uid;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    /* Note: Reading filename from tracepoint args requires BTF/vmlinux.h
     * For simplicity, we'll just set it to empty for now */
    event->filename[0] = '\0';

    /* Submit event to user-space */
    bpf_ringbuf_submit(event, 0);

    return 0;
}
