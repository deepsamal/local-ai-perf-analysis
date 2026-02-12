// SPDX-License-Identifier: GPL-2.0
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* BPF map for communicating CUDA events to user-space */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB */
} cuda_events SEC(".maps");

/* Track in-flight CUDA operations for timing */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);   /* pid_tgid */
    __type(value, struct cuda_call_info);
} cuda_calls SEC(".maps");

/* uprobe: cudaMalloc entry */
SEC("uprobe/cudaMalloc")
int trace_cuda_malloc_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 size;
    struct cuda_call_info info = {};
    
    /* Get size argument (second parameter) */
    size = PT_REGS_PARM2(ctx);
    
    info.timestamp = bpf_ktime_get_ns();
    info.op_type = CUDA_OP_MALLOC;
    info.size = size;
    info.pid = pid_tgid >> 32;
    
    bpf_map_update_elem(&cuda_calls, &pid_tgid, &info, BPF_ANY);
    
    return 0;
}

/* uretprobe: cudaMalloc return */
SEC("uretprobe/cudaMalloc")
int trace_cuda_malloc_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuda_call_info *info;
    struct cuda_event *event;
    int ret;
    
    info = bpf_map_lookup_elem(&cuda_calls, &pid_tgid);
    if (!info)
        return 0;
    
    /* Get return value */
    ret = PT_REGS_RC(ctx);
    
    /* Reserve space in ring buffer */
    event = bpf_ringbuf_reserve(&cuda_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&cuda_calls, &pid_tgid);
        return 0;
    }
    
    __u64 end_time = bpf_ktime_get_ns();
    event->timestamp = info->timestamp;  /* Start time */
    event->duration_ns = end_time - info->timestamp;
    event->pid = info->pid;
    event->tid = pid_tgid & 0xFFFFFFFF;
    event->op_type = CUDA_OP_MALLOC;
    event->size = info->size;
    event->ret_val = ret;
    event->ptr = 0; /* Would need to read from devPtr argument */
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&cuda_calls, &pid_tgid);
    
    return 0;
}

/* uprobe: cudaFree entry */
SEC("uprobe/cudaFree")
int trace_cuda_free_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 ptr;
    struct cuda_call_info info = {};
    
    /* Get device pointer argument */
    ptr = PT_REGS_PARM1(ctx);
    
    info.timestamp = bpf_ktime_get_ns();
    info.op_type = CUDA_OP_FREE;
    info.ptr = ptr;
    info.pid = pid_tgid >> 32;
    
    bpf_map_update_elem(&cuda_calls, &pid_tgid, &info, BPF_ANY);
    
    return 0;
}

/* uretprobe: cudaFree return */
SEC("uretprobe/cudaFree")
int trace_cuda_free_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuda_call_info *info;
    struct cuda_event *event;
    int ret;
    
    info = bpf_map_lookup_elem(&cuda_calls, &pid_tgid);
    if (!info)
        return 0;
    
    ret = PT_REGS_RC(ctx);
    
    event = bpf_ringbuf_reserve(&cuda_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&cuda_calls, &pid_tgid);
        return 0;
    }
    
    __u64 end_time = bpf_ktime_get_ns();
    event->timestamp = info->timestamp;  /* Start time */
    event->duration_ns = end_time - info->timestamp;
    event->pid = info->pid;
    event->tid = pid_tgid & 0xFFFFFFFF;
    event->op_type = CUDA_OP_FREE;
    event->ptr = info->ptr;
    event->ret_val = ret;
    event->size = 0;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&cuda_calls, &pid_tgid);
    
    return 0;
}

/* uprobe: cudaMemcpy entry */
SEC("uprobe/cudaMemcpy")
int trace_cuda_memcpy_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 size;
    struct cuda_call_info info = {};
    
    /* Get size argument (third parameter) */
    size = PT_REGS_PARM3(ctx);
    
    info.timestamp = bpf_ktime_get_ns();
    info.op_type = CUDA_OP_MEMCPY;
    info.size = size;
    info.pid = pid_tgid >> 32;
    
    bpf_map_update_elem(&cuda_calls, &pid_tgid, &info, BPF_ANY);
    
    return 0;
}

/* uretprobe: cudaMemcpy return */
SEC("uretprobe/cudaMemcpy")
int trace_cuda_memcpy_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuda_call_info *info;
    struct cuda_event *event;
    int ret;
    
    info = bpf_map_lookup_elem(&cuda_calls, &pid_tgid);
    if (!info)
        return 0;
    
    ret = PT_REGS_RC(ctx);
    
    event = bpf_ringbuf_reserve(&cuda_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&cuda_calls, &pid_tgid);
        return 0;
    }
    
    __u64 end_time = bpf_ktime_get_ns();
    event->timestamp = info->timestamp;  /* Start time */
    event->duration_ns = end_time - info->timestamp;
    event->pid = info->pid;
    event->tid = pid_tgid & 0xFFFFFFFF;
    event->op_type = CUDA_OP_MEMCPY;
    event->size = info->size;
    event->ret_val = ret;
    event->ptr = 0;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&cuda_calls, &pid_tgid);
    
    return 0;
}

/* uprobe: cudaLaunchKernel entry */
SEC("uprobe/cudaLaunchKernel")
int trace_cuda_launch_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuda_call_info info = {};
    
    info.timestamp = bpf_ktime_get_ns();
    info.op_type = CUDA_OP_LAUNCH_KERNEL;
    info.pid = pid_tgid >> 32;
    
    bpf_map_update_elem(&cuda_calls, &pid_tgid, &info, BPF_ANY);
    
    return 0;
}

/* uretprobe: cudaLaunchKernel return */
SEC("uretprobe/cudaLaunchKernel")
int trace_cuda_launch_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuda_call_info *info;
    struct cuda_event *event;
    int ret;
    
    info = bpf_map_lookup_elem(&cuda_calls, &pid_tgid);
    if (!info)
        return 0;
    
    ret = PT_REGS_RC(ctx);
    
    event = bpf_ringbuf_reserve(&cuda_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&cuda_calls, &pid_tgid);
        return 0;
    }
    
    __u64 end_time = bpf_ktime_get_ns();
    event->timestamp = info->timestamp;  /* Start time */
    event->duration_ns = end_time - info->timestamp;
    event->pid = info->pid;
    event->tid = pid_tgid & 0xFFFFFFFF;
    event->op_type = CUDA_OP_LAUNCH_KERNEL;
    event->size = 0;
    event->ret_val = ret;
    event->ptr = 0;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&cuda_calls, &pid_tgid);
    
    return 0;
}

/* uprobe: cudaDeviceSynchronize entry */
SEC("uprobe/cudaDeviceSynchronize")
int trace_cuda_sync_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuda_call_info info = {};
    
    info.timestamp = bpf_ktime_get_ns();
    info.op_type = CUDA_OP_SYNC;
    info.pid = pid_tgid >> 32;
    
    bpf_map_update_elem(&cuda_calls, &pid_tgid, &info, BPF_ANY);
    
    return 0;
}

/* uretprobe: cudaDeviceSynchronize return */
SEC("uretprobe/cudaDeviceSynchronize")
int trace_cuda_sync_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuda_call_info *info;
    struct cuda_event *event;
    int ret;
    
    info = bpf_map_lookup_elem(&cuda_calls, &pid_tgid);
    if (!info)
        return 0;
    
    ret = PT_REGS_RC(ctx);
    
    event = bpf_ringbuf_reserve(&cuda_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&cuda_calls, &pid_tgid);
        return 0;
    }
    
    __u64 end_time = bpf_ktime_get_ns();
    event->timestamp = info->timestamp;  /* Start time */
    event->duration_ns = end_time - info->timestamp;
    event->pid = info->pid;
    event->tid = pid_tgid & 0xFFFFFFFF;
    event->op_type = CUDA_OP_SYNC;
    event->size = 0;
    event->ret_val = ret;
    event->ptr = 0;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&cuda_calls, &pid_tgid);
    
    return 0;
}
