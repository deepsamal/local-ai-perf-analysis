// SPDX-License-Identifier: GPL-2.0
/*
 * CUDA runtime tracer.
 *
 * Hooks uprobe/uretprobe pairs on libcudart.so for both synchronous and
 * asynchronous CUDA runtime API calls. On each entry probe we capture the
 * user-space stack trace of the *submitter* (typically the agent's Python
 * or C++ frame that called into PyTorch / llama.cpp / etc.). Stack IDs
 * are produced into a shared, pinned stack_traces map so user-space can
 * resolve them via blazesym.
 *
 * Why entry, not return: for async ops the work is queued at entry and
 * the kernel runs later — return-probe stacks would be inside libcudart's
 * dispatch path, not the agent's logic. Capturing at entry preserves the
 * "who initiated this" attribution.
 */

/* clang -target bpf defines __BPF__ automatically. */
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.h"
#include "pidns.h" /* pid-namespace translation */

char LICENSE[] SEC("license") = "GPL";

/* Ring buffer for CUDA events. Sized for ~5k events at steady state;
 * heavier than the original 256K because async workloads emit more
 * events per second.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} cuda_events SEC(".maps");

/* In-flight calls keyed by pid_tgid */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct cuda_call_info);
} cuda_calls SEC(".maps");

/* --verbose: last pid-chain snapshot of a CUDA-calling task. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pidns_dbg);
} pidns_debug SEC(".maps");

/* Per-cpu counter used to decide whether to capture a stack on this
 * uprobe fire. Indexed by 0; we keep one slot. Sample period is set
 * from the cuda_cfg map at runtime.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} stack_sample_counter SEC(".maps");

/* User-tunable knobs, read from the cuda_cfg map below. The same struct
 * definition is mirrored in unified_trace.c; keep them in sync.
 */
struct cuda_tracer_cfg {
    __u32 target_pid;            /* 0 = all PIDs */
    __u32 sample_period_sync;    /* sync calls: every Nth event captures stack */
    __u32 sample_period_async;   /* async calls: every Nth event captures stack */
    __u8  capture_stacks;        /* 0 = disable stack capture entirely */
    __u8  debug_pidns;           /* --verbose: snapshot one task's pid chain */
    __u8  _pad[2];
    __u32 pidns_inum;            /* tracer's pid-namespace inode; 0 = no translation */
    __u32 _pad2;
    __u64 pidns_dev;             /* st_dev of that nsfs file (for the helper) */
};
/* Config lives in a one-entry array map that user space fills after load
 * and before attach -- NOT in `const volatile` .rodata. clang 10 (the
 * default on Ubuntu 20.04 / older WSL distros) constant-folds const
 * volatile struct members to their initializers, silently ignoring every
 * knob user space set (pid filter, sampling, pid namespace). A runtime
 * map lookup cannot be folded. All-zero (not yet written) = defaults. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cuda_tracer_cfg);
} cuda_cfg SEC(".maps");

static __always_inline struct cuda_tracer_cfg *get_cfg(void)
{
    __u32 k = 0;
    return bpf_map_lookup_elem(&cuda_cfg, &k);
}

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

/* Decide if we should capture a stack on this entry probe. Per-cpu
 * counter keeps overhead bounded; period is per-op-class (async vs sync).
 */
static __always_inline __s32 maybe_capture_stack(struct pt_regs *ctx, __u32 flags,
                                                  struct cuda_tracer_cfg *cfgp)
{
    if (!cfgp->capture_stacks)
        return -1;

    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&stack_sample_counter, &key);
    if (!cnt)
        return -1;

    __u32 period = (flags & CUDA_EV_FLAG_ASYNC) ? cfgp->sample_period_async
                                                : cfgp->sample_period_sync;
    if (period == 0)
        period = 1;

    __u64 c = (*cnt)++;
    if (c % period != 0)
        return -1;

    /* BPF_F_FAST_STACK_CMP de-dups identical stacks aggressively. */
    return bpf_get_stackid(ctx, &stack_traces,
                           BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);
}

/* Common entry-probe path. Records call metadata + stack ID in the
 * in-flight hash. Returns 0 on success, non-zero if filtered out.
 */
static __always_inline int record_entry(struct pt_regs *ctx,
                                        __u32 op_type, __u32 flags,
                                        __u64 size, __u64 ptr, __u64 stream_id)
{
    struct cuda_tracer_cfg *cfgp = get_cfg();
    if (!cfgp)
        return 1;
    __u64 pid_tgid = bpf_get_current_pid_tgid();   /* root-ns; map key only */
    __u32 pid, tid;
    current_ids_ns(cfgp->pidns_dev, cfgp->pidns_inum, &pid, &tid);

    if (cfgp->target_pid != 0 && pid != cfgp->target_pid)
        return 1;

    if (cfgp->debug_pidns) {
        __u32 k0 = 0;
        struct pidns_dbg *d = bpf_map_lookup_elem(&pidns_debug, &k0);
        if (d)
            pidns_snapshot(d, cfgp->pidns_dev, cfgp->pidns_inum);
    }

    struct cuda_call_info info = {};
    info.timestamp = bpf_ktime_get_ns();
    info.op_type = op_type;
    info.pid = pid;
    info.tid = tid;
    info.size = size;
    info.ptr = ptr;
    info.stream_id = stream_id;
    info.flags = flags;

    __s32 sid = maybe_capture_stack(ctx, flags, cfgp);
    info.stack_id = sid;
    if (sid >= 0)
        info.flags |= CUDA_EV_FLAG_STACK_SAMPLED;

    bpf_map_update_elem(&cuda_calls, &pid_tgid, &info, BPF_ANY);
    return 0;
}

/* Common return-probe path. Pulls in-flight info, fills duration + ret,
 * submits to ring buffer.
 */
static __always_inline int submit_event(struct pt_regs *ctx, __u32 op_type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cuda_call_info *info = bpf_map_lookup_elem(&cuda_calls, &pid_tgid);
    if (!info)
        return 0;

    /* Op-type mismatch can happen if a probe was missed (e.g. tail-call
     * from one CUDA API into another). Drop rather than emit garbage.
     */
    if (info->op_type != op_type) {
        bpf_map_delete_elem(&cuda_calls, &pid_tgid);
        return 0;
    }

    struct cuda_event *event = bpf_ringbuf_reserve(&cuda_events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&cuda_calls, &pid_tgid);
        return 0;
    }

    __u64 end_time = bpf_ktime_get_ns();
    event->timestamp = info->timestamp;
    event->duration_ns = end_time - info->timestamp;
    event->pid = info->pid;
    event->tid = info->tid;
    event->op_type = op_type;
    event->size = info->size;
    event->ptr = info->ptr;
    event->ret_val = PT_REGS_RC(ctx);
    event->stream_id = info->stream_id;
    event->stack_id = info->stack_id;
    event->flags = info->flags;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&cuda_calls, &pid_tgid);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Synchronous ops (preserved from prior version)                     */
/* ------------------------------------------------------------------ */

SEC("uprobe/cudaMalloc")
int trace_cuda_malloc_entry(struct pt_regs *ctx) {
    /* cudaMalloc(void **devPtr, size_t size) — size is PARM2 */
    return record_entry(ctx, CUDA_OP_MALLOC, 0, PT_REGS_PARM2(ctx), 0, 0);
}
SEC("uretprobe/cudaMalloc")
int trace_cuda_malloc_return(struct pt_regs *ctx) {
    return submit_event(ctx, CUDA_OP_MALLOC);
}

SEC("uprobe/cudaFree")
int trace_cuda_free_entry(struct pt_regs *ctx) {
    return record_entry(ctx, CUDA_OP_FREE, 0, 0, PT_REGS_PARM1(ctx), 0);
}
SEC("uretprobe/cudaFree")
int trace_cuda_free_return(struct pt_regs *ctx) {
    return submit_event(ctx, CUDA_OP_FREE);
}

SEC("uprobe/cudaMemcpy")
int trace_cuda_memcpy_entry(struct pt_regs *ctx) {
    /* cudaMemcpy(dst, src, count, kind) — count is PARM3 */
    return record_entry(ctx, CUDA_OP_MEMCPY, 0, PT_REGS_PARM3(ctx), 0, 0);
}
SEC("uretprobe/cudaMemcpy")
int trace_cuda_memcpy_return(struct pt_regs *ctx) {
    return submit_event(ctx, CUDA_OP_MEMCPY);
}

SEC("uprobe/cudaLaunchKernel")
int trace_cuda_launch_entry(struct pt_regs *ctx) {
    /* cudaLaunchKernel(func, gridDim, blockDim, args, sharedMem, stream)
     * stream is PARM6 (kept as 6 even though gridDim/blockDim are
     * structs — they're passed by value on the stack on x86_64 SysV
     * for small structs; for non-default stream tracking with this API
     * we'd need a different approach, but for now we record the func
     * pointer as ptr and skip stream extraction here).
     */
    return record_entry(ctx, CUDA_OP_LAUNCH_KERNEL, 0, 0,
                        PT_REGS_PARM1(ctx), 0);
}
SEC("uretprobe/cudaLaunchKernel")
int trace_cuda_launch_return(struct pt_regs *ctx) {
    return submit_event(ctx, CUDA_OP_LAUNCH_KERNEL);
}

SEC("uprobe/cudaDeviceSynchronize")
int trace_cuda_sync_entry(struct pt_regs *ctx) {
    return record_entry(ctx, CUDA_OP_SYNC, 0, 0, 0, 0);
}
SEC("uretprobe/cudaDeviceSynchronize")
int trace_cuda_sync_return(struct pt_regs *ctx) {
    return submit_event(ctx, CUDA_OP_SYNC);
}

/* ------------------------------------------------------------------ */
/* Async / stream-aware ops (new for AI-agent perf analysis)          */
/* ------------------------------------------------------------------ */

SEC("uprobe/cudaMemcpyAsync")
int trace_cuda_memcpy_async_entry(struct pt_regs *ctx) {
    /* cudaMemcpyAsync(dst, src, count, kind, stream)
     * count = PARM3, stream = PARM5
     */
    return record_entry(ctx, CUDA_OP_MEMCPY_ASYNC, CUDA_EV_FLAG_ASYNC,
                        PT_REGS_PARM3(ctx), 0, PT_REGS_PARM5(ctx));
}
SEC("uretprobe/cudaMemcpyAsync")
int trace_cuda_memcpy_async_return(struct pt_regs *ctx) {
    return submit_event(ctx, CUDA_OP_MEMCPY_ASYNC);
}

SEC("uprobe/cudaStreamSynchronize")
int trace_cuda_stream_sync_entry(struct pt_regs *ctx) {
    /* cudaStreamSynchronize(stream) — stream = PARM1.
     * This is the call that blocks the agent thread waiting for the
     * stream to drain; capture stack so we can attribute the wait.
     */
    return record_entry(ctx, CUDA_OP_STREAM_SYNC, 0, 0, 0,
                        PT_REGS_PARM1(ctx));
}
SEC("uretprobe/cudaStreamSynchronize")
int trace_cuda_stream_sync_return(struct pt_regs *ctx) {
    return submit_event(ctx, CUDA_OP_STREAM_SYNC);
}

SEC("uprobe/cudaStreamCreate")
int trace_cuda_stream_create_entry(struct pt_regs *ctx) {
    /* cudaStreamCreate(cudaStream_t *pStream) — pStream is the OUT
     * pointer. We can't read *pStream here; user space ties events
     * by timestamp.
     */
    return record_entry(ctx, CUDA_OP_STREAM_CREATE, 0, 0,
                        PT_REGS_PARM1(ctx), 0);
}
SEC("uretprobe/cudaStreamCreate")
int trace_cuda_stream_create_return(struct pt_regs *ctx) {
    return submit_event(ctx, CUDA_OP_STREAM_CREATE);
}

SEC("uprobe/cudaStreamDestroy")
int trace_cuda_stream_destroy_entry(struct pt_regs *ctx) {
    return record_entry(ctx, CUDA_OP_STREAM_DESTROY, 0, 0, 0,
                        PT_REGS_PARM1(ctx));
}
SEC("uretprobe/cudaStreamDestroy")
int trace_cuda_stream_destroy_return(struct pt_regs *ctx) {
    return submit_event(ctx, CUDA_OP_STREAM_DESTROY);
}

SEC("uprobe/cudaEventRecord")
int trace_cuda_event_record_entry(struct pt_regs *ctx) {
    /* cudaEventRecord(event, stream) — stream = PARM2, event = PARM1 */
    return record_entry(ctx, CUDA_OP_EVENT_RECORD, CUDA_EV_FLAG_ASYNC,
                        0, PT_REGS_PARM1(ctx), PT_REGS_PARM2(ctx));
}
SEC("uretprobe/cudaEventRecord")
int trace_cuda_event_record_return(struct pt_regs *ctx) {
    return submit_event(ctx, CUDA_OP_EVENT_RECORD);
}

SEC("uprobe/cudaEventSynchronize")
int trace_cuda_event_sync_entry(struct pt_regs *ctx) {
    /* cudaEventSynchronize(event) — blocks until event completes.
     * Like cudaStreamSynchronize, this is where the agent waits.
     */
    return record_entry(ctx, CUDA_OP_EVENT_SYNC, 0, 0,
                        PT_REGS_PARM1(ctx), 0);
}
SEC("uretprobe/cudaEventSynchronize")
int trace_cuda_event_sync_return(struct pt_regs *ctx) {
    return submit_event(ctx, CUDA_OP_EVENT_SYNC);
}

SEC("uprobe/cudaEventQuery")
int trace_cuda_event_query_entry(struct pt_regs *ctx) {
    return record_entry(ctx, CUDA_OP_EVENT_QUERY, 0, 0,
                        PT_REGS_PARM1(ctx), 0);
}
SEC("uretprobe/cudaEventQuery")
int trace_cuda_event_query_return(struct pt_regs *ctx) {
    return submit_event(ctx, CUDA_OP_EVENT_QUERY);
}

SEC("uprobe/cudaLaunchKernelExC")
int trace_cuda_launch_ex_entry(struct pt_regs *ctx) {
    /* cudaLaunchKernelExC(const cudaLaunchConfig_t *config, const void *func, void **args)
     * The config struct contains stream; we don't dereference here to
     * keep verifier happy, but we mark it ASYNC and capture stack.
     */
    return record_entry(ctx, CUDA_OP_LAUNCH_KERNEL_EX, CUDA_EV_FLAG_ASYNC,
                        0, PT_REGS_PARM2(ctx), 0);
}
SEC("uretprobe/cudaLaunchKernelExC")
int trace_cuda_launch_ex_return(struct pt_regs *ctx) {
    return submit_event(ctx, CUDA_OP_LAUNCH_KERNEL_EX);
}

SEC("uprobe/cudaGraphLaunch")
int trace_cuda_graph_launch_entry(struct pt_regs *ctx) {
    /* cudaGraphLaunch(graphExec, stream) — stream = PARM2.
     * NB: a single graph launch may dispatch hundreds of kernels.
     * User space should warn the user that kernel-level visibility
     * is lost inside graph-launched regions.
     */
    return record_entry(ctx, CUDA_OP_GRAPH_LAUNCH, CUDA_EV_FLAG_ASYNC,
                        0, PT_REGS_PARM1(ctx), PT_REGS_PARM2(ctx));
}
SEC("uretprobe/cudaGraphLaunch")
int trace_cuda_graph_launch_return(struct pt_regs *ctx) {
    return submit_event(ctx, CUDA_OP_GRAPH_LAUNCH);
}
