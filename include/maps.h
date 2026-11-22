/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MAPS_H
#define __MAPS_H

/*
 * Shared BPF maps used across multiple BPF objects.
 *
 * The stack_traces map must be ONE kernel map shared by:
 *   - trace_cpu_sched.bpf.c (off-CPU stacks on sched_switch OFF events)
 *   - trace_cuda.bpf.c (uprobe entries on CUDA ops)
 *   - unified_trace.c (user-space lookup + blazesym resolution)
 * so that every stack_id lands in the same ID space.
 *
 * Sharing is done in user space, NOT via bpffs pinning: unified_trace
 * loads the CPU object first, then calls bpf_map__reuse_fd() on the GPU
 * object's stack_traces before loading it. Earlier versions used
 * LIBBPF_PIN_BY_NAME, which had two failure modes:
 *   1. A stale pin from a build with a different map spec made the next
 *      bpf_object__load() fail with -EINVAL ("can't reuse pinned map").
 *   2. The pinned map outlived every run, so its buckets filled up with
 *      old stacks and new bpf_get_stackid() calls started failing.
 * Each tracer run now gets a fresh map that dies with the process.
 */

#ifdef __BPF__

#include <bpf/bpf_helpers.h>

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

/* Stack trace map. Each BPF object declares it identically; user space
 * makes them the same kernel object via bpf_map__reuse_fd().
 */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 10000);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(__u64));
} stack_traces SEC(".maps");

#endif /* __BPF__ */

/* Legacy pin path from the LIBBPF_PIN_BY_NAME era. unified_trace removes
 * a stale pin at startup so old maps don't linger in bpffs.
 */
#define STACK_TRACES_LEGACY_PIN_PATH "/sys/fs/bpf/stack_traces"

#endif /* __MAPS_H */
