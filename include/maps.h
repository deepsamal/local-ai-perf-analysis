/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MAPS_H
#define __MAPS_H

/*
 * Shared BPF maps used across multiple BPF objects.
 *
 * The stack_traces map is pinned by name in the BPF filesystem so that:
 *   - trace_cpu_sched.bpf.c (sched_switch ON events)
 *   - trace_cuda.bpf.c (uprobe entries on async CUDA ops)
 *   - unified_trace.c (user-space resolver via blazesym)
 * all reference the same stack-ID address space. This lets us trace an
 * async cudaMemcpyAsync call back to the agent code that submitted it
 * AND the CPU sched events that preceded it, with consistent IDs.
 *
 * Requires /sys/fs/bpf to be mounted (libbpf will mount it on demand
 * if not, when LIBBPF_PIN_BY_NAME is set on a map).
 */

#ifdef __BPF__

#include <bpf/bpf_helpers.h>

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

/* Pinned, name-shared stack trace map. Each BPF object that needs to
 * call bpf_get_stackid() against this map declares it identically and
 * libbpf will reuse the pinned instance after the first load.
 */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 10000);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(__u64));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stack_traces SEC(".maps");

#endif /* __BPF__ */

/* Pin path used by user-space code when it wants to open the map
 * by FD before any BPF object is loaded. libbpf normally manages
 * this transparently; exposed here for diagnostics and tests.
 */
#define STACK_TRACES_PIN_PATH "/sys/fs/bpf/stack_traces"

#endif /* __MAPS_H */
