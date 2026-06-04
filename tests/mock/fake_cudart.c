/* SPDX-License-Identifier: MIT */
/*
 * Mock libcudart.so used by the test harness when no real GPU is available.
 *
 * Why this exists: the eBPF uprobe tracer attaches by symbol name to a shared
 * library on disk. To exercise the tracer end-to-end without a GPU, we ship
 * a shared library that exports the exact symbol names libcudart.so does
 * (`cudaMalloc`, `cudaMemcpyAsync`, `cudaStreamSynchronize`, etc.) as no-op
 * stubs. Each stub busy-waits for a small, varied duration so timings show
 * up as non-zero in the captured trace — otherwise the duration field would
 * be all zeros and the validator couldn't distinguish missed events from
 * zero-cost calls.
 *
 * Build: gcc -fPIC -shared fake_cudart.c -o libfake_cudart.so
 *
 * Caveats:
 *   - Signatures are simplified (most return int; real CUDA returns
 *     cudaError_t which is int-typed anyway). The tracer only reads
 *     PT_REGS_PARM_N at entry and PT_REGS_RC at return, so as long as
 *     argument positions match, things work.
 *   - Stream pointers are returned as small integers; the tracer treats
 *     them as opaque so this is fine.
 *   - This file is intentionally NOT linked against -lcuda; it's a
 *     drop-in API surface for symbol resolution only.
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Busy-wait for `target_ns` nanoseconds. We want the tracer to see a
 * non-trivial duration but we don't want the test to take long, so the
 * caller passes microsecond-scale targets.
 */
static void busy_wait_ns(uint64_t target_ns)
{
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    do {
        clock_gettime(CLOCK_MONOTONIC, &now);
    } while ((uint64_t)((now.tv_sec - start.tv_sec) * 1000000000ULL
                       + (now.tv_nsec - start.tv_nsec)) < target_ns);
}

/* ---- synchronous API ------------------------------------------------ */

int cudaMalloc(void **devPtr, size_t size)
{
    busy_wait_ns(20000);  /* ~20 µs — modest alloc */
    /* Hand back a fake device pointer keyed off the size so test
     * validators can sanity-check the ptr field if they want.
     */
    *devPtr = (void *)(uintptr_t)(0xD0000000UL + size);
    return 0;
}

int cudaFree(void *devPtr)
{
    (void)devPtr;
    busy_wait_ns(10000);
    return 0;
}

int cudaMemcpy(void *dst, const void *src, size_t count, int kind)
{
    (void)dst; (void)src; (void)kind;
    /* Sync memcpy is slow on purpose — that's the whole point of the
     * async variant the tracer was extended to capture.
     */
    busy_wait_ns(50000 + count / 10);  /* size-proportional */
    return 0;
}

int cudaLaunchKernel(const void *func, void *gridDim, void *blockDim,
                     void **args, size_t sharedMem, void *stream)
{
    (void)func; (void)gridDim; (void)blockDim; (void)args; (void)sharedMem; (void)stream;
    busy_wait_ns(15000);
    return 0;
}

int cudaDeviceSynchronize(void)
{
    busy_wait_ns(80000);
    return 0;
}

/* ---- async / stream API --------------------------------------------- */

int cudaMemcpyAsync(void *dst, const void *src, size_t count, int kind, void *stream)
{
    (void)dst; (void)src; (void)kind; (void)stream;
    /* Async returns fast — work is "queued" not "done". */
    busy_wait_ns(2000 + count / 100);
    return 0;
}

int cudaStreamSynchronize(void *stream)
{
    (void)stream;
    /* This is where the agent blocks; should look long on the timeline. */
    busy_wait_ns(120000);
    return 0;
}

static unsigned long next_stream = 0x57000001UL;  /* monotonic fake stream ids */
int cudaStreamCreate(void **pStream)
{
    busy_wait_ns(5000);
    *pStream = (void *)(uintptr_t)(next_stream++);
    return 0;
}

int cudaStreamDestroy(void *stream)
{
    (void)stream;
    busy_wait_ns(5000);
    return 0;
}

int cudaEventRecord(void *event, void *stream)
{
    (void)event; (void)stream;
    busy_wait_ns(1000);
    return 0;
}

int cudaEventSynchronize(void *event)
{
    (void)event;
    busy_wait_ns(60000);
    return 0;
}

int cudaEventQuery(void *event)
{
    (void)event;
    busy_wait_ns(500);
    return 0;
}

int cudaLaunchKernelExC(const void *config, const void *func, void **args)
{
    (void)config; (void)func; (void)args;
    busy_wait_ns(20000);
    return 0;
}

int cudaGraphLaunch(void *graphExec, void *stream)
{
    (void)graphExec; (void)stream;
    /* Graphs are the punchline: a single uprobe covers many real
     * kernels, so we make this duration noticeably longer than a
     * single kernel launch.
     */
    busy_wait_ns(200000);
    return 0;
}
