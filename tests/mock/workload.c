/* SPDX-License-Identifier: MIT */
/*
 * Deterministic CUDA-like workload that exercises every uprobe attach
 * point the tracer cares about. dlopen-s libfake_cudart.so and calls
 * each shimmed symbol in a fixed pattern; the unified_trace.py
 * validator asserts exact event counts against the pattern below.
 *
 * Build & run:
 *   gcc -O2 -ldl workload.c -o workload
 *   LD_LIBRARY_PATH=. ./workload --iters 100 --lib ./libfake_cudart.so
 *
 * Why dlopen and not direct linking: we want the tracer to attach to
 * the SAME on-disk file the workload actually calls into. If we linked
 * libfake_cudart.so statically, the symbols would be interposed and
 * uprobe attach-by-path would miss them.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Per-iteration event count produced by run_iter().
 * Bump this if you add/remove calls below — the validator reads it from
 * the workload's stderr summary line.
 */
#define EVENTS_PER_ITER 12

typedef int (*fn_malloc_t)(void **, size_t);
typedef int (*fn_free_t)(void *);
typedef int (*fn_memcpy_t)(void *, const void *, size_t, int);
typedef int (*fn_memcpy_async_t)(void *, const void *, size_t, int, void *);
typedef int (*fn_kernel_t)(const void *, void *, void *, void **, size_t, void *);
typedef int (*fn_kernel_ex_t)(const void *, const void *, void **);
typedef int (*fn_devsync_t)(void);
typedef int (*fn_strmsync_t)(void *);
typedef int (*fn_strmcreate_t)(void **);
typedef int (*fn_strmdestroy_t)(void *);
typedef int (*fn_evrec_t)(void *, void *);
typedef int (*fn_evsync_t)(void *);
typedef int (*fn_evquery_t)(void *);
typedef int (*fn_graphlaunch_t)(void *, void *);

struct cuda_syms {
    fn_malloc_t        cudaMalloc;
    fn_free_t          cudaFree;
    fn_memcpy_t        cudaMemcpy;
    fn_memcpy_async_t  cudaMemcpyAsync;
    fn_kernel_t        cudaLaunchKernel;
    fn_kernel_ex_t     cudaLaunchKernelExC;
    fn_devsync_t       cudaDeviceSynchronize;
    fn_strmsync_t      cudaStreamSynchronize;
    fn_strmcreate_t    cudaStreamCreate;
    fn_strmdestroy_t   cudaStreamDestroy;
    fn_evrec_t         cudaEventRecord;
    fn_evsync_t        cudaEventSynchronize;
    fn_evquery_t       cudaEventQuery;
    fn_graphlaunch_t   cudaGraphLaunch;
};

#define LOAD(sym) do { \
    s->sym = (typeof(s->sym))dlsym(h, #sym); \
    if (!s->sym) { fprintf(stderr, "missing symbol: %s\n", #sym); return -1; } \
} while (0)

static int load_syms(void *h, struct cuda_syms *s)
{
    LOAD(cudaMalloc);
    LOAD(cudaFree);
    LOAD(cudaMemcpy);
    LOAD(cudaMemcpyAsync);
    LOAD(cudaLaunchKernel);
    LOAD(cudaLaunchKernelExC);
    LOAD(cudaDeviceSynchronize);
    LOAD(cudaStreamSynchronize);
    LOAD(cudaStreamCreate);
    LOAD(cudaStreamDestroy);
    LOAD(cudaEventRecord);
    LOAD(cudaEventSynchronize);
    LOAD(cudaEventQuery);
    LOAD(cudaGraphLaunch);
    return 0;
}

/* One iteration emits exactly EVENTS_PER_ITER events in a fixed order.
 * The pattern mimics a typical agent step: stream create, async H2D,
 * kernel launch, stream sync (block), D2H async, then free.
 */
static void run_iter(const struct cuda_syms *s)
{
    void *d_a = NULL, *d_b = NULL;
    void *stream = NULL;
    void *evt = (void *)0xE5E47A1;  /* opaque event handle */
    char host_buf[256];
    memset(host_buf, 0xab, sizeof(host_buf));

    s->cudaStreamCreate(&stream);                                  /* 1 */
    s->cudaMalloc(&d_a, 4096);                                     /* 2 */
    s->cudaMalloc(&d_b, 4096);                                     /* 3 */
    s->cudaMemcpyAsync(d_a, host_buf, sizeof(host_buf), 1, stream);/* 4 */
    s->cudaLaunchKernel((void *)0x4144, (void *)1, (void *)1,
                        NULL, 0, stream);                          /* 5 */
    s->cudaEventRecord(evt, stream);                               /* 6 */
    s->cudaEventQuery(evt);                                        /* 7 */
    s->cudaStreamSynchronize(stream);                              /* 8 */
    s->cudaMemcpyAsync(host_buf, d_b, sizeof(host_buf), 2, stream);/* 9 */
    s->cudaFree(d_a);                                              /* 10 */
    s->cudaFree(d_b);                                              /* 11 */
    s->cudaStreamDestroy(stream);                                  /* 12 */
}

int main(int argc, char **argv)
{
    int iters = 50;
    const char *libpath = "./libfake_cudart.so";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--iters") && i + 1 < argc) {
            iters = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--lib") && i + 1 < argc) {
            libpath = argv[++i];
        } else {
            fprintf(stderr, "usage: %s [--iters N] [--lib PATH]\n", argv[0]);
            return 1;
        }
    }

    /* RTLD_NOW so missing symbols fail loudly, not at first call. */
    void *h = dlopen(libpath, RTLD_NOW);
    if (!h) {
        fprintf(stderr, "dlopen(%s) failed: %s\n", libpath, dlerror());
        return 2;
    }

    struct cuda_syms s = {0};
    if (load_syms(h, &s) != 0) {
        dlclose(h);
        return 3;
    }

    /* Print our pid first so the test driver can attach the tracer to
     * the right process without racing.
     */
    fprintf(stdout, "MOCK_WORKLOAD pid=%d iters=%d events_per_iter=%d total=%d\n",
            getpid(), iters, EVENTS_PER_ITER, iters * EVENTS_PER_ITER);
    fflush(stdout);

    /* Warmup window. The tracer attaches ~30 uprobes; each requires
     * opening libcudart.so + locating the symbol + perf_event_open,
     * which on a slow box can take 1–2 seconds total. We sleep here
     * so the workload doesn't sprint through its iters before the
     * probes are armed. The shell wrapper sleeps too, so total
     * attach window is ~3s.
     */
    fprintf(stderr, "MOCK_WORKLOAD warmup_start\n");
    sleep(3);
    fprintf(stderr, "MOCK_WORKLOAD warmup_done starting_iters\n");

    for (int i = 0; i < iters; i++) {
        run_iter(&s);
        /* Sprinkle a 1 ms inter-iter sleep so 100 iters take ~100 ms
         * of wall-clock + ~30 ms of in-CUDA-call busy-wait. That gives
         * the tracer plenty of polls to consume events even if a
         * couple of probes attach late.
         */
        usleep(1000);
    }

    fprintf(stderr, "MOCK_WORKLOAD done iters=%d total_events=%d\n",
            iters, iters * EVENTS_PER_ITER);

    dlclose(h);
    return 0;
}
