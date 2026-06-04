// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "common.h"
#include "blazesym_wrap.h"

static volatile bool exiting = false;

/* Stack trace map FD */
static int stack_map_fd = -1;
static int target_pid_for_stacks = 0;

/* blazesym symbolizer handle. NULL = symbolization disabled (build w/o
 * Rust toolchain or --no-symbolize flag). When NULL we fall back to the
 * old lib+offset format so the tracer still works.
 */
static bsw_symbolizer_t *symbolizer = NULL;
static int symbolize_enabled = 1;
static int max_stack_frames_in_json = 12; /* truncate JSON stacks to keep file size bounded */

/* Collected events */
#define MAX_EVENTS 100000
static struct unified_event {
    __u64 timestamp;
    int type; /* 0=CPU, 1=GPU */
    union {
        struct cpu_sched_event cpu;
        struct cuda_event gpu;
    };
} events[MAX_EVENTS];
static int event_count = 0;

static void sig_handler(int sig)
{
    exiting = true;
}

static const char* cuda_op_name(int op_type)
{
    switch (op_type) {
        case CUDA_OP_MALLOC: return "cudaMalloc";
        case CUDA_OP_FREE: return "cudaFree";
        case CUDA_OP_MEMCPY: return "cudaMemcpy";
        case CUDA_OP_LAUNCH_KERNEL: return "cudaLaunchKernel";
        case CUDA_OP_SYNC: return "cudaDeviceSynchronize";
        case CUDA_OP_MEMCPY_ASYNC: return "cudaMemcpyAsync";
        case CUDA_OP_STREAM_SYNC: return "cudaStreamSynchronize";
        case CUDA_OP_STREAM_CREATE: return "cudaStreamCreate";
        case CUDA_OP_STREAM_DESTROY: return "cudaStreamDestroy";
        case CUDA_OP_EVENT_RECORD: return "cudaEventRecord";
        case CUDA_OP_EVENT_SYNC: return "cudaEventSynchronize";
        case CUDA_OP_EVENT_QUERY: return "cudaEventQuery";
        case CUDA_OP_LAUNCH_KERNEL_EX: return "cudaLaunchKernelExC";
        case CUDA_OP_GRAPH_LAUNCH: return "cudaGraphLaunch";
        default: return "Unknown";
    }
}

/* Categorize ops for Chrome Tracing "cat" field. */
static const char* cuda_op_category(int op_type)
{
    switch (op_type) {
        case CUDA_OP_SYNC:
        case CUDA_OP_STREAM_SYNC:
        case CUDA_OP_EVENT_SYNC:
            return "gpu_sync";          /* CPU blocks here — interesting for stall analysis */
        case CUDA_OP_MEMCPY:
        case CUDA_OP_MEMCPY_ASYNC:
            return "gpu_xfer";          /* data movement */
        case CUDA_OP_LAUNCH_KERNEL:
        case CUDA_OP_LAUNCH_KERNEL_EX:
        case CUDA_OP_GRAPH_LAUNCH:
            return "gpu_compute";
        case CUDA_OP_MALLOC:
        case CUDA_OP_FREE:
            return "gpu_mem";
        default:
            return "gpu";
    }
}

static const char* sched_event_name(int event_type)
{
    switch (event_type) {
        case CPU_SCHED_ON: return "On-CPU";
        case CPU_SCHED_OFF: return "Off-CPU";
        case CPU_SCHED_WAKEUP: return "Wakeup";
        default: return "Unknown";
    }
}

static int handle_cpu_event(void *ctx, void *data, size_t data_sz)
{
    if (event_count >= MAX_EVENTS)
        return 0;
    
    struct cpu_sched_event *e = data;
    events[event_count].timestamp = e->timestamp;
    events[event_count].type = 0; /* CPU */
    events[event_count].cpu = *e;
    event_count++;
    
    return 0;
}

static int handle_gpu_event(void *ctx, void *data, size_t data_sz)
{
    if (event_count >= MAX_EVENTS)
        return 0;
    
    struct cuda_event *e = data;
    events[event_count].timestamp = e->timestamp;
    events[event_count].type = 1; /* GPU */
    events[event_count].gpu = *e;
    event_count++;
    
    return 0;
}

/* Escape a string for embedding in JSON. Conservatively handles the
 * characters that actually appear in symbol names (quote, backslash,
 * control characters). Truncates to dst_len-1 bytes.
 */
static void json_escape(char *dst, size_t dst_len, const char *src)
{
    size_t di = 0;
    if (dst_len == 0) return;
    for (size_t si = 0; src[si] && di + 2 < dst_len; si++) {
        unsigned char c = (unsigned char)src[si];
        if (c == '"' || c == '\\') {
            if (di + 3 >= dst_len) break;
            dst[di++] = '\\';
            dst[di++] = c;
        } else if (c < 0x20) {
            if (di + 7 >= dst_len) break;
            di += snprintf(dst + di, dst_len - di, "\\u%04x", c);
        } else {
            dst[di++] = c;
        }
    }
    dst[di] = '\0';
}

/* Pull stack addresses from the BPF stack map for the given stack_id.
 * Returns the number of valid (non-zero) addresses written into out[].
 */
static int read_stack_addrs(int stack_id, __u64 *out, int out_cap)
{
    if (stack_id < 0 || stack_map_fd < 0)
        return 0;

    __u64 stack[PERF_MAX_STACK_DEPTH];
    memset(stack, 0, sizeof(stack));
    if (bpf_map_lookup_elem(stack_map_fd, &stack_id, stack) != 0)
        return 0;

    int n = 0;
    for (int i = 0; i < PERF_MAX_STACK_DEPTH && n < out_cap; i++) {
        if (stack[i] == 0)
            break;
        out[n++] = stack[i];
    }
    return n;
}

/* Write a JSON array of resolved stack frames to `f` for the given
 * stack_id, attributed to `pid`. Emits exactly one JSON value (an
 * array). If symbolization is disabled or fails, falls back to a list
 * of raw hex addresses so the caller still has something to grep on.
 *
 * Format:
 *   [{"sym":"...", "file":"...", "line":123, "lib":"libfoo.so", "inlined":0}, ...]
 */
static void emit_stack_json(FILE *f, int stack_id, int pid)
{
    __u64 addrs[PERF_MAX_STACK_DEPTH];
    int n = read_stack_addrs(stack_id, addrs, PERF_MAX_STACK_DEPTH);
    if (n == 0) {
        fprintf(f, "[]");
        return;
    }
    if (n > max_stack_frames_in_json)
        n = max_stack_frames_in_json;

    if (!symbolize_enabled || symbolizer == NULL) {
        /* Fallback: raw addresses. Still useful for grep/manual addr2line. */
        fprintf(f, "[");
        for (int i = 0; i < n; i++) {
            fprintf(f, "%s{\"addr\":\"0x%llx\"}", i ? "," : "",
                    (unsigned long long)addrs[i]);
        }
        fprintf(f, "]");
        return;
    }

    /* blazesym can expand inlined frames, so allocate headroom. */
    int frame_cap = n * 4;
    struct bsw_frame *frames = calloc(frame_cap, sizeof(*frames));
    if (!frames) {
        fprintf(f, "[]");
        return;
    }

    size_t nout = bsw_resolve(symbolizer, (uint32_t)pid,
                              addrs, (size_t)n,
                              frames, (size_t)frame_cap);

    fprintf(f, "[");
    char esc_sym[BSW_STR_MAX * 2];
    char esc_file[BSW_STR_MAX * 2];
    char esc_lib[BSW_STR_MAX * 2];
    for (size_t i = 0; i < nout; i++) {
        json_escape(esc_sym, sizeof(esc_sym),
                    frames[i].sym[0] ? frames[i].sym : "??");
        json_escape(esc_file, sizeof(esc_file), frames[i].file);
        json_escape(esc_lib, sizeof(esc_lib), frames[i].lib);
        fprintf(f, "%s{\"sym\":\"%s\"", i ? "," : "", esc_sym);
        if (esc_file[0])
            fprintf(f, ",\"file\":\"%s\"", esc_file);
        if (frames[i].line)
            fprintf(f, ",\"line\":%u", frames[i].line);
        if (esc_lib[0])
            fprintf(f, ",\"lib\":\"%s\"", esc_lib);
        if (frames[i].inlined)
            fprintf(f, ",\"inlined\":1");
        fprintf(f, "}");
    }
    fprintf(f, "]");
    free(frames);
}

static int compare_events(const void *a, const void *b)
{
    const struct unified_event *ea = a;
    const struct unified_event *eb = b;
    if (ea->timestamp < eb->timestamp) return -1;
    if (ea->timestamp > eb->timestamp) return 1;
    return 0;
}

static void output_chrome_tracing_json(const char *filename)
{
    FILE *f = fopen(filename, "w");
    if (!f) {
        fprintf(stderr, "ERROR: Cannot open %s\n", filename);
        return;
    }
    
    /* Find minimum timestamp to normalize all events to start at t=0 */
    __u64 min_timestamp = UINT64_MAX;
    for (int i = 0; i < event_count; i++) {
        if (events[i].timestamp < min_timestamp) {
            min_timestamp = events[i].timestamp;
        }
    }
    printf("Normalizing timestamps: base=%llu ns (%.3f ms since boot)\n", 
           min_timestamp, min_timestamp / 1000000.0);
    
    /* Debug: count event types before processing */
    int on_count = 0, off_count = 0, wakeup_count = 0;
    for (int i = 0; i < event_count; i++) {
        if (events[i].type == 0) {
            if (events[i].cpu.event_type == CPU_SCHED_ON) on_count++;
            else if (events[i].cpu.event_type == CPU_SCHED_OFF) off_count++;
            else if (events[i].cpu.event_type == CPU_SCHED_WAKEUP) wakeup_count++;
        }
    }
    printf("Event counts: ON=%d, OFF=%d, WAKEUP=%d, GPU=%d\n", 
           on_count, off_count, wakeup_count, event_count - on_count - off_count - wakeup_count);
    
    fprintf(f, "{\n");
    fprintf(f, "  \"traceEvents\": [\n");
    
    /* Track thread states for duration events - use dynamic allocation to avoid stack overflow */
    /* Allocate large enough to handle high PIDs (up to 10 million) */
    __u64 *cpu_on_time = calloc(10000000, sizeof(__u64));
    if (!cpu_on_time) {
        fprintf(stderr, "ERROR: Failed to allocate memory for cpu_on_time tracking\n");
        fclose(f);
        return;
    }
    
    int output_count = 0; /* Track how many events we actually output */
    int thread_name_written = 0; /* Track if we've written thread name metadata */
    __u32 seen_pid = 0, seen_tid = 0;
    
    for (int i = 0; i < event_count; i++) {
        struct unified_event *e = &events[i];
        /* Normalize timestamp relative to first event and convert ns to us */
        double ts_us = (e->timestamp - min_timestamp) / 1000.0;
        int should_output = 1; /* Flag to track if we output this event */
        
        /* Add thread name metadata on first event */
        if (!thread_name_written && e->type == 0) {
            seen_pid = e->cpu.pid;
            seen_tid = e->cpu.tid;
            
            /* Add CPU thread name */
            if (output_count > 0) fprintf(f, ",\n");
            fprintf(f, "    {\"name\": \"thread_name\", \"ph\": \"M\", \"pid\": %u, \"tid\": %u, "
                    "\"args\": {\"name\": \"CPU [%s]\"}}", seen_pid, seen_tid, e->cpu.comm);
            output_count++;
            
            /* Add single GPU thread name */
            fprintf(f, ",\n");
            fprintf(f, "    {\"name\": \"thread_name\", \"ph\": \"M\", \"pid\": %u, \"tid\": %u, "
                    "\"args\": {\"name\": \"GPU (CUDA)\"}}", seen_pid, seen_tid + 1000000);
            output_count++;
            
            thread_name_written = 1;
        }
        
        if (e->type == 0) {
            /* CPU scheduling event */
            struct cpu_sched_event *cpu = &e->cpu;
            
            if (cpu->event_type == CPU_SCHED_ON) {
                /* Thread scheduled on CPU - start duration  */
                /* Bounds check to avoid segfault */
                if (cpu->tid < 10000000) {
                    cpu_on_time[cpu->tid] = e->timestamp;
                }

                if (output_count > 0) fprintf(f, ",\n");

                /* Keep name consistent as "On-CPU" so Begin/End events match */
                fprintf(f, "    {\"name\": \"On-CPU\", \"cat\": \"cpu\", "
                        "\"ph\": \"B\", \"ts\": %.3f, \"pid\": %u, \"tid\": %u, "
                        "\"args\": {\"cpu\": %u, \"comm\": \"%s\"",
                        ts_us, cpu->pid, cpu->tid, cpu->cpu, cpu->comm);

                /* Emit resolved stack as a structured array. The pid for
                 * symbolization is the event's own pid so we can attribute
                 * stacks from any process, not just the target.
                 */
                if (cpu->stack_id >= 0) {
                    fprintf(f, ", \"stack\": ");
                    emit_stack_json(f, cpu->stack_id, cpu->pid);
                }

                fprintf(f, "}}");
                output_count++;
            } else if (cpu->event_type == CPU_SCHED_OFF) {
                /* Thread switched off CPU - end duration */
                if (cpu->tid < 10000000 && cpu_on_time[cpu->tid] != 0) {
                    double dur_us = (e->timestamp - cpu_on_time[cpu->tid]) / 1000.0;
                    if (output_count > 0) fprintf(f, ",\n");
                    fprintf(f, "    {\"name\": \"On-CPU\", \"cat\": \"cpu\", "
                            "\"ph\": \"E\", \"ts\": %.3f, \"pid\": %u, \"tid\": %u, "
                            "\"args\": {\"duration_us\": %.3f, \"state\": %llu}}",
                            ts_us, cpu->pid, cpu->tid, dur_us, cpu->prev_state);
                    cpu_on_time[cpu->tid] = 0;
                    output_count++;
                } else {
                    should_output = 0;
                }
            } else if (cpu->event_type == CPU_SCHED_WAKEUP) {
                /* Instant event for wakeup */
                if (output_count > 0) fprintf(f, ",\n");
                fprintf(f, "    {\"name\": \"Wakeup\", \"cat\": \"cpu\", "
                        "\"ph\": \"i\", \"ts\": %.3f, \"pid\": %u, \"tid\": %u, "
                        "\"s\": \"t\"}",
                        ts_us, cpu->pid, cpu->tid);
                output_count++;
            } else {
                should_output = 0;
            }
        } else {
            /* GPU CUDA event.
             * Stream-aware layout: each unique stream gets its own row
             * inside the GPU "process" so async overlap is visible at a
             * glance in chrome://tracing. The base GPU virtual tid is
             * gpu->tid + 1_000_000; we add a stream-hash offset (0–255)
             * to spread streams across rows. Stream 0 (default) sits on
             * the base row.
             */
            struct cuda_event *gpu = &e->gpu;
            double dur_us = gpu->duration_ns / 1000.0;
            __u32 stream_offset = 0;
            if (gpu->stream_id != 0) {
                /* Mix the high and low halves of the pointer-valued
                 * stream id, then truncate to 8 bits.
                 */
                __u64 s = gpu->stream_id;
                stream_offset = (__u32)((s ^ (s >> 32)) & 0xFFu);
                if (stream_offset == 0) stream_offset = 1; /* keep default-stream row clean */
            }
            __u32 gpu_virtual_tid = gpu->tid + 1000000 + stream_offset;

            if (output_count > 0) fprintf(f, ",\n");
            fprintf(f, "    {\"name\": \"%s\", \"cat\": \"%s\", "
                    "\"ph\": \"X\", \"ts\": %.3f, \"dur\": %.3f, "
                    "\"pid\": %u, \"tid\": %u, "
                    "\"args\": {\"ret\": %d, \"comm\": \"%s\"",
                    cuda_op_name(gpu->op_type), cuda_op_category(gpu->op_type),
                    ts_us, dur_us,
                    gpu->pid, gpu_virtual_tid, gpu->ret_val, gpu->comm);

            /* Always emit stream_id when non-zero so Perfetto's filter UI
             * can group by stream.
             */
            if (gpu->stream_id != 0)
                fprintf(f, ", \"stream_id\": \"0x%llx\"",
                        (unsigned long long)gpu->stream_id);

            /* Mark async ops explicitly so a viewer / downstream tool
             * can compute overlap metrics without re-deriving from name.
             */
            if (gpu->flags & CUDA_EV_FLAG_ASYNC)
                fprintf(f, ", \"async\": true");

            /* Size-bearing ops */
            if (gpu->op_type == CUDA_OP_MALLOC ||
                gpu->op_type == CUDA_OP_MEMCPY ||
                gpu->op_type == CUDA_OP_MEMCPY_ASYNC) {
                fprintf(f, ", \"size_bytes\": %llu", (unsigned long long)gpu->size);
                if (gpu->size >= 1024ULL*1024ULL*1024ULL) {
                    fprintf(f, ", \"size\": \"%.2f GB\"", gpu->size / (1024.0*1024.0*1024.0));
                } else if (gpu->size >= 1024*1024) {
                    fprintf(f, ", \"size\": \"%.2f MB\"", gpu->size / (1024.0*1024.0));
                } else if (gpu->size >= 1024) {
                    fprintf(f, ", \"size\": \"%.2f KB\"", gpu->size / 1024.0);
                } else {
                    fprintf(f, ", \"size\": \"%llu B\"", (unsigned long long)gpu->size);
                }
            }
            if (gpu->op_type == CUDA_OP_FREE && gpu->ptr != 0) {
                fprintf(f, ", \"ptr\": \"0x%llx\"", (unsigned long long)gpu->ptr);
            }

            /* The novel bit: attribute this async submission to the agent
             * code that initiated it. Only present when we sampled a stack
             * AND the user enabled symbolization.
             */
            if (gpu->stack_id >= 0) {
                fprintf(f, ", \"stack\": ");
                emit_stack_json(f, gpu->stack_id, gpu->pid);
            }

            fprintf(f, "}}");
            output_count++;
        }
    }
    
    fprintf(f, "\n  ],\n");
    fprintf(f, "  \"displayTimeUnit\": \"ms\",\n");
    fprintf(f, "  \"metadata\": {\n");
    fprintf(f, "    \"event_count\": %d,\n", event_count);
    fprintf(f, "    \"tool\": \"ebpf-unified-trace\"\n");
    fprintf(f, "  }\n");
    fprintf(f, "}\n");
    
    free(cpu_on_time);
    fclose(f);
    printf("\n✓ Chrome Tracing JSON written to: %s\n", filename);
    printf("  Open in browser: chrome://tracing  (or https://ui.perfetto.dev)\n");
    printf("  Tip: GPU events are spread across per-stream rows so async\n"
           "       overlap is visible at a glance. Look for non-overlapping\n"
           "       gpu_compute rows below a long gpu_sync row to spot stalls.\n");
}

int main(int argc, char **argv)
{
    struct bpf_object *cpu_obj = NULL, *gpu_obj = NULL;
    struct bpf_link *sched_switch_link = NULL, *sched_wakeup_link = NULL;
    /* Sized for the full CUDA uprobe set (14 ops × 2 entry+return). */
    struct bpf_link *gpu_links[32] = {NULL};
    struct ring_buffer *cpu_rb = NULL, *gpu_rb = NULL;
    int err, cpu_map_fd, gpu_map_fd;
    int target_pid = 0;
    int duration = 10;
    const char *output_file = "trace.json";
    char *cuda_lib_path = NULL;
    int capture_stacks_cli = 1;          /* default ON; --no-stacks to disable */
    int symbolize_cli = 1;               /* default ON; --no-symbolize to disable */
    int sample_period_async = 8;         /* 1-in-8 by default for async ops */
    int sample_period_sync = 1;          /* every sync op by default */

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
            target_pid = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            duration = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "--cuda-lib") == 0 && i + 1 < argc) {
            cuda_lib_path = argv[++i];
        } else if (strcmp(argv[i], "--no-stacks") == 0) {
            capture_stacks_cli = 0;
        } else if (strcmp(argv[i], "--no-symbolize") == 0) {
            symbolize_cli = 0;
        } else if (strcmp(argv[i], "--stack-sample-async") == 0 && i + 1 < argc) {
            sample_period_async = atoi(argv[++i]);
            if (sample_period_async <= 0) sample_period_async = 1;
        } else if (strcmp(argv[i], "--stack-sample-sync") == 0 && i + 1 < argc) {
            sample_period_sync = atoi(argv[++i]);
            if (sample_period_sync <= 0) sample_period_sync = 1;
        } else if (strcmp(argv[i], "--max-stack-frames") == 0 && i + 1 < argc) {
            max_stack_frames_in_json = atoi(argv[++i]);
            if (max_stack_frames_in_json <= 0) max_stack_frames_in_json = 12;
        } else {
            fprintf(stderr,
                    "Usage: %s [--pid PID] [--duration SEC] [--output FILE]\n"
                    "          [--cuda-lib PATH] [--no-stacks] [--no-symbolize]\n"
                    "          [--stack-sample-async N] [--stack-sample-sync N]\n"
                    "          [--max-stack-frames N]\n",
                    argv[0]);
            return 1;
        }
    }
    symbolize_enabled = symbolize_cli;
    
    if (!cuda_lib_path) {
        /* Try common paths */
        const char *paths[] = {
            "/usr/local/cuda/lib64/libcudart.so",
            "/usr/local/cuda-12.6/targets/x86_64-linux/lib/libcudart.so.12",
        };
        for (int i = 0; i < sizeof(paths)/sizeof(paths[0]); i++) {
            if (access(paths[i], F_OK) == 0) {
                cuda_lib_path = (char *)paths[i];
                break;
            }
        }
    }
    
    if (!cuda_lib_path) {
        fprintf(stderr, "ERROR: CUDA library not found. Specify with --cuda-lib\n");
        return 1;
    }
    
    printf("Unified CPU+GPU Tracing\n");
    printf("=======================\n");
    if (target_pid) {
        printf("Target PID: %d\n", target_pid);
    } else {
        printf("Target PID: ALL\n");
    }
    printf("Duration: %d seconds\n", duration);
    printf("CUDA library: %s\n", cuda_lib_path);
    printf("Output: %s\n\n", output_file);
    
    /* Enable libbpf logging for debugging */
    libbpf_set_print(NULL);
    
    /* Load CPU scheduling BPF program */
    cpu_obj = bpf_object__open_file("obj/trace_cpu_sched.bpf.o", NULL);
    if (libbpf_get_error(cpu_obj)) {
        fprintf(stderr, "ERROR: failed to open CPU BPF object\n");
        goto cleanup;
    }
    
    /* Set target_pid filter for CPU tracing BEFORE loading */
    if (target_pid != 0) {
        struct bpf_map *rodata = bpf_object__find_map_by_name(cpu_obj, ".rodata");
        if (rodata) {
            bpf_map__set_initial_value(rodata, &target_pid, sizeof(target_pid));
        }
    }
    
    err = bpf_object__load(cpu_obj);
    if (err) {
        fprintf(stderr, "ERROR: failed to load CPU BPF object: %d\n", err);
        goto cleanup;
    }
    
    /* Get stack traces map for symbol resolution */
    struct bpf_map *stack_map = bpf_object__find_map_by_name(cpu_obj, "stack_traces");
    if (stack_map) {
        stack_map_fd = bpf_map__fd(stack_map);
        target_pid_for_stacks = target_pid;
        printf("✓ Stack trace collection enabled\n");
    } else {
        fprintf(stderr, "WARNING: stack_traces map not found\n");
    }
    
    /* Attach CPU scheduling tracepoints */
    struct bpf_program *prog;
    prog = bpf_object__find_program_by_name(cpu_obj, "trace_sched_switch");
    if (prog) {
        sched_switch_link = bpf_program__attach(prog);
        if (!libbpf_get_error(sched_switch_link)) {
            printf("✓ Attached sched_switch tracepoint\n");
        } else {
            fprintf(stderr, "WARNING: Failed to attach sched_switch\n");
        }
    } else {
        fprintf(stderr, "WARNING: sched_switch program not found\n");
    }
    
    prog = bpf_object__find_program_by_name(cpu_obj, "trace_sched_wakeup");
    if (prog) {
        sched_wakeup_link = bpf_program__attach(prog);
        if (!libbpf_get_error(sched_wakeup_link)) {
            printf("✓ Attached sched_wakeup tracepoint\n");
        } else {
            fprintf(stderr, "WARNING: Failed to attach sched_wakeup\n");
        }
    } else {
        fprintf(stderr, "WARNING: sched_wakeup program not found\n");
    }
    
    /* Load GPU CUDA BPF program */
    gpu_obj = bpf_object__open_file("obj/trace_cuda.bpf.o", NULL);
    if (libbpf_get_error(gpu_obj)) {
        fprintf(stderr, "ERROR: failed to open GPU BPF object\n");
        goto cleanup;
    }
    
    /* Configure GPU BPF .rodata knobs BEFORE loading.
     *
     * This struct MUST match `struct cuda_tracer_cfg` in trace_cuda.bpf.c
     * exactly. We use a single struct (rather than separate variables)
     * because clang for BPF reorders independent globals by size to pack
     * .rodata tightly, which makes any external layout assumption fragile.
     * A single struct uses ordinary C layout rules — predictable on both
     * sides.
     */
    struct cuda_tracer_cfg {
        __u32 target_pid;
        __u32 sample_period_sync;
        __u32 sample_period_async;
        __u8  capture_stacks;
        __u8  _pad[3];
    };
    struct cuda_tracer_cfg gpu_cfg = {
        .target_pid          = (__u32)target_pid,
        .sample_period_sync  = (__u32)sample_period_sync,
        .sample_period_async = (__u32)sample_period_async,
        .capture_stacks      = (__u8)capture_stacks_cli,
    };
    /* Find the .rodata map by its actual libbpf-assigned name. Newer
     * libbpf prefixes the section with the object name (e.g.
     * "trace_cu.rodata") so a plain ".rodata" lookup fails silently.
     * Fall back to scanning all maps if the literal name isn't found.
     */
    struct bpf_map *gpu_rodata = bpf_object__find_map_by_name(gpu_obj, ".rodata");
    if (!gpu_rodata) {
        struct bpf_map *m;
        bpf_object__for_each_map(m, gpu_obj) {
            const char *name = bpf_map__name(m);
            if (name && strstr(name, ".rodata")) {
                gpu_rodata = m;
                break;
            }
        }
    }
    if (gpu_rodata) {
        size_t actual_sz = bpf_map__value_size(gpu_rodata);
        if (actual_sz != sizeof(gpu_cfg)) {
            fprintf(stderr,
                    "WARNING: GPU .rodata size mismatch (kernel=%zu, user=%zu); "
                    "PID filter and stack sampling may be ignored.\n",
                    actual_sz, sizeof(gpu_cfg));
        }
        int rc = bpf_map__set_initial_value(gpu_rodata, &gpu_cfg, sizeof(gpu_cfg));
        if (rc) {
            fprintf(stderr, "WARNING: failed to set GPU .rodata: %d\n", rc);
        }
    } else {
        fprintf(stderr, "WARNING: GPU .rodata map not found; using defaults\n");
    }

    err = bpf_object__load(gpu_obj);
    if (err) {
        fprintf(stderr, "ERROR: failed to load GPU BPF object: %d\n", err);
        goto cleanup;
    }
    
    /* Attach CUDA uprobes. Failure for any single function is non-fatal
     * — newer ops (cudaLaunchKernelExC, cudaGraphLaunch) may be absent
     * in older libcudart and we still want a useful tracer.
     */
    struct {
        const char *func_name;
        const char *probe_name;
    } cuda_funcs[] = {
        {"cudaMalloc", "trace_cuda_malloc_entry"},
        {"cudaMalloc", "trace_cuda_malloc_return"},
        {"cudaFree", "trace_cuda_free_entry"},
        {"cudaFree", "trace_cuda_free_return"},
        {"cudaMemcpy", "trace_cuda_memcpy_entry"},
        {"cudaMemcpy", "trace_cuda_memcpy_return"},
        {"cudaLaunchKernel", "trace_cuda_launch_entry"},
        {"cudaLaunchKernel", "trace_cuda_launch_return"},
        {"cudaDeviceSynchronize", "trace_cuda_sync_entry"},
        {"cudaDeviceSynchronize", "trace_cuda_sync_return"},
        /* Async / stream-aware (new) */
        {"cudaMemcpyAsync", "trace_cuda_memcpy_async_entry"},
        {"cudaMemcpyAsync", "trace_cuda_memcpy_async_return"},
        {"cudaStreamSynchronize", "trace_cuda_stream_sync_entry"},
        {"cudaStreamSynchronize", "trace_cuda_stream_sync_return"},
        {"cudaStreamCreate", "trace_cuda_stream_create_entry"},
        {"cudaStreamCreate", "trace_cuda_stream_create_return"},
        {"cudaStreamDestroy", "trace_cuda_stream_destroy_entry"},
        {"cudaStreamDestroy", "trace_cuda_stream_destroy_return"},
        {"cudaEventRecord", "trace_cuda_event_record_entry"},
        {"cudaEventRecord", "trace_cuda_event_record_return"},
        {"cudaEventSynchronize", "trace_cuda_event_sync_entry"},
        {"cudaEventSynchronize", "trace_cuda_event_sync_return"},
        {"cudaEventQuery", "trace_cuda_event_query_entry"},
        {"cudaEventQuery", "trace_cuda_event_query_return"},
        {"cudaLaunchKernelExC", "trace_cuda_launch_ex_entry"},
        {"cudaLaunchKernelExC", "trace_cuda_launch_ex_return"},
        {"cudaGraphLaunch", "trace_cuda_graph_launch_entry"},
        {"cudaGraphLaunch", "trace_cuda_graph_launch_return"},
    };
    
    int gpu_link_count = 0;
    const int gpu_links_cap = (int)(sizeof(gpu_links) / sizeof(gpu_links[0]));
    for (int i = 0; i < (int)(sizeof(cuda_funcs) / sizeof(cuda_funcs[0])); i++) {
        if (gpu_link_count >= gpu_links_cap) {
            fprintf(stderr, "WARNING: gpu_links[] full; %d more probes skipped\n",
                    (int)(sizeof(cuda_funcs)/sizeof(cuda_funcs[0])) - i);
            break;
        }
        prog = bpf_object__find_program_by_name(gpu_obj, cuda_funcs[i].probe_name);
        if (!prog) continue;

        bool is_retprobe = strstr(cuda_funcs[i].probe_name, "return") != NULL;
        LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,
            .func_name = cuda_funcs[i].func_name,
            .retprobe = is_retprobe,
        );

        gpu_links[gpu_link_count] = bpf_program__attach_uprobe_opts(
            prog, -1, cuda_lib_path, 0, &uprobe_opts);

        if (!libbpf_get_error(gpu_links[gpu_link_count]))
            gpu_link_count++;
    }
    printf("✓ Attached %d CUDA uprobes\n", gpu_link_count);

    /* Initialize symbolizer. Safe to call even if --no-symbolize is set;
     * we just skip the bsw_resolve path at JSON-emit time.
     */
    if (symbolize_enabled) {
        symbolizer = bsw_new();
        if (!symbolizer) {
            fprintf(stderr, "WARNING: bsw_new() failed; falling back to raw addresses in JSON output\n");
            symbolize_enabled = 0;
        } else {
            char ver[64] = "?";
            bsw_version(ver, sizeof(ver));
            printf("✓ blazesym symbolizer ready (v%s)\n", ver);
        }
    } else {
        printf("ℹ blazesym symbolization disabled (--no-symbolize)\n");
    }
    if (!capture_stacks_cli) {
        printf("ℹ stack capture disabled (--no-stacks); stacks will be omitted\n");
    } else {
        printf("ℹ stack sampling: sync=1/%d  async=1/%d  (use --stack-sample-{sync,async} to tune)\n",
               sample_period_sync, sample_period_async);
    }
    
    /* Set up ring buffers */
    cpu_map_fd = bpf_object__find_map_fd_by_name(cpu_obj, "cpu_events");
    if (cpu_map_fd < 0) {
        fprintf(stderr, "ERROR: failed to find cpu_events map\n");
        goto cleanup;
    }
    
    cpu_rb = ring_buffer__new(cpu_map_fd, handle_cpu_event, NULL, NULL);
    if (!cpu_rb) {
        fprintf(stderr, "ERROR: failed to create CPU ring buffer\n");
        goto cleanup;
    }
    
    gpu_map_fd = bpf_object__find_map_fd_by_name(gpu_obj, "cuda_events");
    if (gpu_map_fd < 0) {
        fprintf(stderr, "ERROR: failed to find cuda_events map\n");
        goto cleanup;
    }
    
    gpu_rb = ring_buffer__new(gpu_map_fd, handle_gpu_event, NULL, NULL);
    if (!gpu_rb) {
        fprintf(stderr, "ERROR: failed to create GPU ring buffer\n");
        goto cleanup;
    }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGALRM, sig_handler);
    
    alarm(duration);
    
    printf("\nTracing for %d seconds... Press Ctrl+C to stop early.\n\n", duration);
    
    /* Poll for events */
    while (!exiting) {
        err = ring_buffer__poll(cpu_rb, 10);
        if (err == -EINTR) break;
        
        err = ring_buffer__poll(gpu_rb, 10);
        if (err == -EINTR) break;
    }
    
    printf("\nCollected %d events. Processing...\n", event_count);
    
    /* Sort events by timestamp */
    qsort(events, event_count, sizeof(struct unified_event), compare_events);
    
    /* Output Chrome Tracing JSON */
    output_chrome_tracing_json(output_file);
    
cleanup:
    ring_buffer__free(cpu_rb);
    ring_buffer__free(gpu_rb);
    bpf_link__destroy(sched_switch_link);
    bpf_link__destroy(sched_wakeup_link);
    for (int i = 0; i < (int)(sizeof(gpu_links)/sizeof(gpu_links[0])); i++)
        bpf_link__destroy(gpu_links[i]);
    bpf_object__close(cpu_obj);
    bpf_object__close(gpu_obj);
    if (symbolizer) {
        bsw_free(symbolizer);
        symbolizer = NULL;
    }

    return 0;
}
