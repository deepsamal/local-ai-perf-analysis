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

static volatile bool exiting = false;

/* Stack trace map FD */
static int stack_map_fd = -1;
static int target_pid_for_stacks = 0;

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
        default: return "Unknown";
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

/* Simple symbol resolution: find library name for an address */
static int resolve_address_to_lib(int pid, __u64 addr, char *lib_name, size_t lib_name_len, __u64 *offset)
{
    char maps_file[64];
    snprintf(maps_file, sizeof(maps_file), "/proc/%d/maps", pid);
    
    FILE *f = fopen(maps_file, "r");
    if (!f) return -1;
    
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        __u64 start, end, file_offset;
        char perms[8], dev[16], inode[32];
        char path[256] = "";
        
        int n = sscanf(line, "%llx-%llx %s %llx %s %s %[^\n]",
                      &start, &end, perms, &file_offset, dev, inode, path);
        
        if (addr >= start && addr < end) {
            *offset = addr - start + file_offset;
            if (n >= 7 && path[0] != '\0') {
                /* Extract just the basename */
                char *basename = strrchr(path, '/');
                snprintf(lib_name, lib_name_len, "%s", basename ? basename + 1 : path);
            } else if (perms[0] == 'r' && perms[2] == 'x') {
                snprintf(lib_name, lib_name_len, "[exec]");
            } else {
                snprintf(lib_name, lib_name_len, "[anon]");
            }
            fclose(f);
            return 0;
        }
    }
    
    fclose(f);
    return -1;
}

/* Get stack trace and resolve to function/library names */
static void get_stack_info(int stack_id, int pid, char *output, size_t output_len)
{
    if (stack_id < 0 || stack_map_fd < 0) {
        output[0] = '\0';
        return;
    }
    
    __u64 stack[PERF_MAX_STACK_DEPTH];
    if (bpf_map_lookup_elem(stack_map_fd, &stack_id, stack) != 0) {
        output[0] = '\0';
        return;
    }
    
    /* Find first valid address and resolve it */
    char lib[128] = "unknown";
    __u64 offset = 0;
    for (int i = 0; i < PERF_MAX_STACK_DEPTH && stack[i] != 0; i++) {
        if (stack[i] != 0) {
            if (resolve_address_to_lib(pid, stack[i], lib, sizeof(lib), &offset) == 0) {
                snprintf(output, output_len, "%s+0x%llx", lib, offset);
            } else {
                snprintf(output, output_len, "0x%llx", stack[i]);
            }
            return;
        }
    }
    
    output[0] = '\0';
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
                
                /* Get stack trace info if available */
                char stack_info[512] = "";
                if (cpu->stack_id >= 0 && target_pid_for_stacks > 0) {
                    get_stack_info(cpu->stack_id, target_pid_for_stacks, stack_info, sizeof(stack_info));
                }
                
                /* Keep name consistent as "On-CPU" so Begin/End events match */
                fprintf(f, "    {\"name\": \"On-CPU\", \"cat\": \"cpu\", "
                        "\"ph\": \"B\", \"ts\": %.3f, \"pid\": %u, \"tid\": %u, "
                        "\"args\": {\"cpu\": %u, \"comm\": \"%s\"",
                        ts_us, cpu->pid, cpu->tid, cpu->cpu, cpu->comm);
                
                /* Add stack trace to args if available */
                if (stack_info[0]) {
                    fprintf(f, ", \"function\": \"%s\"", stack_info);
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
            /* GPU CUDA event - all on same thread, overlaps will stack vertically */
            struct cuda_event *gpu = &e->gpu;
            double dur_us = gpu->duration_ns / 1000.0;
            
            /* Put all GPU operations on a single virtual thread */
            __u32 gpu_virtual_tid = gpu->tid + 1000000;
            
            if (output_count > 0) fprintf(f, ",\n");
            fprintf(f, "    {\"name\": \"%s\", \"cat\": \"gpu\", "
                    "\"ph\": \"X\", \"ts\": %.3f, \"dur\": %.3f, "
                    "\"pid\": %u, \"tid\": %u, "
                    "\"args\": {\"ret\": %d, \"comm\": \"%s\"",
                    cuda_op_name(gpu->op_type), ts_us, dur_us,
                    gpu->pid, gpu_virtual_tid, gpu->ret_val, gpu->comm);
            
            /* Add operation-specific args */
            if (gpu->op_type == CUDA_OP_MALLOC || gpu->op_type == CUDA_OP_MEMCPY) {
                fprintf(f, ", \"size_bytes\": %llu", gpu->size);
                if (gpu->size >= 1024*1024*1024) {
                    fprintf(f, ", \"size\": \"%.2f GB\"", gpu->size / (1024.0*1024.0*1024.0));
                } else if (gpu->size >= 1024*1024) {
                    fprintf(f, ", \"size\": \"%.2f MB\"", gpu->size / (1024.0*1024.0));
                } else if (gpu->size >= 1024) {
                    fprintf(f, ", \"size\": \"%.2f KB\"", gpu->size / 1024.0);
                } else {
                    fprintf(f, ", \"size\": \"%llu B\"", gpu->size);
                }
            }
            if (gpu->op_type == CUDA_OP_FREE && gpu->ptr != 0) {
                fprintf(f, ", \"ptr\": \"0x%llx\"", gpu->ptr);
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
    printf("  Open in browser: chrome://tracing\n");
    printf("  Or upload to: https://ui.perfetto.dev\n");
    printf("  Note: GPU operations on single thread, overlaps shown stacked\n");
}

int main(int argc, char **argv)
{
    struct bpf_object *cpu_obj = NULL, *gpu_obj = NULL;
    struct bpf_link *sched_switch_link = NULL, *sched_wakeup_link = NULL;
    struct bpf_link *gpu_links[12] = {NULL};
    struct ring_buffer *cpu_rb = NULL, *gpu_rb = NULL;
    int err, cpu_map_fd, gpu_map_fd;
    int target_pid = 0;
    int duration = 10;
    const char *output_file = "trace.json";
    char *cuda_lib_path = NULL;
    
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
        } else {
            fprintf(stderr, "Usage: %s [--pid PID] [--duration SEC] [--output FILE] [--cuda-lib PATH]\n", argv[0]);
            return 1;
        }
    }
    
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
    
    /* Set target_pid filter for GPU tracing BEFORE loading */
    if (target_pid != 0) {
        struct bpf_map *rodata = bpf_object__find_map_by_name(gpu_obj, ".rodata");
        if (rodata) {
            bpf_map__set_initial_value(rodata, &target_pid, sizeof(target_pid));
        }
    }
    
    err = bpf_object__load(gpu_obj);
    if (err) {
        fprintf(stderr, "ERROR: failed to load GPU BPF object: %d\n", err);
        goto cleanup;
    }
    
    /* Attach CUDA uprobes */
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
    };
    
    int gpu_link_count = 0;
    for (int i = 0; i < sizeof(cuda_funcs) / sizeof(cuda_funcs[0]); i++) {
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
    for (int i = 0; i < 12; i++)
        bpf_link__destroy(gpu_links[i]);
    bpf_object__close(cpu_obj);
    bpf_object__close(gpu_obj);
    
    return 0;
}
