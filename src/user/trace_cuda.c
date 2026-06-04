// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "common.h"

static volatile bool exiting = false;

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

static void print_size_human(unsigned long long size)
{
    if (size < 1024) {
        printf("%llu B", size);
    } else if (size < 1024 * 1024) {
        printf("%.2f KB", size / 1024.0);
    } else if (size < 1024 * 1024 * 1024) {
        printf("%.2f MB", size / (1024.0 * 1024.0));
    } else {
        printf("%.2f GB", size / (1024.0 * 1024.0 * 1024.0));
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct cuda_event *e = data;
    double duration_ms = e->duration_ns / 1000000.0;
    
    printf("%lld.%06lld %-7d %-7d %-16s %-22s ",
           e->timestamp / 1000000000,
           (e->timestamp % 1000000000) / 1000,
           e->pid,
           e->tid,
           e->comm,
           cuda_op_name(e->op_type));
    
    /* Print operation-specific details */
    switch (e->op_type) {
        case CUDA_OP_MALLOC:
            printf("size=");
            print_size_human(e->size);
            break;
        case CUDA_OP_FREE:
            printf("ptr=0x%llx", (unsigned long long)e->ptr);
            break;
        case CUDA_OP_MEMCPY:
            printf("size=");
            print_size_human(e->size);
            break;
        case CUDA_OP_MEMCPY_ASYNC:
            printf("size=");
            print_size_human(e->size);
            printf(" stream=0x%llx", (unsigned long long)e->stream_id);
            break;
        case CUDA_OP_LAUNCH_KERNEL:
            printf("kernel_launch func=0x%llx", (unsigned long long)e->ptr);
            break;
        case CUDA_OP_LAUNCH_KERNEL_EX:
            printf("kernel_launch_ex");
            break;
        case CUDA_OP_GRAPH_LAUNCH:
            printf("graph_launch stream=0x%llx", (unsigned long long)e->stream_id);
            break;
        case CUDA_OP_SYNC:
            printf("device_sync");
            break;
        case CUDA_OP_STREAM_SYNC:
            printf("stream_sync stream=0x%llx", (unsigned long long)e->stream_id);
            break;
        case CUDA_OP_STREAM_CREATE:
            printf("stream_create");
            break;
        case CUDA_OP_STREAM_DESTROY:
            printf("stream_destroy stream=0x%llx", (unsigned long long)e->stream_id);
            break;
        case CUDA_OP_EVENT_RECORD:
            printf("event_record event=0x%llx stream=0x%llx",
                   (unsigned long long)e->ptr, (unsigned long long)e->stream_id);
            break;
        case CUDA_OP_EVENT_SYNC:
            printf("event_sync event=0x%llx", (unsigned long long)e->ptr);
            break;
        case CUDA_OP_EVENT_QUERY:
            printf("event_query event=0x%llx", (unsigned long long)e->ptr);
            break;
    }

    printf(" duration=%.3f ms ret=%d", duration_ms, e->ret_val);
    if (e->stack_id >= 0)
        printf(" stack_id=%d", e->stack_id);
    printf("\n");
    
    return 0;
}

static char* find_cuda_library(void)
{
    const char *paths[] = {
        "/usr/local/cuda/lib64/libcudart.so",
        "/usr/lib/x86_64-linux-gnu/libcudart.so",
        "/usr/lib64/libcudart.so",
        "/usr/lib/libcudart.so",
    };
    
    for (int i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        if (access(paths[i], F_OK) == 0) {
            return strdup(paths[i]);
        }
    }
    
    return NULL;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    /* Sized for the full set of entry+return probes (14 ops × 2). */
    struct bpf_link *links[32] = {NULL};
    struct ring_buffer *rb = NULL;
    int err, map_fd, link_idx = 0;
    const char *obj_path = "obj/trace_cuda.bpf.o";
    char *cuda_lib_path = NULL;
    
    /* Find CUDA library */
    if (argc > 1) {
        cuda_lib_path = strdup(argv[1]);
    } else {
        cuda_lib_path = find_cuda_library();
    }
    
    if (!cuda_lib_path) {
        fprintf(stderr, "ERROR: CUDA library not found.\n");
        fprintf(stderr, "Usage: %s [path_to_libcudart.so]\n", argv[0]);
        fprintf(stderr, "\nSearched in:\n");
        fprintf(stderr, "  /usr/local/cuda/lib64/libcudart.so\n");
        fprintf(stderr, "  /usr/lib/x86_64-linux-gnu/libcudart.so\n");
        fprintf(stderr, "  /usr/lib64/libcudart.so\n");
        fprintf(stderr, "  /usr/lib/libcudart.so\n");
        return 1;
    }
    
    printf("Using CUDA library: %s\n", cuda_lib_path);

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(NULL);

    /* Load BPF object file */
    obj = bpf_object__open_file(obj_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: failed to open BPF object: %s\n", obj_path);
        free(cuda_lib_path);
        return 1;
    }

    /* Load BPF programs into kernel */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    /* Attach uprobes for CUDA functions.
     * Order matters only for log readability — attach failures for any
     * single function are non-fatal so users on older CUDA versions
     * that lack newer symbols (e.g. cudaLaunchKernelExC) still get
     * a working tracer for the symbols that do exist.
     */
    struct {
        const char *func_name;
        const char *probe_name;
    } cuda_funcs[] = {
        /* Synchronous ops (original) */
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
        /* Async / stream-aware ops (added for AI-agent perf analysis) */
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
    
    for (int i = 0; i < sizeof(cuda_funcs) / sizeof(cuda_funcs[0]); i++) {
        struct bpf_program *prog;
        bool is_retprobe = strstr(cuda_funcs[i].probe_name, "return") != NULL;
        
        prog = bpf_object__find_program_by_name(obj, cuda_funcs[i].probe_name);
        if (!prog) {
            fprintf(stderr, "WARNING: failed to find program %s\n", 
                    cuda_funcs[i].probe_name);
            continue;
        }
        
        LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,
            .func_name = cuda_funcs[i].func_name,
            .retprobe = is_retprobe,
        );
        
        links[link_idx] = bpf_program__attach_uprobe_opts(
            prog, -1, cuda_lib_path, 0, &uprobe_opts);
        
        if (libbpf_get_error(links[link_idx])) {
            fprintf(stderr, "WARNING: failed to attach uprobe %s to %s\n",
                    cuda_funcs[i].probe_name, cuda_funcs[i].func_name);
            links[link_idx] = NULL;
        } else {
            link_idx++;
        }
    }
    
    if (link_idx == 0) {
        fprintf(stderr, "ERROR: no uprobes attached successfully\n");
        goto cleanup;
    }
    
    printf("Successfully attached %d uprobes\n", link_idx);

    /* Set up ring buffer for receiving events */
    map_fd = bpf_object__find_map_fd_by_name(obj, "cuda_events");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: failed to find cuda_events map\n");
        goto cleanup;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ERROR: failed to create ring buffer\n");
        goto cleanup;
    }

    /* Set up signal handler */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("\nTracing CUDA operations... Press Ctrl+C to exit.\n\n");
    printf("%-19s %-7s %-7s %-16s %-22s %s\n",
           "TIMESTAMP", "PID", "TID", "COMM", "OPERATION", "DETAILS");

    /* Poll for events */
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "ERROR: polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    for (int i = 0; i < (int)(sizeof(links)/sizeof(links[0])); i++) {
        bpf_link__destroy(links[i]);
    }
    bpf_object__close(obj);
    free(cuda_lib_path);

    return err != 0;
}
