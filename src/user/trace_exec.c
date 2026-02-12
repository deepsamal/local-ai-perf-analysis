// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "common.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct exec_event *e = data;
    
    printf("PID: %-7d UID: %-7d COMM: %-16s FILENAME: %s\n",
           e->pid, e->uid, e->comm, e->filename);
    
    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct ring_buffer *rb = NULL;
    int err, map_fd;
    const char *obj_path = "obj/trace_exec.bpf.o";

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(NULL);

    /* Load BPF object file */
    obj = bpf_object__open_file(obj_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: failed to open BPF object: %s\n", obj_path);
        return 1;
    }

    /* Load BPF programs into kernel */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    /* Find and attach BPF program */
    prog = bpf_object__find_program_by_name(obj, "trace_execve");
    if (!prog) {
        fprintf(stderr, "ERROR: failed to find BPF program\n");
        goto cleanup;
    }

    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: failed to attach BPF program\n");
        link = NULL;
        goto cleanup;
    }

    /* Set up ring buffer for receiving events */
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: failed to find events map\n");
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

    printf("Tracing execve() calls... Press Ctrl+C to exit.\n");
    printf("%-7s %-7s %-16s %s\n", "PID", "UID", "COMM", "FILENAME");

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
    bpf_link__destroy(link);
    bpf_object__close(obj);
    
    return err != 0;
}
