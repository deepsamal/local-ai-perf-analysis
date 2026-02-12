// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int ifindex_global = 0;
static int prog_fd_global = -1;

static void cleanup_xdp(void)
{
    if (ifindex_global > 0 && prog_fd_global >= 0) {
        bpf_xdp_detach(ifindex_global, XDP_FLAGS_SKB_MODE, NULL);
    }
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    int err, map_fd, ifindex;
    __u32 key = 0;
    __u64 count;
    const char *obj_path = "obj/count_packets.bpf.o";
    const char *ifname = "lo"; /* Default to loopback */

    if (argc > 1) {
        ifname = argv[1];
    }

    /* Get interface index */
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "ERROR: invalid interface %s\n", ifname);
        return 1;
    }

    /* Load BPF object */
    obj = bpf_object__open_file(obj_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: failed to load BPF object\n");
        goto cleanup;
    }

    /* Find XDP program */
    prog = bpf_object__find_program_by_name(obj, "xdp_count_packets");
    if (!prog) {
        fprintf(stderr, "ERROR: failed to find XDP program\n");
        goto cleanup;
    }

    /* Get program fd */
    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "ERROR: failed to get program fd\n");
        goto cleanup;
    }

    /* Try to attach in SKB (generic) mode first - more compatible */
    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        fprintf(stderr, "ERROR: failed to attach XDP program to %s: %d\n", ifname, err);
        goto cleanup;
    }
    
    printf("XDP program attached to %s in SKB mode\n", ifname);

    /* Get map file descriptor */
    map_fd = bpf_object__find_map_fd_by_name(obj, "packet_count");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: failed to find map\n");
        goto cleanup;
    }

    /* Store globals for cleanup */
    ifindex_global = ifindex;
    prog_fd_global = prog_fd;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    atexit(cleanup_xdp);

    printf("Counting packets on interface %s... Press Ctrl+C to exit.\n", ifname);

    /* Poll packet count every second */
    while (!exiting) {
        sleep(1);
        
        if (bpf_map_lookup_elem(map_fd, &key, &count) == 0) {
            printf("Packets: %llu\n", count);
        }
    }

cleanup:
    cleanup_xdp();
    bpf_object__close(obj);
    
    return err != 0;
}
