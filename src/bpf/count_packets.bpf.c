// SPDX-License-Identifier: GPL-2.0
#include "common.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

/* BPF map to store packet count */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} packet_count SEC(".maps");

/* XDP program to count packets */
SEC("xdp")
int xdp_count_packets(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *count;

    /* Lookup packet counter */
    count = bpf_map_lookup_elem(&packet_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    /* Pass packet through */
    return XDP_PASS;
}
