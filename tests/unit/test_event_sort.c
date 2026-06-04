/* SPDX-License-Identifier: MIT */
/*
 * Unit test for the unified_event timestamp comparator.
 *
 * unified_trace.c calls qsort over unified_event entries before emitting
 * Chrome JSON. The comparator must produce a stable, ascending order
 * even when CPU and GPU events arrive interleaved from two ring buffers.
 *
 * We re-declare the comparator and minimal struct here rather than
 * including unified_trace.c (which would drag in libbpf). This is the
 * documented "test the algorithm, not the binary" pattern.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

/* Minimal mirror of the relevant fields. The real struct embeds full
 * cpu/gpu event structs in a union, but the comparator only touches
 * timestamp + type, so this is sufficient.
 */
struct ue {
    uint64_t timestamp;
    int type;
};

/* Copied verbatim from unified_trace.c compare_events(). */
static int compare_events(const void *a, const void *b)
{
    const struct ue *ea = a;
    const struct ue *eb = b;
    if (ea->timestamp < eb->timestamp) return -1;
    if (ea->timestamp > eb->timestamp) return 1;
    return 0;
}

static void check_sorted(struct ue *arr, int n)
{
    for (int i = 1; i < n; i++) {
        if (arr[i].timestamp < arr[i-1].timestamp) {
            fprintf(stderr, "FAIL: not sorted at index %d (%llu < %llu)\n",
                    i, (unsigned long long)arr[i].timestamp,
                    (unsigned long long)arr[i-1].timestamp);
            exit(1);
        }
    }
}

int main(void)
{
    /* Case 1: already sorted */
    struct ue a[] = { {10, 0}, {20, 1}, {30, 0}, {40, 1} };
    qsort(a, 4, sizeof(struct ue), compare_events);
    check_sorted(a, 4);
    assert(a[0].timestamp == 10);
    assert(a[3].timestamp == 40);

    /* Case 2: reverse order */
    struct ue b[] = { {400, 0}, {300, 1}, {200, 0}, {100, 1} };
    qsort(b, 4, sizeof(struct ue), compare_events);
    check_sorted(b, 4);
    assert(b[0].timestamp == 100);
    assert(b[3].timestamp == 400);

    /* Case 3: equal timestamps (CPU + GPU events at same ns) — order
     * between equal-timestamp entries is undefined but the resulting
     * array must still be monotonic, which check_sorted verifies.
     */
    struct ue c[] = { {500, 0}, {500, 1}, {500, 0}, {500, 1} };
    qsort(c, 4, sizeof(struct ue), compare_events);
    check_sorted(c, 4);

    /* Case 4: large array — exercise qsort's recursion */
    enum { N = 10000 };
    struct ue *big = malloc(N * sizeof(struct ue));
    assert(big);
    for (int i = 0; i < N; i++) {
        big[i].timestamp = (uint64_t)((N - i) * 7919U);
        big[i].type = i & 1;
    }
    qsort(big, N, sizeof(struct ue), compare_events);
    check_sorted(big, N);
    free(big);

    /* Case 5: high-bit timestamps (eBPF gives ns since boot — easily
     * fits in 64 bits but exceeds 32 bits within minutes of uptime).
     */
    struct ue d[] = {
        {0xFFFFFFFF00000000ULL, 0},
        {0xFFFFFFFF00000001ULL, 1},
        {0xFFFFFFFE00000000ULL, 0},
    };
    qsort(d, 3, sizeof(struct ue), compare_events);
    check_sorted(d, 3);
    assert(d[0].timestamp == 0xFFFFFFFE00000000ULL);

    printf("OK test_event_sort: 5 cases passed\n");
    return 0;
}
