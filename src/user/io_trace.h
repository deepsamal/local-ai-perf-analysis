/* SPDX-License-Identifier: GPL-2.0 */
/*
 * User-space half of the network / subprocess / disk probes.
 *
 * Included by unified_trace.c only (after its static helpers: json_escape,
 * emit_stack_json, write_cfg_map, stack_map_fd, verbose, libbpf_quiet).
 * Kept in a header so the loader and the Chrome-JSON writer for these
 * three surfaces sit in one place without turning unified_trace.c into a
 * multi-file build.
 *
 * What happens here that the BPF side cannot do:
 *   net         group calls into connections, lay connections out on
 *               per-peer rows, and derive "await response" spans (time
 *               from the last byte of a request to the first byte of
 *               the reply) -- the number that matters for a client that
 *               waits in poll()/epoll rather than in recv().
 *   subprocess  stitch fork/exec/exit into one lifetime span per child.
 *   disk        join the dentry components into a path, prefix the
 *               mount point, aggregate per path.
 */
#ifndef __IO_TRACE_H
#define __IO_TRACE_H

#include <arpa/inet.h>
#include "io_common.h"

/* Virtual thread ids for the extra rows. Real tids are < 2^22. */
#define IO_TID_NET_BASE   10000000u
#define IO_TID_PROC_BASE  20000000u   /* + child pid */
#define IO_TID_WAIT_BASE  40000000u   /* + waiting tid */
#define IO_TID_DISK_BASE  50000000u   /* + reading/writing tid */

/* ---- options (set from the command line) ------------------------------ */
static int io_opt_net = 1, io_opt_proc = 1, io_opt_disk = 1;
static int io_opt_follow_children = 1;
static int io_opt_target = -1;          /* -1 = same as --pid */
static long io_opt_disk_min_us = 0;
static int io_opt_kprobes_only = 0;     /* skip the fentry attempt */

/* ---- collected records ------------------------------------------------ */
#define IO_MAX_NET  500000
#define IO_MAX_PROC 100000
#define IO_MAX_DISK 200000

static struct io_net_event  *io_net;   static size_t io_net_n,  io_net_cap;
static struct io_proc_event *io_proc;  static size_t io_proc_n, io_proc_cap;
static struct io_disk_event *io_disk;  static size_t io_disk_n, io_disk_cap;
static unsigned long io_overflow, io_bad_records;

#define IO_APPEND(arr, n, cap, max, src)                                   \
    do {                                                                   \
        if ((n) >= (size_t)(max)) { io_overflow++; break; }                \
        if ((n) == (cap)) {                                                \
            size_t nc_ = (cap) ? (cap) * 2 : 1024;                         \
            void *p_ = realloc((arr), nc_ * sizeof(*(arr)));               \
            if (!p_) { io_overflow++; break; }                             \
            (arr) = p_; (cap) = nc_;                                       \
        }                                                                  \
        memcpy(&(arr)[(n)++], (src), sizeof(*(arr)));                      \
    } while (0)

static int handle_io_event(void *ctx, void *data, size_t sz)
{
    (void)ctx;
    if (sz < sizeof(struct io_hdr)) { io_bad_records++; return 0; }
    const struct io_hdr *h = data;
    switch (h->type) {
    case IO_NET_SEND: case IO_NET_RECV:
        if (sz < sizeof(struct io_net_event)) { io_bad_records++; break; }
        IO_APPEND(io_net, io_net_n, io_net_cap, IO_MAX_NET, data);
        break;
    case IO_PROC_FORK: case IO_PROC_EXEC: case IO_PROC_EXIT: case IO_PROC_WAIT:
        if (sz < sizeof(struct io_proc_event)) { io_bad_records++; break; }
        IO_APPEND(io_proc, io_proc_n, io_proc_cap, IO_MAX_PROC, data);
        break;
    case IO_DISK_READ: case IO_DISK_WRITE:
        if (sz < sizeof(struct io_disk_event)) { io_bad_records++; break; }
        IO_APPEND(io_disk, io_disk_n, io_disk_cap, IO_MAX_DISK, data);
        break;
    default:
        io_bad_records++;
    }
    return 0;
}

/* ---- loader ----------------------------------------------------------- */

struct io_obj {
    const char *name;
    const char *path;
    int *enabled;
    struct bpf_object *obj;
    struct bpf_link *links[16];
    int nlinks;
    const char *variant;        /* "fentry", "kprobe" or "tracepoint" */
};
static struct io_obj io_objs[] = {
    /* Loaded first: tracepoints only, so it never needs the retry below
     * and can own the shared maps. */
    { "subprocess", "obj/trace_process.bpf.o", &io_opt_proc },
    { "net",        "obj/trace_net.bpf.o",     &io_opt_net  },
    { "disk",       "obj/trace_disk.bpf.o",    &io_opt_disk },
};
#define IO_NOBJS ((int)(sizeof(io_objs) / sizeof(io_objs[0])))

/* Maps that must be one kernel object across every BPF object. */
enum { IO_SH_STACKS, IO_SH_EVENTS, IO_SH_CFG, IO_SH_TRACKED, IO_SH_DROPS, IO_SH_N };
static const char *io_shared_name[IO_SH_N] = {
    "stack_traces", "io_events", "io_cfg", "io_tracked", "io_drops",
};
static int io_shared_fd[IO_SH_N] = { -1, -1, -1, -1, -1 };
static struct bpf_object *io_shared_owner[IO_SH_N];

static struct ring_buffer *io_rb;
static struct io_tracer_cfg io_cfg_val;

static void io_obj_close(struct io_obj *o)
{
    for (int i = 0; i < o->nlinks; i++)
        bpf_link__destroy(o->links[i]);
    o->nlinks = 0;
    if (o->obj) {
        for (int i = 0; i < IO_SH_N; i++)
            if (io_shared_owner[i] == o->obj) {
                io_shared_owner[i] = NULL;
                io_shared_fd[i] = -1;
            }
        bpf_object__close(o->obj);
        o->obj = NULL;
    }
}

/* Open, configure, load and attach one object using the program set
 * named by `prefix` ("fe_" or "kp_"); tp_* programs are always used.
 * Returns 0 on success; on failure everything is torn down again. */
static int io_obj_try(struct io_obj *o, const char *prefix)
{
    struct bpf_program *prog;
    int has_fe = 0, has_kp = 0, err;

    o->obj = bpf_object__open_file(o->path, NULL);
    if (libbpf_get_error(o->obj)) {
        o->obj = NULL;
        return -ENOENT;
    }
    bpf_object__for_each_program(prog, o->obj) {
        const char *n = bpf_program__name(prog);
        int is_fe = strncmp(n, "fe_", 3) == 0, is_kp = strncmp(n, "kp_", 3) == 0;
        has_fe |= is_fe;
        has_kp |= is_kp;
        if (is_fe || is_kp)
            bpf_program__set_autoload(prog, strncmp(n, prefix, 3) == 0);
    }
    for (int i = 0; i < IO_SH_N; i++) {
        struct bpf_map *m = bpf_object__find_map_by_name(o->obj, io_shared_name[i]);
        if (m && io_shared_fd[i] >= 0 &&
            (err = bpf_map__reuse_fd(m, io_shared_fd[i])) != 0) {
            fprintf(stderr, "WARNING: %s: cannot share map %s: %s\n",
                    o->name, io_shared_name[i], strerror(-err));
            io_obj_close(o);
            return err;
        }
    }
    err = bpf_object__load(o->obj);
    if (err) {
        io_obj_close(o);
        return err;
    }
    for (int i = 0; i < IO_SH_N; i++) {
        struct bpf_map *m = bpf_object__find_map_by_name(o->obj, io_shared_name[i]);
        if (m && io_shared_fd[i] < 0) {
            io_shared_fd[i] = bpf_map__fd(m);
            io_shared_owner[i] = o->obj;
        }
    }
    if (write_cfg_map(o->obj, "io_cfg", &io_cfg_val, sizeof(io_cfg_val), o->name) != 0) {
        io_obj_close(o);
        return -EINVAL;
    }
    bpf_object__for_each_program(prog, o->obj) {
        if (!bpf_program__autoload(prog))
            continue;
        if (o->nlinks >= (int)(sizeof(o->links) / sizeof(o->links[0])))
            break;
        struct bpf_link *l = bpf_program__attach(prog);
        err = libbpf_get_error(l);
        if (err) {
            if (!libbpf_quiet)
                fprintf(stderr, "WARNING: %s: attaching %s failed: %s\n",
                        o->name, bpf_program__name(prog), strerror(-err));
            io_obj_close(o);
            return err;
        }
        o->links[o->nlinks++] = l;
    }
    o->variant = !(has_fe || has_kp) ? "tracepoint"
               : prefix[0] == 'f' ? "fentry" : "kprobe";
    return 0;
}

/* Load the three probe objects. Each one is optional: a kernel that
 * cannot attach one surface still gets the others. Must run after the
 * CPU object (so stack_traces can be shared) and before the GPU one. */
static void io_setup(int target_pid, __u32 pidns_inum, __u64 pidns_dev, int capture_stacks)
{
    int target = io_opt_target >= 0 ? io_opt_target : target_pid;

    memset(&io_cfg_val, 0, sizeof(io_cfg_val));
    io_cfg_val.target_tgid     = (__u32)target;
    io_cfg_val.pidns_inum      = pidns_inum;
    io_cfg_val.pidns_dev       = pidns_dev;
    io_cfg_val.disk_min_ns     = (__u64)io_opt_disk_min_us * 1000ULL;
    io_cfg_val.capture_stacks  = (__u8)capture_stacks;
    io_cfg_val.follow_children = (__u8)io_opt_follow_children;
    io_cfg_val.self_tgid       = (__u32)getpid();

    io_shared_fd[IO_SH_STACKS] = stack_map_fd;   /* -1 if no CPU object */

    int loaded = 0;
    for (int i = 0; i < IO_NOBJS; i++) {
        struct io_obj *o = &io_objs[i];
        if (!*o->enabled)
            continue;
        /* First try is expected to fail on kernels without BPF
         * trampolines; keep libbpf's complaints for --verbose. */
        int err = -ENOTSUP;
        if (!io_opt_kprobes_only) {
            libbpf_quiet = !verbose;
            err = io_obj_try(o, "fe_");
            libbpf_quiet = 0;
        }
        if (err && err != -ENOENT)
            err = io_obj_try(o, "kp_");
        if (err) {
            fprintf(stderr, "WARNING: %s probes disabled: %s (%s). "
                    "Re-run with --verbose for the libbpf log.\n",
                    o->name, o->path, strerror(-err));
            *o->enabled = 0;
            continue;
        }
        printf("✓ %s probes attached (%s, %d programs)\n", o->name, o->variant, o->nlinks);
        loaded++;
    }
    if (!loaded)
        return;

    if (stack_map_fd < 0)
        stack_map_fd = io_shared_fd[IO_SH_STACKS];

    io_rb = ring_buffer__new(io_shared_fd[IO_SH_EVENTS], handle_io_event, NULL, NULL);
    if (!io_rb)
        fprintf(stderr, "WARNING: cannot create ring buffer for net/subprocess/disk events\n");

    if (target)
        printf("ℹ net/subprocess/disk: process tree of pid %d%s\n", target,
               io_opt_follow_children ? " (children followed)" : "");
    else
        printf("ℹ net/subprocess/disk: ALL processes (use --pid or --io-pid to narrow)\n");
}

static void io_poll(int timeout_ms)
{
    if (io_rb)
        ring_buffer__poll(io_rb, timeout_ms);
}

static unsigned long long io_kernel_drops(void)
{
    int fd = io_shared_fd[IO_SH_DROPS];
    int ncpu = libbpf_num_possible_cpus();
    unsigned long long total = 0;
    if (fd < 0 || ncpu <= 0)
        return 0;
    __u64 *vals = calloc(ncpu, sizeof(__u64));
    __u32 key = 0;
    if (vals && bpf_map_lookup_elem(fd, &key, vals) == 0)
        for (int c = 0; c < ncpu; c++)
            total += vals[c];
    free(vals);
    return total;
}

static void io_cleanup(void)
{
    ring_buffer__free(io_rb);
    io_rb = NULL;
    /* Reverse order: the first object owns the shared maps. */
    for (int i = IO_NOBJS - 1; i >= 0; i--)
        io_obj_close(&io_objs[i]);
}

/* ---- small helpers ---------------------------------------------------- */

static __u64 io_min_ts(__u64 cur)
{
    for (size_t i = 0; i < io_net_n; i++)  if (io_net[i].h.ts  < cur) cur = io_net[i].h.ts;
    for (size_t i = 0; i < io_proc_n; i++) if (io_proc[i].h.ts < cur) cur = io_proc[i].h.ts;
    for (size_t i = 0; i < io_disk_n; i++) if (io_disk[i].h.ts < cur) cur = io_disk[i].h.ts;
    return cur;
}

static __u64 io_max_ts(__u64 cur)
{
#define IO_END(h) ((h).ts + (h).dur_ns)
    for (size_t i = 0; i < io_net_n; i++)  if (IO_END(io_net[i].h)  > cur) cur = IO_END(io_net[i].h);
    for (size_t i = 0; i < io_proc_n; i++) if (IO_END(io_proc[i].h) > cur) cur = IO_END(io_proc[i].h);
    for (size_t i = 0; i < io_disk_n; i++) if (IO_END(io_disk[i].h) > cur) cur = IO_END(io_disk[i].h);
    return cur;
}

#define IO_SEP(f, cnt) do { if ((*(cnt))++ > 0) fprintf((f), ",\n"); } while (0)

/* Symbolized stacks are memoised per (pid, stack id): the same stack
 * shows up on thousands of reads, and blazesym is not free. */
#define IO_STACK_CACHE 8192u
static struct io_stack_memo { int used, pid, stack_id; char *json; } *io_stack_cache;

static void io_emit_stack(FILE *f, int stack_id, int pid)
{
    if (!io_stack_cache)
        io_stack_cache = calloc(IO_STACK_CACHE, sizeof(*io_stack_cache));
    if (!io_stack_cache) {
        emit_stack_json(f, stack_id, pid);
        return;
    }
    __u32 idx = ((__u32)pid * 2654435761u ^ (__u32)stack_id * 40503u) & (IO_STACK_CACHE - 1);
    for (__u32 probe = 0; probe < 64; probe++) {
        struct io_stack_memo *m = &io_stack_cache[(idx + probe) & (IO_STACK_CACHE - 1)];
        if (m->used && m->pid == pid && m->stack_id == stack_id) {
            fputs(m->json, f);
            return;
        }
        if (!m->used) {
            char *buf = NULL;
            size_t len = 0;
            FILE *mf = open_memstream(&buf, &len);
            if (!mf)
                break;
            emit_stack_json(mf, stack_id, pid);
            fclose(mf);
            m->used = 1; m->pid = pid; m->stack_id = stack_id; m->json = buf;
            fputs(buf, f);
            return;
        }
    }
    emit_stack_json(f, stack_id, pid);
}

/* pid -> last seen comm, for process_name metadata. */
#define IO_PIDTAB 16384u
static struct io_pidname { __u32 pid; char comm[TASK_COMM_LEN]; } *io_pidtab;

static void io_note_pid(const struct io_hdr *h)
{
    if (!io_pidtab)
        io_pidtab = calloc(IO_PIDTAB, sizeof(*io_pidtab));
    if (!io_pidtab || h->pid == 0)
        return;
    __u32 idx = (h->pid * 2654435761u) & (IO_PIDTAB - 1);
    for (__u32 probe = 0; probe < IO_PIDTAB; probe++) {
        struct io_pidname *p = &io_pidtab[(idx + probe) & (IO_PIDTAB - 1)];
        if (p->pid == 0 || p->pid == h->pid) {
            p->pid = h->pid;
            memcpy(p->comm, h->comm, TASK_COMM_LEN);
            p->comm[TASK_COMM_LEN - 1] = 0;
            return;
        }
    }
}

static const char *io_basename(const char *p)
{
    const char *s = strrchr(p, '/');
    return (s && s[1]) ? s + 1 : p;
}

/* ---- network ---------------------------------------------------------- */

static int io_is_v4mapped(const __u8 *a)
{
    static const __u8 pfx[12] = { 0,0,0,0, 0,0,0,0, 0,0,0xff,0xff };
    return memcmp(a, pfx, 12) == 0;
}

static void io_fmt_addr(char *out, size_t cap, __u16 family, const __u8 *a, __u16 port)
{
    char ip[INET6_ADDRSTRLEN] = "?";
    if (family == AF_INET6 && !io_is_v4mapped(a)) {
        inet_ntop(AF_INET6, a, ip, sizeof(ip));
        snprintf(out, cap, "[%s]:%u", ip, port);
    } else {
        inet_ntop(AF_INET, family == AF_INET6 ? a + 12 : a, ip, sizeof(ip));
        snprintf(out, cap, "%s:%u", ip, port);
    }
}

static int io_is_loopback(const struct io_net_event *e)
{
    static const __u8 lo6[16] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
    if (memcmp(e->saddr, e->daddr, 16) == 0)
        return 1;
    if (e->family == AF_INET6 && !io_is_v4mapped(e->daddr))
        return memcmp(e->daddr, lo6, 16) == 0;
    return (e->family == AF_INET6 ? e->daddr[12] : e->daddr[0]) == 127;
}

/* Order calls so that each connection is one contiguous run, in order
 * of completion. Completion order (not start order) is what makes a
 * reader thread already parked in recv() sort after the send that it
 * is waiting on. */
static int io_net_cmp(const void *a, const void *b)
{
    const struct io_net_event *x = a, *y = b;
    if (x->h.pid != y->h.pid) return x->h.pid < y->h.pid ? -1 : 1;
    if (x->sock != y->sock)   return x->sock < y->sock ? -1 : 1;
    if (x->sport != y->sport) return x->sport < y->sport ? -1 : 1;
    if (x->dport != y->dport) return x->dport < y->dport ? -1 : 1;
    __u64 ex = x->h.ts + x->h.dur_ns, ey = y->h.ts + y->h.dur_ns;
    if (ex != ey) return ex < ey ? -1 : 1;
    return 0;
}

struct io_conn {
    size_t first, count;        /* run in the sorted io_net[] */
    __u64 start, end;
    __u32 row_tid;
    /* summary */
    __u64 sent, recvd, wait_ns;
    unsigned requests;
};
static struct io_conn *io_conns;
static size_t io_conn_n;

static int io_same_peer(const struct io_net_event *a, const struct io_net_event *b)
{
    return a->h.pid == b->h.pid && a->family == b->family &&
           a->dport == b->dport && memcmp(a->daddr, b->daddr, 16) == 0;
}

static int io_conn_cmp(const void *a, const void *b)
{
    const struct io_conn *x = a, *y = b;
    const struct io_net_event *ex = &io_net[x->first], *ey = &io_net[y->first];
    if (ex->h.pid != ey->h.pid) return ex->h.pid < ey->h.pid ? -1 : 1;
    int c = memcmp(ex->daddr, ey->daddr, 16);
    if (c) return c;
    if (ex->dport != ey->dport) return ex->dport < ey->dport ? -1 : 1;
    if (ex->family != ey->family) return ex->family < ey->family ? -1 : 1;
    if (x->start != y->start) return x->start < y->start ? -1 : 1;
    return 0;
}

struct io_peer_sum {
    __u32 pid;
    char comm[TASK_COMM_LEN];
    char peer[80];
    int loopback;
    unsigned conns, requests;
    __u64 sent, recvd, wait_ns;
};
static struct io_peer_sum *io_peers;
static size_t io_peer_n;

static void io_emit_net(FILE *f, __u64 base, int *cnt)
{
    if (io_net_n == 0)
        return;
    qsort(io_net, io_net_n, sizeof(*io_net), io_net_cmp);

    /* 1. connections = contiguous runs */
    io_conns = calloc(io_net_n, sizeof(*io_conns));
    io_peers = calloc(io_net_n, sizeof(*io_peers));
    if (!io_conns || !io_peers)
        return;
    for (size_t i = 0; i < io_net_n; i++) {
        const struct io_net_event *e = &io_net[i];
        struct io_conn *c = io_conn_n ? &io_conns[io_conn_n - 1] : NULL;
        const struct io_net_event *p = i ? &io_net[i - 1] : NULL;
        if (!p || p->h.pid != e->h.pid || p->sock != e->sock ||
            p->sport != e->sport || p->dport != e->dport) {
            c = &io_conns[io_conn_n++];
            c->first = i;
            c->start = e->h.ts;
        }
        c->count++;
        if (e->h.ts < c->start) c->start = e->h.ts;
        if (e->h.ts + e->h.dur_ns > c->end) c->end = e->h.ts + e->h.dur_ns;
    }

    /* 2. rows: one per (process, peer), plus extra lanes when several
     *    connections to the same peer are open at once. */
    qsort(io_conns, io_conn_n, sizeof(*io_conns), io_conn_cmp);
    __u32 next_tid = IO_TID_NET_BASE;
    __u64 lane_end[64];
    __u32 lane_tid[64];
    int nlanes = 0;
    struct io_peer_sum *ps = NULL;
    for (size_t ci = 0; ci < io_conn_n; ci++) {
        struct io_conn *c = &io_conns[ci];
        const struct io_net_event *e0 = &io_net[c->first];
        if (ci == 0 || !io_same_peer(e0, &io_net[io_conns[ci - 1].first])) {
            nlanes = 0;
            ps = &io_peers[io_peer_n++];
            ps->pid = e0->h.pid;
            memcpy(ps->comm, e0->h.comm, TASK_COMM_LEN);
            ps->comm[TASK_COMM_LEN - 1] = 0;
            io_fmt_addr(ps->peer, sizeof(ps->peer), e0->family, e0->daddr, e0->dport);
            ps->loopback = io_is_loopback(e0);
        }
        int lane = -1;
        for (int l = 0; l < nlanes; l++)
            if (lane_end[l] <= c->start) { lane = l; break; }
        if (lane < 0) {
            lane = nlanes < 64 ? nlanes++ : 63;
            lane_tid[lane] = next_tid++;
            char esc[96];
            json_escape(esc, sizeof(esc), ps->peer);
            IO_SEP(f, cnt);
            fprintf(f, "    {\"name\": \"thread_name\", \"ph\": \"M\", \"pid\": %u, \"tid\": %u, "
                    "\"args\": {\"name\": \"net %s%s%s\"}}",
                    e0->h.pid, lane_tid[lane], esc,
                    ps->loopback ? " (loopback)" : "", lane ? " +" : "");
        }
        lane_end[lane] = c->end;
        c->row_tid = lane_tid[lane];

        /* 3. events of this connection */
        char peer[80], local[80], esc_comm[64];
        io_fmt_addr(peer, sizeof(peer), e0->family, e0->daddr, e0->dport);
        io_fmt_addr(local, sizeof(local), e0->family, e0->saddr, e0->sport);
        int client = e0->h.type == IO_NET_SEND;   /* who spoke first */
        int awaiting = 0, prev_recv_stack = -2;
        __u64 req_end = 0, req_bytes = 0;
        __s32 req_stack = -1;
        __u32 req_tid = 0;

        for (size_t k = 0; k < c->count; k++) {
            const struct io_net_event *e = &io_net[c->first + k];
            int is_send = e->h.type == IO_NET_SEND;
            __u64 end = e->h.ts + e->h.dur_ns;
            io_note_pid(&e->h);
            json_escape(esc_comm, sizeof(esc_comm), e->h.comm);

            if (!is_send && awaiting && e->bytes > 0 && end >= req_end) {
                /* first reply byte after a request: the wait is over */
                IO_SEP(f, cnt);
                fprintf(f, "    {\"name\": \"await response\", \"cat\": \"net_wait\", "
                        "\"ph\": \"X\", \"ts\": %.3f, \"dur\": %.3f, \"pid\": %u, \"tid\": %u, "
                        "\"args\": {\"peer\": \"%s\", \"loopback\": %s, \"request_bytes\": %llu, "
                        "\"thread\": %u",
                        (req_end - base) / 1000.0, (end - req_end) / 1000.0,
                        e->h.pid, c->row_tid, peer, ps->loopback ? "true" : "false",
                        (unsigned long long)req_bytes, req_tid);
                if (req_stack >= 0) {
                    fprintf(f, ", \"stack\": ");
                    io_emit_stack(f, req_stack, e->h.pid);
                }
                fprintf(f, "}}");
                c->wait_ns += end - req_end;
                c->requests++;
                awaiting = 0;
                req_bytes = 0;
            }

            IO_SEP(f, cnt);
            fprintf(f, "    {\"name\": \"%s\", \"cat\": \"net\", \"ph\": \"X\", "
                    "\"ts\": %.3f, \"dur\": %.3f, \"pid\": %u, \"tid\": %u, "
                    "\"args\": {\"bytes\": %lld, \"peer\": \"%s\", \"local\": \"%s\", "
                    "\"loopback\": %s, \"thread\": %u, \"comm\": \"%s\"",
                    is_send ? "tcp_send" : (e->bytes ? "tcp_recv" : "tcp_recv (EOF)"),
                    (e->h.ts - base) / 1000.0, e->h.dur_ns / 1000.0,
                    e->h.pid, c->row_tid, (long long)e->bytes, peer, local,
                    ps->loopback ? "true" : "false", e->h.tid, esc_comm);
            /* Every send carries its stack; a recv only when it differs
             * from the previous recv on this connection (a streamed
             * reply is thousands of identical ones). */
            if (e->h.stack_id >= 0 && (is_send || e->h.stack_id != prev_recv_stack)) {
                fprintf(f, ", \"stack\": ");
                io_emit_stack(f, e->h.stack_id, e->h.pid);
            }
            fprintf(f, "}}");

            if (is_send) {
                c->sent += e->bytes;
                if (client) {
                    awaiting = 1;
                    req_end = end;
                    req_bytes += e->bytes;
                    req_stack = e->h.stack_id;
                    req_tid = e->h.tid;
                }
            } else {
                c->recvd += e->bytes;
                prev_recv_stack = e->h.stack_id;
            }
        }
        ps->conns++;
        ps->requests += c->requests;
        ps->sent += c->sent;
        ps->recvd += c->recvd;
        ps->wait_ns += c->wait_ns;
    }
}

/* ---- subprocess ------------------------------------------------------- */

struct io_child {
    __u32 pid, ppid, ptid;
    __u64 fork_ts, exit_ts;
    __s32 fork_stack, exit_code;
    int exited, execs;
    char exec[IO_EXEC_PATH_LEN];
    char comm[TASK_COMM_LEN];
};
static struct io_child *io_children;
static size_t io_child_n;
static __u64 io_child_total_ns;

static int io_proc_cmp(const void *a, const void *b)
{
    const struct io_proc_event *x = a, *y = b;
    /* order by the moment the record was produced */
    __u64 tx = x->h.ts + x->h.dur_ns, ty = y->h.ts + y->h.dur_ns;
    if (tx != ty) return tx < ty ? -1 : 1;
    return (int)x->h.type - (int)y->h.type;
}

/* Most recent child with this pid that has not exited (pids get reused). */
static struct io_child *io_child_find(__u32 pid)
{
    for (size_t i = io_child_n; i-- > 0; )
        if (io_children[i].pid == pid)
            return io_children[i].exited ? NULL : &io_children[i];
    return NULL;
}

static void io_emit_proc(FILE *f, __u64 base, __u64 trace_end, int *cnt)
{
    if (io_proc_n == 0)
        return;
    qsort(io_proc, io_proc_n, sizeof(*io_proc), io_proc_cmp);
    io_children = calloc(io_proc_n, sizeof(*io_children));
    if (!io_children)
        return;

    for (size_t i = 0; i < io_proc_n; i++) {
        const struct io_proc_event *e = &io_proc[i];
        struct io_child *c;
        io_note_pid(&e->h);
        switch (e->h.type) {
        case IO_PROC_FORK:
            c = &io_children[io_child_n++];
            c->pid = e->child_pid;
            c->ppid = e->h.pid;
            c->ptid = e->h.tid;
            c->fork_ts = e->h.ts;
            c->fork_stack = e->h.stack_id;
            memcpy(c->comm, e->h.comm, TASK_COMM_LEN);
            break;
        case IO_PROC_EXEC:
            c = io_child_find(e->h.pid);
            if (c) {
                /* Keep the first image: `sh -c tool` is the thing the
                 * agent launched even if it execs again. */
                if (c->execs++ == 0) {
                    memcpy(c->exec, e->filename, sizeof(c->exec));
                    c->exec[sizeof(c->exec) - 1] = 0;
                }
                char esc[IO_EXEC_PATH_LEN * 2];
                json_escape(esc, sizeof(esc), e->filename);
                IO_SEP(f, cnt);
                fprintf(f, "    {\"name\": \"exec\", \"cat\": \"subprocess\", \"ph\": \"i\", "
                        "\"s\": \"t\", \"ts\": %.3f, \"pid\": %u, \"tid\": %u, "
                        "\"args\": {\"child_pid\": %u, \"exec\": \"%s\"}}",
                        (e->h.ts - base) / 1000.0, c->ppid, IO_TID_PROC_BASE + c->pid,
                        c->pid, esc);
            }
            break;
        case IO_PROC_EXIT:
            c = io_child_find(e->h.pid);
            if (c) {
                c->exited = 1;
                c->exit_ts = e->h.ts;
                c->exit_code = e->exit_code;
                memcpy(c->comm, e->h.comm, TASK_COMM_LEN);
            }
            break;
        case IO_PROC_WAIT: {
            IO_SEP(f, cnt);
            fprintf(f, "    {\"name\": \"thread_name\", \"ph\": \"M\", \"pid\": %u, \"tid\": %u, "
                    "\"args\": {\"name\": \"child waits [tid %u]\"}}",
                    e->h.pid, IO_TID_WAIT_BASE + e->h.tid, e->h.tid);
            IO_SEP(f, cnt);
            fprintf(f, "    {\"name\": \"%s\", \"cat\": \"subprocess\", \"ph\": \"X\", "
                    "\"ts\": %.3f, \"dur\": %.3f, \"pid\": %u, \"tid\": %u, "
                    "\"args\": {\"thread\": %u, \"ret\": %lld",
                    e->syscall_nr == 247 || e->syscall_nr == 95 ? "waitid" : "wait4",
                    (e->h.ts - base) / 1000.0, e->h.dur_ns / 1000.0,
                    e->h.pid, IO_TID_WAIT_BASE + e->h.tid, e->h.tid, (long long)e->ret);
            if (e->ret > 0)
                fprintf(f, ", \"reaped_pid\": %lld", (long long)e->ret);
            if (e->h.stack_id >= 0) {
                fprintf(f, ", \"stack\": ");
                io_emit_stack(f, e->h.stack_id, e->h.pid);
            }
            fprintf(f, "}}");
            break;
        }
        }
    }

    for (size_t i = 0; i < io_child_n; i++) {
        struct io_child *c = &io_children[i];
        __u64 end = c->exited ? c->exit_ts : trace_end;
        if (end < c->fork_ts)
            end = c->fork_ts;
        const char *label = c->exec[0] ? io_basename(c->exec) : c->comm;
        char esc_label[IO_EXEC_PATH_LEN * 2], esc_exec[IO_EXEC_PATH_LEN * 2];
        json_escape(esc_label, sizeof(esc_label), label);
        json_escape(esc_exec, sizeof(esc_exec), c->exec);
        io_child_total_ns += end - c->fork_ts;

        IO_SEP(f, cnt);
        fprintf(f, "    {\"name\": \"thread_name\", \"ph\": \"M\", \"pid\": %u, \"tid\": %u, "
                "\"args\": {\"name\": \"subprocess %u: %s\"}}",
                c->ppid, IO_TID_PROC_BASE + c->pid, c->pid, esc_label);
        IO_SEP(f, cnt);
        fprintf(f, "    {\"name\": \"%s\", \"cat\": \"subprocess\", \"ph\": \"X\", "
                "\"ts\": %.3f, \"dur\": %.3f, \"pid\": %u, \"tid\": %u, "
                "\"args\": {\"child_pid\": %u, \"parent_pid\": %u, \"spawned_by_thread\": %u, "
                "\"exec\": \"%s\", \"execs\": %d",
                esc_label, (c->fork_ts - base) / 1000.0, (end - c->fork_ts) / 1000.0,
                c->ppid, IO_TID_PROC_BASE + c->pid, c->pid, c->ppid, c->ptid,
                esc_exec, c->execs);
        if (c->exited)
            fprintf(f, ", \"exit_status\": %d, \"exit_signal\": %d",
                    (c->exit_code >> 8) & 0xff, c->exit_code & 0x7f);
        else
            fprintf(f, ", \"still_running\": true");
        if (c->fork_stack >= 0) {
            fprintf(f, ", \"stack\": ");
            io_emit_stack(f, c->fork_stack, c->ppid);   /* parent's stack */
        }
        fprintf(f, "}}");
    }
}

/* ---- disk ------------------------------------------------------------- */

static struct io_mount { __u32 dev; char *point; } *io_mounts;
static size_t io_mount_n;

/* dev -> mount point, from /proc/self/mountinfo. Only mounts of a
 * filesystem's own root are useful (the dentry walk ends there); when a
 * filesystem is mounted in several places the shortest path wins. */
static void io_load_mounts(void)
{
    FILE *mf = fopen("/proc/self/mountinfo", "r");
    char line[4096];
    if (!mf)
        return;
    while (fgets(line, sizeof(line), mf)) {
        unsigned maj, min;
        char root[1024], point[2048];
        if (sscanf(line, "%*d %*d %u:%u %1023s %2047s", &maj, &min, root, point) != 4)
            continue;
        if (strcmp(root, "/") != 0)
            continue;
        /* mountinfo escapes space, tab, newline and backslash as \ooo */
        char *w = point;
        for (char *r = point; *r; r++) {
            if (r[0] == '\\' && r[1] >= '0' && r[1] <= '3' && r[2] && r[3]) {
                *w++ = (char)(((r[1] - '0') << 6) | ((r[2] - '0') << 3) | (r[3] - '0'));
                r += 3;
            } else {
                *w++ = *r;
            }
        }
        *w = 0;
        __u32 dev = (maj << 20) | min;
        size_t k;
        for (k = 0; k < io_mount_n; k++)
            if (io_mounts[k].dev == dev)
                break;
        if (k < io_mount_n) {
            if (strlen(point) < strlen(io_mounts[k].point)) {
                free(io_mounts[k].point);
                io_mounts[k].point = strdup(point);
            }
            continue;
        }
        void *p = realloc(io_mounts, (io_mount_n + 1) * sizeof(*io_mounts));
        if (!p)
            break;
        io_mounts = p;
        io_mounts[io_mount_n].dev = dev;
        io_mounts[io_mount_n].point = strdup(point);
        io_mount_n++;
    }
    fclose(mf);
}

/* Returns 1 if the result is an absolute path, 0 if only a tail of it
 * is known (deeper than IO_PATH_DIRS, or an unknown mount). */
static int io_build_path(const struct io_disk_event *e, char *out, size_t cap)
{
    size_t n = 0;
    int absolute = 0;
    out[0] = 0;
    if (e->reached_root) {
        const char *mp = NULL;
        for (size_t k = 0; k < io_mount_n; k++)
            if (io_mounts[k].dev == e->dev) { mp = io_mounts[k].point; break; }
        if (mp) {
            absolute = 1;
            if (strcmp(mp, "/") != 0)
                n += snprintf(out + n, cap - n, "%s", mp);
        } else {
            n += snprintf(out + n, cap - n, "<dev %u:%u>", e->dev >> 20, e->dev & 0xfffff);
        }
    } else {
        n += snprintf(out + n, cap - n, "...");
    }
    int nd = e->ndirs <= IO_PATH_DIRS ? e->ndirs : IO_PATH_DIRS;
    for (int i = nd - 1; i >= 0 && n < cap; i--) {
        char d[IO_PATH_DIR_LEN + 1];
        memcpy(d, e->dirs[i], IO_PATH_DIR_LEN);
        d[IO_PATH_DIR_LEN] = 0;
        if (strcmp(d, "/") == 0 || d[0] == 0)
            continue;
        /* '~' marks a name cut at the slot size */
        n += snprintf(out + n, cap - n, "/%s%s", d,
                      strlen(d) == IO_PATH_DIR_LEN - 1 ? "~" : "");
    }
    if (n < cap) {
        char l[IO_PATH_LEAF_LEN + 1];
        memcpy(l, e->leaf, IO_PATH_LEAF_LEN);
        l[IO_PATH_LEAF_LEN] = 0;
        snprintf(out + n, cap - n, "/%s%s", l,
                 strlen(l) == IO_PATH_LEAF_LEN - 1 ? "~" : "");
    }
    return absolute;
}

struct io_path_sum {
    char *path;
    unsigned reads, writes;
    __u64 rbytes, wbytes, ns;
};
static struct io_path_sum *io_paths;
static size_t io_path_n;
static __u64 io_disk_ns, io_disk_rbytes, io_disk_wbytes;
static unsigned long io_disk_abs;

static int io_disk_cmp(const void *a, const void *b)
{
    const struct io_disk_event *x = a, *y = b;
    return x->h.ts < y->h.ts ? -1 : x->h.ts > y->h.ts;
}
static int io_path_cmp(const void *a, const void *b)
{
    return strcmp(((const struct io_path_sum *)a)->path, ((const struct io_path_sum *)b)->path);
}
static int io_path_cmp_ns(const void *a, const void *b)
{
    const struct io_path_sum *x = a, *y = b;
    return x->ns > y->ns ? -1 : x->ns < y->ns;
}

static void io_emit_disk(FILE *f, __u64 base, int *cnt)
{
    if (io_disk_n == 0)
        return;
    io_load_mounts();
    qsort(io_disk, io_disk_n, sizeof(*io_disk), io_disk_cmp);
    io_paths = calloc(io_disk_n, sizeof(*io_paths));

    /* last stack emitted per thread row; direct-mapped, collisions only
     * cost a repeated stack or thread_name record */
    struct { __u32 pid, tid; __s32 stack; } *rows = calloc(4096, sizeof(*rows));
    if (!io_paths || !rows) {
        free(rows);
        return;
    }

    for (size_t i = 0; i < io_disk_n; i++) {
        const struct io_disk_event *e = &io_disk[i];
        int is_read = e->h.type == IO_DISK_READ;
        char path[1024], esc_path[2048], esc_leaf[IO_PATH_LEAF_LEN * 2 + 8], leaf[IO_PATH_LEAF_LEN + 1];
        int absolute = io_build_path(e, path, sizeof(path));
        json_escape(esc_path, sizeof(esc_path), path);
        memcpy(leaf, e->leaf, IO_PATH_LEAF_LEN);
        leaf[IO_PATH_LEAF_LEN] = 0;
        json_escape(esc_leaf, sizeof(esc_leaf), leaf);
        io_note_pid(&e->h);

        __u32 slot = (e->h.pid * 31u + e->h.tid) & 4095u;
        int new_row = rows[slot].pid != e->h.pid || rows[slot].tid != e->h.tid;
        if (new_row) {
            rows[slot].pid = e->h.pid;
            rows[slot].tid = e->h.tid;
            rows[slot].stack = -2;
            IO_SEP(f, cnt);
            fprintf(f, "    {\"name\": \"thread_name\", \"ph\": \"M\", \"pid\": %u, \"tid\": %u, "
                    "\"args\": {\"name\": \"disk I/O [tid %u]\"}}",
                    e->h.pid, IO_TID_DISK_BASE + e->h.tid, e->h.tid);
        }

        IO_SEP(f, cnt);
        fprintf(f, "    {\"name\": \"%s %s\", \"cat\": \"disk\", \"ph\": \"X\", "
                "\"ts\": %.3f, \"dur\": %.3f, \"pid\": %u, \"tid\": %u, "
                "\"args\": {\"op\": \"%s\", \"path\": \"%s\", \"path_absolute\": %s, "
                "\"bytes\": %lld, \"offset\": %llu, \"ino\": %llu, \"dev\": \"%u:%u\", \"thread\": %u",
                is_read ? "read" : "write", esc_leaf,
                (e->h.ts - base) / 1000.0, e->h.dur_ns / 1000.0,
                e->h.pid, IO_TID_DISK_BASE + e->h.tid,
                is_read ? "read" : "write", esc_path, absolute ? "true" : "false",
                (long long)e->bytes, (unsigned long long)e->offset,
                (unsigned long long)e->ino, e->dev >> 20, e->dev & 0xfffff, e->h.tid);
        if (e->h.stack_id >= 0 && e->h.stack_id != rows[slot].stack) {
            fprintf(f, ", \"stack\": ");
            io_emit_stack(f, e->h.stack_id, e->h.pid);
        }
        rows[slot].stack = e->h.stack_id;
        fprintf(f, "}}");

        io_disk_ns += e->h.dur_ns;
        if (is_read) io_disk_rbytes += e->bytes; else io_disk_wbytes += e->bytes;
        io_disk_abs += absolute;
        struct io_path_sum *s = &io_paths[i];
        s->path = strdup(path);
        s->reads = is_read; s->writes = !is_read;
        s->rbytes = is_read ? e->bytes : 0;
        s->wbytes = is_read ? 0 : e->bytes;
        s->ns = e->h.dur_ns;
    }
    free(rows);

    /* collapse per path */
    for (size_t i = 0; i < io_disk_n; i++)
        if (!io_paths[i].path)
            io_paths[i].path = strdup("?");
    qsort(io_paths, io_disk_n, sizeof(*io_paths), io_path_cmp);
    size_t w = 0;
    for (size_t i = 0; i < io_disk_n; i++) {
        if (w && strcmp(io_paths[w - 1].path, io_paths[i].path) == 0) {
            struct io_path_sum *d = &io_paths[w - 1];
            d->reads += io_paths[i].reads;   d->writes += io_paths[i].writes;
            d->rbytes += io_paths[i].rbytes; d->wbytes += io_paths[i].wbytes;
            d->ns += io_paths[i].ns;
            free(io_paths[i].path);
        } else {
            io_paths[w++] = io_paths[i];
        }
    }
    io_path_n = w;
    qsort(io_paths, io_path_n, sizeof(*io_paths), io_path_cmp_ns);
}

/* ---- entry points used by unified_trace.c ----------------------------- */

static void io_emit_chrome(FILE *f, __u64 base, __u64 trace_end, int *cnt)
{
    io_emit_net(f, base, cnt);
    io_emit_proc(f, base, trace_end, cnt);
    io_emit_disk(f, base, cnt);

    if (io_pidtab)
        for (__u32 i = 0; i < IO_PIDTAB; i++) {
            if (io_pidtab[i].pid == 0)
                continue;
            char esc[64];
            json_escape(esc, sizeof(esc), io_pidtab[i].comm);
            IO_SEP(f, cnt);
            fprintf(f, "    {\"name\": \"process_name\", \"ph\": \"M\", \"pid\": %u, "
                    "\"args\": {\"name\": \"%s\"}}", io_pidtab[i].pid, esc);
        }
}

/* One "io": {...}, block for the trace's metadata object. */
static void io_emit_metadata(FILE *f)
{
    __u64 sent = 0, recvd = 0, wait_ns = 0;
    unsigned requests = 0;
    for (size_t i = 0; i < io_peer_n; i++) {
        sent += io_peers[i].sent; recvd += io_peers[i].recvd;
        wait_ns += io_peers[i].wait_ns; requests += io_peers[i].requests;
    }
    fprintf(f, "    \"io\": {\n");
    fprintf(f, "      \"probes\": {");
    for (int i = 0; i < IO_NOBJS; i++)
        fprintf(f, "%s\"%s\": \"%s\"", i ? ", " : "", io_objs[i].name,
                io_objs[i].obj ? io_objs[i].variant : "off");
    fprintf(f, "},\n");
    fprintf(f, "      \"target_pid\": %u, \"follow_children\": %s,\n",
            io_cfg_val.target_tgid, io_cfg_val.follow_children ? "true" : "false");
    fprintf(f, "      \"dropped_in_kernel\": %llu, \"dropped_in_tracer\": %lu,\n",
            io_kernel_drops(), io_overflow);

    fprintf(f, "      \"net\": {\"calls\": %zu, \"connections\": %zu, \"requests\": %u, "
            "\"bytes_sent\": %llu, \"bytes_received\": %llu, \"await_response_ms\": %.3f, \"peers\": [",
            io_net_n, io_conn_n, requests, (unsigned long long)sent,
            (unsigned long long)recvd, wait_ns / 1e6);
    for (size_t i = 0; i < io_peer_n && i < 50; i++) {
        struct io_peer_sum *p = &io_peers[i];
        char esc[64];
        json_escape(esc, sizeof(esc), p->comm);
        fprintf(f, "%s\n        {\"pid\": %u, \"comm\": \"%s\", \"peer\": \"%s\", \"loopback\": %s, "
                "\"connections\": %u, \"requests\": %u, \"bytes_sent\": %llu, "
                "\"bytes_received\": %llu, \"await_response_ms\": %.3f}",
                i ? "," : "", p->pid, esc, p->peer, p->loopback ? "true" : "false",
                p->conns, p->requests, (unsigned long long)p->sent,
                (unsigned long long)p->recvd, p->wait_ns / 1e6);
    }
    fprintf(f, "]},\n");

    fprintf(f, "      \"subprocess\": {\"spawned\": %zu, \"total_lifetime_ms\": %.3f},\n",
            io_child_n, io_child_total_ns / 1e6);

    fprintf(f, "      \"disk\": {\"calls\": %zu, \"paths\": %zu, \"paths_absolute\": %lu, "
            "\"bytes_read\": %llu, \"bytes_written\": %llu, \"time_ms\": %.3f, \"top_paths\": [",
            io_disk_n, io_path_n, io_disk_abs, (unsigned long long)io_disk_rbytes,
            (unsigned long long)io_disk_wbytes, io_disk_ns / 1e6);
    for (size_t i = 0; i < io_path_n && i < 25; i++) {
        struct io_path_sum *p = &io_paths[i];
        char esc[2048];
        json_escape(esc, sizeof(esc), p->path);
        fprintf(f, "%s\n        {\"path\": \"%s\", \"reads\": %u, \"writes\": %u, "
                "\"bytes_read\": %llu, \"bytes_written\": %llu, \"time_ms\": %.3f}",
                i ? "," : "", esc, p->reads, p->writes,
                (unsigned long long)p->rbytes, (unsigned long long)p->wbytes, p->ns / 1e6);
    }
    fprintf(f, "]}\n");
    fprintf(f, "    },\n");
}

static void io_print_summary(void)
{
    unsigned long long drops = io_kernel_drops();
    printf("\nNetwork / subprocess / disk\n");
    printf("  net:        %zu TCP calls on %zu connections\n", io_net_n, io_conn_n);
    for (size_t i = 0; i < io_peer_n && i < 8; i++) {
        struct io_peer_sum *p = &io_peers[i];
        printf("    %-15s pid %-7u -> %-24s %u req, %llu B out, %llu B in, waited %.1f ms\n",
               p->comm, p->pid, p->peer, p->requests, (unsigned long long)p->sent,
               (unsigned long long)p->recvd, p->wait_ns / 1e6);
    }
    printf("  subprocess: %zu spawned, %.1f ms total lifetime\n",
           io_child_n, io_child_total_ns / 1e6);
    for (size_t i = 0; i < io_child_n && i < 8; i++) {
        struct io_child *c = &io_children[i];
        printf("    pid %-7u <- %-7u %-28s %s%.1f ms\n", c->pid, c->ppid,
               c->exec[0] ? io_basename(c->exec) : c->comm,
               c->exited ? "" : "(running) ",
               c->exited ? (c->exit_ts - c->fork_ts) / 1e6 : 0.0);
    }
    printf("  disk:       %zu file reads/writes on %zu paths, %.1f ms, %llu B read, %llu B written\n",
           io_disk_n, io_path_n, io_disk_ns / 1e6,
           (unsigned long long)io_disk_rbytes, (unsigned long long)io_disk_wbytes);
    for (size_t i = 0; i < io_path_n && i < 5; i++)
        printf("    %8.3f ms  %s\n", io_paths[i].ns / 1e6, io_paths[i].path);
    if (drops)
        fprintf(stderr, "WARNING: %llu net/subprocess/disk events dropped in the kernel "
                "(ring buffer full); narrow with --pid/--io-pid or --disk-min-us\n", drops);
    if (io_overflow)
        fprintf(stderr, "WARNING: %lu net/subprocess/disk events dropped by the tracer "
                "(per-type record cap reached)\n", io_overflow);
    if (io_bad_records)
        fprintf(stderr, "WARNING: %lu malformed net/subprocess/disk records\n", io_bad_records);
}

#endif /* __IO_TRACE_H */
