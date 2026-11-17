// SPDX-License-Identifier: GPL-2.0
/*
 * Network tracer (roadmap Phase 1): TCP send/recv timing for the agent.
 *
 * Probes tcp_sendmsg / tcp_recvmsg, i.e. the TCP layer: timing, size and
 * peer, never payload. (Reading decrypted prompts at SSL_read/SSL_write
 * is what AgentSight does, for a different purpose.) One record per call
 * that moved data; calls that return an error -- including the -EAGAIN
 * of every non-blocking poll -- are dropped here.
 *
 * Two program sets do the same work:
 *   fe_*  fentry/fexit   lower overhead, no kretprobe instance limit;
 *                        needs BPF trampolines and kernel >= 5.17
 *                        (bpf_get_func_ret)
 *   kp_*  kprobe/kretprobe  works wherever kprobes do
 * unified_trace autoloads one set: fentry first, kprobes as fallback.
 *
 * The user stack is captured on the way OUT of the call. It is the same
 * stack as on the way in (the thread has been in the kernel throughout)
 * and this way calls that end up dropped never pay for a stack walk.
 */
#include "io_common.h"

char LICENSE[] SEC("license") = "GPL";

/* bpf_get_func_ret(), helper 184, kernel >= 5.17. Declared here because
 * the libbpf headers on Ubuntu 22.04 (0.5) predate it. */
static long (*io_get_func_ret)(void *ctx, __u64 *value) = (void *)184;

/* Minimal CO-RE views of the socket. Fields that sit inside anonymous
 * unions in the kernel are declared flat; libbpf matches by name. */
struct in6_addr {
    __u8 b[16];
};

struct sock_common {
    __be32 skc_daddr;
    __be32 skc_rcv_saddr;
    __be16 skc_dport;
    __u16  skc_num;
    unsigned short skc_family;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
} __attribute__((preserve_access_index));

#define IO_AF_INET  2
#define IO_AF_INET6 10

struct net_call {
    __u64 ts;
    __u64 sk;
    __u32 type;
    __u32 pid;
    __u32 tid;
    __u32 _pad;
};

/* In-flight calls keyed by (root-ns) pid_tgid. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct net_call);
} net_calls SEC(".maps");

static __always_inline int net_enter(struct sock *sk, __u32 type)
{
    struct io_tracer_cfg *c = io_get_cfg();
    if (!c)
        return 0;
    struct net_call nc = {};
    if (!io_wanted(c, &nc.pid, &nc.tid))
        return 0;
    __u64 id = bpf_get_current_pid_tgid();
    nc.ts = bpf_ktime_get_ns();
    nc.sk = (__u64)sk;
    nc.type = type;
    bpf_map_update_elem(&net_calls, &id, &nc, BPF_ANY);
    return 0;
}

static __always_inline int net_exit(void *ctx, int ret, __u32 type)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct net_call *ncp = bpf_map_lookup_elem(&net_calls, &id);
    if (!ncp)
        return 0;
    struct net_call nc = *ncp;
    bpf_map_delete_elem(&net_calls, &id);

    if (nc.type != type || ret < 0)
        return 0;
    if (type == IO_NET_SEND && ret == 0)
        return 0;               /* a recv of 0 is EOF and is kept */

    struct io_tracer_cfg *c = io_get_cfg();
    if (!c)
        return 0;

    struct io_net_event ev;
    __builtin_memset(&ev, 0, sizeof(ev));
    ev.h.ts       = nc.ts;
    ev.h.dur_ns   = bpf_ktime_get_ns() - nc.ts;
    ev.h.type     = type;
    ev.h.pid      = nc.pid;
    ev.h.tid      = nc.tid;
    ev.h.stack_id = io_stack(ctx, c);
    bpf_get_current_comm(&ev.h.comm, sizeof(ev.h.comm));
    ev.sock  = nc.sk;
    ev.bytes = ret;

    struct sock *sk = (struct sock *)nc.sk;
    __u16 dport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);
    ev.family = BPF_CORE_READ(sk, __sk_common.skc_family);
    ev.sport  = BPF_CORE_READ(sk, __sk_common.skc_num);
    ev.dport  = __builtin_bswap16(dport_be);

    if (ev.family == IO_AF_INET6 &&
        bpf_core_field_exists(sk->__sk_common.skc_v6_daddr)) {
        BPF_CORE_READ_INTO(&ev.saddr, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&ev.daddr, sk, __sk_common.skc_v6_daddr);
    } else {
        __u32 s4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u32 d4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(ev.saddr, &s4, sizeof(s4));
        __builtin_memcpy(ev.daddr, &d4, sizeof(d4));
    }

    io_emit(&ev, sizeof(ev));
    return 0;
}

/* ---- fentry/fexit set ------------------------------------------------- */

SEC("fentry/tcp_sendmsg")
int BPF_PROG(fe_tcp_sendmsg, struct sock *sk)
{
    return net_enter(sk, IO_NET_SEND);
}

SEC("fexit/tcp_sendmsg")
int BPF_PROG(fe_tcp_sendmsg_exit)
{
    __u64 ret = 0;
    io_get_func_ret(ctx, &ret);
    return net_exit(ctx, (int)ret, IO_NET_SEND);
}

SEC("fentry/tcp_recvmsg")
int BPF_PROG(fe_tcp_recvmsg, struct sock *sk)
{
    return net_enter(sk, IO_NET_RECV);
}

/* tcp_recvmsg's argument count changed in 5.19, which moves the return
 * value's slot in the fexit context; bpf_get_func_ret() is immune. */
SEC("fexit/tcp_recvmsg")
int BPF_PROG(fe_tcp_recvmsg_exit)
{
    __u64 ret = 0;
    io_get_func_ret(ctx, &ret);
    return net_exit(ctx, (int)ret, IO_NET_RECV);
}

/* ---- kprobe/kretprobe set --------------------------------------------- */

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kp_tcp_sendmsg, struct sock *sk)
{
    return net_enter(sk, IO_NET_SEND);
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(kp_tcp_sendmsg_exit, long ret)
{
    return net_exit(ctx, (int)ret, IO_NET_SEND);
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(kp_tcp_recvmsg, struct sock *sk)
{
    return net_enter(sk, IO_NET_RECV);
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(kp_tcp_recvmsg_exit, long ret)
{
    return net_exit(ctx, (int)ret, IO_NET_RECV);
}
