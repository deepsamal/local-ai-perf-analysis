# Network probes

`src/bpf/trace_net.bpf.c` · roadmap Phase 1

Shows when the agent is waiting on a TCP peer: a tool API, a remote model,
a vector database, or a local model server such as `ollama serve` on
`127.0.0.1:11434`.

## What is captured

One record per `tcp_sendmsg` / `tcp_recvmsg` call that moved data, made by
the traced process or any of its children:

| Field | Source |
|---|---|
| start, duration | entry and exit of the kernel function |
| bytes | the function's return value |
| local and peer address, ports, IPv4/IPv6 | `struct sock` |
| loopback or remote | derived from the addresses |
| user stack of the caller | `bpf_get_stackid`, taken on the way out of the call |

Calls that return an error are dropped in the kernel. That includes every
`-EAGAIN` from a non-blocking socket, so an event loop polling a quiet
connection costs nothing in the trace.

## How it appears in the trace

Category `net`, events `tcp_send` and `tcp_recv`, on a row named
`net <peer> (loopback)` under the process that made the call. Connections
to the same peer share a row. Extra rows (`+`) appear only when several
connections to that peer are open at once.

Category `net_wait`, event `await response`: the time from the last byte
of a request to the first byte of the reply, with the stack of the code
that sent the request. This is derived in user space, per connection, for
connections where the traced process spoke first.

`await response` exists because the duration of `tcp_recvmsg` is not the
wait. A Python socket with a timeout, and every asyncio or epoll client,
waits in `poll`/`epoll_wait` and calls `recv` only once data is there. In
the synthetic agent each `tcp_recvmsg` takes about 10 µs while the request
takes 150 ms. For a streaming model API, `await response` is the time to
first token.

`metadata.io.net` in the JSON has totals per process and peer: connections,
requests, bytes each way, and total wait.

## What is not captured

- **Payload.** Timing, size and peer only. Reading decrypted prompts at
  `SSL_read`/`SSL_write` is what AgentSight does, for security analysis.
  The two tools sit at different layers of the same traffic.
- **TLS handshake, HTTP request/response matching, DNS.** A pipelined or
  multiplexed connection (HTTP/2) is treated as one request at a time.
- **Connection setup.** `connect()` latency is not measured.
- **UDP and QUIC, Unix-domain sockets, pipes.** A stdio MCP server or a
  tool reached over a Unix socket is invisible here. Its process shows up
  through the subprocess probes.
- **`sendfile`/`splice`** go through `tcp_sendmsg_locked` and are missed.
- **The request that is already in flight when tracing starts.** If only
  its receive side is seen, the connection is taken for a server-side one
  and gets no `await response` span.

## Probe variants

fentry/fexit is used where the kernel supports BPF trampolines and
`bpf_get_func_ret` (5.17+); otherwise kprobe/kretprobe. The start-up line
says which: `✓ net probes attached (fentry, 4 programs)`. `--io-kprobes`
forces the kprobe set.

With kretprobes the kernel keeps a limited number of return-probe
instances per function. Many threads blocked in `recv` at once can exhaust
them, and those calls are then missed. fexit has no such limit.

## Flags

`--no-net` turns the surface off. `--pid` selects the process tree;
`--io-pid` selects it for the network, subprocess and disk probes only.
