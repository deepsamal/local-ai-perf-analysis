# Subprocess probes

`src/bpf/trace_process.bpf.c` · roadmap Phase 2

Without these, an agent running a code interpreter, a shell tool or a
browser looks idle: its thread is off-CPU and the work happens in a
process the tracer was never pointed at.

## What is captured

| Record | Probe | Carries |
|---|---|---|
| fork | `tp_btf/sched_process_fork` | parent, child, user stack of the parent |
| exec | `tp_btf/sched_process_exec` | the new image's path |
| exit | `tp_btf/sched_process_exit` (thread-group leader) | exit status and signal |
| wait | `tp_btf/sys_enter` + `sys_exit`, `wait4` and `waitid` only | duration, reaped pid, stack |

New threads are not processes and are skipped. Waits that return 0 or an
error in under 1 ms are dropped (that is `WNOHANG` polling).

**Children are followed.** A child of a traced process joins the traced
set at fork, so its own network and disk activity is recorded too, under
its own pid. `--no-follow-children` turns that off.

## How it appears in the trace

Category `subprocess`:

- One span per child from fork to exit, on a row named
  `subprocess <pid>: <program>` under the **parent**. `args` holds the
  exec path, exit status, the spawning thread, and the parent's stack at
  fork. A child still alive at the end of the trace runs to the end and
  has `still_running: true`.
- An `exec` instant on that row. The gap between the start of the span and
  `exec` is the fork-to-exec delay.
- `wait4` / `waitid` spans on a row `child waits [tid N]`.

The label is the first image the child exec'd, so `sh -c tool` shows as
`sh`. `args.execs` counts further execs.

## The lifetime span is the stall, not `wait4`

The roadmap expected `wait4` duration to match the subprocess lifetime. It
doesn't for `subprocess.run()`: Python blocks reading the child's pipes
until they close, and only then calls `wait4`, which returns at once. In
the synthetic agent the children live 130–560 ms and the reaping `wait4`
takes about 0.1 ms. The validator therefore checks the lifetime against
the snippet's sleep, and separately that every child was reaped by a
captured wait. A caller that blocks in `waitpid` itself would show a long
`wait4` span; the synthetic agent has no such call, so that case is untested.

## What is not captured

- **Children that already existed** when tracing started: no fork was
  seen, so there is no span. Their exit is ignored.
- **Daemons the agent talks to but did not spawn** (a model server started
  earlier). Point a second run at them, or use system-wide mode.
- **Containers.** `docker run` shows the `docker` client only.
- **Arguments.** Only the exec path is recorded, not `argv`.
- **A process whose main thread exits while other threads keep running**
  is reported as exited at that moment.
- **Stacks of children that have exited** by the time the trace is written
  cannot be symbolised, because `/proc/<pid>/maps` is gone. They appear as
  raw addresses with `err: symbolize_failed`. The fork stack is the
  parent's and resolves normally.

## Cost

`sys_enter` and `sys_exit` are raw tracepoints, so the two programs run on
every syscall of every process. `sys_enter` returns after one integer
compare unless the syscall is a wait. `sys_exit` returns after one
array-map read unless a traced wait is in flight. They are used instead of
a kprobe on the wait entry point because raw tracepoints exist on every
BTF kernel and need no architecture-specific symbol. Syscall numbers are
defined for x86-64 and arm64.

## Flags

`--no-subprocess` turns the surface off. With it off, children are not
followed either.
