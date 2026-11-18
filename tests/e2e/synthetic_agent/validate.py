#!/usr/bin/env python3
"""Phased validator for the synthetic agent's trace output.

Design contract: as new probe surfaces land in roadmap phases, this
file gains assertions. Phase 0 assertions must all pass NOW. Phase 1+
assertions emit `PEND` (pending) with a one-line explanation of why
they're blocked. Running this script produces the project's
**state report** — a quantified view of what the tool currently sees
and what it misses.

Exit codes:
  0 = all Phase 0 assertions pass (whatever else is pending or failing)
  1 = a Phase 0 assertion failed (regression in the existing tool)
  2 = trace file missing / malformed
  3 = with --strict: a phase 1-3 assertion failed
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path


# Color codes; turn off if not a TTY or NO_COLOR is set per spec.
def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


_USE_COLOR = _supports_color()
GREEN = "\033[32m" if _USE_COLOR else ""
RED = "\033[31m" if _USE_COLOR else ""
YELLOW = "\033[33m" if _USE_COLOR else ""
DIM = "\033[2m" if _USE_COLOR else ""
BOLD = "\033[1m" if _USE_COLOR else ""
RESET = "\033[0m" if _USE_COLOR else ""


@dataclass
class Result:
    """Result of a single validator assertion."""
    name: str
    status: str  # "PASS", "FAIL", "PEND"
    detail: str = ""
    phase: int = 0


@dataclass
class State:
    """Collected statistics across the whole trace."""
    events_total: int = 0
    events_real: int = 0  # non-metadata
    categories: set = field(default_factory=set)
    pids: dict = field(default_factory=dict)  # pid -> event count
    gpu_event_count: int = 0
    cpu_event_count: int = 0
    stack_present_count: int = 0
    stack_nonempty_count: int = 0      # >= 1 resolved symbol frame
    stack_lookup_failed: int = 0       # tracer: stack id not in stack map
    stack_symbolize_failed: int = 0    # tracer: addrs found, blazesym got 0 frames
    total_duration_us: float = 0.0


def _parse_trace(path: Path) -> tuple[dict, State]:
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        print(f"{RED}FATAL{RESET}: trace file is not valid JSON: {e}", file=sys.stderr)
        sys.exit(2)
    events = data.get("traceEvents", [])
    if not isinstance(events, list):
        print(f"{RED}FATAL{RESET}: traceEvents is not a list", file=sys.stderr)
        sys.exit(2)

    state = State()
    state.events_total = len(events)
    real = [e for e in events if e.get("ph") != "M"]
    state.events_real = len(real)
    for e in real:
        cat = e.get("cat", "")
        if cat:
            state.categories.add(cat)
            if cat.startswith("gpu"):
                state.gpu_event_count += 1
            elif cat == "cpu":
                state.cpu_event_count += 1
        pid = e.get("pid")
        if pid:
            state.pids[pid] = state.pids.get(pid, 0) + 1
        args = e.get("args") or {}
        if "stack" in args:
            state.stack_present_count += 1
            stack = args["stack"]
            if isinstance(stack, list) and stack:
                err = stack[0].get("err") if isinstance(stack[0], dict) else None
                if err == "stack_lookup_failed":
                    state.stack_lookup_failed += 1
                elif err == "symbolize_failed":
                    state.stack_symbolize_failed += 1
                elif any(isinstance(fr, dict) and fr.get("sym") not in (None, "", "??")
                         for fr in stack):
                    state.stack_nonempty_count += 1
        if e.get("ph") == "X" and e.get("dur"):
            state.total_duration_us += e["dur"]
    return data, state


# ---------------------------------------------------------------------------
# Phased assertions. Each function returns a list of Result.
# ---------------------------------------------------------------------------


def phase_0_assertions(state: State) -> list[Result]:
    """Foundation — what the current tool must produce."""
    rs: list[Result] = []
    rs.append(Result(
        "trace contains events",
        "PASS" if state.events_real > 0 else "FAIL",
        f"{state.events_real} non-metadata events",
        phase=0,
    ))
    rs.append(Result(
        "trace has GPU compute category",
        "PASS" if "gpu_compute" in state.categories else "FAIL",
        f"categories seen: {sorted(state.categories) or 'none'}",
        phase=0,
    ))
    rs.append(Result(
        "trace has at least 20 GPU events",
        "PASS" if state.gpu_event_count >= 20 else "FAIL",
        f"counted {state.gpu_event_count} gpu events",
        phase=0,
    ))
    rs.append(Result(
        "trace has stack arrays",
        "PASS" if state.stack_present_count > 0 else "FAIL",
        f"{state.stack_present_count} events have a 'stack' key",
        phase=0,
    ))
    rs.append(Result(
        "stack arrays are non-empty (blazesym resolved frames)",
        "PASS" if state.stack_nonempty_count > 0 else "FAIL",
        f"{state.stack_nonempty_count}/{state.stack_present_count} resolved "
        f"({state.stack_lookup_failed} lookup_failed, "
        f"{state.stack_symbolize_failed} symbolize_failed)",
        phase=0,
    ))
    return rs


# Phases 1-3 look at individual events, not just category counts. The
# agent is deterministic, so each assertion can state what the trace
# must contain for a given --iters / --latency-ms.
#
# Status meanings here:
#   PEND  the probe surface produced nothing at all (not built, disabled,
#         or failed to attach) -- the assertion can't be evaluated
#   PASS / FAIL  the surface is live and the trace does / doesn't hold up

SEARCH_PORT = 8765
CORPUS_MARK = "/synthetic_agent/corpus/doc_"


@dataclass
class Ctx:
    """What the phase 1-3 assertions need to know about the run."""
    events: list
    agent_pid: int | None
    iters: int
    latency_ms: int
    measured_ms: dict = field(default_factory=dict)

    def mine(self, e: dict) -> bool:
        return self.agent_pid is None or e.get("pid") == self.agent_pid


def _stack_syms(e: dict) -> list[str]:
    stack = (e.get("args") or {}).get("stack") or []
    out = []
    for fr in stack:
        if isinstance(fr, dict):
            out.append(f"{fr.get('sym', '')} {fr.get('file', '')}")
    return out


def _stack_resolved(e: dict) -> bool:
    stack = (e.get("args") or {}).get("stack") or []
    return any(isinstance(fr, dict) and fr.get("sym") not in (None, "", "??")
               for fr in stack)


def _stack_mentions(evs: list, *needles: str) -> int:
    """How many of `evs` have a frame naming any of `needles`."""
    n = 0
    for e in evs:
        if any(nd in s for s in _stack_syms(e) for nd in needles):
            n += 1
    return n


def _attribution_results(evs: list, what: str, func: str, phase: int) -> list[Result]:
    """Two-step stack check shared by all three phases: do the stacks
    resolve at all, and do they reach the agent's Python function."""
    with_stack = [e for e in evs if "stack" in (e.get("args") or {})]
    resolved = [e for e in with_stack if _stack_resolved(e)]
    rs = [Result(
        f"{what} stacks resolve to symbols",
        "PASS" if resolved else "FAIL",
        f"{len(resolved)}/{len(with_stack)} stacks resolved ({len(evs)} events)",
        phase=phase,
    )]
    hits = _stack_mentions(with_stack, func, "agent.py")
    rs.append(Result(
        f"{what} stacks include {func}() / agent.py",
        "PASS" if hits else "FAIL",
        f"{hits}/{len(with_stack)} stacks name the agent's Python code"
        + ("" if hits else " -- native frames only; Python frames need a "
           "frame-pointer build of CPython plus -X perf (docs/PYTHON_ATTRIBUTION.md)"),
        phase=phase,
    ))
    return rs


def _pending(names: list[str], why: str, phase: int) -> list[Result]:
    return [Result(n, "PEND", why, phase=phase) for n in names]


def phase_1_assertions(ctx: Ctx) -> list[Result]:
    """Network probes (trace_net.bpf.c)."""
    names = [
        "trace has 'net' category events",
        "search_tool() calls captured as request/response pairs",
        "network wait matches iterations x server latency (within 20%)",
        "peer identified as loopback",
        "network stacks resolve to symbols",
        "network stacks include search_tool() / agent.py",
    ]
    all_net = [e for e in ctx.events if str(e.get("cat", "")).startswith("net")]
    if not all_net:
        return _pending(names, "no network events in trace (probes not attached?)", 1)

    def to_server(e):
        return ctx.mine(e) and str((e.get("args") or {}).get("peer", "")).endswith(f":{SEARCH_PORT}")

    calls = [e for e in all_net if e.get("cat") == "net" and to_server(e)]
    sends = [e for e in calls if e["name"] == "tcp_send" and e["args"].get("bytes", 0) > 0]
    recvs = [e for e in calls if e["name"] == "tcp_recv" and e["args"].get("bytes", 0) > 0]
    waits = [e for e in all_net if e.get("cat") == "net_wait" and to_server(e)]
    wait_ms = sum(e.get("dur", 0) for e in waits) / 1000.0
    expect_ms = ctx.iters * ctx.latency_ms
    ctx.measured_ms["network"] = wait_ms

    rs = [Result(names[0], "PASS", f"{len(all_net)} events", phase=1)]
    ok = len(waits) == ctx.iters and len(sends) >= ctx.iters and len(recvs) >= ctx.iters
    rs.append(Result(
        names[1], "PASS" if ok else "FAIL",
        f"{len(waits)} await-response spans (expected {ctx.iters}); "
        f"{len(sends)} sends, {len(recvs)} recvs to :{SEARCH_PORT}",
        phase=1,
    ))
    within = expect_ms > 0 and abs(wait_ms - expect_ms) <= 0.2 * expect_ms
    rs.append(Result(
        names[2], "PASS" if within else "FAIL",
        f"measured {wait_ms:.0f} ms vs expected {expect_ms} ms "
        f"({(wait_ms - expect_ms) / expect_ms * 100:+.1f}%)" if expect_ms else "no expectation",
        phase=1,
    ))
    lo = [e for e in calls if e["args"].get("loopback") is True]
    rs.append(Result(
        names[3], "PASS" if calls and len(lo) == len(calls) else "FAIL",
        f"{len(lo)}/{len(calls)} calls flagged loopback",
        phase=1,
    ))
    rs += _attribution_results(sends + waits, "network", "search_tool", 1)
    return rs


def phase_2_assertions(ctx: Ctx) -> list[Result]:
    """Subprocess probes (trace_process.bpf.c)."""
    names = [
        "trace has 'subprocess' category events",
        "run_code_tool() spawns captured as fork + exec",
        "subprocess lifetime matches the snippet's sleep",
        "every spawned child is reaped by a captured wait",
        "subprocess stacks resolve to symbols",
        "subprocess stacks include run_code_tool() / agent.py",
    ]
    all_sp = [e for e in ctx.events if e.get("cat") == "subprocess"]
    if not all_sp:
        return _pending(names, "no subprocess events in trace (probes not attached?)", 2)

    spawns = sorted(
        (e for e in all_sp if e.get("ph") == "X" and "child_pid" in (e.get("args") or {})
         and ctx.mine(e)),
        key=lambda e: e["ts"],
    )
    waits = [e for e in all_sp if e.get("ph") == "X" and e.get("name") in ("wait4", "waitid")
             and ctx.mine(e)]
    ctx.measured_ms["subprocess"] = sum(e.get("dur", 0) for e in spawns) / 1000.0

    # The agent runs snippet (step % 5) on every third step; snippet k
    # sleeps 100 + 100k ms.
    steps = [i for i in range(ctx.iters) if i % 3 == 0]
    expect_sleep = [100 + (i % 5) * 100 for i in steps]

    rs = [Result(names[0], "PASS", f"{len(all_sp)} events", phase=2)]
    py = [e for e in spawns if "python" in str(e["args"].get("exec", ""))]
    rs.append(Result(
        names[1],
        "PASS" if len(spawns) == len(steps) and len(py) == len(spawns) else "FAIL",
        f"{len(spawns)} children of the agent (expected {len(steps)}), "
        f"{len(py)} exec'd a python interpreter",
        phase=2,
    ))

    # Allow interpreter start-up on top of the sleep, nothing below it.
    slack_ms = 400
    life = [e.get("dur", 0) / 1000.0 for e in spawns]
    good = len(life) == len(expect_sleep) and all(
        want <= got <= want + slack_ms for got, want in zip(life, expect_sleep))
    rs.append(Result(
        names[2], "PASS" if good else "FAIL",
        "lifetimes " + ", ".join(f"{x:.0f}" for x in life) + " ms vs sleeps "
        + ", ".join(str(x) for x in expect_sleep) + f" ms (+0..{slack_ms} ms start-up)",
        phase=2,
    ))

    reaped = {e["args"].get("reaped_pid") for e in waits}
    missing = [e["args"]["child_pid"] for e in spawns if e["args"]["child_pid"] not in reaped]
    wait_ms = [e.get("dur", 0) / 1000.0 for e in waits if e["args"].get("reaped_pid")]
    rs.append(Result(
        names[3], "PASS" if spawns and not missing else "FAIL",
        f"{len(spawns) - len(missing)}/{len(spawns)} children reaped; the reaping wait itself "
        f"took {max(wait_ms, default=0):.2f} ms at most -- subprocess.run() blocks on the "
        "child's pipes and only then calls wait4, so the stall is the lifetime span, not wait4",
        phase=2,
    ))
    rs += _attribution_results(spawns, "subprocess", "run_code_tool", 2)
    return rs


def phase_3_assertions(ctx: Ctx) -> list[Result]:
    """Disk probes (trace_disk.bpf.c)."""
    names = [
        "trace has 'disk' category events",
        "read_documents() reads captured with path attribution",
        "path resolution succeeded on >= 80% of file events",
        "disk stacks resolve to symbols",
        "disk stacks include read_documents() / agent.py",
    ]
    all_disk = [e for e in ctx.events if e.get("cat") == "disk"]
    if not all_disk:
        return _pending(names, "no disk events in trace (probes not attached?)", 3)

    mine = [e for e in all_disk if ctx.mine(e)]
    corpus = [e for e in mine if e["args"].get("op") == "read"
              and CORPUS_MARK in str(e["args"].get("path", ""))]
    ctx.measured_ms["disk"] = sum(e.get("dur", 0) for e in corpus) / 1000.0

    want_docs = set()
    for i in range(ctx.iters):
        want_docs |= {i % 20, (i + 7) % 20, (i + 13) % 20}
    got_docs = set()
    for e in corpus:
        tail = str(e["args"]["path"]).rsplit("doc_", 1)[-1].split(".")[0]
        if tail.isdigit():
            got_docs.add(int(tail))

    rs = [Result(names[0], "PASS", f"{len(all_disk)} events", phase=3)]
    ok = len(corpus) >= 3 * ctx.iters and want_docs <= got_docs
    rs.append(Result(
        names[1], "PASS" if ok else "FAIL",
        f"{len(corpus)} reads under the corpus (expected >= {3 * ctx.iters}); "
        f"{len(want_docs & got_docs)}/{len(want_docs)} expected documents seen",
        phase=3,
    ))
    absolute = [e for e in mine if e["args"].get("path_absolute") is True]
    frac = len(absolute) / len(mine) if mine else 0.0
    rs.append(Result(
        names[2], "PASS" if frac >= 0.8 else "FAIL",
        f"{len(absolute)}/{len(mine)} agent file events have an absolute path ({frac * 100:.0f}%)",
        phase=3,
    ))
    rs += _attribution_results(corpus, "disk", "read_documents", 3)
    return rs


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def _status_glyph(s: str) -> str:
    if s == "PASS":
        return f"{GREEN}PASS{RESET}"
    if s == "FAIL":
        return f"{RED}FAIL{RESET}"
    if s == "PEND":
        return f"{YELLOW}PEND{RESET}"
    return s


def _print_phase(title: str, results: list[Result]) -> None:
    print(f"\n{BOLD}=== {title} ==={RESET}")
    for r in results:
        glyph = _status_glyph(r.status)
        # Detail in dim text on a continuation line when present.
        if r.detail:
            print(f"  [{glyph}] {r.name}")
            print(f"         {DIM}{r.detail}{RESET}")
        else:
            print(f"  [{glyph}] {r.name}")


def _estimate_invisible_time(
    iters: int, latency_ms: int = 150
) -> dict[str, float]:
    """Rough wall-clock estimate per bottleneck class for the synthetic
    agent. These match the synthetic_agent.py defaults; if you tune
    AGENT_ITERS etc, the estimates scale linearly.

    Used to tell the user 'X% of your agent's time is invisible to the
    current tool', which is the killer signal for motivating the
    roadmap phases."""
    network_s = iters * (latency_ms / 1000.0)
    # Subprocess runs every 3rd iter; snippet duration varies 100-500 ms;
    # average ~300 ms each, including spawn overhead.
    subprocess_count = (iters + 2) // 3  # ceil(iters/3)
    subprocess_s = subprocess_count * 0.3
    # Disk: 3 file reads per iter at ~150 µs each (page cache).
    disk_s = iters * 3 * 0.00015
    # GPU: roughly 2 small matmuls per iter; varies widely by HW, but
    # ~10-30 ms per iter total is typical for our tensor sizes.
    gpu_s = iters * 0.02
    return {
        "network": network_s,
        "subprocess": subprocess_s,
        "disk": disk_s,
        "gpu": gpu_s,
    }


def _print_state_report(state: State, iters: int, latency_ms: int = 150,
                        measured_ms: dict | None = None) -> None:
    measured_ms = measured_ms or {}
    print(f"\n{BOLD}=== state report ==={RESET}")
    print(f"  events:        {state.events_total} total / {state.events_real} real")
    print(f"  categories:    {', '.join(sorted(state.categories)) or '(none)'}")
    print(f"  PIDs in trace: {sorted(state.pids.keys())[:8]}"
          + (' ...' if len(state.pids) > 8 else ''))
    print(f"  stacks:        {state.stack_nonempty_count} non-empty "
          f"/ {state.stack_present_count} attempted "
          f"/ {state.events_real} total")
    print(f"  visible time:  {state.total_duration_us/1000:.1f} ms "
          f"(sum of all event durations — overlap counted multiply)")

    # The killer signal: how much of the agent is INVISIBLE today.
    est = _estimate_invisible_time(iters, latency_ms)
    total_est = sum(est.values())

    visible_classes = []
    invisible_classes = []
    if "gpu_compute" in state.categories or "gpu_xfer" in state.categories:
        visible_classes.append(("gpu", est["gpu"]))
    else:
        invisible_classes.append(("gpu", est["gpu"]))
    for cls in ("network", "disk", "subprocess"):
        in_trace = (
            (cls == "network" and any(c.startswith("net") for c in state.categories))
            or (cls == "disk" and "disk" in state.categories)
            or (cls == "subprocess" and "subprocess" in state.categories)
        )
        if in_trace:
            visible_classes.append((cls, est[cls]))
        else:
            invisible_classes.append((cls, est[cls]))

    visible_s = sum(t for _, t in visible_classes)
    invisible_s = sum(t for _, t in invisible_classes)

    print(f"\n{BOLD}  estimated agent wall-clock attribution{RESET}")
    print(f"  {DIM}(synthetic — recomputes if you tune AGENT_ITERS / latency){RESET}")
    print(f"    visible to tool:   {visible_s*1000:6.0f} ms  ({visible_s/total_est*100:4.1f}%)")
    for cls, t in visible_classes:
        got = f"   measured {measured_ms[cls]:7.1f} ms" if cls in measured_ms else ""
        print(f"      {GREEN}+{RESET} {cls:11s} {t*1000:6.0f} ms{got}")
    print(f"    invisible to tool: {invisible_s*1000:6.0f} ms  ({invisible_s/total_est*100:4.1f}%)")
    for cls, t in invisible_classes:
        print(f"      {YELLOW}-{RESET} {cls:11s} {t*1000:6.0f} ms")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("trace", type=Path)
    parser.add_argument("--iters", type=int, default=10,
                        help="must match AGENT_ITERS used in the run")
    parser.add_argument("--agent-pid", type=int, default=None,
                        help="pid of the synthetic agent; phase 1-3 assertions "
                        "then only count its events")
    parser.add_argument("--latency-ms", type=int, default=150,
                        help="must match the fake search server's --latency-ms")
    parser.add_argument("--write-report", type=Path, default=None,
                        help="optionally write a Markdown state report")
    parser.add_argument("--strict", action="store_true",
                        help="exit 3 when a phase 1-3 assertion fails "
                        "(default: only Phase 0 failures are fatal)")
    args = parser.parse_args()

    if not args.trace.exists():
        print(f"{RED}FATAL{RESET}: trace not found at {args.trace}", file=sys.stderr)
        return 2

    data, state = _parse_trace(args.trace)

    ctx = Ctx(
        events=[e for e in data.get("traceEvents", []) if e.get("ph") != "M"],
        agent_pid=args.agent_pid,
        iters=args.iters,
        latency_ms=args.latency_ms,
    )
    phase_results = {
        0: phase_0_assertions(state),
        1: phase_1_assertions(ctx),
        2: phase_2_assertions(ctx),
        3: phase_3_assertions(ctx),
    }
    _print_phase("Phase 0 — foundation (must pass today)", phase_results[0])
    _print_phase("Phase 1 — network bottleneck visibility (Task #14)", phase_results[1])
    _print_phase("Phase 2 — subprocess bottleneck visibility (Task #16)", phase_results[2])
    _print_phase("Phase 3 — disk bottleneck visibility (Task #15)", phase_results[3])
    _print_state_report(state, args.iters, args.latency_ms, ctx.measured_ms)

    # Summary
    phase_0_fails = [r for r in phase_results[0] if r.status == "FAIL"]
    later_fails = [r for p, rs in phase_results.items() if p > 0
                   for r in rs if r.status == "FAIL"]
    n_pend = sum(1 for rs in phase_results.values() for r in rs if r.status == "PEND")
    n_pass = sum(1 for rs in phase_results.values() for r in rs if r.status == "PASS")

    print(f"\n{BOLD}=== summary ==={RESET}")
    print(f"  passing:   {n_pass}")
    print(f"  pending:   {n_pend}  (probe surface produced no events)")
    print(f"  failing:   {len(phase_0_fails) + len(later_fails)}")
    for r in phase_0_fails + later_fails:
        print(f"    {RED}-{RESET} phase {r.phase}: {r.name}")

    if args.write_report:
        _write_markdown_report(
            args.write_report, args.trace, data, state, phase_results, args.iters,
            args.latency_ms, ctx.measured_ms,
        )
        print(f"\n  wrote markdown state report to {args.write_report}")

    if phase_0_fails:
        print(f"\n{RED}STATUS: FAIL{RESET} — Phase 0 has {len(phase_0_fails)} broken assertion(s)")
        return 1
    if later_fails:
        print(f"\n{YELLOW}STATUS: BASELINE OK, GAPS{RESET} — Phase 0 passes; "
              f"{len(later_fails)} phase 1-3 assertion(s) fail, {n_pend} pending")
        return 3 if args.strict else 0
    print(f"\n{GREEN}STATUS: OK{RESET} — Phase 0 passes; "
          f"{n_pend} assertions pending")
    return 0


def _write_markdown_report(
    path: Path, trace_path: Path, data: dict, state: State,
    phase_results: dict, iters: int, latency_ms: int = 150,
    measured_ms: dict | None = None,
) -> None:
    measured_ms = measured_ms or {}
    """Write a state-of-the-art report for commit alongside the roadmap."""
    lines: list[str] = []
    lines.append("# Synthetic agent state report")
    lines.append("")
    lines.append("Auto-generated by `tests/e2e/synthetic_agent/validate.py --write-report`.")
    lines.append("Snapshot of what the tool currently captures vs. what it misses,")
    lines.append("measured against a fixed synthetic agent workload.")
    lines.append("")
    lines.append(f"**Trace source:** `{trace_path}`")
    lines.append(f"**Trace events:** {state.events_total} total, {state.events_real} non-metadata")
    lines.append(f"**Iterations:** {iters}")
    lines.append("")
    lines.append("## Captured")
    lines.append("")
    lines.append(f"- Categories: `{sorted(state.categories) or 'none'}`")
    lines.append(f"- GPU events: {state.gpu_event_count}")
    lines.append(f"- CPU events: {state.cpu_event_count}")
    lines.append(f"- Stack arrays attempted: {state.stack_present_count}")
    lines.append(f"- Stack arrays non-empty (blazesym resolved): {state.stack_nonempty_count}")
    lines.append(f"- Stack lookups failed (stack map problem): {state.stack_lookup_failed}")
    lines.append(f"- Stacks found but unsymbolized (blazesym/pid problem): {state.stack_symbolize_failed}")
    lines.append("")
    lines.append("## Per-phase assertion status")
    lines.append("")
    for phase, results in phase_results.items():
        phase_name = {
            0: "Phase 0 — foundation",
            1: "Phase 1 — network",
            2: "Phase 2 — subprocess",
            3: "Phase 3 — disk",
        }[phase]
        lines.append(f"### {phase_name}")
        lines.append("")
        lines.append("| Status | Assertion | Detail |")
        lines.append("|---|---|---|")
        for r in results:
            lines.append(f"| {r.status} | {r.name} | {r.detail} |")
        lines.append("")

    est = _estimate_invisible_time(iters, latency_ms)
    total = sum(est.values())
    lines.append("## Estimated agent wall-clock attribution")
    lines.append("")
    lines.append("Synthetic numbers (the agent is deterministic so we can predict the budget):")
    lines.append("")
    lines.append("| Bottleneck class | Estimated time | Visible today? | Measured in this trace |")
    lines.append("|---|---|---|---|")
    visible_pct = 0.0
    for cls in ("gpu", "network", "subprocess", "disk"):
        t_ms = est[cls] * 1000
        visible = (
            (cls == "gpu" and "gpu_compute" in state.categories)
            or (cls == "network" and any(c.startswith("net") for c in state.categories))
            or (cls == "subprocess" and "subprocess" in state.categories)
            or (cls == "disk" and "disk" in state.categories)
        )
        if visible:
            visible_pct += t_ms / (total * 1000) * 100
        got = f"{measured_ms[cls]:.1f} ms" if cls in measured_ms else "—"
        lines.append(
            f"| {cls} | ~{t_ms:.0f} ms | {'✅ yes' if visible else '❌ no — see roadmap'} | {got} |"
        )
    lines.append("")
    lines.append(
        f"**Current visibility: ~{visible_pct:.0f}% of estimated agent wall-clock.**"
    )
    if visible_pct < 99.5:
        lines.append(
            f"The remaining ~{100-visible_pct:.0f}% lives in bottleneck classes the tool "
            "doesn't yet instrument — see [ROADMAP.md](ROADMAP.md) Phases 1–3."
        )
    lines.append("")
    lines.append(
        "Network is the time from the last byte of each request to the first byte "
        "of its reply; subprocess is fork-to-exit lifetime; disk is time inside "
        "`vfs_read` on the corpus files (page-cache hits included)."
    )
    lines.append("")
    path.write_text("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main())
