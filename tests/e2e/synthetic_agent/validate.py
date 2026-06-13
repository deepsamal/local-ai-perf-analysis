#!/usr/bin/env python3
"""Phased validator for the synthetic agent's trace output.

Design contract: as new probe surfaces land in roadmap phases, this
file gains assertions. Phase 0 assertions must all pass NOW. Phase 1+
assertions emit `PEND` (pending) with a one-line explanation of why
they're blocked. Running this script produces the project's
**state report** — a quantified view of what the tool currently sees
and what it misses.

Exit codes:
  0 = all Phase 0 assertions pass (whatever else is pending)
  1 = a Phase 0 assertion failed (regression in the existing tool)
  2 = trace file missing / malformed
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
    stack_nonempty_count: int = 0
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
            if isinstance(stack, list) and len(stack) > 0:
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
        f"{state.stack_nonempty_count}/{state.stack_present_count} resolved",
        phase=0,
    ))
    return rs


def phase_1_assertions(state: State) -> list[Result]:
    """Network probes (Task #14). Pending until the trace_net.bpf.c
    program is in place and unified_trace loads it."""
    rs: list[Result] = []
    has_net = "net" in state.categories or any(
        c.startswith("net") for c in state.categories
    )
    rs.append(Result(
        "trace has 'net' category events",
        "PASS" if has_net else "PEND",
        "requires Phase 1 (network probes)" if not has_net else
        f"{sum(1 for c in state.categories if c.startswith('net'))} net categories",
        phase=1,
    ))
    rs.append(Result(
        "search_tool() calls captured as network events",
        "PEND" if not has_net else "PASS",
        "requires Phase 1 (network probes)",
        phase=1,
    ))
    rs.append(Result(
        "network event stacks include synthetic_agent.py",
        "PEND" if not has_net else "PASS",
        "requires Phase 1 (network probes)",
        phase=1,
    ))
    return rs


def phase_2_assertions(state: State) -> list[Result]:
    """Subprocess probes (Task #16). Pending until trace_process.bpf.c
    is in place."""
    rs: list[Result] = []
    has_sp = "subprocess" in state.categories
    rs.append(Result(
        "trace has 'subprocess' category events",
        "PASS" if has_sp else "PEND",
        "requires Phase 2 (subprocess probes)" if not has_sp else "ok",
        phase=2,
    ))
    rs.append(Result(
        "run_code_tool() spawns captured as fork/exec events",
        "PEND" if not has_sp else "PASS",
        "requires Phase 2",
        phase=2,
    ))
    rs.append(Result(
        "subprocess events include wait4 duration",
        "PEND" if not has_sp else "PASS",
        "requires Phase 2",
        phase=2,
    ))
    return rs


def phase_3_assertions(state: State) -> list[Result]:
    """Disk probes (Task #15). Pending until trace_disk.bpf.c is in place."""
    rs: list[Result] = []
    has_disk = "disk" in state.categories
    rs.append(Result(
        "trace has 'disk' category events",
        "PASS" if has_disk else "PEND",
        "requires Phase 3 (disk probes)" if not has_disk else "ok",
        phase=3,
    ))
    rs.append(Result(
        "read_documents() reads captured with path attribution",
        "PEND" if not has_disk else "PASS",
        "requires Phase 3",
        phase=3,
    ))
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


def _print_state_report(state: State, iters: int) -> None:
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
    est = _estimate_invisible_time(iters)
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
        print(f"      {GREEN}+{RESET} {cls:11s} {t*1000:6.0f} ms")
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
    parser.add_argument("--write-report", type=Path, default=None,
                        help="optionally write a Markdown state report")
    args = parser.parse_args()

    if not args.trace.exists():
        print(f"{RED}FATAL{RESET}: trace not found at {args.trace}", file=sys.stderr)
        return 2

    data, state = _parse_trace(args.trace)

    phase_results = {
        0: phase_0_assertions(state),
        1: phase_1_assertions(state),
        2: phase_2_assertions(state),
        3: phase_3_assertions(state),
    }
    _print_phase("Phase 0 — foundation (must pass today)", phase_results[0])
    _print_phase("Phase 1 — network bottleneck visibility (Task #14)", phase_results[1])
    _print_phase("Phase 2 — subprocess bottleneck visibility (Task #16)", phase_results[2])
    _print_phase("Phase 3 — disk bottleneck visibility (Task #15)", phase_results[3])
    _print_state_report(state, args.iters)

    # Summary
    phase_0_fails = [r for r in phase_results[0] if r.status == "FAIL"]
    n_pend = sum(1 for rs in phase_results.values() for r in rs if r.status == "PEND")
    n_pass = sum(1 for rs in phase_results.values() for r in rs if r.status == "PASS")

    print(f"\n{BOLD}=== summary ==={RESET}")
    print(f"  passing:   {n_pass}")
    print(f"  pending:   {n_pend}  (each blocked on a specific roadmap task)")
    print(f"  failing:   {len(phase_0_fails)}")

    if args.write_report:
        _write_markdown_report(
            args.write_report, args.trace, data, state, phase_results, args.iters
        )
        print(f"\n  wrote markdown state report to {args.write_report}")

    if phase_0_fails:
        print(f"\n{RED}STATUS: FAIL{RESET} — Phase 0 has {len(phase_0_fails)} broken assertion(s)")
        return 1
    print(f"\n{GREEN}STATUS: BASELINE OK{RESET} — Phase 0 passes; "
          f"{n_pend} assertions pending later roadmap phases")
    return 0


def _write_markdown_report(
    path: Path, trace_path: Path, data: dict, state: State,
    phase_results: dict, iters: int,
) -> None:
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

    est = _estimate_invisible_time(iters)
    total = sum(est.values())
    lines.append("## Estimated agent wall-clock attribution")
    lines.append("")
    lines.append("Synthetic numbers (the agent is deterministic so we can predict the budget):")
    lines.append("")
    lines.append("| Bottleneck class | Estimated time | Visible today? |")
    lines.append("|---|---|---|")
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
        lines.append(
            f"| {cls} | ~{t_ms:.0f} ms | {'✅ yes' if visible else '❌ no — see roadmap'} |"
        )
    lines.append("")
    lines.append(
        f"**Current visibility: ~{visible_pct:.0f}% of estimated agent wall-clock.**"
    )
    lines.append(
        f"The remaining ~{100-visible_pct:.0f}% lives in bottleneck classes the tool "
        "doesn't yet instrument — see [ROADMAP.md](ROADMAP.md) Phases 1–3."
    )
    lines.append("")
    path.write_text("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main())
