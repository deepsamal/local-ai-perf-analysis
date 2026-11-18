//! Correlates the raw ETW stream into timeline spans for the target
//! process(es). Platform-independent so it is unit-tested on Linux.
//!
//! CPU model (per thread), driven by CSwitch + ReadyThread:
//!   on-CPU    : CSwitch(new=tid) .. CSwitch(old=tid)
//!   blocked   : switched out with state Waiting .. ReadyThread(tid)
//!   runnable  : ReadyThread(tid) (or preempted switch-out) .. switched in
//! This mirrors the eBPF tool's "Off-CPU (blocked)" / "Runnable (preempted)"
//! spans so both traces read the same in Perfetto.
//!
//! GPU model (per DxgKrnl context, PresentMon-style):
//!   * DmaPacket_Start/Info present for the context -> hardware execution
//!     span = [max(dma_start, previous completion on the context), done].
//!   * Otherwise (hardware-scheduled queues emit no DMA events) fall back to
//!     QueuePacket_Start .. QueuePacket_Stop, which includes queueing time.
//!
//! Wait/Signal packets are synchronisation, not work, and are skipped.

use crate::model::*;
use crate::stacks::{folded_key, module_name, user_frames, StackIndex, Symbols};
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone, Default)]
pub struct Target {
    pub pids: Vec<u32>,
    /// Case-insensitive image name match, e.g. "ollama.exe" or "ollama".
    pub names: Vec<String>,
    pub follow_children: bool,
    /// Never trace this pid (the collector itself, which is a descendant of
    /// the target when launched from it).
    pub exclude_pid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Phase {
    Complete { dur_us: f64 },
    Instant,
}

#[derive(Debug, Clone)]
pub struct Span {
    pub name: String,
    pub cat: &'static str,
    pub ts_us: f64,
    pub phase: Phase,
    pub pid: u32,
    pub tid: u32,
    pub args: serde_json::Value,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ProcSummary {
    pub name: String,
    pub on_cpu_ms: f64,
    pub blocked_ms: f64,
    pub runnable_ms: f64,
    pub blocked_by_reason_ms: BTreeMap<String, f64>,
    pub gpu_busy_ms: f64,
    pub gpu_packets: u64,
    pub gpu_source: String,
    pub hard_faults: u64,
    pub hard_fault_bytes: u64,
    pub tcp_sent_bytes: u64,
    pub tcp_recv_bytes: u64,
    pub threads: usize,
    pub cpu_samples: u64,
    /// Samples inside ETW's own stack walking (observer overhead of --stacks).
    pub tracing_overhead_samples: u64,
    pub blocked_spans_with_stack: u64,
    /// Thread samples taken by the Python sampler (0 = not a Python process).
    pub py_thread_samples: u64,
    /// Blocked spans that got a Python stack from those samples.
    pub blocked_spans_with_py_stack: u64,
}

#[derive(Debug, Default)]
pub struct Analysis {
    pub spans: Vec<Span>,
    pub t0: Ts,
    pub targets: Vec<u32>,
    pub proc_names: HashMap<u32, String>,
    pub thread_pid: HashMap<u32, u32>,
    pub summary: BTreeMap<u32, ProcSummary>,
    pub unknown_tid_switches: u64,
    /// (pid, tid) -> "name-or-entry-point (tid)"
    pub thread_labels: BTreeMap<(u32, u32), String>,
    /// Folded on-CPU sample stacks (weight = samples, ~1 ms each).
    pub folded_oncpu: BTreeMap<String, u64>,
    /// Folded blocked stacks (weight = microseconds blocked).
    pub folded_offcpu: BTreeMap<String, u64>,
    pub stacks_in_capture: usize,
    /// Folded Python stacks, weight = samples (wall clock: a waiting
    /// thread is sampled too).
    pub folded_py: BTreeMap<String, u64>,
    /// Folded Python stacks of blocked spans, weight = microseconds blocked.
    pub folded_py_offcpu: BTreeMap<String, u64>,
    /// (pid, Python track id) -> real thread id, for track labels.
    pub py_tracks: BTreeMap<(u32, u32), u32>,
    /// Folded native stacks of the code that submitted GPU work, weight =
    /// microseconds of GPU execution of the packets that carried a stack.
    pub folded_gpu: BTreeMap<String, u64>,
    /// TCP traffic by the Python code that caused it.
    pub py_net: BTreeMap<PyNetKey, PyNet>,
}

/// (process label, first frame outside the networking libraries, remote)
pub type PyNetKey = (String, String, String);

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct PyNet {
    pub sent_bytes: u64,
    pub recv_bytes: u64,
    pub events: u64,
    /// Events matched through the thread that logged them, as opposed to
    /// "the only Python thread in a socket call at that moment".
    pub by_thread: u64,
}

/// Is this Python frame ("func (file:line)") inside a networking library
/// rather than the code that decided to talk to the network?
pub fn py_net_plumbing(frame: &str) -> bool {
    let file = frame.rsplit_once(" (").map(|x| x.1).unwrap_or("").replace('\\', "/").to_ascii_lowercase();
    const LIBS: [&str; 16] = [
        "socket.py", "ssl.py", "selectors.py", "http/client.py", "socketserver.py", "urllib/", "urllib3/",
        "asyncio/", "requests/", "httpx/", "httpcore/", "aiohttp/", "anyio/", "h11/", "h2/", "websockets/",
    ];
    LIBS.iter().any(|l| file.starts_with(l) || file.contains(&format!("/{l}")))
}

/// How far from a GPU submission an on-CPU sample of the submitting thread
/// may be and still stand in for it (FILETIME ticks): 2 ms.
const GPU_SAMPLE_MAX: Ts = 20_000;
/// User frames kept on a GPU span (leaf-most).
const GPU_STACK_FRAMES: usize = 16;

/// Frames kept on a TCP event (leaf-most).
const PY_TCP_FRAMES: usize = 16;

/// Sampled Python stacks per thread, for joining to spans by time.
struct PyIndex<'a> {
    /// tid -> runs, ordered by time
    by_tid: HashMap<u32, Vec<PyRun<'a>>>,
    /// pid -> its Python threads
    by_pid: HashMap<u32, Vec<u32>>,
}

/// (first sample, last sample, frames leaf first)
type PyRun<'a> = (Ts, Ts, &'a [String]);

/// How far outside a span a sample may lie and still be attached to it
/// (FILETIME ticks). A thread about to block, or just woken, is still in
/// the same Python call a few sampling periods either side.
const PY_NEAREST_MAX: Ts = 500_000; // 50 ms

impl<'a> PyIndex<'a> {
    fn build(raw: &'a [Raw]) -> Self {
        let mut by_tid: HashMap<u32, Vec<PyRun<'a>>> = HashMap::new();
        let mut by_pid: HashMap<u32, Vec<u32>> = HashMap::new();
        for r in raw {
            if let Raw::PyStack { ts, last_ts, pid, tid, frames, .. } = r {
                if !frames.is_empty() {
                    by_tid.entry(*tid).or_default().push((*ts, *last_ts, frames.as_slice()));
                    let v = by_pid.entry(*pid).or_default();
                    if !v.contains(tid) {
                        v.push(*tid);
                    }
                }
            }
        }
        for v in by_tid.values_mut() {
            v.sort_by_key(|x| x.0);
        }
        PyIndex { by_tid, by_pid }
    }

    /// The one Python thread of `pid` that was inside a networking library
    /// at `ts`, if there is exactly one. Used for TCP events the kernel
    /// logged from a thread that is not the caller.
    fn only_thread_in_net_call(&self, pid: u32, ts: Ts) -> Option<(u32, &'a [String])> {
        let mut hit = None;
        for &tid in self.by_pid.get(&pid)? {
            if let Some((f, _, _)) = self.lookup(tid, ts, ts) {
                if f.iter().take(8).any(|x| py_net_plumbing(x)) {
                    if hit.is_some() {
                        return None; // ambiguous
                    }
                    hit = Some((tid, f));
                }
            }
        }
        hit
    }

    /// Python stack of `tid` for the span [from, to]: the run that covers
    /// most of it, else the nearest sample within PY_NEAREST_MAX.
    /// Returns (frames, samples fell inside the span, distance in ms).
    fn lookup(&self, tid: u32, from: Ts, to: Ts) -> Option<(&'a [String], bool, f64)> {
        let runs = self.by_tid.get(&tid)?;
        let mut best: Option<(Ts, &'a [String])> = None;
        let mut nearest: Option<(Ts, &'a [String])> = None;
        for &(s, e, f) in runs {
            if e >= from && s <= to {
                // +1 so a single sample inside the span counts
                let overlap = e.min(to) - s.max(from) + 1;
                if best.map(|b| overlap > b.0).unwrap_or(true) {
                    best = Some((overlap, f));
                }
            } else {
                let gap = if e < from { from - e } else { s - to };
                if gap <= PY_NEAREST_MAX && nearest.map(|n| gap < n.0).unwrap_or(true) {
                    nearest = Some((gap, f));
                }
            }
        }
        match (best, nearest) {
            (Some((_, f)), _) => Some((f, true, 0.0)),
            (None, Some((gap, f))) => Some((f, false, gap as f64 / 10_000.0)),
            _ => None,
        }
    }
}

/// Frames kept per Python stack in the JSON (leaf-most).
const PY_MAX_FRAMES: usize = 48;

fn us(t: Ts, t0: Ts) -> f64 {
    (t - t0) as f64 / 10.0
}

pub fn name_matches(image: &str, want: &str) -> bool {
    let img = image.rsplit(['\\', '/']).next().unwrap_or(image).to_ascii_lowercase();
    let want = want.to_ascii_lowercase();
    img == want || img.strip_suffix(".exe") == Some(want.as_str())
}

/// Resolve the target PID set from process records (snapshot + starts).
pub fn resolve_targets(raw: &[Raw], t: &Target) -> HashSet<u32> {
    let mut set: HashSet<u32> = t.pids.iter().copied().collect();
    let mut children: Vec<(u32, u32)> = Vec::new(); // (ppid, pid) in time order
    for r in raw {
        if let Raw::Proc { pid, ppid, name, start: true, .. } = r {
            if t.names.iter().any(|w| name_matches(name, w)) {
                set.insert(*pid);
            }
            children.push((*ppid, *pid));
        }
    }
    if t.follow_children {
        // Iterate to a fixed point so grandchildren are included.
        loop {
            let before = set.len();
            for (pp, p) in &children {
                if set.contains(pp) {
                    set.insert(*p);
                }
            }
            if set.len() == before {
                break;
            }
        }
    }
    set
}

#[derive(Default, Clone, Copy)]
struct ThreadCpu {
    on_since: Option<Ts>,
    off_since: Option<Ts>,
    blocked: bool,
    reason: i8,
    ready_at: Option<Ts>,
    /// (waker pid, waker tid, ReadyThread ts) for the current blocked period
    waker: Option<(u32, u32, Ts)>,
}

#[derive(Default)]
struct GpuCtx {
    pid: u32,
    queued: HashMap<u32, (Ts, u32, u32)>, // seq -> (queue start, packet type, submitting tid)
    dma_start: HashMap<u32, Ts>,
    last_done: Ts,
}

pub fn analyze(mut raw: Vec<Raw>, target: &Target) -> Analysis {
    raw.sort_by_key(|r| r.ts());
    let mut targets = resolve_targets(&raw, target);
    if let Some(me) = target.exclude_pid {
        targets.remove(&me);
    }
    let t0 = raw.iter().map(|r| r.ts()).filter(|&t| t > 0).min().unwrap_or(0);

    let mut a = Analysis { t0, ..Default::default() };
    a.targets = {
        let mut v: Vec<u32> = targets.iter().copied().collect();
        v.sort();
        v
    };

    // Contexts that ever produced DMA completions use the DMA model.
    let dma_ctx: HashSet<u64> = raw
        .iter()
        .filter_map(|r| if let Raw::GpuDmaDone { ctx, .. } = r { Some(*ctx) } else { None })
        .collect();

    let stacks = StackIndex::build(&raw);
    let py = PyIndex::build(&raw);
    let syms = Symbols::build(&raw);
    a.stacks_in_capture = stacks.len();
    // Latest known name / entry point per thread id.
    let mut tinfo: HashMap<u32, (u64, String)> = HashMap::new();
    for r in &raw {
        if let Raw::ThreadInfo { pid, tid, start_addr, name, .. } = r {
            let e = tinfo.entry(*tid).or_insert((0, String::new()));
            if *start_addr != 0 {
                e.0 = *start_addr;
            }
            if !name.is_empty() {
                e.1 = name.clone();
            }
            let _ = pid;
        }
    }
    let thread_label = |pid: u32, tid: u32| -> String {
        match tinfo.get(&tid) {
            Some((_, n)) if !n.is_empty() => format!("{n} ({tid})"),
            Some((sa, _)) if *sa != 0 => format!("{} ({tid})", syms.resolve(pid, *sa)),
            _ => format!("thread {tid}"),
        }
    };
    let proc_label = |names: &HashMap<u32, String>, pid: u32| -> String {
        format!("{} ({pid})", names.get(&pid).map(|n| module_name(n)).unwrap_or_else(|| "?".into()))
    };

    let mut cpu: HashMap<u32, ThreadCpu> = HashMap::new();
    let mut gpu: HashMap<u64, GpuCtx> = HashMap::new();
    let mut threads_seen: HashMap<u32, HashSet<u32>> = HashMap::new();

    macro_rules! summ {
        ($pid:expr) => {
            a.summary.entry($pid).or_insert_with(|| ProcSummary {
                name: a.proc_names.get(&$pid).cloned().unwrap_or_default(),
                ..Default::default()
            })
        };
    }

    // On-CPU sample times per thread, for "what was this thread doing
    // around time t".
    let mut sample_ts: HashMap<u32, Vec<Ts>> = HashMap::new();
    for r in &raw {
        if let Raw::Stack { ts, tid, on: StackOn::Sample, .. } = r {
            sample_ts.entry(*tid).or_default().push(*ts);
        }
    }
    for v in sample_ts.values_mut() {
        v.sort_unstable();
        v.dedup();
    }
    // Last stack written to each GPU track, so a run of packets from one
    // code path carries it once.
    let mut gpu_last_stack: HashMap<(u32, u64), Vec<String>> = HashMap::new();

    // Who submitted this GPU packet. ETW can attach a stack to the DxgKrnl
    // event, but only its kernel half arrives (syscall -> DxgkSubmitCommand,
    // identical for every packet). The submitting thread is on-CPU when it
    // submits, so the 1 kHz sample of that thread nearest in time (--stacks)
    // shows the user code instead. Also the thread's Python stack, if any.
    macro_rules! gpu_submitter {
        ($args:ident, $pid:expr, $ctx:expr, $qs:expr, $qtid:expr, $dur:expr) => {
            if $qtid != 0 {
                $args["submit_thread"] = serde_json::json!($qtid);
                let near = sample_ts.get(&$qtid).and_then(|v| {
                    let i = v.partition_point(|&t| t < $qs);
                    [i.checked_sub(1), Some(i)]
                        .into_iter()
                        .flatten()
                        .filter_map(|j| v.get(j).copied())
                        .min_by_key(|t| (t - $qs).abs())
                        .filter(|t| (t - $qs).abs() <= GPU_SAMPLE_MAX)
                });
                if let Some(f) = near.and_then(|t| stacks.get(t, $qtid, StackOn::Sample)) {
                    let mut f = syms.frames($pid, &user_frames(f));
                    collapse_etw_overhead(&mut f);
                    let k = folded_key(&proc_label(&a.proc_names, $pid), &thread_label($pid, $qtid), &f, None);
                    *a.folded_gpu.entry(k).or_default() += ($dur as f64).round() as u64;
                    f.truncate(GPU_STACK_FRAMES);
                    let last = gpu_last_stack.entry(($pid, $ctx)).or_default();
                    if *last != f {
                        $args["stack"] = serde_json::json!(f);
                        $args["stack_from"] = serde_json::json!("nearest on-CPU sample of the submitting thread");
                        *last = f;
                    }
                }
                if let Some((f, _, _)) = py.lookup($qtid, $qs, $qs) {
                    $args["py_stack"] = serde_json::json!(&f[..f.len().min(PY_TCP_FRAMES)]);
                }
            }
        };
    }

    for r in &raw {
        match r {
            Raw::Proc { pid, name, start: true, .. } => {
                a.proc_names.insert(*pid, name.clone());
            }
            Raw::Proc { .. } => {}
            Raw::Thread { pid, tid, start, .. } => {
                if *start {
                    a.thread_pid.insert(*tid, *pid);
                    cpu.remove(tid); // tid reuse: forget the old thread's state
                }
            }
            Raw::Ready { ts, tid, waker_pid, waker_tid } => {
                let st = cpu.entry(*tid).or_default();
                if st.on_since.is_none() && st.ready_at.is_none() {
                    st.ready_at = Some(*ts);
                    if *waker_tid != 0 {
                        st.waker = Some((*waker_pid, *waker_tid, *ts));
                    }
                }
            }
            Raw::Sample { ts, tid } => {
                if let Some(&pid) = a.thread_pid.get(tid) {
                    if targets.contains(&pid) {
                        summ!(pid).cpu_samples += 1;
                        let mut frames = stacks
                            .get(*ts, *tid, StackOn::Sample)
                            .map(|f| syms.frames(pid, f))
                            .unwrap_or_else(|| vec!["[no stack]".into()]);
                        if collapse_etw_overhead(&mut frames) {
                            summ!(pid).tracing_overhead_samples += 1;
                        }
                        let k = folded_key(&proc_label(&a.proc_names, pid), &thread_label(pid, *tid), &frames, None);
                        *a.folded_oncpu.entry(k).or_default() += 1;
                    }
                }
            }
            Raw::ThreadInfo { .. } | Raw::Image { .. } | Raw::Stack { .. } | Raw::Sym { .. } => {}
            Raw::CSwitch { ts, new_tid, old_tid, old_state, wait_reason } => {
                let ts = *ts;
                // Outgoing thread.
                if *old_tid != 0 {
                    let pid = a.thread_pid.get(old_tid).copied();
                    let st = cpu.entry(*old_tid).or_default();
                    if let (Some(on), Some(pid)) = (st.on_since, pid) {
                        if targets.contains(&pid) && ts > on {
                            let dur = (ts - on) as f64 / 10.0;
                            a.spans.push(Span {
                                name: "Running".into(),
                                cat: "cpu_on",
                                ts_us: us(on, t0),
                                phase: Phase::Complete { dur_us: dur },
                                pid,
                                tid: *old_tid,
                                args: serde_json::Value::Null,
                            });
                            summ!(pid).on_cpu_ms += dur / 1000.0;
                        }
                    } else if pid.is_none() && st.on_since.is_some() {
                        a.unknown_tid_switches += 1;
                    }
                    st.on_since = None;
                    st.off_since = Some(ts);
                    st.blocked = *old_state == THREAD_STATE_WAITING;
                    st.reason = *wait_reason;
                    st.waker = None;
                    // A preempted thread is runnable immediately.
                    st.ready_at = if st.blocked { None } else { Some(ts) };
                }
                // Incoming thread.
                if *new_tid != 0 {
                    let pid = a.thread_pid.get(new_tid).copied();
                    let st = cpu.entry(*new_tid).or_default();
                    if let (Some(off), Some(pid)) = (st.off_since, pid) {
                        if targets.contains(&pid) {
                            threads_seen.entry(pid).or_default().insert(*new_tid);
                            let ready = st.ready_at.unwrap_or(ts).clamp(off, ts);
                            if st.blocked && ready > off {
                                let dur = (ready - off) as f64 / 10.0;
                                let reason = wait_reason_name(st.reason);
                                let mut args = serde_json::json!({ "wait_reason": reason });
                                // The CSwitch stack shows where the thread waited; depending
                                // on the Windows build it is logged on the switch-in or the
                                // switch-out of the waiting thread.
                                let stack = stacks
                                    .get(ts, *new_tid, StackOn::CSwitch)
                                    .or_else(|| stacks.get(off, *new_tid, StackOn::CSwitch))
                                    .map(|f| syms.frames(pid, &user_frames(f)));
                                if let Some((wpid, wtid, wts)) = st.waker {
                                    let wname = a.proc_names.get(&wpid).map(|n| module_name(n)).unwrap_or_default();
                                    args["woken_by"] = serde_json::json!(format!("{wname} pid {wpid} tid {wtid}"));
                                    if let Some(f) = stacks.get(wts, wtid, StackOn::Ready) {
                                        args["waker_stack"] = serde_json::json!(syms.frames(wpid, &user_frames(f)));
                                    }
                                }
                                if let Some(f) = &stack {
                                    let k = folded_key(
                                        &proc_label(&a.proc_names, pid),
                                        &thread_label(pid, *new_tid),
                                        f,
                                        Some(&format!("[{reason}]")),
                                    );
                                    *a.folded_offcpu.entry(k).or_default() += dur.round() as u64;
                                    args["stack"] = serde_json::json!(f);
                                }
                                // Which Python code was this thread in while it waited?
                                let py_hit = py.lookup(*new_tid, off, ready);
                                if let Some((f, inside, gap_ms)) = py_hit {
                                    let shown = &f[..f.len().min(PY_MAX_FRAMES)];
                                    args["py_stack"] = serde_json::json!(shown);
                                    args["py_match"] = serde_json::json!(if inside { "sampled during wait" } else { "nearest sample" });
                                    if !inside {
                                        args["py_gap_ms"] = serde_json::json!((gap_ms * 100.0).round() / 100.0);
                                    }
                                    let k = folded_key(
                                        &proc_label(&a.proc_names, pid),
                                        &thread_label(pid, *new_tid),
                                        f,
                                        Some(&format!("[{reason}]")),
                                    );
                                    *a.folded_py_offcpu.entry(k).or_default() += dur.round() as u64;
                                }
                                a.spans.push(Span {
                                    name: "Off-CPU (blocked)".into(),
                                    cat: "cpu_off",
                                    ts_us: us(off, t0),
                                    phase: Phase::Complete { dur_us: dur },
                                    pid,
                                    tid: *new_tid,
                                    args,
                                });
                                let s = summ!(pid);
                                s.blocked_ms += dur / 1000.0;
                                if stack.is_some() {
                                    s.blocked_spans_with_stack += 1;
                                }
                                if py_hit.is_some() {
                                    s.blocked_spans_with_py_stack += 1;
                                }
                                *s.blocked_by_reason_ms.entry(reason).or_default() += dur / 1000.0;
                            }
                            if ts > ready {
                                let dur = (ts - ready) as f64 / 10.0;
                                a.spans.push(Span {
                                    name: "Runnable (preempted)".into(),
                                    cat: "cpu_runq",
                                    ts_us: us(ready, t0),
                                    phase: Phase::Complete { dur_us: dur },
                                    pid,
                                    tid: *new_tid,
                                    args: serde_json::json!({ "after": if st.blocked { "wakeup" } else { "preemption" } }),
                                });
                                summ!(pid).runnable_ms += dur / 1000.0;
                            }
                        }
                    }
                    st.on_since = Some(ts);
                    st.off_since = None;
                    st.ready_at = None;
                }
            }
            Raw::HardFault { ts, tid, bytes } => {
                if let Some(&pid) = a.thread_pid.get(tid) {
                    if targets.contains(&pid) {
                        a.spans.push(Span {
                            name: "Hard page fault".into(),
                            cat: "mem_fault",
                            ts_us: us(*ts, t0),
                            phase: Phase::Instant,
                            pid,
                            tid: *tid,
                            args: serde_json::json!({ "bytes": bytes }),
                        });
                        let s = summ!(pid);
                        s.hard_faults += 1;
                        s.hard_fault_bytes += *bytes as u64;
                    }
                }
            }
            Raw::GpuQueueStart { ts, pid, tid, ctx, seq, packet_type } => {
                let c = gpu.entry(*ctx).or_default();
                c.pid = *pid;
                if *packet_type != PACKET_WAIT && *packet_type != PACKET_SIGNAL {
                    c.queued.insert(*seq, (*ts, *packet_type, *tid));
                }
            }
            Raw::GpuDmaStart { ts, ctx, seq } => {
                gpu.entry(*ctx).or_default().dma_start.insert(*seq, *ts);
            }
            Raw::GpuDmaDone { ts, ctx, seq } => {
                let c = gpu.entry(*ctx).or_default();
                let q = c.queued.remove(seq);
                if let Some(start) = c.dma_start.remove(seq) {
                    let begin = start.max(c.last_done);
                    c.last_done = *ts;
                    let pid = c.pid;
                    if targets.contains(&pid) && *ts > begin {
                        let dur = (*ts - begin) as f64 / 10.0;
                        let mut args = serde_json::json!({
                            "ctx": format!("{ctx:#x}"), "seq": seq,
                            "queued_us": q.map(|(qs, _, _)| (begin - qs) as f64 / 10.0),
                        });
                        if let Some((qs, _, qtid)) = q {
                            gpu_submitter!(args, pid, *ctx, qs, qtid, dur);
                        }
                        a.spans.push(Span {
                            name: "GPU execute".into(),
                            cat: "gpu_exec",
                            ts_us: us(begin, t0),
                            phase: Phase::Complete { dur_us: dur },
                            pid,
                            tid: gpu_track(*ctx),
                            args,
                        });
                        let s = summ!(pid);
                        s.gpu_busy_ms += dur / 1000.0;
                        s.gpu_packets += 1;
                        s.gpu_source = "dma".into();
                    }
                }
            }
            Raw::GpuQueueStop { ts, ctx, seq } => {
                if dma_ctx.contains(ctx) {
                    continue;
                }
                let c = gpu.entry(*ctx).or_default();
                if let Some((start, ptype, qtid)) = c.queued.remove(seq) {
                    let begin = start.max(c.last_done);
                    c.last_done = *ts;
                    let pid = c.pid;
                    if targets.contains(&pid) && *ts > begin {
                        let dur = (*ts - begin) as f64 / 10.0;
                        let mut args = serde_json::json!({
                            "ctx": format!("{ctx:#x}"), "seq": seq, "packet_type": ptype,
                            "note": "hardware-scheduled queue: includes queueing time",
                        });
                        gpu_submitter!(args, pid, *ctx, start, qtid, dur);
                        a.spans.push(Span {
                            name: "GPU queue packet".into(),
                            cat: "gpu_exec",
                            ts_us: us(begin, t0),
                            phase: Phase::Complete { dur_us: dur },
                            pid,
                            tid: gpu_track(*ctx),
                            args,
                        });
                        let s = summ!(pid);
                        s.gpu_busy_ms += dur / 1000.0;
                        s.gpu_packets += 1;
                        if s.gpu_source.is_empty() {
                            s.gpu_source = "queue".into();
                        }
                    }
                }
            }
            Raw::PyStack { ts, last_ts, pid, tid, samples, frames } => {
                if targets.contains(pid) && !frames.is_empty() {
                    // One track per Python thread, numbered in order of
                    // appearance (thread ids don't fit in the low 16 bits).
                    let existing = a.py_tracks.iter().find(|(k, v)| k.0 == *pid && **v == *tid).map(|(k, _)| k.1);
                    let track = existing.unwrap_or_else(|| {
                        let n = a.py_tracks.keys().filter(|k| k.0 == *pid).count() as u32;
                        let t = PY_TRACK | (n & 0xFFFF);
                        a.py_tracks.insert((*pid, t), *tid);
                        t
                    });
                    let leaf = frames[0].split(" (").next().unwrap_or(&frames[0]).to_string();
                    // A run of one sample has no extent; give it 0.1 ms.
                    let dur = ((*last_ts - *ts).max(1_000)) as f64 / 10.0;
                    a.spans.push(Span {
                        name: leaf,
                        cat: "python",
                        ts_us: us(*ts, t0),
                        phase: Phase::Complete { dur_us: dur },
                        pid: *pid,
                        tid: track,
                        args: serde_json::json!({
                            "thread": tid,
                            "samples": samples,
                            "stack": &frames[..frames.len().min(PY_MAX_FRAMES)],
                        }),
                    });
                    let k = folded_key(&proc_label(&a.proc_names, *pid), &thread_label(*pid, *tid), frames, None);
                    *a.folded_py.entry(k).or_default() += *samples as u64;
                    summ!(*pid).py_thread_samples += *samples as u64;
                }
            }
            Raw::Tcp { ts, pid, tid, send, bytes, raddr, rport, lport } => {
                if targets.contains(pid) {
                    let remote = format!("{raddr}:{rport}");
                    let mut args = serde_json::json!({ "bytes": bytes, "remote": remote, "lport": lport });
                    // Python code behind this traffic. First choice: the
                    // thread that logged the event, when it belongs to this
                    // process (true for most sends). Otherwise the only
                    // Python thread sitting in a socket call at that moment.
                    let own_thread = *tid != 0 && a.thread_pid.get(tid) == Some(pid);
                    let direct = if own_thread { py.lookup(*tid, *ts, *ts).map(|(f, _, _)| (*tid, f)) } else { None };
                    let hit = direct.map(|h| (h, true)).or_else(|| py.only_thread_in_net_call(*pid, *ts).map(|h| (h, false)));
                    if let Some(((ptid, f), by_thread)) = hit {
                        args["py_stack"] = serde_json::json!(&f[..f.len().min(PY_TCP_FRAMES)]);
                        args["py_thread"] = serde_json::json!(ptid);
                        args["py_match"] = serde_json::json!(if by_thread {
                            "thread that logged the event"
                        } else {
                            "only Python thread in a socket call"
                        });
                        let caller = f.iter().find(|x| !py_net_plumbing(x)).unwrap_or(&f[f.len() - 1]).clone();
                        let e = a.py_net.entry((proc_label(&a.proc_names, *pid), caller, remote.clone())).or_default();
                        e.events += 1;
                        e.by_thread += by_thread as u64;
                        if *send {
                            e.sent_bytes += *bytes as u64;
                        } else {
                            e.recv_bytes += *bytes as u64;
                        }
                    }
                    a.spans.push(Span {
                        name: if *send { "TCP send".into() } else { "TCP recv".into() },
                        cat: "net_tcp",
                        ts_us: us(*ts, t0),
                        phase: Phase::Instant,
                        pid: *pid,
                        tid: NET_TRACK,
                        args,
                    });
                    let s = summ!(*pid);
                    if *send {
                        s.tcp_sent_bytes += *bytes as u64;
                    } else {
                        s.tcp_recv_bytes += *bytes as u64;
                    }
                }
            }
        }
    }

    let tracks: HashSet<(u32, u32)> = a.spans.iter().map(|s| (s.pid, s.tid)).collect();
    for (pid, tid) in tracks {
        if tid & 0xFFFF_0000 != 0xFFFF_0000 && tid & 0xFFFF_0000 != 0xFFFE_0000 {
            a.thread_labels.insert((pid, tid), thread_label(pid, tid));
        }
    }
    for pid in &a.targets {
        let n = threads_seen.get(pid).map_or(0, |s| s.len());
        let name = a.proc_names.get(pid).cloned().unwrap_or_default();
        let s = a.summary.entry(*pid).or_default();
        s.threads = n;
        s.name = name;
    }
    a
}

/// ETW captures stacks by walking them inside the traced thread (the user
/// half via an APC on return to user mode), so samples land in that code.
/// Replace everything leafward of the outermost such frame with one marker.
pub fn collapse_etw_overhead(leaf_first: &mut Vec<String>) -> bool {
    let is_etw = |f: &str| {
        let func = f.split_once('!').map_or(f, |(_, n)| n);
        func.starts_with("Etwp") || func.starts_with("EtwTrace") || func == "KiDeliverApc"
    };
    match leaf_first.iter().rposition(|f| is_etw(f)) {
        Some(i) => {
            leaf_first.drain(..=i);
            leaf_first.insert(0, "[ETW stack walk]".into());
            true
        }
        None => false,
    }
}

/// Synthetic track ids so GPU contexts and network show as their own rows
/// under the owning process (real Windows TIDs are multiples of 4 and far
/// below these).
pub const NET_TRACK: u32 = 0xFFFF_0000;
/// Sampled Python stacks, one track per Python thread.
pub const PY_TRACK: u32 = 0xFFFB_0000;
pub fn gpu_track(ctx: u64) -> u32 {
    0xFFFE_0000 | ((ctx >> 4) as u32 & 0xFFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Vec<Raw> {
        vec![
            Raw::Proc { ts: 0, pid: 100, ppid: 4, name: "C:\\Program Files\\Ollama\\ollama.exe".into(), start: true },
            Raw::Proc { ts: 0, pid: 200, ppid: 100, name: "ollama_llama_server.exe".into(), start: true },
            Raw::Proc { ts: 0, pid: 300, ppid: 4, name: "other.exe".into(), start: true },
            Raw::Thread { ts: 0, pid: 100, tid: 1000, start: true },
            Raw::Thread { ts: 0, pid: 200, tid: 2000, start: true },
            Raw::Thread { ts: 0, pid: 300, tid: 3000, start: true },
        ]
    }

    fn tgt(follow: bool) -> Target {
        Target { pids: vec![], names: vec!["ollama".into()], follow_children: follow, exclude_pid: None }
    }

    #[test]
    fn targets_by_name_and_children() {
        let raw = base();
        assert_eq!(resolve_targets(&raw, &tgt(false)), HashSet::from([100]));
        assert_eq!(resolve_targets(&raw, &tgt(true)), HashSet::from([100, 200]));
        let by_pid = Target { pids: vec![300], ..Default::default() };
        assert_eq!(resolve_targets(&raw, &by_pid), HashSet::from([300]));
    }

    #[test]
    fn blocked_then_runnable_then_running() {
        let mut raw = base();
        raw.extend([
            // 1000 runs at t=1000 (0.1ms), blocks at 2000 on UserRequest(6)
            Raw::CSwitch { ts: 1000, new_tid: 1000, old_tid: 0, old_state: 0, wait_reason: 0 },
            Raw::CSwitch { ts: 2000, new_tid: 0, old_tid: 1000, old_state: 5, wait_reason: 6 },
            Raw::Ready { ts: 5000, tid: 1000, waker_pid: 0, waker_tid: 0 },
            Raw::CSwitch { ts: 6000, new_tid: 1000, old_tid: 3000, old_state: 1, wait_reason: 32 },
            Raw::CSwitch { ts: 7000, new_tid: 3000, old_tid: 1000, old_state: 1, wait_reason: 32 },
            Raw::CSwitch { ts: 9000, new_tid: 1000, old_tid: 3000, old_state: 1, wait_reason: 32 },
        ]);
        let a = analyze(raw, &tgt(false));
        let kinds: Vec<(&str, f64, f64)> = a
            .spans
            .iter()
            .map(|s| match s.phase {
                Phase::Complete { dur_us } => (s.cat, s.ts_us, dur_us),
                Phase::Instant => (s.cat, s.ts_us, 0.0),
            })
            .collect();
        // t0 = 1000 ticks
        assert_eq!(
            kinds,
            vec![
                ("cpu_on", 0.0, 100.0),
                ("cpu_off", 100.0, 300.0),
                ("cpu_runq", 400.0, 100.0),
                ("cpu_on", 500.0, 100.0),
                ("cpu_runq", 600.0, 200.0),
            ]
        );
        assert_eq!(a.spans[1].args["wait_reason"], "UserRequest");
        assert_eq!(a.spans[4].args["after"], "preemption");
        let s = &a.summary[&100];
        assert!((s.on_cpu_ms - 0.2).abs() < 1e-9);
        assert!((s.blocked_ms - 0.3).abs() < 1e-9);
        assert!((s.runnable_ms - 0.3).abs() < 1e-9);
        // Non-target thread 3000 produced no spans.
        assert!(a.spans.iter().all(|s| s.pid == 100));
    }

    #[test]
    fn python_stacks_join_blocked_spans() {
        let fr = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<String>>();
        let mut raw = base();
        raw.extend([
            Raw::CSwitch { ts: 1_000, new_tid: 2000, old_tid: 0, old_state: 0, wait_reason: 0 },
            // blocks 2_000 .. 1_502_000 (150 ms), sampled twice in between
            Raw::CSwitch { ts: 2_000, new_tid: 0, old_tid: 2000, old_state: 5, wait_reason: 6 },
            Raw::PyStack {
                ts: 100_000,
                last_ts: 1_400_000,
                pid: 200,
                tid: 2000,
                samples: 14,
                frames: fr(&["readinto (socket.py:723)", "search_tool (agent.py:14)"]),
            },
            Raw::Ready { ts: 1_502_000, tid: 2000, waker_pid: 0, waker_tid: 0 },
            Raw::CSwitch { ts: 1_502_500, new_tid: 2000, old_tid: 0, old_state: 0, wait_reason: 0 },
            // blocks again briefly; only a sample 2 ms later exists
            Raw::CSwitch { ts: 1_600_000, new_tid: 0, old_tid: 2000, old_state: 5, wait_reason: 4 },
            Raw::Ready { ts: 1_601_000, tid: 2000, waker_pid: 0, waker_tid: 0 },
            Raw::CSwitch { ts: 1_601_500, new_tid: 2000, old_tid: 0, old_state: 0, wait_reason: 0 },
            Raw::PyStack {
                ts: 1_621_000,
                last_ts: 1_621_000,
                pid: 200,
                tid: 2000,
                samples: 1,
                frames: fr(&["think (agent.py:17)"]),
            },
        ]);
        let a = analyze(raw, &tgt(true));
        let off: Vec<&Span> = a.spans.iter().filter(|s| s.cat == "cpu_off").collect();
        assert_eq!(off.len(), 2);
        assert_eq!(off[0].args["py_stack"][1], "search_tool (agent.py:14)");
        assert_eq!(off[0].args["py_match"], "sampled during wait");
        assert_eq!(off[1].args["py_stack"][0], "think (agent.py:17)");
        assert_eq!(off[1].args["py_match"], "nearest sample");
        assert_eq!(off[1].args["py_gap_ms"], 2.0);
        // one Python track with two stretches, named by leaf function
        let py: Vec<&Span> = a.spans.iter().filter(|s| s.cat == "python").collect();
        assert_eq!(py.len(), 2);
        assert_eq!(py[0].name, "readinto");
        assert_eq!(py[0].tid, PY_TRACK);
        assert_eq!(a.py_tracks[&(200, PY_TRACK)], 2000);
        assert_eq!(a.summary[&200].py_thread_samples, 15);
        assert_eq!(a.summary[&200].blocked_spans_with_py_stack, 2);
        let (k, us) = a.folded_py_offcpu.iter().next().unwrap();
        assert!(k.ends_with("search_tool (agent.py:14);readinto (socket.py:723);[UserRequest]"), "{k}");
        assert_eq!(*us, 150_000);
    }

    #[test]
    fn tcp_events_get_python_callers() {
        let fr = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<String>>();
        let reader = fr(&["readinto (socket.py:669)", "_read_next_chunk_size (http\\client.py:516)", "chat_stream (driver.py:233)", "run (driver.py:410)"]);
        let sender = fr(&["send (http\\client.py:995)", "chat_stream (driver.py:225)", "run (driver.py:410)"]);
        let mut raw = base();
        raw.extend([
            Raw::Thread { ts: 0, pid: 200, tid: 2004, start: true },
            // thread 2000 sends, then sits in a read; thread 2004 is idle
            Raw::PyStack { ts: 1_000, last_ts: 1_000, pid: 200, tid: 2000, samples: 1, frames: sender },
            Raw::PyStack { ts: 100_000, last_ts: 900_000, pid: 200, tid: 2000, samples: 9, frames: reader },
            Raw::PyStack { ts: 1_000, last_ts: 900_000, pid: 200, tid: 2004, samples: 10, frames: fr(&["wait (threading.py:306)", "pump (driver.py:453)"]) },
            // send logged by the calling thread
            Raw::Tcp { ts: 2_000, pid: 200, tid: 2000, send: true, bytes: 300, raddr: "127.0.0.1".into(), rport: 11434, lport: 5 },
            // receive logged from a thread of another process
            Raw::Tcp { ts: 500_000, pid: 200, tid: 3000, send: false, bytes: 4096, raddr: "127.0.0.1".into(), rport: 11434, lport: 5 },
        ]);
        let a = analyze(raw, &tgt(true));
        let tcp: Vec<&Span> = a.spans.iter().filter(|s| s.cat == "net_tcp").collect();
        assert_eq!(tcp[0].args["py_match"], "thread that logged the event");
        assert_eq!(tcp[0].args["py_stack"][1], "chat_stream (driver.py:225)");
        assert_eq!(tcp[1].args["py_match"], "only Python thread in a socket call");
        assert_eq!(tcp[1].args["py_thread"], 2000);
        let rows: Vec<_> = a.py_net.iter().collect();
        assert_eq!(rows.len(), 2);
        let recv = rows.iter().find(|r| r.0 .1 == "chat_stream (driver.py:233)").unwrap();
        assert_eq!((recv.1.recv_bytes, recv.1.by_thread, recv.0 .2.as_str()), (4096, 0, "127.0.0.1:11434"));
        let send = rows.iter().find(|r| r.0 .1 == "chat_stream (driver.py:225)").unwrap();
        assert_eq!((send.1.sent_bytes, send.1.by_thread), (300, 1));
        assert!(py_net_plumbing("create_connection (C:/Py/Lib/site-packages/urllib3/util/connection.py:73)"));
        assert!(!py_net_plumbing("chat_stream (driver.py:233)"));
    }

    #[test]
    fn gpu_packets_carry_the_submitting_stack() {
        let mut raw = base();
        raw.extend([
            Raw::Image { ts: 0, pid: 200, base: 0x1000, size: 0x1000, path: "C:\\x\\ggml-cuda.dll".into() },
            Raw::Sym { pid: 200, addr: 0x1100, name: "ggml-cuda.dll!ggml_cuda_compute".into() },
            Raw::Sym { pid: 200, addr: 0x1200, name: "ggml-cuda.dll!launch".into() },
            Raw::GpuQueueStart { ts: 100, pid: 200, tid: 2000, ctx: 0xA0, seq: 1, packet_type: 0 },
            // on-CPU sample of the submitting thread 0.03 ms later
            Raw::Sample { ts: 400, tid: 2000 },
            Raw::Stack { ts: 400, tid: 2000, on: StackOn::Sample, frames: vec![KERNEL_ADDR_MIN + 5, 0x1200, 0x1100] },
            Raw::GpuDmaStart { ts: 120, ctx: 0xA0, seq: 1 },
            Raw::GpuDmaDone { ts: 1_120, ctx: 0xA0, seq: 1 },
            // same code path: counted, but the stack is not repeated
            Raw::GpuQueueStart { ts: 1_200, pid: 200, tid: 2000, ctx: 0xA0, seq: 2, packet_type: 0 },
            Raw::GpuDmaStart { ts: 1_220, ctx: 0xA0, seq: 2 },
            Raw::GpuDmaDone { ts: 1_320, ctx: 0xA0, seq: 2 },
            // no sample within 2 ms: no stack at all
            Raw::GpuQueueStart { ts: 90_000, pid: 200, tid: 2000, ctx: 0xA0, seq: 3, packet_type: 0 },
            Raw::GpuDmaStart { ts: 90_020, ctx: 0xA0, seq: 3 },
            Raw::GpuDmaDone { ts: 90_120, ctx: 0xA0, seq: 3 },
        ]);
        let a = analyze(raw, &tgt(true));
        let g: Vec<&Span> = a.spans.iter().filter(|s| s.cat == "gpu_exec").collect();
        assert_eq!(g.len(), 3);
        assert_eq!(g[0].args["stack"], serde_json::json!(["ggml-cuda.dll!launch", "ggml-cuda.dll!ggml_cuda_compute"]));
        assert_eq!(g[0].args["submit_thread"], 2000);
        assert!(g[1].args.get("stack").is_none());
        assert!(g[2].args.get("stack").is_none());
        assert_eq!(a.folded_gpu.len(), 1);
        let (k, us) = a.folded_gpu.iter().next().unwrap();
        assert!(k.ends_with("ggml-cuda.dll!ggml_cuda_compute;ggml-cuda.dll!launch"), "{k}");
        // 100 us (packet 1) + 10 us (packet 2); packet 3 has no sample nearby
        assert_eq!(*us, 110);
    }

    #[test]
    fn gpu_dma_model_serialises_per_context() {
        let mut raw = base();
        raw.extend([
            Raw::GpuQueueStart { ts: 100, pid: 100, tid: 0, ctx: 0xA0, seq: 1, packet_type: 0 },
            Raw::GpuQueueStart { ts: 110, pid: 100, tid: 0, ctx: 0xA0, seq: 2, packet_type: 0 },
            Raw::GpuQueueStart { ts: 115, pid: 100, tid: 0, ctx: 0xA0, seq: 3, packet_type: PACKET_WAIT },
            Raw::GpuDmaStart { ts: 120, ctx: 0xA0, seq: 1 },
            Raw::GpuDmaStart { ts: 125, ctx: 0xA0, seq: 2 },
            Raw::GpuDmaDone { ts: 220, ctx: 0xA0, seq: 1 },
            Raw::GpuDmaDone { ts: 300, ctx: 0xA0, seq: 2 },
            Raw::GpuQueueStop { ts: 320, ctx: 0xA0, seq: 2 }, // ignored: DMA ctx
        ]);
        let a = analyze(raw, &tgt(false));
        let g: Vec<_> = a.spans.iter().filter(|s| s.cat == "gpu_exec").collect();
        assert_eq!(g.len(), 2);
        // second packet starts when first completes (220), not at 125
        assert_eq!(g[1].ts_us, (220 - 100) as f64 / 10.0);
        assert_eq!(g[1].phase, Phase::Complete { dur_us: 8.0 });
        let s = &a.summary[&100];
        assert_eq!(s.gpu_packets, 2);
        assert_eq!(s.gpu_source, "dma");
    }

    #[test]
    fn gpu_queue_fallback_and_attribution() {
        let mut raw = base();
        raw.extend([
            Raw::GpuQueueStart { ts: 100, pid: 300, tid: 0, ctx: 0xB0, seq: 7, packet_type: 0 },
            Raw::GpuQueueStop { ts: 200, ctx: 0xB0, seq: 7 },
            Raw::GpuQueueStart { ts: 100, pid: 100, tid: 0, ctx: 0xC0, seq: 1, packet_type: 0 },
            Raw::GpuQueueStop { ts: 400, ctx: 0xC0, seq: 1 },
            Raw::GpuQueueStart { ts: 410, pid: 100, tid: 0, ctx: 0xC0, seq: 2, packet_type: PACKET_SIGNAL },
            Raw::GpuQueueStop { ts: 420, ctx: 0xC0, seq: 2 },
        ]);
        let a = analyze(raw, &tgt(false));
        let g: Vec<_> = a.spans.iter().filter(|s| s.cat == "gpu_exec").collect();
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].pid, 100);
        assert_eq!(a.summary[&100].gpu_source, "queue");
    }

    #[test]
    fn faults_and_tcp() {
        let mut raw = base();
        raw.extend([
            Raw::HardFault { ts: 10, tid: 2000, bytes: 4096 },
            Raw::HardFault { ts: 11, tid: 1000, bytes: 65536 },
            Raw::Tcp { ts: 12, pid: 200, tid: 0, send: true, bytes: 512, raddr: "127.0.0.1".into(), rport: 11434, lport: 50000 },
            Raw::Tcp { ts: 13, pid: 200, tid: 0, send: false, bytes: 2048, raddr: "127.0.0.1".into(), rport: 11434, lport: 50000 },
        ]);
        let a = analyze(raw, &tgt(true));
        assert_eq!(a.summary[&100].hard_faults, 1);
        assert_eq!(a.summary[&200].hard_fault_bytes, 4096);
        assert_eq!(a.summary[&200].tcp_sent_bytes, 512);
        assert_eq!(a.summary[&200].tcp_recv_bytes, 2048);
    }

    #[test]
    fn tid_reuse_resets_state() {
        let mut raw = base();
        raw.extend([
            Raw::CSwitch { ts: 100, new_tid: 1000, old_tid: 0, old_state: 0, wait_reason: 0 },
            Raw::CSwitch { ts: 200, new_tid: 0, old_tid: 1000, old_state: 5, wait_reason: 6 },
            Raw::Thread { ts: 300, pid: 300, tid: 1000, start: true }, // reused by other.exe
            Raw::CSwitch { ts: 400, new_tid: 1000, old_tid: 0, old_state: 0, wait_reason: 0 },
        ]);
        let a = analyze(raw, &tgt(false));
        assert!(a.spans.iter().all(|s| s.cat == "cpu_on"));
    }

    #[test]
    fn stacks_wakers_samples_and_labels() {
        let mut raw = base();
        raw.extend([
            Raw::ThreadInfo { ts: 0, pid: 100, tid: 1000, start_addr: 0x1100, name: String::new() },
            Raw::ThreadInfo { ts: 0, pid: 200, tid: 2000, start_addr: 0, name: "decode".into() },
            Raw::Image { ts: 0, pid: 100, base: 0x1000, size: 0x1000, path: "C:\\o\\ggml.dll".into() },
            Raw::Sym { pid: 100, addr: 0x1100, name: "ggml.dll!worker".into() },
            Raw::Sym { pid: 100, addr: 0x1200, name: "ggml.dll!wait".into() },
            Raw::Sym { pid: 100, addr: 0x1300, name: "ggml.dll!compute".into() },
            Raw::CSwitch { ts: 100, new_tid: 1000, old_tid: 0, old_state: 0, wait_reason: 0 },
            Raw::Sample { ts: 150, tid: 1000 },
            Raw::Stack { ts: 150, tid: 1000, on: StackOn::Sample, frames: vec![0x1300, 0x1100] },
            Raw::CSwitch { ts: 200, new_tid: 0, old_tid: 1000, old_state: 5, wait_reason: 15 },
            Raw::Ready { ts: 500, tid: 1000, waker_pid: 200, waker_tid: 2000 },
            Raw::Stack { ts: 500, tid: 2000, on: StackOn::Ready, frames: vec![0xdead] },
            Raw::CSwitch { ts: 600, new_tid: 1000, old_tid: 0, old_state: 0, wait_reason: 0 },
            Raw::Stack { ts: 600, tid: 1000, on: StackOn::CSwitch, frames: vec![0x1200, 0x1100] },
        ]);
        let a = analyze(raw, &tgt(false));
        let off = a.spans.iter().find(|s| s.cat == "cpu_off").unwrap();
        assert_eq!(off.args["stack"], serde_json::json!(["ggml.dll!wait", "ggml.dll!worker"]));
        assert_eq!(off.args["woken_by"], "ollama_llama_server.exe pid 200 tid 2000");
        assert_eq!(off.args["waker_stack"], serde_json::json!(["0xdead"]));
        assert_eq!(a.thread_labels[&(100, 1000)], "ggml.dll!worker (1000)");
        assert_eq!(a.summary[&100].cpu_samples, 1);
        assert_eq!(a.summary[&100].blocked_spans_with_stack, 1);
        assert_eq!(
            a.folded_oncpu.keys().next().unwrap(),
            "ollama.exe (100);ggml.dll!worker (1000);ggml.dll!worker;ggml.dll!compute"
        );
        assert_eq!(a.folded_offcpu.values().next(), Some(&30)); // 300 ticks = 30 us
    }

    #[test]
    fn etw_overhead_is_collapsed() {
        let mut f: Vec<String> = ["ntoskrnl.exe!RtlpUnwindPrologue", "ntoskrnl.exe!EtwpTraceStackWalk", "ntoskrnl.exe!EtwpStackWalkApc",
            "ntoskrnl.exe!KiDeliverApc", "ntoskrnl.exe!KiCheckForKernelApcDelivery", "dxgkrnl.sys!DxgkSubmitCommand", "app!main"]
            .iter().map(|s| s.to_string()).collect();
        assert!(collapse_etw_overhead(&mut f));
        assert_eq!(f, vec!["[ETW stack walk]", "ntoskrnl.exe!KiCheckForKernelApcDelivery", "dxgkrnl.sys!DxgkSubmitCommand", "app!main"]);
        let mut g = vec!["app!work".to_string()];
        assert!(!collapse_etw_overhead(&mut g));
    }
}
