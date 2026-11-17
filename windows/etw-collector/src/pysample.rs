//! Python frames without touching the target: an out-of-process sampler
//! built on the py-spy library.
//!
//! ETW (and eBPF) stacks stop at the interpreter: every Python call is the
//! same `_PyEval_EvalFrameDefault`, and a stock CPython has no frame
//! pointers to walk anyway. py-spy instead reads the interpreter's own
//! thread and frame structures out of the target's memory, so it works on
//! the Python the user already has, with no restart and no code in the
//! target.
//!
//! It is a sampler, not an event-time unwinder. The stacks land in the raw
//! stream as run-length encoded `Raw::PyStack` records (one per stretch
//! where a thread's Python stack did not change) and `spans.rs` joins them
//! to blocked spans by thread id and time. A thread that is waiting keeps
//! its stack for the whole wait, so the join is exact where it matters;
//! for events much shorter than the sampling period it is approximate.
//!
//! Sampling is non-blocking: the target is never suspended. Suspending it
//! at 100 Hz would add context switches to the very scheduling data this
//! tool records. The price is an occasional torn read, counted in the
//! notes as an error.

use crate::model::{Raw, Ts};
use py_spy::config::{Config, LockingStrategy};
use py_spy::PythonSpy;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// FILETIME ticks (100 ns since 1601) for "now", the clock ETW events use.
pub fn filetime_now() -> Ts {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (d.as_nanos() / 100) as Ts + 116_444_736_000_000_000
}

/// Image names worth trying to attach to. Attaching scans the target's
/// memory for an interpreter, which is slow and pointless on e.g. ollama.exe.
pub fn looks_like_python(image: &str) -> bool {
    let n = image.rsplit(['\\', '/']).next().unwrap_or(image).to_ascii_lowercase();
    let n = n.strip_suffix(".exe").unwrap_or(&n);
    n == "py" || n.starts_with("python") || n.starts_with("pypy") || n == "uv" || n == "uvicorn" || n == "gunicorn"
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct PyStats {
    pub rate_hz: u32,
    pub attached_pids: Vec<u32>,
    pub attach_failures: u64,
    pub ticks: u64,
    pub thread_samples: u64,
    pub sample_errors: u64,
    pub runs: usize,
    /// Wall time the sampler thread spent reading the targets.
    pub sampler_busy_ms: f64,
    pub mean_tick_us: f64,
    pub max_tick_us: f64,
    pub elapsed_s: f64,
}

pub struct PyResult {
    pub events: Vec<Raw>,
    pub stats: PyStats,
    pub notes: Vec<String>,
}

pub struct PySampler {
    stop: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<PyResult>,
}

struct Run {
    ts: Ts,
    last_ts: Ts,
    samples: u32,
    frames: Vec<String>,
}

fn frame_label(f: &py_spy::Frame) -> String {
    let file = f.short_filename.as_deref().unwrap_or(&f.filename);
    format!("{} ({}:{})", f.name, file, f.line)
}

/// Start sampling. `targets` returns the current (pid, image name) set;
/// it is polled about once a second so processes that start mid-capture
/// (a venv launcher's real interpreter, a spawned tool) are picked up.
pub fn start(targets: Box<dyn Fn() -> Vec<(u32, String)> + Send>, rate_hz: u32) -> PySampler {
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    let handle = std::thread::spawn(move || run(targets, rate_hz.clamp(1, 1000), s));
    PySampler { stop, handle }
}

impl PySampler {
    pub fn finish(self) -> PyResult {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.join().unwrap_or_else(|_| PyResult {
            events: Vec::new(),
            stats: PyStats::default(),
            notes: vec!["python sampler thread panicked".into()],
        })
    }
}

fn run(targets: Box<dyn Fn() -> Vec<(u32, String)> + Send>, rate_hz: u32, stop: Arc<AtomicBool>) -> PyResult {
    let period = Duration::from_nanos(1_000_000_000 / rate_hz as u64);
    let config = Config { blocking: LockingStrategy::NonBlocking, ..Config::default() };
    let mut spies: HashMap<u32, PythonSpy> = HashMap::new();
    // pid -> failed attach attempts; a launcher or a non-Python process
    // with a Python-looking name is given up on after a few tries.
    let mut attempts: HashMap<u32, u32> = HashMap::new();
    let mut consecutive_errors: HashMap<u32, u32> = HashMap::new();
    let mut open: HashMap<(u32, u32), Run> = HashMap::new();
    let mut events: Vec<Raw> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut st = PyStats { rate_hz, ..Default::default() };
    let t0 = Instant::now();
    let mut next_scan = Instant::now();
    let mut busy = Duration::ZERO;
    let mut max_tick = Duration::ZERO;
    // Read errors that were only a process having exited.
    let mut exited_errors: u64 = 0;

    let close = |events: &mut Vec<Raw>, pid: u32, tid: u32, r: Run| {
        events.push(Raw::PyStack { ts: r.ts, last_ts: r.last_ts, pid, tid, samples: r.samples, frames: r.frames });
    };

    while !stop.load(Ordering::Relaxed) {
        let tick = Instant::now();
        if tick >= next_scan {
            next_scan = tick + Duration::from_secs(1);
            for (pid, name) in targets() {
                if spies.contains_key(&pid) || !looks_like_python(&name) {
                    continue;
                }
                let n = attempts.entry(pid).or_insert(0);
                if *n >= 4 {
                    // (u32::MAX marks a process that exited)
                    continue;
                }
                *n = n.saturating_add(1);
                let ta = Instant::now();
                match PythonSpy::new(pid as py_spy::Pid, &config) {
                    Ok(spy) => {
                        notes.push(format!(
                            "python: attached to pid {pid} ({name}) in {:.0} ms, {:.1}s into the capture",
                            ta.elapsed().as_secs_f64() * 1e3,
                            t0.elapsed().as_secs_f64()
                        ));
                        st.attached_pids.push(pid);
                        spies.insert(pid, spy);
                    }
                    Err(e) => {
                        st.attach_failures += 1;
                        if *n == 4 {
                            notes.push(format!("python: could not attach to pid {pid} ({name}): {e}"));
                        }
                    }
                }
            }
        }

        let work = Instant::now();
        let now = filetime_now();
        let mut gone: Vec<u32> = Vec::new();
        for (&pid, spy) in spies.iter_mut() {
            match spy.get_stack_traces() {
                Ok(traces) => {
                    consecutive_errors.remove(&pid);
                    for t in traces {
                        let Some(tid) = t.os_thread_id else { continue };
                        let tid = tid as u32;
                        st.thread_samples += 1;
                        let frames: Vec<String> = t.frames.iter().map(frame_label).collect();
                        match open.get_mut(&(pid, tid)) {
                            Some(r) if r.frames == frames => {
                                r.last_ts = now;
                                r.samples += 1;
                            }
                            _ => {
                                if let Some(old) = open.remove(&(pid, tid)) {
                                    close(&mut events, pid, tid, old);
                                }
                                open.insert((pid, tid), Run { ts: now, last_ts: now, samples: 1, frames });
                            }
                        }
                    }
                }
                Err(_) => {
                    st.sample_errors += 1;
                    let c = consecutive_errors.entry(pid).or_insert(0);
                    *c += 1;
                    // ~1 s of nothing but errors: the process has exited.
                    if *c > rate_hz.max(20) {
                        gone.push(pid);
                    }
                }
            }
        }
        for pid in gone {
            spies.remove(&pid);
            consecutive_errors.remove(&pid);
            // The process has exited; don't try to attach to it again.
            attempts.insert(pid, u32::MAX);
            exited_errors += rate_hz.max(20) as u64 + 1;
            notes.push(format!("python: pid {pid} exited; detached"));
        }
        if !spies.is_empty() {
            st.ticks += 1;
            let d = work.elapsed();
            busy += d;
            max_tick = max_tick.max(d);
        }

        let spent = tick.elapsed();
        if spent < period {
            std::thread::sleep(period - spent);
        }
    }

    let mut keys: Vec<(u32, u32)> = open.keys().copied().collect();
    keys.sort_unstable();
    for k in keys {
        if let Some(r) = open.remove(&k) {
            close(&mut events, k.0, k.1, r);
        }
    }
    st.runs = events.len();
    st.elapsed_s = t0.elapsed().as_secs_f64();
    st.sample_errors = st.sample_errors.saturating_sub(exited_errors);
    st.sampler_busy_ms = busy.as_secs_f64() * 1e3;
    st.mean_tick_us = if st.ticks > 0 { busy.as_secs_f64() * 1e6 / st.ticks as f64 } else { 0.0 };
    st.max_tick_us = max_tick.as_secs_f64() * 1e6;
    if st.attached_pids.is_empty() {
        notes.push("python: no Python interpreter found among the target processes".into());
    } else {
        notes.push(format!(
            "python: {} thread samples in {} ticks at {} Hz from {} process(es), {} read errors; \
             sampler busy {:.0} ms of {:.1} s ({:.1}% of one core), {:.0} us per tick (max {:.0})",
            st.thread_samples,
            st.ticks,
            rate_hz,
            st.attached_pids.len(),
            st.sample_errors,
            st.sampler_busy_ms,
            st.elapsed_s,
            st.sampler_busy_ms / (st.elapsed_s * 10.0).max(1e-9),
            st.mean_tick_us,
            st.max_tick_us
        ));
    }
    PyResult { events, stats: st, notes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_image_names() {
        assert!(looks_like_python("C:\\Users\\x\\venv\\Scripts\\python.exe"));
        assert!(looks_like_python("/usr/bin/python3.12"));
        assert!(looks_like_python("pythonw.exe"));
        assert!(!looks_like_python("ollama.exe"));
        assert!(!looks_like_python("pycharm64.exe"));
    }

    #[test]
    fn filetime_is_after_2020() {
        // 2020-01-01 in FILETIME ticks
        assert!(filetime_now() > 132_223_104_000_000_000);
    }
}
