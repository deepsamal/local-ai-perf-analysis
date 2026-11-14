//! Windows-only capture: one NT Kernel Logger-style session (CSwitch,
//! ReadyThread, thread/process rundown, hard faults; needs Administrator)
//! plus one user session (DxgKrnl GPU scheduling, Kernel-Network TCP,
//! Kernel-Process; Administrator or the "Performance Log Users" group).
//!
//! Callbacks translate each event into `model::Raw` and run it through the
//! `LiveFilter`; everything else happens offline in `spans.rs`.

use crate::filter::LiveFilter;
use crate::model::Raw;
use crate::spans::Target;
use anyhow::{anyhow, Result};
use ferrisetw::parser::{Parser, Pointer};
use ferrisetw::provider::kernel_providers::{
    KernelProvider, CONTEXT_SWITCH_PROVIDER, MEMORY_HARD_FAULT_PROVIDER, PROCESS_PROVIDER,
    THREAD_DISPATCHER_PROVIDER, THREAD_PROVIDER,
};
use ferrisetw::provider::{EventFilter, Provider};
use ferrisetw::{EventRecord, KernelTrace, SchemaLocator, UserTrace, GUID};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DXGKRNL: &str = "802EC45A-1E99-4B83-9920-87C98277BA9D";
pub const KERNEL_NETWORK: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
pub const KERNEL_PROCESS: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";

// DxgKrnl event ids (see docs/ETW_COLLECTOR.md for the field list).
const DXG_DMA_START: u16 = 175;
const DXG_DMA_INFO: u16 = 177;
const DXG_QUEUE_START: u16 = 178;
const DXG_QUEUE_STOP: u16 = 180;
const DXG_QUEUE_START_2: u16 = 0xF4;
const DXG_QUEUE_START_3: u16 = 0xF5;
const DXG_KW_BASE: u64 = 0x1;
const DXG_KW_PERFORMANCE: u64 = 0x4000_0000_0000_0000;

#[derive(Debug, Clone)]
pub struct Options {
    pub target: Target,
    pub duration: Option<Duration>,
    pub cpu: bool,
    pub faults: bool,
    pub gpu: bool,
    pub net: bool,
    pub verbose: bool,
}

#[derive(Default)]
pub struct Shared {
    pub events: Vec<Raw>,
    pub filter: LiveFilter,
    /// (provider, event id/opcode, field) -> parse failures
    pub parse_errors: BTreeMap<String, u64>,
    /// (provider, event id/opcode) -> count, for --verbose diagnostics
    pub seen: BTreeMap<String, u64>,
}

pub struct CaptureResult {
    pub events: Vec<Raw>,
    pub kernel_session: bool,
    pub user_session: bool,
    pub notes: Vec<String>,
    pub parse_errors: BTreeMap<String, u64>,
    pub seen: BTreeMap<String, u64>,
    pub kept: u64,
    pub dropped: u64,
    pub elapsed: Duration,
}

type Sh = Arc<Mutex<Shared>>;

fn push(sh: &Sh, r: Raw) {
    if let Ok(mut s) = sh.lock() {
        if s.filter.observe(&r) {
            s.events.push(r);
        }
    }
}

fn note_err(sh: &Sh, key: String) {
    if let Ok(mut s) = sh.lock() {
        *s.parse_errors.entry(key).or_default() += 1;
    }
}

fn note_seen(sh: &Sh, key: String) {
    if let Ok(mut s) = sh.lock() {
        *s.seen.entry(key).or_default() += 1;
    }
}

/// Helper that parses fields and records which ones failed, so a schema
/// mismatch on some Windows build shows up as a counted diagnostic instead
/// of silently empty output.
struct P<'a, 'b> {
    p: Parser<'a, 'b>,
    sh: &'a Sh,
    tag: &'a str,
}

impl<'a, 'b> P<'a, 'b> {
    fn u32(&self, f: &str) -> Option<u32> {
        self.p.try_parse::<u32>(f).map_err(|_| note_err(self.sh, format!("{}:{f}", self.tag))).ok()
    }
    fn u16(&self, f: &str) -> Option<u16> {
        self.p.try_parse::<u16>(f).map_err(|_| note_err(self.sh, format!("{}:{f}", self.tag))).ok()
    }
    fn i8(&self, f: &str) -> Option<i8> {
        self.p.try_parse::<i8>(f).map_err(|_| note_err(self.sh, format!("{}:{f}", self.tag))).ok()
    }
    fn ptr(&self, f: &str) -> Option<u64> {
        if let Ok(v) = self.p.try_parse::<Pointer>(f) {
            return Some(*v as u64);
        }
        if let Ok(v) = self.p.try_parse::<u64>(f) {
            return Some(v);
        }
        note_err(self.sh, format!("{}:{f}", self.tag));
        None
    }
    fn string(&self, f: &str) -> Option<String> {
        self.p.try_parse::<String>(f).map_err(|_| note_err(self.sh, format!("{}:{f}", self.tag))).ok()
    }
    fn ip(&self, f: &str) -> Option<String> {
        self.p
            .try_parse::<std::net::IpAddr>(f)
            .map(|a| a.to_string())
            .map_err(|_| note_err(self.sh, format!("{}:{f}", self.tag)))
            .ok()
    }
}

macro_rules! parser {
    ($sh:expr, $rec:expr, $loc:expr, $tag:expr) => {{
        match $loc.event_schema($rec) {
            Ok(schema) => Some((schema, $tag)),
            Err(_) => {
                note_err($sh, format!("{}:<schema>", $tag));
                None
            }
        }
    }};
}

// ---------------------------------------------------------------- kernel

fn kernel_thread_cb(sh: Sh) -> impl FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    move |rec, loc| {
        let op = rec.opcode();
        let tag = format!("Thread/op{op}");
        if !matches!(op, 1 | 2 | 3 | 4 | 36 | 50) {
            return;
        }
        let Some((schema, tag)) = parser!(&sh, rec, loc, tag) else { return };
        let p = P { p: Parser::create(rec, &schema), sh: &sh, tag: &tag };
        let ts = rec.raw_timestamp();
        let r = match op {
            1..=4 => match (p.u32("ProcessId"), p.u32("TThreadId")) {
                (Some(pid), Some(tid)) => Raw::Thread { ts, pid, tid, start: op == 1 || op == 3 },
                _ => return,
            },
            36 => match (p.u32("NewThreadId"), p.u32("OldThreadId"), p.i8("OldThreadState"), p.i8("OldThreadWaitReason")) {
                (Some(new_tid), Some(old_tid), Some(old_state), Some(wait_reason)) => {
                    Raw::CSwitch { ts, new_tid, old_tid, old_state, wait_reason }
                }
                _ => return,
            },
            50 => match p.u32("TThreadId") {
                Some(tid) => Raw::Ready { ts, tid },
                None => return,
            },
            _ => return,
        };
        push(&sh, r);
    }
}

fn kernel_process_cb(sh: Sh) -> impl FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    move |rec, loc| {
        let op = rec.opcode();
        if !matches!(op, 1..=3) {
            return;
        }
        let Some((schema, tag)) = parser!(&sh, rec, loc, format!("Process/op{op}")) else { return };
        let p = P { p: Parser::create(rec, &schema), sh: &sh, tag: &tag };
        if let (Some(pid), Some(ppid)) = (p.u32("ProcessId"), p.u32("ParentId")) {
            let name = p.string("ImageFileName").unwrap_or_default();
            push(&sh, Raw::Proc { ts: rec.raw_timestamp(), pid, ppid, name, start: op != 2 });
        }
    }
}

fn kernel_fault_cb(sh: Sh) -> impl FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    move |rec, loc| {
        if rec.opcode() != 32 {
            return;
        }
        let Some((schema, tag)) = parser!(&sh, rec, loc, "PageFault/op32".to_string()) else { return };
        let p = P { p: Parser::create(rec, &schema), sh: &sh, tag: &tag };
        if let (Some(tid), Some(bytes)) = (p.u32("TThreadId"), p.u32("ByteCount")) {
            push(&sh, Raw::HardFault { ts: rec.raw_timestamp(), tid, bytes });
        }
    }
}

fn start_kernel(sh: &Sh, o: &Options) -> Result<KernelTrace> {
    let mut b = KernelTrace::new().named("lapa-etw-kernel".to_string());
    // Thread class carries CSwitch (CSWITCH flag) and ReadyThread
    // (DISPATCHER flag) in addition to thread start/end/rundown.
    let mut tflags = THREAD_PROVIDER.flags;
    if o.cpu {
        tflags |= CONTEXT_SWITCH_PROVIDER.flags | THREAD_DISPATCHER_PROVIDER.flags;
    }
    let thread = KernelProvider::new(THREAD_PROVIDER.guid, tflags);
    b = b.enable(Provider::kernel(&thread).add_callback(kernel_thread_cb(sh.clone())).build());
    b = b.enable(Provider::kernel(&PROCESS_PROVIDER).add_callback(kernel_process_cb(sh.clone())).build());
    if o.faults {
        b = b.enable(Provider::kernel(&MEMORY_HARD_FAULT_PROVIDER).add_callback(kernel_fault_cb(sh.clone())).build());
    }
    b.start_and_process().map_err(|e| anyhow!("{e:?}"))
}

// ------------------------------------------------------------------ user

fn dxg_cb(sh: Sh, verbose: bool) -> impl FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    move |rec, loc| {
        let id = rec.event_id();
        if verbose {
            note_seen(&sh, format!("DxgKrnl/{id}"));
        }
        let Some((schema, tag)) = parser!(&sh, rec, loc, format!("DxgKrnl/{id}")) else { return };
        let p = P { p: Parser::create(rec, &schema), sh: &sh, tag: &tag };
        let ts = rec.raw_timestamp();
        let r = match id {
            DXG_QUEUE_START | DXG_QUEUE_START_2 | DXG_QUEUE_START_3 => {
                match (p.ptr("hContext"), p.u32("SubmitSequence"), p.u32("PacketType")) {
                    (Some(ctx), Some(seq), Some(packet_type)) => {
                        Raw::GpuQueueStart { ts, pid: rec.process_id(), ctx, seq, packet_type }
                    }
                    _ => return,
                }
            }
            DXG_QUEUE_STOP => match (p.ptr("hContext"), p.u32("SubmitSequence")) {
                (Some(ctx), Some(seq)) => Raw::GpuQueueStop { ts, ctx, seq },
                _ => return,
            },
            DXG_DMA_START => match (p.ptr("hContext"), p.u32("ulQueueSubmitSequence")) {
                (Some(ctx), Some(seq)) => Raw::GpuDmaStart { ts, ctx, seq },
                _ => return,
            },
            DXG_DMA_INFO => match (p.ptr("hContext"), p.u32("ulQueueSubmitSequence")) {
                (Some(ctx), Some(seq)) => Raw::GpuDmaDone { ts, ctx, seq },
                _ => return,
            },
            _ => return,
        };
        push(&sh, r);
    }
}

fn net_cb(sh: Sh) -> impl FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    move |rec, loc| {
        let id = rec.event_id();
        // 10/11: TCPv4 send/recv, 26/27: TCPv6 send/recv
        let send = match id {
            10 | 26 => true,
            11 | 27 => false,
            _ => return,
        };
        let Some((schema, tag)) = parser!(&sh, rec, loc, format!("KernelNetwork/{id}")) else { return };
        let p = P { p: Parser::create(rec, &schema), sh: &sh, tag: &tag };
        if let (Some(pid), Some(bytes)) = (p.u32("PID"), p.u32("size")) {
            let raddr = p.ip("daddr").unwrap_or_default();
            // Port fields are logged in network byte order.
            let rport = p.u16("dport").map(u16::from_be).unwrap_or(0);
            let lport = p.u16("sport").map(u16::from_be).unwrap_or(0);
            push(&sh, Raw::Tcp { ts: rec.raw_timestamp(), pid, send, bytes, raddr, rport, lport });
        }
    }
}

fn proc_cb(sh: Sh) -> impl FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    move |rec, loc| {
        let id = rec.event_id();
        if id != 1 && id != 2 {
            return;
        }
        let Some((schema, tag)) = parser!(&sh, rec, loc, format!("KernelProcess/{id}")) else { return };
        let p = P { p: Parser::create(rec, &schema), sh: &sh, tag: &tag };
        if let Some(pid) = p.u32("ProcessID") {
            let ppid = if id == 1 { p.u32("ParentProcessID").unwrap_or(0) } else { 0 };
            let name = if id == 1 { p.string("ImageName").unwrap_or_default() } else { String::new() };
            push(&sh, Raw::Proc { ts: rec.raw_timestamp(), pid, ppid, name, start: id == 1 });
        }
    }
}

fn start_user(sh: &Sh, o: &Options) -> Result<UserTrace> {
    let mut b = UserTrace::new().named("lapa-etw-user".to_string());
    // Kernel-Process: WINEVENT_KEYWORD_PROCESS (0x10). Catches children
    // that start mid-capture even without the kernel session.
    b = b.enable(
        Provider::by_guid(GUID::from(KERNEL_PROCESS))
            .any(0x10)
            .add_filter(EventFilter::ByEventIds(vec![1, 2]))
            .add_callback(proc_cb(sh.clone()))
            .build(),
    );
    if o.gpu {
        b = b.enable(
            Provider::by_guid(GUID::from(DXGKRNL))
                .any(DXG_KW_BASE | DXG_KW_PERFORMANCE)
                .level(5)
                .add_filter(EventFilter::ByEventIds(vec![
                    DXG_DMA_START, DXG_DMA_INFO, DXG_QUEUE_START, DXG_QUEUE_STOP, DXG_QUEUE_START_2, DXG_QUEUE_START_3,
                ]))
                .add_callback(dxg_cb(sh.clone(), o.verbose))
                .build(),
        );
    }
    if o.net {
        // KERNEL_NETWORK_KEYWORD_IPV4 | _IPV6
        b = b.enable(
            Provider::by_guid(GUID::from(KERNEL_NETWORK))
                .any(0x10 | 0x20)
                .add_filter(EventFilter::ByEventIds(vec![10, 11, 26, 27]))
                .add_callback(net_cb(sh.clone()))
                .build(),
        );
    }
    b.start_and_process().map_err(|e| anyhow!("{e:?}"))
}

// -------------------------------------------------------------- snapshot

/// Toolhelp snapshot of existing processes and threads (ts = 0), so the
/// filter knows the target's threads before the kernel rundown arrives and
/// so name/child resolution works without the kernel session.
pub fn snapshot() -> Vec<Raw> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
    let mut out = Vec::new();
    unsafe {
        let h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
        if h == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(h, &mut pe) != 0 {
            loop {
                let len = pe.szExeFile.iter().position(|&c| c == 0).unwrap_or(pe.szExeFile.len());
                let name = String::from_utf16_lossy(&pe.szExeFile[..len]);
                out.push(Raw::Proc { ts: 0, pid: pe.th32ProcessID, ppid: pe.th32ParentProcessID, name, start: true });
                if Process32NextW(h, &mut pe) == 0 {
                    break;
                }
            }
        }
        let mut te: THREADENTRY32 = std::mem::zeroed();
        te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        if Thread32First(h, &mut te) != 0 {
            loop {
                out.push(Raw::Thread { ts: 0, pid: te.th32OwnerProcessID, tid: te.th32ThreadID, start: true });
                if Thread32Next(h, &mut te) == 0 {
                    break;
                }
            }
        }
        CloseHandle(h);
    }
    // Children must follow parents for follow-children resolution.
    out.sort_by_key(|r| match r {
        Raw::Proc { .. } => 0,
        _ => 1,
    });
    out
}

// --------------------------------------------------------------- capture

pub fn capture(o: &Options, stop: Arc<AtomicBool>) -> Result<CaptureResult> {
    let sh: Sh = Arc::new(Mutex::new(Shared { filter: LiveFilter::new(o.target.clone()), ..Default::default() }));
    let snap = snapshot();
    let nsnap = snap.len();
    for r in snap {
        push(&sh, r);
    }
    // Resolve the target set once against the snapshot so we can tell the
    // user early if nothing matched (processes may still start later).
    let initial = sh.lock().unwrap().filter.target_pids().len();
    let mut notes = vec![format!("toolhelp snapshot: {nsnap} records; {initial} target process(es) running at start")];

    let need_kernel = o.cpu || o.faults;
    let kernel = if need_kernel {
        match start_kernel(&sh, o) {
            Ok(t) => Some(t),
            Err(e) => {
                notes.push(format!(
                    "kernel session unavailable ({e}); CPU scheduling and hard-fault data disabled. \
                     Run from an elevated prompt to enable it."
                ));
                None
            }
        }
    } else {
        None
    };
    let user = match start_user(&sh, o) {
        Ok(t) => Some(t),
        Err(e) => {
            notes.push(format!(
                "user session unavailable ({e}); GPU/TCP/process events disabled. \
                 Requires Administrator or membership in 'Performance Log Users'."
            ));
            None
        }
    };
    if kernel.is_none() && user.is_none() {
        return Err(anyhow!("no ETW session could be started:\n  {}", notes.join("\n  ")));
    }

    let t0 = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        if let Some(d) = o.duration {
            if t0.elapsed() >= d {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let elapsed = t0.elapsed();
    let kernel_session = kernel.is_some();
    let user_session = user.is_some();
    if let Some(k) = kernel {
        if let Err(e) = k.stop() {
            notes.push(format!("kernel session stop: {e:?}"));
        }
    }
    if let Some(u) = user {
        if let Err(e) = u.stop() {
            notes.push(format!("user session stop: {e:?}"));
        }
    }

    let mut s = sh.lock().unwrap();
    Ok(CaptureResult {
        events: std::mem::take(&mut s.events),
        kernel_session,
        user_session,
        notes,
        parse_errors: std::mem::take(&mut s.parse_errors),
        seen: std::mem::take(&mut s.seen),
        kept: s.filter.kept,
        dropped: s.filter.dropped,
        elapsed,
    })
}
