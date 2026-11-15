//! Windows-only capture: one NT Kernel Logger-style session (CSwitch,
//! ReadyThread, thread/process rundown, hard faults; needs Administrator)
//! plus one user session (DxgKrnl GPU scheduling, Kernel-Network TCP,
//! Kernel-Process; Administrator or the "Performance Log Users" group).
//!
//! Callbacks translate each event into `model::Raw` and run it through the
//! `LiveFilter`; everything else happens offline in `spans.rs`.

use crate::filter::LiveFilter;
use crate::model::{Raw, StackOn};
use crate::spans::Target;
use anyhow::{anyhow, Result};
use ferrisetw::parser::{Parser, Pointer};
use ferrisetw::provider::kernel_providers::{
    KernelProvider, CONTEXT_SWITCH_PROVIDER, IMAGE_LOAD_PROVIDER, MEMORY_HARD_FAULT_PROVIDER,
    PROCESS_PROVIDER, PROFILE_PROVIDER, THREAD_DISPATCHER_PROVIDER, THREAD_PROVIDER,
};
use ferrisetw::provider::{EventFilter, Provider};
use ferrisetw::{EventRecord, KernelTrace, SchemaLocator, UserTrace, GUID};
use crate::winsys;
use std::collections::{BTreeMap, HashMap};
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
    /// Stack walks on CSwitch/ReadyThread + 1 kHz SampledProfile, module
    /// rundown and DbgHelp symbolisation (kernel session, Administrator).
    pub stacks: bool,
    pub symbol_path: Option<String>,
}

#[derive(Default)]
pub struct Shared {
    pub events: Vec<Raw>,
    pub filter: LiveFilter,
    /// (provider, event id/opcode, field) -> parse failures
    pub parse_errors: BTreeMap<String, u64>,
    /// (provider, event id/opcode) -> count, for --verbose diagnostics
    pub seen: BTreeMap<String, u64>,
    /// Thread whose next StackWalk event belongs to the given kept event.
    pub stack_owner: HashMap<u32, (i64, Owner)>,
    pub stack_stats: BTreeMap<String, u64>,
    pub path_map: Option<winsys::PathMap>,
    /// Per CPU: index of a kept ReadyThread whose stack walk (logged next on
    /// the same CPU, in the waker's context) has not arrived yet.
    pub cpu_ready: HashMap<u16, usize>,
    /// Kernel-only stacks awaiting their user-mode half, keyed by
    /// (stack thread, EventTimeStamp of the original event).
    pub partial: HashMap<(u32, u64), (i64, StackOn)>,
}

#[derive(Clone, Copy, Debug)]
pub enum Owner {
    CSwitchNew,
    CSwitchOld,
    Sample,
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
    pub stack_stats: BTreeMap<String, u64>,
    pub kernel_stats: Option<winsys::SessionStats>,
    pub user_stats: Option<winsys::SessionStats>,
}

type Sh = Arc<Mutex<Shared>>;

fn push(sh: &Sh, r: Raw) {
    if let Ok(mut s) = sh.lock() {
        if s.filter.observe(&r) {
            s.events.push(r);
        }
    }
}

fn cpu_of(rec: &EventRecord) -> u16 {
    // SAFETY: ferrisetw's EventRecord is #[repr(transparent)] over EVENT_RECORD.
    let er = unsafe { &*(rec as *const EventRecord as *const windows_sys::Win32::System::Diagnostics::Etw::EVENT_RECORD) };
    unsafe { er.BufferContext.Anonymous.ProcessorIndex }
}

/// Push an event; if kept, remember which threads' next stack walk belongs to it.
fn push_owned(sh: &Sh, r: Raw, owners: &[(u32, Owner)], cpu: u16) {
    if let Ok(mut s) = sh.lock() {
        // Any stack-carrying event on this CPU supersedes a pending Ready.
        s.cpu_ready.remove(&cpu);
        if s.filter.observe(&r) {
            let ts = r.ts();
            s.events.push(r);
            for (tid, o) in owners {
                if *tid != 0 {
                    s.stack_owner.insert(*tid, (ts, *o));
                }
            }
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
        if !matches!(op, 1..=4 | 36 | 50 | 72) {
            return;
        }
        let Some((schema, tag)) = parser!(&sh, rec, loc, tag) else { return };
        let p = P { p: Parser::create(rec, &schema), sh: &sh, tag: &tag };
        let ts = rec.raw_timestamp();
        match op {
            1..=4 => {
                if let (Some(pid), Some(tid)) = (p.u32("ProcessId"), p.u32("TThreadId")) {
                    let start = op == 1 || op == 3;
                    push(&sh, Raw::Thread { ts, pid, tid, start });
                    if start {
                        // Optional fields: silently absent on older schemas.
                        let start_addr = p.p.try_parse::<Pointer>("Win32StartAddr").map(|v| *v as u64).unwrap_or(0);
                        let name = p.p.try_parse::<String>("ThreadName").unwrap_or_default();
                        if start_addr != 0 || !name.is_empty() {
                            push(&sh, Raw::ThreadInfo { ts, pid, tid, start_addr, name });
                        }
                    }
                }
            }
            72 => {
                // Thread SetName (Windows 10 1709+)
                let tid = p.p.try_parse::<u32>("ThreadId").or_else(|_| p.p.try_parse::<u32>("TThreadId"));
                if let (Ok(tid), Ok(name)) = (tid, p.p.try_parse::<String>("ThreadName")) {
                    let pid = p.p.try_parse::<u32>("ProcessId").unwrap_or(0);
                    push(&sh, Raw::ThreadInfo { ts, pid, tid, start_addr: 0, name });
                }
            }
            36 => {
                if let (Some(new_tid), Some(old_tid), Some(old_state), Some(wait_reason)) =
                    (p.u32("NewThreadId"), p.u32("OldThreadId"), p.i8("OldThreadState"), p.i8("OldThreadWaitReason"))
                {
                    push_owned(
                        &sh,
                        Raw::CSwitch { ts, new_tid, old_tid, old_state, wait_reason },
                        &[(old_tid, Owner::CSwitchOld), (new_tid, Owner::CSwitchNew)],
                        cpu_of(rec),
                    );
                }
            }
            50 => {
                if let Some(tid) = p.u32("TThreadId") {
                    // The kernel logger leaves the header thread id at -1 here;
                    // the waker is filled in from the stack walk that follows
                    // on the same CPU (it runs in the waker's context).
                    let cpu = cpu_of(rec);
                    if let Ok(mut s) = sh.lock() {
                        let r = Raw::Ready { ts, tid, waker_pid: 0, waker_tid: 0 };
                        if s.filter.observe(&r) {
                            let idx = s.events.len();
                            s.events.push(r);
                            s.cpu_ready.insert(cpu, idx);
                        } else {
                            s.cpu_ready.remove(&cpu);
                        }
                    }
                }
            }
            _ => {}
        }
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

fn kernel_profile_cb(sh: Sh) -> impl FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    move |rec, loc| {
        if rec.opcode() != 46 {
            return;
        }
        let Some((schema, tag)) = parser!(&sh, rec, loc, "PerfInfo/op46".to_string()) else { return };
        let p = P { p: Parser::create(rec, &schema), sh: &sh, tag: &tag };
        if let Some(tid) = p.u32("ThreadId") {
            push_owned(&sh, Raw::Sample { ts: rec.raw_timestamp(), tid }, &[(tid, Owner::Sample)], cpu_of(rec));
        }
    }
}

fn kernel_image_cb(sh: Sh) -> impl FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    move |rec, loc| {
        let op = rec.opcode();
        // 10 = Load, 3 = DCStart (rundown of already-loaded modules)
        if op != 10 && op != 3 {
            return;
        }
        let Some((schema, tag)) = parser!(&sh, rec, loc, format!("Image/op{op}")) else { return };
        let p = P { p: Parser::create(rec, &schema), sh: &sh, tag: &tag };
        if let (Some(base), Some(size), Some(pid), Some(path)) =
            (p.ptr("ImageBase"), p.ptr("ImageSize"), p.u32("ProcessId"), p.string("FileName"))
        {
            let path = match sh.lock().ok().and_then(|s| s.path_map.as_ref().map(|m| m.to_dos(&path))) {
                Some(p) => p,
                None => path,
            };
            push(&sh, Raw::Image { ts: rec.raw_timestamp(), pid, base, size, path });
        }
    }
}

/// StackWalk_Event (opcode 32): u64 EventTimeStamp, u32 StackProcess,
/// u32 StackThread, then leaf-first return addresses. Parsed from the raw
/// payload: TDH would need one lookup per Stack1..Stack192 property.
fn kernel_stack_cb(sh: Sh) -> impl FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    move |rec, _| {
        if rec.opcode() != 32 {
            return;
        }
        // SAFETY: ferrisetw's EventRecord is #[repr(transparent)] over EVENT_RECORD.
        let er = unsafe { &*(rec as *const EventRecord as *const windows_sys::Win32::System::Diagnostics::Etw::EVENT_RECORD) };
        if er.UserData.is_null() || er.UserDataLength < 16 {
            return;
        }
        let data = unsafe { std::slice::from_raw_parts(er.UserData as *const u8, er.UserDataLength as usize) };
        let ptr = if rec.event_flags() & 0x0020 != 0 { 4 } else { 8 }; // EVENT_HEADER_FLAG_32_BIT_HEADER
        // The kernel half of a stack is logged at once; the user half is
        // logged when the thread next returns to user mode, as a separate
        // event carrying the same EventTimeStamp.
        let qpc = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let pid = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let tid = u32::from_le_bytes(data[12..16].try_into().unwrap());
        let cpu = cpu_of(rec);
        let frames: Vec<u64> = data[16..]
            .chunks_exact(ptr)
            .map(|c| if ptr == 8 { u64::from_le_bytes(c.try_into().unwrap()) } else { u32::from_le_bytes(c.try_into().unwrap()) as u64 })
            .collect();
        let kernel_only = !frames.is_empty() && frames.iter().all(|&a| a >= crate::model::KERNEL_ADDR_MIN);
        if let Ok(mut s) = sh.lock() {
            if let Some((ts, on)) = s.partial.remove(&(tid, qpc)) {
                *s.stack_stats.entry("user_half_joined".into()).or_default() += 1;
                s.events.push(Raw::Stack { ts, tid, on, frames });
                return;
            }
            if let Some(idx) = s.cpu_ready.remove(&cpu) {
                if let Some(Raw::Ready { ts, waker_pid, waker_tid, .. }) = s.events.get_mut(idx) {
                    *waker_pid = pid;
                    *waker_tid = tid;
                    let ts = *ts;
                    *s.stack_stats.entry("matched_Ready".into()).or_default() += 1;
                    if kernel_only {
                        s.partial.insert((tid, qpc), (ts, StackOn::Ready));
                    }
                    s.events.push(Raw::Stack { ts, tid, on: StackOn::Ready, frames });
                    return;
                }
            }
            match s.stack_owner.remove(&tid) {
                Some((ts, o)) => {
                    let on = match o {
                        Owner::CSwitchNew | Owner::CSwitchOld => StackOn::CSwitch,
                        Owner::Sample => StackOn::Sample,
                    };
                    // A CSwitch registers both threads; drop the sibling entry
                    // so it cannot capture a later, unrelated stack.
                    if matches!(o, Owner::CSwitchNew | Owner::CSwitchOld) {
                        let sib = s.stack_owner.iter().find(|(_, v)| v.0 == ts && matches!(v.1, Owner::CSwitchNew | Owner::CSwitchOld)).map(|(k, _)| *k);
                        if let Some(k) = sib {
                            s.stack_owner.remove(&k);
                        }
                    }
                    *s.stack_stats.entry(format!("matched_{o:?}")).or_default() += 1;
                    if kernel_only {
                        s.partial.insert((tid, qpc), (ts, on));
                    }
                    s.events.push(Raw::Stack { ts, tid, on, frames });
                }
                None => *s.stack_stats.entry("unmatched".into()).or_default() += 1,
            }
        }
    }
}

const KERNEL_SESSION: &str = "lapa-etw-kernel";

fn start_kernel(sh: &Sh, o: &Options) -> Result<KernelTrace> {
    let mut b = KernelTrace::new().named(KERNEL_SESSION.to_string());
    if o.stacks {
        // Stack walks on every context switch are bulky: bigger buffers.
        b = b.set_trace_properties(ferrisetw::trace::TraceProperties {
            buffer_size: 1024,
            min_buffer: 64,
            max_buffer: 512,
            ..Default::default()
        });
    }
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
    if o.stacks {
        b = b.enable(Provider::kernel(&IMAGE_LOAD_PROVIDER).add_callback(kernel_image_cb(sh.clone())).build());
        if o.cpu {
            b = b.enable(Provider::kernel(&PROFILE_PROVIDER).add_callback(kernel_profile_cb(sh.clone())).build());
        }
        let walk = KernelProvider::new(GUID::from(winsys::STACKWALK_GUID), 0);
        b = b.enable(Provider::kernel(&walk).add_callback(kernel_stack_cb(sh.clone())).build());
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
                // QueuePacket_Start_2/_3 (244/245) carry no PacketType; they
                // are command-buffer submissions, i.e. render packets.
                let packet_type = if id == DXG_QUEUE_START { p.u32("PacketType") } else { Some(0) };
                match (p.ptr("hContext"), p.u32("SubmitSequence"), packet_type) {
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

#[derive(Clone, Copy, Debug, PartialEq)]
enum UserProv {
    Process,
    Gpu,
    Net,
}

impl UserProv {
    fn label(self) -> &'static str {
        match self {
            UserProv::Process => "Microsoft-Windows-Kernel-Process",
            UserProv::Gpu => "Microsoft-Windows-DxgKrnl",
            UserProv::Net => "Microsoft-Windows-Kernel-Network",
        }
    }

    fn build(self, sh: &Sh, o: &Options) -> Provider {
        match self {
            // WINEVENT_KEYWORD_PROCESS (0x10). Catches children that start
            // mid-capture even without the kernel session.
            UserProv::Process => Provider::by_guid(GUID::from(KERNEL_PROCESS))
                .any(0x10)
                .add_filter(EventFilter::ByEventIds(vec![1, 2]))
                .add_callback(proc_cb(sh.clone()))
                .build(),
            UserProv::Gpu => Provider::by_guid(GUID::from(DXGKRNL))
                .any(DXG_KW_BASE | DXG_KW_PERFORMANCE)
                .level(5)
                .add_filter(EventFilter::ByEventIds(vec![
                    DXG_DMA_START, DXG_DMA_INFO, DXG_QUEUE_START, DXG_QUEUE_STOP, DXG_QUEUE_START_2, DXG_QUEUE_START_3,
                ]))
                .add_callback(dxg_cb(sh.clone(), o.verbose))
                .build(),
            // KERNEL_NETWORK_KEYWORD_IPV4 | _IPV6
            UserProv::Net => Provider::by_guid(GUID::from(KERNEL_NETWORK))
                .any(0x10 | 0x20)
                .add_filter(EventFilter::ByEventIds(vec![10, 11, 26, 27]))
                .add_callback(net_cb(sh.clone()))
                .build(),
        }
    }
}

const USER_SESSION: &str = "lapa-etw-user";

fn try_user(sh: &Sh, o: &Options, provs: &[UserProv]) -> Result<UserTrace> {
    let mut b = UserTrace::new().named(USER_SESSION.to_string());
    for p in provs {
        b = b.enable(p.build(sh, o));
    }
    b.start_and_process().map_err(|e| {
        // ferrisetw leaves the session running if StartTrace succeeded but
        // EnableTraceEx2 failed; stop it so the next attempt can reuse the name.
        let _ = ferrisetw::trace::stop_trace_by_name(USER_SESSION);
        anyhow!("{e:?}")
    })
}

/// Start the user session with every requested provider; if that fails,
/// probe each provider alone and keep the ones the caller may enable.
fn start_user(sh: &Sh, o: &Options, notes: &mut Vec<String>) -> Result<UserTrace> {
    let _ = ferrisetw::trace::stop_trace_by_name(USER_SESSION); // stale session from a crashed run
    let mut want = vec![UserProv::Process];
    if o.gpu {
        want.push(UserProv::Gpu);
    }
    if o.net {
        want.push(UserProv::Net);
    }
    let first = match try_user(sh, o, &want) {
        Ok(t) => return Ok(t),
        Err(e) => e,
    };
    notes.push(format!("user session with all providers failed: {first}; probing individually"));
    let mut ok = Vec::new();
    for p in &want {
        match try_user(sh, o, &[*p]) {
            Ok(t) => {
                let _ = t.stop();
                notes.push(format!("  {}: ok", p.label()));
                ok.push(*p);
            }
            Err(e) => notes.push(format!("  {}: {e}", p.label())),
        }
    }
    if ok.is_empty() {
        return Err(first);
    }
    try_user(sh, o, &ok)
}

/// (elevated administrator, member of Performance Log Users) for this token.
pub fn token_groups() -> (bool, bool) {
    use windows_sys::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, WinBuiltinAdministratorsSid, WinBuiltinPerfLoggingUsersSid,
        SECURITY_MAX_SID_SIZE, WELL_KNOWN_SID_TYPE,
    };
    fn member(kind: WELL_KNOWN_SID_TYPE) -> bool {
        let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut len = SECURITY_MAX_SID_SIZE;
        unsafe {
            if CreateWellKnownSid(kind, std::ptr::null_mut(), sid.as_mut_ptr() as _, &mut len) == 0 {
                return false;
            }
            let mut is = 0;
            CheckTokenMembership(std::ptr::null_mut(), sid.as_mut_ptr() as _, &mut is) != 0 && is != 0
        }
    }
    (member(WinBuiltinAdministratorsSid), member(WinBuiltinPerfLoggingUsersSid))
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
    let (admin, perflog) = token_groups();
    notes.push(format!("token: elevated administrator = {admin}, Performance Log Users = {perflog}"));

    let need_kernel = o.cpu || o.faults || o.stacks;
    if o.stacks {
        sh.lock().unwrap().path_map = Some(winsys::PathMap::new());
        if o.cpu {
            if let Err(e) = winsys::enable_profile_privilege() {
                notes.push(format!("on-CPU sampling may be unavailable: {e}"));
            }
        }
    }
    let kernel = if need_kernel {
        match start_kernel(&sh, o) {
            Ok(t) => {
                if o.stacks {
                    match winsys::enable_stack_tracing(KERNEL_SESSION) {
                        Ok(()) => notes.push("stack walking enabled on CSwitch, ReadyThread, SampledProfile".into()),
                        Err(e) => notes.push(format!("stack walking unavailable: {e}")),
                    }
                }
                Some(t)
            }
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
    let user = match start_user(&sh, o, &mut notes) {
        Ok(t) => Some(t),
        Err(e) => {
            notes.push(format!(
                "user session unavailable ({e}); GPU/TCP/process events disabled. \
                 DxgKrnl needs Administrator or 'Performance Log Users'; Kernel-Process and \
                 Kernel-Network need Administrator."
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
    let kernel_stats = if kernel_session { winsys::session_stats(KERNEL_SESSION) } else { None };
    let user_stats = if user_session { winsys::session_stats(USER_SESSION) } else { None };
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
    let mut events = std::mem::take(&mut s.events);
    if o.stacks {
        let t = Instant::now();
        let mut thread_pid = HashMap::new();
        for r in &events {
            if let Raw::Thread { pid, tid, start: true, .. } = r {
                thread_pid.insert(*tid, *pid);
            }
        }
        let wanted = crate::stacks::Symbols::wanted(&events, &thread_pid);
        let (syms, st) = winsys::symbolize(&events, &wanted, o.symbol_path.as_deref());
        notes.push(format!(
            "symbolised {} addresses in {:.1}s: {:?}{}",
            wanted.len(),
            t.elapsed().as_secs_f64(),
            st,
            if o.symbol_path.is_none() { " (exports only; pass --symbol-path for PDB symbols)" } else { "" }
        ));
        events.extend(syms);
    }
    Ok(CaptureResult {
        events,
        stack_stats: std::mem::take(&mut s.stack_stats),
        kernel_stats,
        user_stats,
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
