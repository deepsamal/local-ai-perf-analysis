//! Raw, platform-independent event model.
//!
//! ETW callbacks translate each event into one `Raw` record as cheaply as
//! possible; all correlation happens afterwards in `spans.rs`. Keeping the
//! raw stream serializable (`--save-raw` / `--replay`) lets the analysis be
//! developed and tested on any OS without re-capturing.

use serde::{Deserialize, Serialize};

/// Event timestamp in FILETIME units (100 ns ticks). ferrisetw delivers
/// header timestamps already converted to system time when the session is
/// not opened with PROCESS_TRACE_MODE_RAW_TIMESTAMP, so kernel and user
/// sessions share one clock.
pub type Ts = i64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "k")]
pub enum Raw {
    /// Process seen at start-up (snapshot, ts = 0) or started/stopped.
    Proc { ts: Ts, pid: u32, ppid: u32, name: String, start: bool },
    /// Thread start/rundown (`start = true`) or end, from the kernel
    /// Thread class. Needed to map CSwitch thread ids to processes.
    Thread { ts: Ts, pid: u32, tid: u32, start: bool },
    /// Context switch (kernel Thread class, opcode 36).
    /// `old_state` is KTHREAD_STATE (5 = Waiting); `wait_reason` is
    /// KWAIT_REASON of the outgoing thread.
    CSwitch { ts: Ts, new_tid: u32, old_tid: u32, old_state: i8, wait_reason: i8 },
    /// ReadyThread (kernel Thread class, opcode 50): `tid` became runnable.
    /// The event is logged by the thread that did the waking (`waker_*`;
    /// 0 when unknown, e.g. woken from a DPC or an older capture).
    Ready {
        ts: Ts,
        tid: u32,
        #[serde(default)]
        waker_pid: u32,
        #[serde(default)]
        waker_tid: u32,
    },
    /// Extra thread details: entry point and name (Thread start/rundown
    /// Win32StartAddr + ThreadName, or the SetName event).
    ThreadInfo { ts: Ts, pid: u32, tid: u32, start_addr: u64, name: String },
    /// Module mapped into `pid` (pid 0 = kernel drivers), for symbolising.
    Image { ts: Ts, pid: u32, base: u64, size: u64, path: String },
    /// SampledProfile (PerfInfo class, opcode 46): `tid` was on-CPU.
    Sample { ts: Ts, tid: u32 },
    /// Call stack (leaf first) captured by ETW stack walking for the event of
    /// kind `on` that `tid` logged/was the subject of at `ts`.
    Stack { ts: Ts, tid: u32, on: StackOn, frames: Vec<u64> },
    /// Symbol for an address in `pid` (pid 0 = kernel), resolved on the
    /// capture machine so replays elsewhere stay readable.
    Sym { pid: u32, addr: u64, name: String },
    /// Hard page fault serviced from disk (kernel PageFault class).
    HardFault { ts: Ts, tid: u32, bytes: u32 },
    /// DxgKrnl QueuePacket_Start: work queued by process `pid` on `ctx`.
    /// `tid` is the submitting thread (0 in captures made before it was
    /// recorded).
    GpuQueueStart {
        ts: Ts,
        pid: u32,
        #[serde(default)]
        tid: u32,
        ctx: u64,
        seq: u32,
        packet_type: u32,
    },
    /// DxgKrnl QueuePacket_Stop.
    GpuQueueStop { ts: Ts, ctx: u64, seq: u32 },
    /// DxgKrnl DmaPacket_Start: packet handed to the GPU's hardware queue.
    GpuDmaStart { ts: Ts, ctx: u64, seq: u32 },
    /// DxgKrnl DmaPacket_Info: packet completed (completion interrupt).
    GpuDmaDone { ts: Ts, ctx: u64, seq: u32 },
    /// Python stack of thread `tid` (leaf first, "func (file:line)"), as
    /// sampled out of process by py-spy. Run-length encoded: the stack was
    /// seen unchanged in `samples` consecutive samples from `ts` to
    /// `last_ts`.
    PyStack { ts: Ts, last_ts: Ts, pid: u32, tid: u32, samples: u32, frames: Vec<String> },
    /// Microsoft-Windows-Kernel-Network TCP data send/receive.
    /// `pid` comes from the event payload. `tid` is the thread that logged
    /// the event: the caller for most sends, but a system thread for data
    /// that arrives from the network (0 in older captures).
    Tcp {
        ts: Ts,
        pid: u32,
        #[serde(default)]
        tid: u32,
        send: bool,
        bytes: u32,
        raddr: String,
        rport: u16,
        lport: u16,
    },
}

impl Raw {
    pub fn ts(&self) -> Ts {
        match self {
            Raw::Proc { ts, .. }
            | Raw::Thread { ts, .. }
            | Raw::CSwitch { ts, .. }
            | Raw::Ready { ts, .. }
            | Raw::ThreadInfo { ts, .. }
            | Raw::Image { ts, .. }
            | Raw::Sample { ts, .. }
            | Raw::Stack { ts, .. }
            | Raw::HardFault { ts, .. }
            | Raw::GpuQueueStart { ts, .. }
            | Raw::GpuQueueStop { ts, .. }
            | Raw::GpuDmaStart { ts, .. }
            | Raw::GpuDmaDone { ts, .. }
            | Raw::PyStack { ts, .. }
            | Raw::Tcp { ts, .. } => *ts,
            Raw::Sym { .. } => 0,
        }
    }
}

/// Which event a stack belongs to.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum StackOn {
    /// Context switch: stack of the thread involved (where it blocked).
    CSwitch,
    /// ReadyThread: stack of the waker.
    Ready,
    /// SampledProfile: on-CPU sample.
    Sample,
    /// Stack carried by a DxgKrnl QueuePacket_Start event. No longer
    /// captured: it holds only the kernel half (syscall -> DxgkSubmitCommand),
    /// the same for every packet. Kept so earlier raw captures still load.
    Gpu,
}

/// Addresses at or above this are kernel-mode on x64.
pub const KERNEL_ADDR_MIN: u64 = 0xFFFF_8000_0000_0000;

/// KTHREAD_STATE value for a thread that blocked (vs. was preempted).
pub const THREAD_STATE_WAITING: i8 = 5;

/// DXGKETW_QUEUE_PACKET_TYPE values that are not GPU work.
pub const PACKET_WAIT: u32 = 4; // DXGKETW_WAIT_COMMAND_BUFFER
pub const PACKET_SIGNAL: u32 = 5; // DXGKETW_SIGNAL_COMMAND_BUFFER

/// KWAIT_REASON names (ntddk.h ordering), for readable off-CPU spans.
pub fn wait_reason_name(r: i8) -> String {
    const NAMES: [&str; 38] = [
        "Executive", "FreePage", "PageIn", "PoolAllocation", "DelayExecution",
        "Suspended", "UserRequest", "WrExecutive", "WrFreePage", "WrPageIn",
        "WrPoolAllocation", "WrDelayExecution", "WrSuspended", "WrUserRequest",
        "WrEventPair", "WrQueue", "WrLpcReceive", "WrLpcReply", "WrVirtualMemory",
        "WrPageOut", "WrRendezvous", "WrKeyedEvent", "WrTerminated",
        "WrProcessInSwap", "WrCpuRateControl", "WrCalloutStack", "WrKernel",
        "WrResource", "WrPushLock", "WrMutex", "WrQuantumEnd", "WrDispatchInt",
        "WrPreempted", "WrYieldExecution", "WrFastMutex", "WrGuardedMutex",
        "WrRundown", "WrAlertByThreadId",
    ];
    if r >= 0 && (r as usize) < NAMES.len() {
        NAMES[r as usize].to_string()
    } else {
        format!("Wait({r})")
    }
}
