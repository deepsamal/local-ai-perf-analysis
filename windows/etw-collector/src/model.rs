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
    Ready { ts: Ts, tid: u32 },
    /// Hard page fault serviced from disk (kernel PageFault class).
    HardFault { ts: Ts, tid: u32, bytes: u32 },
    /// DxgKrnl QueuePacket_Start: work queued by process `pid` on `ctx`.
    GpuQueueStart { ts: Ts, pid: u32, ctx: u64, seq: u32, packet_type: u32 },
    /// DxgKrnl QueuePacket_Stop.
    GpuQueueStop { ts: Ts, ctx: u64, seq: u32 },
    /// DxgKrnl DmaPacket_Start: packet handed to the GPU's hardware queue.
    GpuDmaStart { ts: Ts, ctx: u64, seq: u32 },
    /// DxgKrnl DmaPacket_Info: packet completed (completion interrupt).
    GpuDmaDone { ts: Ts, ctx: u64, seq: u32 },
    /// Microsoft-Windows-Kernel-Network TCP data send/receive.
    Tcp { ts: Ts, pid: u32, send: bool, bytes: u32, raddr: String, rport: u16, lport: u16 },
}

impl Raw {
    pub fn ts(&self) -> Ts {
        match self {
            Raw::Proc { ts, .. }
            | Raw::Thread { ts, .. }
            | Raw::CSwitch { ts, .. }
            | Raw::Ready { ts, .. }
            | Raw::HardFault { ts, .. }
            | Raw::GpuQueueStart { ts, .. }
            | Raw::GpuQueueStop { ts, .. }
            | Raw::GpuDmaStart { ts, .. }
            | Raw::GpuDmaDone { ts, .. }
            | Raw::Tcp { ts, .. } => *ts,
        }
    }
}

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
