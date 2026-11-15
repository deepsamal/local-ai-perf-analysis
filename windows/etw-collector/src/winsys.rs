//! Win32 plumbing that ferrisetw 1.2 does not expose: stack-walk
//! configuration on a running session, session statistics, the profiling
//! privilege, NT-path translation and DbgHelp symbolisation.

use crate::model::Raw;
use crate::stacks::module_name;
use std::collections::{BTreeMap, HashMap};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows_sys::Win32::System::Diagnostics::Etw::*;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub const THREAD_GUID: GUID = GUID::from_u128(0x3d6fa8d1_fe05_11d0_9dda_00c04fd7ba7c);
pub const PERFINFO_GUID: GUID = GUID::from_u128(0xce1dbfb4_137e_4da6_87b0_3f59aa102cbc);
pub const STACKWALK_GUID: &str = "DEF2FE46-7BD6-4B80-BD94-F57FE20D0CE3";
pub const PERFINFO_GUID_STR: &str = "CE1DBFB4-137E-4DA6-87B0-3F59AA102CBC";

/// EVENT_TRACE_PROPERTIES followed by room for the logger/file names.
struct Props {
    buf: Vec<u64>,
}

impl Props {
    fn new() -> Self {
        let bytes = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 2 * 1024 * 2;
        let mut buf = vec![0u64; bytes.div_ceil(8)];
        let p = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        unsafe {
            (*p).Wnode.BufferSize = bytes as u32;
            (*p).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            (*p).LogFileNameOffset = (std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 1024 * 2) as u32;
        }
        Props { buf }
    }
    fn ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES
    }
}

fn query(session: &str) -> Result<Props, u32> {
    let mut p = Props::new();
    let name = wide(session);
    let rc = unsafe { ControlTraceW(CONTROLTRACE_HANDLE { Value: 0 }, name.as_ptr(), p.ptr(), EVENT_TRACE_CONTROL_QUERY) };
    if rc != 0 {
        return Err(rc);
    }
    Ok(p)
}

#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub struct SessionStats {
    pub events_lost: u32,
    pub realtime_buffers_lost: u32,
    pub buffers_written: u32,
}

pub fn session_stats(session: &str) -> Option<SessionStats> {
    let mut p = query(session).ok()?;
    let e = unsafe { &*p.ptr() };
    Some(SessionStats {
        events_lost: e.EventsLost,
        realtime_buffers_lost: e.RealTimeBuffersLost,
        buffers_written: e.BuffersWritten,
    })
}

/// Ask the kernel logger to attach a call stack to CSwitch, ReadyThread and
/// SampledProfile events (what WPR's CSwitch/ReadyThread/Profile stacks do).
pub fn enable_stack_tracing(session: &str) -> Result<(), String> {
    let mut p = query(session).map_err(|e| format!("ControlTrace(QUERY) error {e}"))?;
    let handle = unsafe { (*p.ptr()).Wnode.Anonymous1.HistoricalContext };
    let id = |g: GUID, t: u8| CLASSIC_EVENT_ID { EventGuid: g, Type: t, Reserved: [0; 7] };
    let ids = [id(THREAD_GUID, 36), id(THREAD_GUID, 50), id(PERFINFO_GUID, 46)];
    let rc = unsafe {
        TraceSetInformation(
            CONTROLTRACE_HANDLE { Value: handle },
            TraceStackTracingInfo,
            ids.as_ptr() as *const _,
            std::mem::size_of_val(&ids) as u32,
        )
    };
    if rc != 0 {
        return Err(format!("TraceSetInformation(TraceStackTracingInfo) error {rc}"));
    }
    Ok(())
}

/// SampledProfile needs SeSystemProfilePrivilege enabled in our token
/// (administrators hold it, but it is disabled by default).
pub fn enable_profile_privilege() -> Result<(), String> {
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut tok: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut tok) == 0 {
            return Err("OpenProcessToken failed".into());
        }
        let mut luid = LUID { LowPart: 0, HighPart: 0 };
        let name = wide("SeSystemProfilePrivilege");
        let ok = LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) != 0;
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
        };
        let adj = ok && AdjustTokenPrivileges(tok, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut()) != 0;
        // AdjustTokenPrivileges "succeeds" without the privilege; check last error.
        let err = windows_sys::Win32::Foundation::GetLastError();
        CloseHandle(tok);
        if !adj || err != 0 {
            return Err(format!("could not enable SeSystemProfilePrivilege (error {err})"));
        }
    }
    Ok(())
}

/// Maps `\Device\HarddiskVolumeN\...` and `\SystemRoot\...` to DOS paths.
pub struct PathMap {
    devices: Vec<(String, String)>, // (\Device\HarddiskVolume3, C:)
    system_root: String,
}

impl Default for PathMap {
    fn default() -> Self {
        Self::new()
    }
}

impl PathMap {
    pub fn new() -> Self {
        use windows_sys::Win32::Storage::FileSystem::{GetLogicalDrives, QueryDosDeviceW};
        let mut devices = Vec::new();
        let mask = unsafe { GetLogicalDrives() };
        for i in 0..26u32 {
            if mask & (1 << i) == 0 {
                continue;
            }
            let drive = format!("{}:", (b'A' + i as u8) as char);
            let mut buf = vec![0u16; 1024];
            let n = unsafe { QueryDosDeviceW(wide(&drive).as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
            if n > 0 {
                let end = buf.iter().position(|&c| c == 0).unwrap_or(0);
                devices.push((String::from_utf16_lossy(&buf[..end]), drive));
            }
        }
        devices.sort_by_key(|(d, _)| std::cmp::Reverse(d.len()));
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        PathMap { devices, system_root }
    }

    pub fn to_dos(&self, p: &str) -> String {
        let lower = p.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("\\systemroot\\") {
            return format!("{}\\{}", self.system_root, &p[p.len() - rest.len()..]);
        }
        if let Some(rest) = p.strip_prefix("\\??\\") {
            return rest.to_string();
        }
        for (dev, drive) in &self.devices {
            if lower.starts_with(&dev.to_ascii_lowercase()) && p[dev.len()..].starts_with('\\') {
                return format!("{drive}{}", &p[dev.len()..]);
            }
        }
        p.to_string()
    }
}

/// Resolve every wanted (address space, address) with DbgHelp, loading the
/// modules recorded by the ImageLoad rundown. Without a symbol path this
/// yields export names; with `srv*cache*https://msdl.microsoft.com/download/symbols`
/// (and symsrv.dll next to dbghelp.dll) Windows components get full PDB names.
pub fn symbolize(raw: &[Raw], wanted: &[(u32, u64)], symbol_path: Option<&str>) -> (Vec<Raw>, BTreeMap<String, u64>) {
    use windows_sys::Win32::System::Diagnostics::Debug::*;
    let mut images: HashMap<u32, Vec<(u64, u64, String)>> = HashMap::new();
    for r in raw {
        if let Raw::Image { pid, base, size, path, .. } = r {
            images.entry(*pid).or_default().push((*base, *size, path.clone()));
        }
    }
    let mut by_space: BTreeMap<u32, Vec<u64>> = BTreeMap::new();
    for (sp, a) in wanted {
        by_space.entry(*sp).or_default().push(*a);
    }
    let mut stats = BTreeMap::new();
    let mut out = Vec::new();
    unsafe {
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS);
    }
    let search = symbol_path.map(wide);
    for (space, addrs) in by_space {
        // DbgHelp only needs a unique non-null handle per address space when
        // modules are loaded explicitly.
        let h = (0x1_0000usize + space as usize) as HANDLE;
        let ok = unsafe { SymInitializeW(h, search.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()), 0) != 0 };
        if !ok {
            *stats.entry("sym_init_failed".into()).or_default() += 1;
            continue;
        }
        let mods = images.get(&space).cloned().unwrap_or_default();
        for (base, size, path) in &mods {
            let wp = wide(path);
            unsafe {
                SymLoadModuleExW(h, std::ptr::null_mut(), wp.as_ptr(), std::ptr::null(), *base, *size as u32, std::ptr::null(), 0);
            }
        }
        let max_name = 512usize;
        let bytes = std::mem::size_of::<SYMBOL_INFOW>() + max_name * 2;
        let mut buf = vec![0u64; bytes.div_ceil(8)];
        for a in addrs {
            let si = buf.as_mut_ptr() as *mut SYMBOL_INFOW;
            let mut disp = 0u64;
            let found = unsafe {
                std::ptr::write_bytes(buf.as_mut_ptr(), 0, buf.len());
                (*si).SizeOfStruct = std::mem::size_of::<SYMBOL_INFOW>() as u32;
                (*si).MaxNameLen = max_name as u32;
                SymFromAddrW(h, a, &mut disp, si) != 0
            };
            // With export-only symbols the "nearest" export can be far away;
            // a module+offset is more honest than a misleading name.
            if found && disp > crate::stacks::MAX_EXPORT_DISP {
                *stats.entry("too_far_from_export".into()).or_default() += 1;
                continue;
            }
            if !found {
                *stats.entry("unresolved".into()).or_default() += 1;
                continue;
            }
            let name = unsafe {
                let len = ((*si).NameLen as usize).min(max_name);
                let p = std::ptr::addr_of!((*si).Name) as *const u16;
                String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
            };
            // ModBase is not filled in for export-table symbols: use our map.
            let module = mods
                .iter()
                .find(|(b, sz, _)| a >= *b && a < b.saturating_add(*sz))
                .map(|(_, _, p)| module_name(p))
                .unwrap_or_else(|| "?".into());
            let full = if disp == 0 { format!("{module}!{name}") } else { format!("{module}!{name}+0x{disp:x}") };
            *stats.entry("resolved".into()).or_default() += 1;
            out.push(Raw::Sym { pid: space, addr: a, name: full });
        }
        unsafe {
            SymCleanup(h);
        }
    }
    (out, stats)
}
