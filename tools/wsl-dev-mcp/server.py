#!/usr/bin/env python3
"""wsl-dev: a local MCP server that lets an assistant build, test and trace
local-ai-perf-analysis inside WSL2 from a Windows host.

Runs on WINDOWS (launched by the Claude desktop app over stdio) and drives
WSL through wsl.exe. Standard library only -- no pip install needed.

Safety model
------------
* Everything that needs root goes through ONE root-owned wrapper inside
  WSL (/usr/local/sbin/lapa-root, see lapa-root.sh). The wrapper accepts a
  fixed set of subcommands and validates every argument. The sudoers rule
  allows only that wrapper.
* The server itself never builds a root command line.
* `wsl_exec` (run an arbitrary command as your WSL user, never root) is
  only registered when WSL_DEV_ALLOW_EXEC=1 is set in the MCP config.
* Scripts are fed to bash on stdin (`wsl.exe -e bash -s`) so nothing is
  re-parsed by PowerShell/cmd/wsl.exe quoting.

Long-running work (builds, tests, traces) runs as a background *job* whose
log is written to <repo>/runs/wsl-jobs/<id>.log on the Windows side. Tools
wait up to `wait_s` seconds, then return the log tail plus the job id;
poll with `wsl_job`. This keeps every tool call well under host timeouts.

Configuration (environment variables, set in claude_desktop_config.json):
  WSL_DEV_DISTRO       WSL distro name (default: WSL default distro)
  WSL_DEV_REPO         Windows path of the repo (default: two dirs up)
  WSL_DEV_WSL_REPO     Path of the synced copy inside WSL
                       (default: ~/code/<repo-folder-name>)
  WSL_DEV_ALLOW_EXEC   "1" to register wsl_exec (default: off)
  WSL_DEV_WSL_EXE      wsl.exe path (default: wsl.exe; tests override)
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path, PureWindowsPath

SERVER_NAME = "wsl-dev"
SERVER_VERSION = "0.2.0"
DEFAULT_PROTOCOL = "2025-06-18"

HERE = Path(__file__).resolve().parent
WIN_REPO = Path(os.environ.get("WSL_DEV_REPO") or HERE.parent.parent).resolve()
DISTRO = os.environ.get("WSL_DEV_DISTRO", "").strip()
ALLOW_EXEC = os.environ.get("WSL_DEV_ALLOW_EXEC", "0").strip() == "1"
WSL_EXE = os.environ.get("WSL_DEV_WSL_EXE", "wsl.exe")
WSL_REPO = os.environ.get("WSL_DEV_WSL_REPO") or f"$HOME/code/{WIN_REPO.name}"
JOB_DIR = WIN_REPO / "runs" / "wsl-jobs"
WRAPPER = "/usr/local/sbin/lapa-root"
ETW_DIR = WIN_REPO / "windows" / "etw-collector"
ETW_RUNS = WIN_REPO / "runs" / "etw"
CARGO_CMDS = ["version", "check", "build", "test", "clippy"]

MAKE_TARGETS = ["all", "mock", "clean", "test", "test-gpu", "test-python",
                "test-synthetic", "bench"]
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}$")
MAX_WAIT_S = 50          # keep each tool call under remote-bridge timeouts
MAX_JOB_S = 3600         # hard kill for a single job


def to_wsl_path(win_path: Path) -> str:
    """C:\\Users\\Foo Bar\\x -> /mnt/c/Users/Foo Bar/x (best effort)."""
    p = PureWindowsPath(str(win_path))
    if p.drive and len(p.drive) == 2 and p.drive[1] == ":":
        rest = "/".join(p.parts[1:])
        return f"/mnt/{p.drive[0].lower()}/{rest}"
    return str(win_path).replace("\\", "/")


WIN_REPO_WSL = to_wsl_path(WIN_REPO)


def wsl_argv() -> list[str]:
    argv = [WSL_EXE]
    if DISTRO:
        argv += ["-d", DISTRO]
    argv += ["-e", "bash", "-s"]
    return argv


def decode(raw: bytes) -> str:
    # wsl.exe's own messages are UTF-16LE; bash output is UTF-8.
    if raw.count(b"\x00") > len(raw) // 4 and raw:
        try:
            return raw.decode("utf-16-le", errors="replace")
        except Exception:
            pass
    return raw.decode("utf-8", errors="replace")


def prelude() -> str:
    """Common bash header: strict mode, repo vars, sane PATH."""
    return (
        "set -uo pipefail\n"
        f"REPO={WSL_REPO}\n"           # may contain $HOME: expanded by bash
        f"WINREPO={shlex.quote(WIN_REPO_WSL)}\n"
        "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/wsl/lib\n"
    )


def run_sync(script: str, timeout: int = 45) -> tuple[int, str]:
    """Run a short script in WSL and wait for it."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        cp = subprocess.run(wsl_argv(), input=(prelude() + script).encode(),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=timeout, creationflags=flags)
        return cp.returncode, decode(cp.stdout)
    except subprocess.TimeoutExpired as e:
        return 124, decode(e.stdout or b"") + f"\n[timed out after {timeout}s]"
    except FileNotFoundError:
        return 127, f"{WSL_EXE} not found -- is WSL installed?"


# --------------------------------------------------------------------------
# Background jobs
# --------------------------------------------------------------------------

class Job:
    def __init__(self, kind: str, script: str, argv: list | None = None,
                 cwd: Path | None = None):
        self.id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        self.kind = kind
        self.started = time.time()
        self.ended: float | None = None
        self.rc: int | None = None
        JOB_DIR.mkdir(parents=True, exist_ok=True)
        self.log_path = JOB_DIR / f"{self.id}.log"
        self._log = open(self.log_path, "wb")
        self._log.write(f"### job {self.id} kind={kind}\n".encode())
        self._log.flush()
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        if argv is None:
            self.proc = subprocess.Popen(wsl_argv(), stdin=subprocess.PIPE,
                                         stdout=self._log, stderr=subprocess.STDOUT,
                                         creationflags=flags)
            self.proc.stdin.write((prelude() + script).encode())
            self.proc.stdin.close()
        else:
            # Native Windows command (no shell): argv is built from validated
            # parts only.
            self._log.write(("$ " + " ".join(argv) + "\n").encode())
            self._log.flush()
            self.proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                         stdout=self._log, stderr=subprocess.STDOUT,
                                         cwd=str(cwd) if cwd else None,
                                         creationflags=flags)
        threading.Thread(target=self._wait, daemon=True).start()

    def _wait(self):
        try:
            self.rc = self.proc.wait(timeout=MAX_JOB_S)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.rc = self.proc.wait()
            self._log.write(f"\n[killed after {MAX_JOB_S}s]\n".encode())
        self.ended = time.time()
        self._log.write(f"\n### exit code {self.rc}\n".encode())
        self._log.close()

    @property
    def running(self) -> bool:
        return self.rc is None

    def tail(self, nbytes: int = 12000) -> str:
        try:
            data = self.log_path.read_bytes()
        except OSError:
            return ""
        return decode(data[-nbytes:])

    def summary(self, nbytes: int = 12000) -> str:
        dur = (self.ended or time.time()) - self.started
        state = "running" if self.running else f"finished rc={self.rc}"
        head = (f"job {self.id} [{self.kind}] {state} after {dur:.0f}s\n"
                f"full log (Windows): {self.log_path}\n"
                f"---- last {nbytes} bytes ----\n")
        return head + self.tail(nbytes)


JOBS: dict[str, Job] = {}


def start_and_wait(kind: str, script: str, wait_s: int,
                   argv: list | None = None, cwd: Path | None = None) -> str:
    job = Job(kind, script, argv, cwd)
    JOBS[job.id] = job
    deadline = time.time() + max(0, min(wait_s, MAX_WAIT_S))
    while job.running and time.time() < deadline:
        time.sleep(0.5)
    out = job.summary()
    if job.running:
        out += f"\n\n[still running -- poll with wsl_job(id='{job.id}')]"
    return out


# --------------------------------------------------------------------------
# Script builders
# --------------------------------------------------------------------------

SYNC_SCRIPT = r"""
mkdir -p "$REPO"
rsync -a --delete \
  --exclude=bin/ --exclude=obj/ --exclude=src/symbolize/target/ \
  --exclude=.git/ --exclude='*.o' --exclude='*.so' --exclude='*.a' \
  --exclude=__pycache__/ --exclude='*.pyc' --exclude=.vscode/ --exclude=.idea/ \
  --exclude=runs/wsl-jobs/ \
  "$WINREPO/" "$REPO/" || { echo "rsync failed (is rsync installed?)"; exit 1; }
find "$REPO/tools" "$REPO/tests" -type f \( -name '*.sh' -o -name '*.py' \) \
  -exec sed -i 's/\r$//' {} +
echo "synced $(find "$REPO" -type f | wc -l) files -> $REPO"
echo "branch on Windows side: $(git -C "$WINREPO" branch --show-current 2>/dev/null || echo '?')"
"""


def sudo_wrapper(*args: str) -> str:
    return "sudo -n " + WRAPPER + " " + " ".join(shlex.quote(a) for a in args) + "\n"


# --------------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------------

def tool_status(_: dict) -> str:
    script = r"""
echo "distro:   ${WSL_DISTRO_NAME:-?}"
echo "kernel:   $(uname -r)"
[ -e /sys/kernel/btf/vmlinux ] && echo "btf:      yes" || echo "btf:      MISSING"
mount | grep -q ' /sys/fs/bpf ' && echo "bpffs:    mounted" || echo "bpffs:    not mounted (wrapper mounts it)"
if command -v nvidia-smi >/dev/null; then echo "gpu:      $(nvidia-smi -L 2>&1 | head -2 | tr '\n' ' ')"; else echo "gpu:      nvidia-smi not found"; fi
[ -x /usr/local/sbin/lapa-root ] && echo "wrapper:  installed" || echo "wrapper:  MISSING (run tools/wsl-dev-mcp/install-wsl.sh)"
sudo -n -l /usr/local/sbin/lapa-root >/dev/null 2>&1 && echo "sudo:     NOPASSWD ok" || echo "sudo:     NOT configured for lapa-root"
for t in clang rsync make cargo; do printf '%-9s %s\n' "$t:" "$(command -v $t || echo MISSING)"; done
[ -d "$REPO" ] && echo "wsl repo: $REPO" || echo "wsl repo: $REPO (not synced yet)"
echo "win repo: $WINREPO  (branch $(git -C "$WINREPO" branch --show-current 2>/dev/null || echo '?'))"
"""
    rc, out = run_sync(script)
    return out + f"\nexec tool: {'enabled' if ALLOW_EXEC else 'disabled'}"


def tool_sync(args: dict) -> str:
    return start_and_wait("sync", SYNC_SCRIPT, int(args.get("wait_s", 45)))


def tool_make(args: dict) -> str:
    target = args.get("target", "")
    if target not in MAKE_TARGETS:
        raise ValueError(f"target must be one of {MAKE_TARGETS}")
    script = ""
    if args.get("sync", True):
        script += SYNC_SCRIPT
    if args.get("clean", False) and target != "clean":
        script += sudo_wrapper("make", "clean")
    script += sudo_wrapper("make", target)
    return start_and_wait(f"make {target}", script, int(args.get("wait_s", 45)))


def tool_trace(args: dict) -> str:
    argv = ["trace"]
    def num(key, flag, lo, hi):
        if key in args and args[key] is not None:
            v = int(args[key])
            if not lo <= v <= hi:
                raise ValueError(f"{key} must be in [{lo}, {hi}]")
            argv.extend([flag, str(v)])
    num("pid", "--pid", 1, 4194304)
    num("duration", "--duration", 1, 300)
    num("stack_sample_async", "--stack-sample-async", 1, 100000)
    num("stack_sample_sync", "--stack-sample-sync", 1, 100000)
    num("max_stack_frames", "--max-stack-frames", 1, 127)
    if args.get("cuda_lib"):
        lib = str(args["cuda_lib"])
        if not lib.startswith("/") or "\n" in lib:
            raise ValueError("cuda_lib must be an absolute WSL path")
        argv.extend(["--cuda-lib", lib])
    for key, flag in (("no_stacks", "--no-stacks"), ("no_symbolize", "--no-symbolize"),
                      ("no_offcpu_stacks", "--no-offcpu-stacks"), ("verbose", "--verbose")):
        if args.get(key):
            argv.append(flag)
    name = args.get("output_name") or f"trace-{time.strftime('%Y%m%d-%H%M%S')}.json"
    if not NAME_RE.match(name):
        raise ValueError("output_name: letters, digits, '._-' only")
    argv.extend(["--output", name])
    script = (SYNC_SCRIPT if args.get("sync", False) else "") + sudo_wrapper(*argv)
    wait = int(args.get("wait_s", min(int(args.get("duration", 10)) + 15, MAX_WAIT_S)))
    return start_and_wait("trace", script, wait)


def tool_job(args: dict) -> str:
    jid = args.get("id")
    if not jid:
        if not JOBS:
            return "no jobs this session"
        return "\n".join(f"{j.id}  {j.kind:<22} {'running' if j.running else f'rc={j.rc}'}"
                         for j in JOBS.values())
    job = JOBS.get(jid)
    if not job:
        raise ValueError(f"unknown job id {jid}")
    wait = int(args.get("wait_s", 0))
    deadline = time.time() + max(0, min(wait, MAX_WAIT_S))
    while job.running and time.time() < deadline:
        time.sleep(0.5)
    return job.summary(int(args.get("tail_bytes", 12000)))


def tool_cancel(args: dict) -> str:
    job = JOBS.get(args.get("id", ""))
    if not job:
        raise ValueError("unknown job id")
    if job.running:
        job.proc.kill()
        return f"killed job {job.id} (the wsl.exe client; a root child may need `sudo pkill unified_trace`)"
    return f"job {job.id} already finished rc={job.rc}"


PATH_GUARD = r"""
p=$(realpath -m -- "$1")
r=$(realpath -m -- "$REPO")
case "$p" in "$r"/*|/tmp/*) ;; *) echo "DENIED: only paths under $r or /tmp"; exit 3;; esac
[ -f "$p" ] || { echo "not a file: $p"; exit 4; }
"""


def _path_arg(args: dict) -> str:
    path = str(args.get("path", ""))
    if not path or "\n" in path:
        raise ValueError("path required")
    if not path.startswith("/"):
        # $REPO expands in bash; the user-supplied part stays quoted, so a
        # path can never inject shell syntax (wsl_exec is the only way to
        # run arbitrary commands, and it is off by default).
        return f'set -- "$REPO"/{shlex.quote(path)}\n'
    return f"set -- {shlex.quote(path)}\n"


def tool_read(args: dict) -> str:
    n = max(1, min(int(args.get("tail_bytes", 20000)), 200000))
    script = _path_arg(args) + PATH_GUARD + f'echo "== $p ($(stat -c %s "$p") bytes, showing last {n})"\ntail -c {n} -- "$p"\n'
    rc, out = run_sync(script)
    if rc != 0:
        raise RuntimeError(out.strip())
    return out


def tool_copy(args: dict) -> str:
    name = args.get("dest_name") or Path(str(args.get("path", "x"))).name
    if not NAME_RE.match(name):
        raise ValueError("dest_name: letters, digits, '._-' only")
    (WIN_REPO / "runs" / "wsl").mkdir(parents=True, exist_ok=True)
    script = (_path_arg(args) + PATH_GUARD +
              f'mkdir -p "$WINREPO/runs/wsl"\ncp -- "$p" "$WINREPO/runs/wsl/{name}" && '
              f'echo "copied to $WINREPO/runs/wsl/{name} ($(stat -c %s "$p") bytes)"\n')
    rc, out = run_sync(script, timeout=60)
    if rc != 0:
        raise RuntimeError(out.strip())
    return out + f"\nWindows path: {WIN_REPO / 'runs' / 'wsl' / name}"


def tool_exec(args: dict) -> str:
    cmd = str(args.get("command", ""))
    if not cmd.strip():
        raise ValueError("command required")
    script = 'cd "$REPO" 2>/dev/null || cd "$HOME"\n' + cmd + "\n"
    return start_and_wait("exec", script, int(args.get("wait_s", 30)))


# ---- native Windows: etw-collector ---------------------------------------

def _cargo_exe() -> str:
    import shutil
    c = shutil.which("cargo")
    if c:
        return c
    home = Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo")
    c = home / "bin" / "cargo.exe"
    if c.exists():
        return str(c)
    raise RuntimeError("cargo not found on Windows PATH or in %USERPROFILE%\\.cargo\\bin; "
                       "install Rust from https://rustup.rs (MSVC toolchain)")


def tool_win_cargo(args: dict) -> str:
    cmd = args.get("command", "")
    if cmd not in CARGO_CMDS:
        raise ValueError(f"command must be one of {CARGO_CMDS}")
    cargo = _cargo_exe()
    if cmd == "version":
        return start_and_wait("cargo version", "", int(args.get("wait_s", 20)),
                              argv=[cargo, "--version", "--verbose"], cwd=ETW_DIR)
    argv = [cargo, cmd]
    if args.get("release"):
        argv.append("--release")
    if cmd == "clippy":
        argv += ["--all-targets"]
    argv += ["--color", "never"]
    return start_and_wait(f"cargo {cmd}", "", int(args.get("wait_s", 45)), argv=argv, cwd=ETW_DIR)


def tool_win_collect(args: dict) -> str:
    exe = ETW_DIR / "target" / "release" / "etw-collector.exe"
    if not exe.exists():
        raise RuntimeError(f"{exe} not built; run win_cargo(command='build', release=true)")
    argv = [str(exe)]
    pids = args.get("pid") or []
    names = args.get("process_name") or []
    if isinstance(pids, int):
        pids = [pids]
    if isinstance(names, str):
        names = [names]
    for p in pids:
        p = int(p)
        if not 1 <= p <= 0xFFFFFFFF:
            raise ValueError("bad pid")
        argv += ["--pid", str(p)]
    for n in names:
        if not NAME_RE.match(str(n)):
            raise ValueError("process_name: letters, digits, '._-' only")
        argv += ["--process-name", str(n)]
    if not pids and not names:
        raise ValueError("pid or process_name required")
    d = int(args.get("duration", 10))
    if not 1 <= d <= 300:
        raise ValueError("duration must be in [1, 300]")
    argv += ["--duration", str(d)]
    for key, flag in (("follow_children", "--follow-children"), ("no_cpu", "--no-cpu"),
                      ("no_faults", "--no-faults"), ("no_gpu", "--no-gpu"),
                      ("no_net", "--no-net"), ("verbose", "--verbose")):
        if args.get(key):
            argv.append(flag)
    name = args.get("output_name") or f"etw-{time.strftime('%Y%m%d-%H%M%S')}"
    if not NAME_RE.match(name):
        raise ValueError("output_name: letters, digits, '._-' only")
    ETW_RUNS.mkdir(parents=True, exist_ok=True)
    argv += ["--output", str(ETW_RUNS / f"{name}.json")]
    if args.get("save_raw", True):
        argv += ["--save-raw", str(ETW_RUNS / f"{name}.raw.jsonl")]
    wait = int(args.get("wait_s", min(d + 10, MAX_WAIT_S)))
    return start_and_wait("etw collect", "", wait, argv=argv, cwd=WIN_REPO) + \
        "\n\n(runs with this server's privileges: not elevated unless the Claude app is)"


def _schema(props: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": props, "required": required or [],
            "additionalProperties": False}


WAIT = {"type": "integer", "minimum": 0, "maximum": MAX_WAIT_S,
        "description": f"Seconds to wait before returning (<= {MAX_WAIT_S}); job keeps running after."}

TOOLS = {
    "wsl_status": (tool_status, "Report WSL2 readiness: kernel, BTF, bpffs, GPU, wrapper + sudo setup, toolchain, repo paths and branch.", _schema({})),
    "wsl_sync": (tool_sync, "rsync the Windows working tree into the WSL build copy (same excludes as tools/dev-loop.ps1) and strip CRLF from scripts.", _schema({"wait_s": WAIT})),
    "wsl_make": (tool_make, "Sync (default) then run an allowlisted make target as root via the lapa-root wrapper. Runs as a background job.",
                 _schema({"target": {"type": "string", "enum": MAKE_TARGETS},
                          "sync": {"type": "boolean", "default": True},
                          "clean": {"type": "boolean", "default": False},
                          "wait_s": WAIT}, ["target"])),
    "wsl_trace": (tool_trace, "Run bin/unified_trace as root via the wrapper with validated flags. Output goes to runs/<output_name> in the WSL repo.",
                  _schema({"pid": {"type": "integer"}, "duration": {"type": "integer", "minimum": 1, "maximum": 300},
                           "cuda_lib": {"type": "string", "description": "absolute WSL path to libcudart.so"},
                           "stack_sample_async": {"type": "integer"}, "stack_sample_sync": {"type": "integer"},
                           "max_stack_frames": {"type": "integer"}, "no_stacks": {"type": "boolean"},
                           "no_symbolize": {"type": "boolean"}, "no_offcpu_stacks": {"type": "boolean"},
                           "verbose": {"type": "boolean"}, "output_name": {"type": "string"},
                           "sync": {"type": "boolean", "default": False}, "wait_s": WAIT})),
    "wsl_job": (tool_job, "Show a job's status and log tail (or list jobs when id is omitted). Optionally wait for it.",
                _schema({"id": {"type": "string"}, "wait_s": WAIT,
                         "tail_bytes": {"type": "integer", "minimum": 100, "maximum": 200000}})),
    "wsl_cancel": (tool_cancel, "Kill a running job.", _schema({"id": {"type": "string"}}, ["id"])),
    "wsl_read": (tool_read, "Read the tail of a file inside WSL (WSL repo or /tmp only). Relative paths are relative to the WSL repo.",
                 _schema({"path": {"type": "string"}, "tail_bytes": {"type": "integer", "minimum": 1, "maximum": 200000}}, ["path"])),
    "wsl_copy_to_windows": (tool_copy, "Copy a file from WSL (WSL repo or /tmp only) into <Windows repo>/runs/wsl/ so it can be opened from Windows.",
                            _schema({"path": {"type": "string"}, "dest_name": {"type": "string"}}, ["path"])),
    "win_cargo": (tool_win_cargo, "Run cargo (version/check/build/test/clippy) natively on Windows in windows/etw-collector, as the normal user. Background job.",
                  _schema({"command": {"type": "string", "enum": CARGO_CMDS},
                           "release": {"type": "boolean", "default": False}, "wait_s": WAIT}, ["command"])),
    "win_collect": (tool_win_collect, "Run the built etw-collector.exe (not elevated) for a target pid/process name. Writes runs/etw/<output_name>.json (+ .raw.jsonl).",
                    _schema({"pid": {"type": "array", "items": {"type": "integer"}},
                             "process_name": {"type": "array", "items": {"type": "string"}},
                             "duration": {"type": "integer", "minimum": 1, "maximum": 300},
                             "follow_children": {"type": "boolean"}, "no_cpu": {"type": "boolean"},
                             "no_faults": {"type": "boolean"}, "no_gpu": {"type": "boolean"},
                             "no_net": {"type": "boolean"}, "verbose": {"type": "boolean"},
                             "save_raw": {"type": "boolean", "default": True},
                             "output_name": {"type": "string"}, "wait_s": WAIT})),
}
if ALLOW_EXEC:
    TOOLS["wsl_exec"] = (tool_exec, "Run an arbitrary bash command in WSL as your normal user (NOT root), cwd = WSL repo. Enabled via WSL_DEV_ALLOW_EXEC=1.",
                         _schema({"command": {"type": "string"}, "wait_s": WAIT}, ["command"]))


# --------------------------------------------------------------------------
# MCP stdio (JSON-RPC 2.0, newline-delimited)
# --------------------------------------------------------------------------

def reply(msg_id, result=None, error=None):
    out = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        out["error"] = error
    else:
        out["result"] = result
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()


def handle(msg: dict):
    method = msg.get("method")
    msg_id = msg.get("id")
    params = msg.get("params") or {}
    if msg_id is None:            # notification (e.g. notifications/initialized)
        return
    if method == "initialize":
        reply(msg_id, {
            "protocolVersion": params.get("protocolVersion", DEFAULT_PROTOCOL),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": ("Build/test/trace local-ai-perf-analysis in WSL2. Long tools return a job id; "
                             "poll with wsl_job. Logs: <repo>/runs/wsl-jobs/."),
        })
    elif method == "ping":
        reply(msg_id, {})
    elif method == "tools/list":
        reply(msg_id, {"tools": [{"name": n, "description": d, "inputSchema": s}
                                 for n, (_, d, s) in TOOLS.items()]})
    elif method == "tools/call":
        name = params.get("name")
        entry = TOOLS.get(name)
        if not entry:
            reply(msg_id, {"content": [{"type": "text", "text": f"unknown tool {name}"}], "isError": True})
            return
        try:
            text = entry[0](params.get("arguments") or {})
            reply(msg_id, {"content": [{"type": "text", "text": text}], "isError": False})
        except Exception as e:  # report tool errors as results, not protocol errors
            reply(msg_id, {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True})
    else:
        reply(msg_id, error={"code": -32601, "message": f"method not found: {method}"})


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            handle(msg)
        except Exception as e:
            if isinstance(msg, dict) and msg.get("id") is not None:
                reply(msg["id"], error={"code": -32603, "message": str(e)})


if __name__ == "__main__":
    main()
