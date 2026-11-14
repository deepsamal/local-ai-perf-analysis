# wsl-dev — local MCP server for building, testing and tracing in WSL2

Lets Claude (via the Claude desktop app) run this project's build, tests and
tracer inside your real WSL2 distro — with its GPU and kernel — instead of
asking you to copy commands into a terminal.

```
Claude ──MCP──▶ server.py (Windows, stdlib Python)
                   │ wsl.exe -e bash -s   (script on stdin, no quoting layers)
                   ▼
                WSL2: rsync → ~/code/local-ai-perf-analysis
                      sudo -n /usr/local/sbin/lapa-root make <target> | trace <flags>
```

## Tools

| Tool | What it does | Root? |
|---|---|---|
| `wsl_status` | Kernel, BTF, bpffs, GPU, wrapper + sudo setup, toolchain, repo paths, branch | no |
| `wsl_sync` | rsync the Windows working tree into the WSL build copy (same excludes as `dev-loop.ps1`), strip CRLF | no |
| `wsl_make` | sync, then an allowlisted make target: `all mock clean test test-gpu test-python test-synthetic bench` | via wrapper |
| `wsl_trace` | `bin/unified_trace` with validated flags; output to `runs/<name>` | via wrapper |
| `wsl_job` / `wsl_cancel` | poll / kill a background job | no |
| `wsl_read` | tail a file in the WSL repo or `/tmp` | no |
| `wsl_copy_to_windows` | copy a WSL file into `runs/wsl/` on the Windows side | no |
| `wsl_exec` | any bash command **as your user, never root** — only when `WSL_DEV_ALLOW_EXEC=1` | no |

Long-running tools start a job, wait up to `wait_s` (≤ 50 s), and return the
log tail plus a job id. Full logs land in `runs/wsl-jobs/<id>.log` on the
Windows side.

## Setup (once)

### 1. WSL side: wrapper + scoped sudo

Inside WSL:

```bash
sudo apt-get install -y rsync          # if not already installed
sudo bash "/mnt/c/Users/Deep Samal/local-ai-perf-analysis/tools/wsl-dev-mcp/install-wsl.sh"
```

This copies `lapa-root.sh` to `/usr/local/sbin/lapa-root` (root-owned, so
later edits in the repo can't change it) and adds
`/etc/sudoers.d/lapa-root` allowing **only that file** without a password.

> The older `NOPASSWD: /usr/bin/make` rule in `tools/README.md` never matched,
> because `dev-loop-runner.sh` runs `sudo -E env PATH=… make`, so the command
> sudo sees is `env`. Allowing `env` would be equivalent to full root, hence the wrapper.

**Caveat:** the wrapper runs `make` on a user-writable Makefile, so anything
that can edit the repo as your WSL user can run code as root through it.
That's inherent to running eBPF tests from a dev tree. Use on a dev box.

### 2. Windows side: register the server

Edit `%APPDATA%\Claude\claude_desktop_config.json` (Claude desktop →
Settings → Developer → Edit Config) and add to `mcpServers` alongside
`simbridge`:

```json
"wsl-dev": {
  "command": "python",
  "args": ["C:\\Users\\Deep Samal\\local-ai-perf-analysis\\tools\\wsl-dev-mcp\\server.py"],
  "env": {
    "WSL_DEV_ALLOW_EXEC": "0"
  }
}
```

- Use the full path to `python.exe` if `python` isn't on your PATH
  (e.g. your conda base `python.exe`). Python 3.8+ (tested on 3.8 and 3.12); no packages needed.
- Optional env: `WSL_DEV_DISTRO` (default: WSL default distro),
  `WSL_DEV_WSL_REPO` (default `$HOME/code/local-ai-perf-analysis`, no spaces).
- Set `WSL_DEV_ALLOW_EXEC` to `"1"` to enable `wsl_exec`; restart the app
  after changing it.

Restart the Claude desktop app. `wsl_status` should report
`wrapper: installed` and `sudo: NOPASSWD ok`.

## Uninstall

```bash
sudo rm /usr/local/sbin/lapa-root /etc/sudoers.d/lapa-root   # in WSL
```

and remove the `wsl-dev` entry from `claude_desktop_config.json`.
