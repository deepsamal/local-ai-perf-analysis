#!/usr/bin/env bash
# lapa-root: the ONLY command the wsl-dev MCP server may run as root.
#
# Installed by install-wsl.sh as /usr/local/sbin/lapa-root (root:root 0755)
# with a sudoers rule allowing just this file without a password.
#
# Subcommands:
#   lapa-root make <target>          allowlisted make targets, in the WSL repo
#   lapa-root trace <flags...>       bin/unified_trace with validated flags;
#                                    --output NAME writes runs/NAME
#
# Everything is derived from SUDO_USER; no caller-controlled environment is
# trusted (sudo's env_reset drops it anyway).
#
# Caveat (same as tools/README.md): `make` executes the Makefile and test
# scripts from a user-writable directory, so anyone who can edit the repo
# as your WSL user can run code as root through this wrapper. Dev box only.

set -euo pipefail

die() { echo "lapa-root: $*" >&2; exit 2; }

[[ $EUID -eq 0 ]] || die "must be run via sudo"
U="${SUDO_USER:-}"
[[ -n "$U" && "$U" != root ]] || die "SUDO_USER not set; run as: sudo -n lapa-root ..."
UH="$(getent passwd "$U" | cut -d: -f6)"
[[ -d "$UH" ]] || die "home for $U not found"

REPO="$UH/code/local-ai-perf-analysis"
[[ -d "$REPO" ]] || die "$REPO missing; run wsl_sync first"
cd "$REPO"

# Same environment tools/dev-loop-runner.sh builds for sudo: user's venv
# and cargo on a space-free PATH, HOME kept as the user's (like sudo -E)
# so cargo finds its registry and run.sh finds ~/venv-perf.
VENV="$UH/venv-perf"
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/wsl/lib"
[[ -d "$UH/.cargo/bin" ]] && PATH="$UH/.cargo/bin:$PATH"
if [[ -d "$VENV/bin" ]]; then PATH="$VENV/bin:$PATH"; export VIRTUAL_ENV="$VENV"; fi
export PATH HOME="$UH" SUDO_USER="$U"

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

is_uint() { [[ "$1" =~ ^[0-9]{1,8}$ ]]; }

cmd="${1:-}"; shift || true
case "$cmd" in
  make)
    [[ $# -eq 1 ]] || die "usage: lapa-root make <target>"
    case "$1" in
      all|mock|clean|test|test-gpu|test-python|test-synthetic|bench) ;;
      *) die "make target not allowed: $1" ;;
    esac
    exec make "$1"
    ;;

  trace)
    [[ -x bin/unified_trace ]] || die "bin/unified_trace not built; run make all"
    args=()
    out=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --pid|--duration|--stack-sample-async|--stack-sample-sync|--max-stack-frames)
          [[ $# -ge 2 ]] && is_uint "$2" || die "$1 needs a number"
          [[ "$1" != --duration || "$2" -le 300 ]] || die "--duration max 300"
          args+=("$1" "$2"); shift 2 ;;
        --cuda-lib)
          [[ $# -ge 2 && "$2" == /* && -f "$2" ]] || die "--cuda-lib needs an existing absolute path"
          args+=("$1" "$2"); shift 2 ;;
        --output)
          [[ $# -ge 2 && "$2" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}$ ]] || die "--output NAME: [A-Za-z0-9_.-]"
          out="runs/$2"; shift 2 ;;
        --no-stacks|--no-symbolize|--no-offcpu-stacks|--verbose)
          args+=("$1"); shift ;;
        *) die "flag not allowed: $1" ;;
      esac
    done
    [[ -n "$out" ]] || out="runs/trace-$(date +%Y%m%d-%H%M%S).json"
    mkdir -p runs
    rc=0
    ./bin/unified_trace "${args[@]}" --output "$out" || rc=$?
    [[ -f "$out" ]] && chown "$U": "$out" && echo "lapa-root: trace written to $REPO/$out"
    exit "$rc"
    ;;

  *)
    die "usage: lapa-root {make <target> | trace <flags...>}"
    ;;
esac
