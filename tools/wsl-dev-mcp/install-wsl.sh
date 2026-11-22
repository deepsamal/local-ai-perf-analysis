#!/usr/bin/env bash
# One-time WSL-side setup for the wsl-dev MCP server.
#
# Run INSIDE WSL, from the Windows copy of the repo:
#   sudo bash "/mnt/c/Users/<you>/local-ai-perf-analysis/tools/wsl-dev-mcp/install-wsl.sh"
#
# Installs:
#   /usr/local/sbin/lapa-root        root:root 0755 (copied, so later edits
#                                    to the repo copy can't change it)
#   /etc/sudoers.d/lapa-root         NOPASSWD for that one file, for $SUDO_USER
#
# Uninstall:
#   sudo rm /usr/local/sbin/lapa-root /etc/sudoers.d/lapa-root

set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
U="${SUDO_USER:-}"
[[ -n "$U" && "$U" != root ]] || { echo "run via sudo from your normal user" >&2; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/lapa-root.sh"
[[ -f "$SRC" ]] || { echo "missing $SRC" >&2; exit 1; }

# Copy with CRLF stripped (the file may come from a Windows checkout).
tmp="$(mktemp)"
sed 's/\r$//' "$SRC" > "$tmp"
install -o root -g root -m 0755 "$tmp" /usr/local/sbin/lapa-root
rm -f "$tmp"
echo "installed /usr/local/sbin/lapa-root"

rule="$U ALL=(root) NOPASSWD: /usr/local/sbin/lapa-root"
tmp="$(mktemp)"
echo "$rule" > "$tmp"
if visudo -cf "$tmp" >/dev/null; then
  install -o root -g root -m 0440 "$tmp" /etc/sudoers.d/lapa-root
  echo "installed /etc/sudoers.d/lapa-root: $rule"
else
  echo "sudoers syntax check failed; nothing installed" >&2
  rm -f "$tmp"; exit 1
fi
rm -f "$tmp"

for t in rsync clang make; do
  command -v "$t" >/dev/null || echo "NOTE: '$t' not found -- sudo apt-get install -y $t"
done
[[ -e /sys/kernel/btf/vmlinux ]] || echo "NOTE: /sys/kernel/btf/vmlinux missing; the sched tracer needs kernel BTF"

echo "done. Check from Windows with the wsl_status tool."
