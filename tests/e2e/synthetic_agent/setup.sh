#!/usr/bin/env bash
# Idempotent setup for the synthetic agent's fixtures: deterministic
# document corpus + executable code snippets. Re-running is safe; we
# only regenerate if the count is wrong.

set -euo pipefail

ROOT="${1:-/tmp/synthetic_agent}"
CORPUS="$ROOT/corpus"
SNIPPETS="$ROOT/snippets"

mkdir -p "$CORPUS" "$SNIPPETS"

# 20 deterministic text files for the disk-read phase. The content is
# generated from a fixed seed so file sizes and byte contents are stable
# across runs — that lets validators assert exact byte counts later.
if [[ "$(ls "$CORPUS" | wc -l)" -ne 20 ]]; then
    rm -f "$CORPUS"/*.txt
    for i in $(seq 0 19); do
        # Each file is ~2 KB, content varies per index but is deterministic.
        {
            echo "Document $i"
            echo "==========="
            for line in $(seq 1 80); do
                printf "Line %d of document %d. lorem ipsum %d %d %d.\n" \
                    "$line" "$i" "$((line*7))" "$((i*13))" "$((line+i))"
            done
        } > "$CORPUS/doc_$i.txt"
    done
fi

# 5 short Python snippets the agent will invoke via subprocess. Each
# sleeps a different controllable duration to simulate variable "code
# interpreter" workloads.
if [[ "$(ls "$SNIPPETS" | wc -l)" -ne 5 ]]; then
    rm -f "$SNIPPETS"/*.py
    for i in $(seq 0 4); do
        cat > "$SNIPPETS/snippet_$i.py" <<EOF
# Synthetic code-interpreter snippet $i.
# Simulates a tool execution of known duration.
import sys, time
DURATION_MS = $((100 + i * 100))   # 100, 200, 300, 400, 500 ms
time.sleep(DURATION_MS / 1000.0)
print(f"snippet_$i completed after {DURATION_MS}ms", file=sys.stderr)
EOF
    done
fi

echo "synthetic_agent fixtures ready:"
echo "  $CORPUS  (20 documents, $(du -sh "$CORPUS" | cut -f1) total)"
echo "  $SNIPPETS  (5 code snippets)"
