#!/usr/bin/env python3
"""Fake search server used by the synthetic agent.

Why a real HTTP server (not a mock): we want the agent's network
behavior to go through real TCP send/recv syscalls so the (future)
network probes have something concrete to capture. A unittest.mock
would short-circuit that.

Stdlib-only on purpose — no `requests` or `aiohttp` dep — so the
test harness doesn't fight Python version mismatches between WSL
system Python and the venv.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


class SearchHandler(BaseHTTPRequestHandler):
    """GET /search?q=... returns canned results after configurable latency."""

    # The class-level constant is overwritten in main() before serving.
    latency_ms: int = 150

    def do_GET(self):  # noqa: N802 — stdlib API requires this case
        # Simulate the latency of a real search backend.
        time.sleep(self.latency_ms / 1000.0)

        # Canned response — deterministic, doesn't depend on the query.
        body = json.dumps(
            {
                "results": [
                    {"id": i, "title": f"result_{i}", "score": 0.9 - i * 0.1}
                    for i in range(5)
                ]
            }
        ).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # noqa: A003
        # Default stdlib handler logs to stderr; we want quieter output
        # under test. Comment in if debugging.
        # sys.stderr.write(f"server: {fmt % args}\n")
        pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--latency-ms",
        type=int,
        default=150,
        help="Per-request artificial delay; lets the network phase "
        "dominate the agent's wall-clock measurably.",
    )
    args = parser.parse_args()

    SearchHandler.latency_ms = args.latency_ms

    # Bind to loopback only — this fixture must not accidentally be
    # network-reachable from anywhere else on the box.
    server = HTTPServer(("127.0.0.1", args.port), SearchHandler)

    # The test driver greps for these tokens, so they must match exactly.
    print(
        f"SEARCH_SERVER_PID={os.getpid()} "
        f"port={args.port} latency_ms={args.latency_ms}",
        flush=True,
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
