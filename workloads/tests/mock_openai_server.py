#!/usr/bin/env python3
"""Minimal OpenAI-compatible streaming server for testing the driver.

Not a model: it sleeps in proportion to prompt length (prefill), then
streams one word per token interval (decode). One request at a time, so
concurrent agents queue the way they do on a single-slot local server.

  python tests/mock_openai_server.py --port 18080 --prefill-tok-s 2000 --decode-tok-s 50
"""

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

CFG = {"prefill": 2000.0, "decode": 50.0, "ctx": 4096}
SLOT = threading.Lock()
LAST_PROMPT = {"text": ""}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path.endswith("/models"):
            self._json(200, {"data": [{"id": "mock-model"}]})
        else:
            self._json(404, {"error": "not found"})

    def _chunk(self, obj):
        data = b"data: " + (obj if isinstance(obj, bytes) else json.dumps(obj).encode()) + b"\n\n"
        self.wfile.write(b"%x\r\n" % len(data) + data + b"\r\n")
        self.wfile.flush()

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        if not self.path.endswith("/chat/completions"):
            self._json(200, {})  # e.g. an unload hook
            return
        prompt = " ".join(m["content"] for m in req["messages"])
        n_prompt = min(len(prompt.split()), CFG["ctx"])
        with SLOT:
            # Prefix cache: only the part that differs from the last prompt is prefilled.
            prev = LAST_PROMPT["text"]
            common = 0
            for a, b in zip(prompt.split(), prev.split()):
                if a != b:
                    break
                common += 1
            LAST_PROMPT["text"] = prompt
            time.sleep(max(0, n_prompt - common) / CFG["prefill"])
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            n = int(req.get("max_tokens", 16))
            for i in range(n):
                time.sleep(1.0 / CFG["decode"])
                self._chunk({"choices": [{"index": 0, "delta": {"content": "word%d " % i},
                                          "finish_reason": "length" if i == n - 1 else None}]})
            self._chunk({"choices": [], "usage": {"prompt_tokens": n_prompt, "completion_tokens": n,
                                                  "total_tokens": n_prompt + n}})
            self._chunk(b"[DONE]")
            self.wfile.write(b"0\r\n\r\n")


class S(ThreadingMixIn, HTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--prefill-tok-s", type=float, default=2000.0)
    ap.add_argument("--decode-tok-s", type=float, default=50.0)
    ap.add_argument("--ctx", type=int, default=4096)
    a = ap.parse_args()
    CFG.update(prefill=a.prefill_tok_s, decode=a.decode_tok_s, ctx=a.ctx)
    print("MOCK_READY port=%d" % a.port, flush=True)
    S(("127.0.0.1", a.port), H).serve_forever()
