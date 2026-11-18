#!/usr/bin/env python3
"""Workload driver for local-ai-perf-analysis.

Runs scripted agents against any OpenAI-compatible endpoint (Ollama,
LM Studio, llama-server, ...) and writes a JSONL "sidecar" with
request-level ground truth: when each request was sent, when every
streamed chunk arrived, and what the server reported as token usage.
The sidecar is what turns a collector trace (ETW or eBPF) from "the GPU
was busy" into "request 7 of the foreground agent waited 900 ms for its
first token while the background agent's prefill held the slot".

Design rules:
  * Agents are SCRIPTED. Prompts are synthetic filler of a requested
    size, temperature is 0 and the seed is fixed, so a run does not
    depend on what the model decides to do.
  * Timing is measured on the client. Nothing here needs a
    backend-specific metric, so results are comparable across backends.
  * Standard library only, Python 3.8+, same code on Windows and Linux.

Usage:
  python driver.py scenarios/w0_single_request_sweep.json \
      --backend backends/ollama.json --model llama3.2:3b --out runs/w0

Sidecar clocks: every event carries
  wall_ns  Unix-epoch nanoseconds  (aligns with ETW / etw-collector)
  mono_ns  CLOCK_MONOTONIC nanoseconds (aligns with eBPF bpf_ktime_get_ns
           on Linux; on Windows it is only useful for intervals)
Both are derived from one high-resolution counter, so intervals are
exact even where the OS wall clock ticks coarsely.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse

SIDECAR_VERSION = 1

# Common short English words: roughly one token each in BPE vocabularies,
# so "N words" is a usable stand-in for "N prompt tokens". The server's
# own usage.prompt_tokens is recorded as the real figure.
WORDS = (
    "the of and to in is that for it as was with be by on not he this are or his "
    "from at which but have an had they you were their one all we can her has "
    "there been if more when will would who so no out up into than them only time "
    "new some could these two may then do first any my now such like our over man "
    "me even most made after also did many before must through years where much "
    "your way well down should because each just those people how too little state "
    "good very make world still own see men work long get here between both life "
    "being under never day same another know while last might us great old year off "
    "come since against go came right used take three"
).split()

GENERATE_INSTRUCTION = (
    "\n\nTask: write one long continuous paragraph of plain prose about the "
    "history of everyday tools. Do not use lists. Do not stop early."
)


# --------------------------------------------------------------------------
# Clock + sidecar
# --------------------------------------------------------------------------


class Clock:
    """One high-resolution counter, anchored once to wall and monotonic time.

    On Windows before Python 3.13 time.time_ns() ticks every ~1-15 ms, so
    we wait for a tick edge before taking the anchor; the anchor is then
    accurate to the counter's resolution rather than to the tick length.
    """

    def __init__(self):
        w0 = time.time_ns()
        deadline = time.perf_counter_ns() + 50_000_000
        while True:
            w = time.time_ns()
            p = time.perf_counter_ns()
            if w != w0 or p > deadline:
                break
        self.wall0 = w
        self.perf0 = p
        self.mono0 = time.monotonic_ns()

    @staticmethod
    def now() -> int:
        return time.perf_counter_ns()

    def wall(self, p: int) -> int:
        return self.wall0 + (p - self.perf0)

    def mono(self, p: int) -> int:
        return self.mono0 + (p - self.perf0)


class Sidecar:
    def __init__(self, path: str, clock: Clock):
        self.clock = clock
        self._f = open(path, "w", encoding="utf-8", newline="\n")
        self._lock = threading.Lock()

    def emit(self, ev: str, t: int = None, **fields):
        t = Clock.now() if t is None else t
        rec = {
            "ev": ev,
            "t_ms": round((t - self.clock.perf0) / 1e6, 3),
            "wall_ns": self.clock.wall(t),
            "mono_ns": self.clock.mono(t),
        }
        rec.update(fields)
        line = json.dumps(rec, separators=(",", ":"))
        with self._lock:
            self._f.write(line + "\n")
            self._f.flush()

    def close(self):
        with self._lock:
            self._f.close()


_print_lock = threading.Lock()


def say(msg: str):
    with _print_lock:
        print(msg, flush=True)


# --------------------------------------------------------------------------
# Backend (OpenAI-compatible HTTP)
# --------------------------------------------------------------------------


class Backend:
    def __init__(self, profile: dict, timeout_s: float):
        self.profile = profile
        self.name = profile.get("name", "backend")
        self.base = profile["base_url"].rstrip("/")
        self.api_key = profile.get("api_key", "")
        self.extra_body = profile.get("extra_body", {})
        self.timeout_s = timeout_s

    def _connect(self, url: str):
        u = urllib.parse.urlsplit(url)
        cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        conn = cls(u.hostname, u.port, timeout=self.timeout_s)
        path = u.path + ("?" + u.query if u.query else "")
        return conn, path

    def _headers(self):
        h = {"Content-Type": "application/json", "Accept": "text/event-stream"}
        if self.api_key:
            h["Authorization"] = "Bearer " + self.api_key
        return h

    def list_models(self) -> list:
        conn, path = self._connect(self.base + "/models")
        try:
            conn.request("GET", path, headers=self._headers())
            r = conn.getresponse()
            body = r.read()
            if r.status != 200:
                raise RuntimeError("GET /models -> HTTP %d: %s" % (r.status, body[:200]))
            return [m.get("id") for m in json.loads(body).get("data", [])]
        finally:
            conn.close()

    def hook(self, which: str, model: str):
        """Run an optional backend-specific action (e.g. 'unload').

        Returns (ok, detail). Backends without the hook return (False, 'no hook').
        """
        spec = self.profile.get("hooks", {}).get(which)
        if not spec:
            return False, "backend profile has no '%s' hook" % which
        body = json.dumps(spec.get("body", {})).replace("{model}", model)
        conn, path = self._connect(spec["url"])
        try:
            conn.request(spec.get("method", "POST"), path, body=body.encode(), headers=self._headers())
            r = conn.getresponse()
            r.read()
            return r.status < 300, "HTTP %d" % r.status
        except OSError as e:
            return False, repr(e)
        finally:
            conn.close()

    def chat_stream(self, model: str, messages: list, max_tokens: int, temperature: float, seed):
        """POST /chat/completions with stream=true.

        Returns a dict with the send time, per-chunk arrival times (perf
        counter ns), the generated text, usage and any error. Never raises
        for HTTP/transport errors: a failed request is a data point.
        """
        body = {
            "model": model,
            "messages": messages,
            "stream": True,
            "stream_options": {"include_usage": True},
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if seed is not None:
            body["seed"] = seed
        body.update(self.extra_body)
        payload = json.dumps(body).encode()
        out = {
            "t_send": 0, "t_headers": 0, "t_end": 0, "chunk_t": [], "reasoning_chunks": 0,
            "text": "", "usage": None, "finish_reason": None, "status": 0, "error": None, "extra": {},
        }
        conn, path = self._connect(self.base + "/chat/completions")
        try:
            out["t_send"] = Clock.now()
            conn.request("POST", path, body=payload, headers=self._headers())
            r = conn.getresponse()
            out["t_headers"] = Clock.now()
            out["status"] = r.status
            if r.status != 200:
                out["error"] = "HTTP %d: %s" % (r.status, r.read()[:300].decode("utf-8", "replace"))
                return out
            parts = []
            while True:
                line = r.readline()
                if not line:
                    break
                t = Clock.now()
                line = line.strip()
                if not line.startswith(b"data:"):
                    continue
                data = line[5:].strip()
                if data == b"[DONE]":
                    break
                try:
                    obj = json.loads(data)
                except ValueError:
                    continue
                if obj.get("usage"):
                    out["usage"] = obj["usage"]
                # llama-server reports per-request timings as an extension.
                if obj.get("timings"):
                    out["extra"]["timings"] = obj["timings"]
                for ch in obj.get("choices") or []:
                    delta = ch.get("delta") or {}
                    content = delta.get("content")
                    reasoning = delta.get("reasoning_content") or delta.get("reasoning")
                    if content:
                        parts.append(content)
                        out["chunk_t"].append(t)
                    elif reasoning:
                        # Thinking models stream reasoning first; it is still
                        # decode work, so it counts toward TTFT and ITL.
                        out["chunk_t"].append(t)
                        out["reasoning_chunks"] += 1
                    if ch.get("finish_reason"):
                        out["finish_reason"] = ch["finish_reason"]
            out["text"] = "".join(parts)
        except (OSError, http.client.HTTPException) as e:
            out["error"] = repr(e)
        finally:
            out["t_end"] = Clock.now()
            conn.close()
        return out


# --------------------------------------------------------------------------
# Agents
# --------------------------------------------------------------------------


def filler(n_words: int, rng: random.Random) -> str:
    return " ".join(rng.choice(WORDS) for _ in range(max(0, n_words)))


class Agent(threading.Thread):
    def __init__(self, spec: dict, run: "Run"):
        super().__init__(name=spec["name"], daemon=True)
        self.spec = spec
        self.run_ctx = run
        self.agent = spec["name"]
        self.role = spec.get("role", "foreground")
        self.rng = random.Random("%s/%s" % (run.seed, self.agent))
        sys_tokens = int(spec.get("system_tokens", 0))
        # The system prompt is fixed per agent: it is the stable prefix a
        # server-side prompt cache can reuse between this agent's turns.
        self.system = "You are agent %s. %s" % (self.agent, filler(sys_tokens, self.rng))
        self.history = []
        self.keep_history = bool(spec.get("history", False))
        # Agent-level model override; a step-level "model" takes precedence,
        # otherwise the run's --model (resolved in main()) is used.
        self.model_default = spec.get("model")
        self.n_req = 0
        self.failed = 0

    # -- steps ------------------------------------------------------------

    def _chat(self, step: dict, idx: int):
        run = self.run_ctx
        d = run.defaults
        prompt_tokens = int(step.get("prompt_tokens", d.get("prompt_tokens", 64)))
        max_tokens = int(step.get("max_tokens", d.get("max_tokens", 64)))
        cache = step.get("cache", "warm")
        model = step.get("model") or self.model_default or run.model
        if "prompt_seed" in step:
            # Same seed -> byte-identical prompt, for deliberate cache hits.
            body_rng = random.Random("%s/%s/%s" % (run.seed, self.agent, step["prompt_seed"]))
        else:
            body_rng = self.rng
        user = filler(prompt_tokens, body_rng) + GENERATE_INSTRUCTION
        system = self.system
        if cache == "cold":
            # A unique token at position 0 defeats any prefix cache, so the
            # whole prompt is prefilled. Use for clean prefill-rate numbers.
            system = "[run %s req %s-%d] %s" % (run.run_id, self.agent, self.n_req, system)
        if step.get("reset_history"):
            self.history = []
        messages = [{"role": "system", "content": system}] + self.history + [{"role": "user", "content": user}]
        self.n_req += 1
        req_id = "%s-%d" % (self.agent, self.n_req)
        common = dict(agent=self.agent, role=self.role, step=idx, req_id=req_id,
                      label=step.get("label", ""))
        run.sidecar.emit("req_start", prompt_tokens_target=prompt_tokens, max_tokens=max_tokens,
                         cache=cache, history_msgs=len(self.history), model=model, **common)
        res = run.backend.chat_stream(model, messages, max_tokens,
                                      float(d.get("temperature", 0.0)), d.get("seed", 0))
        ts = res["chunk_t"]
        t0 = res["t_send"]
        ttft_ms = round((ts[0] - t0) / 1e6, 3) if ts else None
        usage = res["usage"] or {}
        run.sidecar.emit(
            "req_end", t=res["t_end"],
            ok=res["error"] is None and bool(ts), status=res["status"], error=res["error"],
            send_wall_ns=run.clock.wall(t0), send_mono_ns=run.clock.mono(t0),
            headers_ms=round((res["t_headers"] - t0) / 1e6, 3) if res["t_headers"] else None,
            ttft_ms=ttft_ms, total_ms=round((res["t_end"] - t0) / 1e6, 3),
            chunks=len(ts), reasoning_chunks=res["reasoning_chunks"],
            chunk_ms=[round((t - t0) / 1e6, 3) for t in ts],
            chars=len(res["text"]), finish_reason=res["finish_reason"], usage=usage,
            prompt_tokens_target=prompt_tokens, max_tokens=max_tokens, cache=cache,
            model=model, extra=res["extra"], **common)
        if res["error"] or not ts:
            self.failed += 1
            say("[%s] %s FAILED: %s" % (self.agent, req_id, res["error"] or "no tokens streamed"))
        else:
            n = len(ts)
            rate = (n - 1) / ((ts[-1] - ts[0]) / 1e9) if n > 1 and ts[-1] > ts[0] else 0.0
            say("[%s] %s %-5s prompt=%s tok  ttft=%8.1f ms  out=%s tok  decode=%6.1f tok/s  %s" % (
                self.agent, req_id, cache, usage.get("prompt_tokens", "~%d" % prompt_tokens),
                ttft_ms, usage.get("completion_tokens", "~%d" % n), rate, step.get("label", "")))
        if self.keep_history:
            self.history.append({"role": "user", "content": user})
            self.history.append({"role": "assistant", "content": res["text"] or "(no output)"})

    def _tool(self, step: dict, idx: int):
        run = self.run_ctx
        cmd = step["cmd"]
        common = dict(agent=self.agent, role=self.role, step=idx, label=step.get("label", ""))
        run.sidecar.emit("tool_start", cmd=cmd, **common)
        t0 = Clock.now()
        rc, err, pid = None, None, None
        try:
            # shell=True so scenarios can use the platform's own syntax; the
            # command comes from a scenario file the user chose to run.
            p = subprocess.Popen(cmd, shell=True, cwd=step.get("cwd") or None,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            pid = p.pid
            rc = p.wait(timeout=float(step.get("timeout_s", 300)))
        except subprocess.TimeoutExpired:
            p.kill()
            err = "timeout"
        except OSError as e:
            err = repr(e)
        dur = round((Clock.now() - t0) / 1e6, 3)
        run.sidecar.emit("tool_end", cmd=cmd, rc=rc, error=err, pid=pid, dur_ms=dur, **common)
        say("[%s] tool rc=%s %8.1f ms  %s" % (self.agent, rc if err is None else err, dur, cmd[:60]))

    def _hook(self, step: dict, idx: int):
        run = self.run_ctx
        which = step["do"]
        target = step.get("model") or self.model_default or run.model
        ok, detail = run.backend.hook(which, target)
        run.sidecar.emit("hook", hook=which, ok=ok, detail=detail, model=target,
                         agent=self.agent, step=idx)
        say("[%s] %s(%s): %s (%s)" % (self.agent, which, target, "ok" if ok else "skipped", detail))
        if ok and step.get("settle_s"):
            time.sleep(float(step["settle_s"]))

    # -- loop -------------------------------------------------------------

    def run(self):
        run = self.run_ctx
        delay = float(self.spec.get("start_delay_s", 0))
        if delay and run.stop.wait(delay):
            return
        run.sidecar.emit("agent_start", agent=self.agent, role=self.role)
        steps = self.spec.get("steps", [])
        loops = int(self.spec.get("loop", 1))
        idx = 0
        try:
            for _ in range(loops):
                for step in steps:
                    for _ in range(int(step.get("repeat", 1))):
                        if run.stop.is_set():
                            return
                        if self.role == "background" and run.foreground_done.is_set():
                            return
                        do = step.get("do", "chat")
                        if do == "chat":
                            self._chat(step, idx)
                        elif do == "sleep":
                            if run.stop.wait(float(step.get("seconds", 1))):
                                return
                        elif do == "tool":
                            self._tool(step, idx)
                        else:
                            self._hook(step, idx)
                        idx += 1
        finally:
            run.sidecar.emit("agent_end", agent=self.agent, role=self.role,
                             requests=self.n_req, failed=self.failed)


# --------------------------------------------------------------------------
# GPU sampler (nvidia-smi; optional)
# --------------------------------------------------------------------------

GPU_FIELDS = ["memory.used", "memory.total", "utilization.gpu", "temperature.gpu", "power.draw"]
GPU_KEYS = ["mem_used_mb", "mem_total_mb", "util_pct", "temp_c", "power_w"]


def start_gpu_sampler(sidecar: Sidecar, period_ms: int):
    exe = shutil.which("nvidia-smi")
    if not exe:
        return None
    try:
        p = subprocess.Popen(
            [exe, "--query-gpu=" + ",".join(GPU_FIELDS), "--format=csv,noheader,nounits",
             "-lms", str(period_ms)],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    except OSError:
        return None

    def pump():
        for line in p.stdout:
            vals = [v.strip() for v in line.split(",")]
            if len(vals) != len(GPU_KEYS):
                continue
            rec = {}
            for k, v in zip(GPU_KEYS, vals):
                try:
                    rec[k] = float(v)
                except ValueError:
                    rec[k] = None  # "[N/A]" on GPUs that don't report the field
            sidecar.emit("gpu", **rec)

    threading.Thread(target=pump, name="gpu-sampler", daemon=True).start()
    return p


# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------


class Run:
    pass


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("scenario", help="scenario JSON file")
    ap.add_argument("--backend", required=True, help="backend profile JSON (see backends/)")
    ap.add_argument("--model", help="model id; overrides the scenario / backend default")
    ap.add_argument("--out", default="workload_run", help="output prefix; writes <out>.sidecar.jsonl")
    ap.add_argument("--base-url", help="override the backend profile's base_url")
    ap.add_argument("--timeout", type=float, default=600.0, help="per-request socket timeout (s)")
    ap.add_argument("--gpu-sample-ms", type=int, default=1000,
                    help="nvidia-smi sampling period; 0 disables")
    ap.add_argument("--start-delay", type=float, default=0.0,
                    help="sleep before starting agents (lets a tracer attach)")
    ap.add_argument("--list-models", action="store_true", help="print the backend's models and exit")
    a = ap.parse_args(argv)

    with open(a.backend, encoding="utf-8") as f:
        profile = json.load(f)
    if a.base_url:
        profile["base_url"] = a.base_url
    with open(a.scenario, encoding="utf-8") as f:
        scenario = json.load(f)

    backend = Backend(profile, a.timeout)
    try:
        models = backend.list_models()
    except (OSError, RuntimeError, ValueError, http.client.HTTPException) as e:
        print("cannot reach %s at %s: %r" % (backend.name, backend.base, e), file=sys.stderr)
        return 2
    if a.list_models:
        print("\n".join(str(m) for m in models))
        return 0
    model = a.model or scenario.get("model") or profile.get("default_model")
    agent_models = [ag.get("model") for ag in scenario["agents"] if ag.get("model")]
    step_models = [st.get("model")
                   for ag in scenario["agents"] for st in ag.get("steps", []) if st.get("model")]
    scenario_models = sorted(set(agent_models + step_models))
    # Every chat step must have a resolvable model: step-level > agent-level > run-level.
    missing = []
    for ag in scenario["agents"]:
        if ag.get("model") or model:
            continue
        for st in ag.get("steps", []):
            if st.get("do", "chat") == "chat" and not st.get("model"):
                missing.append("agent %s step %s" % (ag.get("name"), st.get("label", "")))
    if missing:
        print("no model given for: %s. Pass --model, or set 'model' on the agent / step "
              "(backend offers: %s)" % (", ".join(missing), ", ".join(map(str, models))),
              file=sys.stderr)
        return 2
    for m in filter(None, [model] + scenario_models):
        if models and m not in models:
            print("warning: '%s' is not in the backend's model list (%s)" % (m, ", ".join(map(str, models))),
                  file=sys.stderr)

    out_dir = os.path.dirname(os.path.abspath(a.out))
    os.makedirs(out_dir, exist_ok=True)
    sidecar_path = a.out + ".sidecar.jsonl"

    run = Run()
    run.clock = Clock()
    run.sidecar = Sidecar(sidecar_path, run.clock)
    run.backend = backend
    run.model = model
    run.defaults = scenario.get("defaults", {})
    run.seed = scenario.get("seed", 0)
    run.run_id = "%x" % (run.clock.wall0 // 1_000_000)
    run.stop = threading.Event()
    run.foreground_done = threading.Event()

    run.sidecar.emit(
        "run_start", t=run.clock.perf0, sidecar_version=SIDECAR_VERSION, run_id=run.run_id,
        scenario=scenario.get("name", os.path.basename(a.scenario)), scenario_file=a.scenario,
        scenario_def=scenario, backend=backend.name, base_url=backend.base,
        model=model, scenario_models=scenario_models,
        process_names=profile.get("process_names", []), driver_pid=os.getpid(),
        host={"platform": platform.platform(), "machine": platform.machine(),
              "python": platform.python_version(), "cpus": os.cpu_count()},
        clock={"wall0_ns": run.clock.wall0, "mono0_ns": run.clock.mono0})
    say("scenario %s -> %s (%s, model %s)" % (scenario.get("name"), sidecar_path, backend.name, model))

    sampler = start_gpu_sampler(run.sidecar, a.gpu_sample_ms) if a.gpu_sample_ms > 0 else None
    if a.start_delay:
        time.sleep(a.start_delay)

    agents = [Agent(spec, run) for spec in scenario["agents"]]
    fg = [ag for ag in agents if ag.role != "background"]
    rc = 0
    try:
        for ag in agents:
            ag.start()
        for ag in fg:
            while ag.is_alive():
                ag.join(0.2)
        run.foreground_done.set()  # background agents stop at their next step
        for ag in agents:
            while ag.is_alive():
                ag.join(0.2)
    except KeyboardInterrupt:
        say("interrupted; stopping agents")
        run.stop.set()
        rc = 130
    finally:
        if sampler:
            sampler.terminate()
        failed = sum(ag.failed for ag in agents)
        total = sum(ag.n_req for ag in agents)
        run.sidecar.emit("run_end", requests=total, failed=failed)
        run.sidecar.close()
    say("done: %d requests, %d failed -> %s" % (total, failed, sidecar_path))
    return rc or (1 if failed else 0)


if __name__ == "__main__":
    sys.exit(main())
