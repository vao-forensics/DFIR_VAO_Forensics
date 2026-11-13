"""Process-wide and host-wide guardrail for LM Studio requests.

The DFIR stack is threaded and may receive multiple Telegram actions at once.
LM Studio/GPU host must see only a small number of concurrent requests, otherwise
VRAM/driver pressure can freeze the whole rig.  This module monkey-patches
``urllib.request.urlopen`` and serializes only OpenAI-compatible LM Studio
endpoints; Qdrant, Telegram, n8n, and other HTTP traffic continue normally.
"""
from __future__ import annotations

import contextlib
import json
import fcntl
import logging
import os
import threading
import time
import urllib.parse
import urllib.request
from typing import Any

try:
    from core.config import EMBED_URL, LLM_FAST_URL, LLM_URL
except Exception:  # pragma: no cover - keep import-safe during partial startup
    LLM_URL = os.getenv("DFIR_LLM_URL", "http://192.168.100.1:1234")
    LLM_FAST_URL = os.getenv("DFIR_FAST_URL", LLM_URL)
    EMBED_URL = os.getenv("DFIR_EMBED_URL", LLM_URL)

_log = logging.getLogger("app")
_original_urlopen = urllib.request.urlopen
_installed = False
_install_lock = threading.Lock()

# Default is intentionally safe for production: one request to LM Studio at a time.
try:
    _CONCURRENCY = max(1, int(os.getenv("DFIR_LLM_CONCURRENCY", "1")))
except Exception:
    _CONCURRENCY = 1

_QUEUE_TIMEOUT = float(os.getenv("DFIR_LLM_QUEUE_TIMEOUT", "1800"))
_LOCK_PATH = os.getenv("DFIR_LLM_QUEUE_LOCK", "/tmp/dfir_lmstudio_queue.lock")
_thread_gate = threading.BoundedSemaphore(_CONCURRENCY)

# ── Observability (ADDITIVE, task: progress cards) ───────────────────────────
# Atomic counters so a progress card can show "inflight / waiting" without ever
# touching the request path. Pure in-process ints under one lock; never raises.
_stats_lock = threading.Lock()
_inflight = 0                      # LLM calls currently executing the HTTP request
_waiters = 0                       # LLM calls blocked waiting for a slot
_wait_started: dict = {}           # id(thread-token) -> monotonic start of wait
_SWAP_HINT_SEC = float(os.getenv("DFIR_LLM_SWAP_HINT_SEC", "12"))


def _stat_enter_wait():
    tok = object()
    with _stats_lock:
        global _waiters
        _waiters += 1
        _wait_started[id(tok)] = time.monotonic()
    return tok


def _stat_acquired(tok):
    with _stats_lock:
        global _waiters, _inflight
        _waiters = max(0, _waiters - 1)
        _wait_started.pop(id(tok), None)
        _inflight += 1


def _stat_released():
    with _stats_lock:
        global _inflight
        _inflight = max(0, _inflight - 1)


def queue_stats() -> dict:
    """Return a snapshot of LLM-queue state. Never raises.

    Keys:
      inflight        int  – LLM HTTP requests currently running
      waiters         int  – LLM requests blocked waiting for the slot
      concurrency     int  – configured max concurrent LLM requests
      longest_wait_sec float – age of the oldest still-waiting request (0 if none)
      swapping        bool – heuristic: a request has waited long enough that the
                             host is very likely loading/swapping a model
    """
    try:
        with _stats_lock:
            now = time.monotonic()
            longest = 0.0
            for t0 in _wait_started.values():
                longest = max(longest, now - t0)
            return {
                "inflight": int(_inflight),
                "waiters": int(_waiters),
                "concurrency": int(_CONCURRENCY),
                "longest_wait_sec": round(longest, 1),
                "swapping": bool(longest >= _SWAP_HINT_SEC),
            }
    except Exception:
        return {"inflight": 0, "waiters": 0, "concurrency": int(_CONCURRENCY),
                "longest_wait_sec": 0.0, "swapping": False}


_LM_ENDPOINTS = (
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/embeddings",
)


def _base_netlocs() -> set[str]:
    netlocs: set[str] = set()
    for base in (LLM_URL, LLM_FAST_URL, EMBED_URL):
        try:
            parsed = urllib.parse.urlparse(str(base))
            if parsed.netloc:
                netlocs.add(parsed.netloc.lower())
        except Exception:
            continue
    return netlocs


def _request_url(req: Any) -> str:
    if isinstance(req, urllib.request.Request):
        return req.full_url
    return str(req)


def is_lmstudio_request(req: Any) -> bool:
    """Return True for configured LM Studio OpenAI-compatible endpoints only."""
    try:
        parsed = urllib.parse.urlparse(_request_url(req))
        if not parsed.netloc or parsed.netloc.lower() not in _base_netlocs():
            return False
        return any(parsed.path.rstrip("/").endswith(path) for path in _LM_ENDPOINTS)
    except Exception:
        return False


@contextlib.contextmanager
def _cross_process_slot():
    """Cross-process guard for future gunicorn worker increases.

    fcntl locks are process-scoped, so this is paired with a thread semaphore for
    the current worker process.  With the default concurrency=1, both threads and
    processes queue behind the same LM Studio slot.
    """
    os.makedirs(os.path.dirname(_LOCK_PATH) or ".", exist_ok=True)
    with open(_LOCK_PATH, "a+") as lock_file:
        start = time.monotonic()
        while True:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() - start > _QUEUE_TIMEOUT:
                    raise TimeoutError(f"LLM queue wait exceeded {_QUEUE_TIMEOUT:.0f}s")
                time.sleep(0.25)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


# ── big-120b hold (2026-10-01) ────────────────────────────────────────────────────────
# big-120b serves Agent agent sessions and owns all five cards. Any bot request for another
# model makes llama-swap evict it, and each next Agent call waited ~2 min for a reload. Owner's
# choice («на вимогу»): while big-120b is loaded, bot calls to other models wait until it unloads
# (llama-swap ttl 900 s after the last Agent request). DFIR_BIG_HOLD_MAX_SEC caps the wait.
_BIG_IDS = {"big-120b", "big", "gpt-oss-120b", "smart", "forensic-xl", "agent-big"}
_BIG_HOLD_MAX = float(os.getenv("DFIR_BIG_HOLD_MAX_SEC", "1200"))
# 2026-10-13 owner: admin button «Agent 120b» writes this file; while it exists every bot call to a
# non-120b model waits (no time cap), so the bot never evicts 120b from under the owner's Agent.
AGENT_MODE_FILE = os.getenv("DFIR_AGENT_MODE_FILE", "/data/state/llm_mode_agent_big")


def _boot_id() -> str:
    try:
        with open("/proc/sys/kernel/random/boot_id") as f:
            return f.read().strip()
    except OSError:
        return ""


def agent_mode_on() -> bool:
    # the file stores the VM boot_id it was set in; after a power cut 120b is gone and the mode must
    # not keep holding client analyses forever (13.10: case_57 stuck at LLM triage after reboot)
    try:
        with open(AGENT_MODE_FILE) as f:
            content = f.read().strip()
    except OSError:
        return False
    if content == _boot_id():
        return True
    try:
        os.rename(AGENT_MODE_FILE, AGENT_MODE_FILE + ".stale")
    except OSError:
        pass
    return False


def agent_mode_set() -> None:
    with open(AGENT_MODE_FILE, "w") as f:
        f.write(_boot_id())


def _hold_while_big(req: Any) -> None:
    try:
        url = _request_url(req)
        if not url.rstrip("/").endswith(("/chat/completions", "/completions")):
            return
        body = req.data if isinstance(req, urllib.request.Request) else None
        if body:
            model = str(json.loads(body.decode("utf-8") if isinstance(body, bytes) else body).get("model") or "")
            if model in _BIG_IDS:
                return
        p = urllib.parse.urlparse(url)
        running_url = "%s://%s/running" % (p.scheme, p.netloc)
        start, logged = time.monotonic(), False
        while True:
            if not agent_mode_on():
                if time.monotonic() - start >= _BIG_HOLD_MAX:
                    return
                with _original_urlopen(running_url, timeout=3) as r:
                    run = json.loads(r.read().decode("utf-8") or "{}").get("running") or []
                if not any(str(m.get("model")) == "big-120b" for m in run):
                    return
            if not logged:
                _log.info("LLM_QUEUE hold: Agent 120b mode / big-120b loaded, waiting before %s", url)
                logged = True
            time.sleep(10)
    except Exception:
        return


# ── DFIR lane B (2026-10-08) ──────────────────────────────────────────────────────────
# Owner's scheme: a second copy of the DFIR reasoner (reasoner-31b-b, cards 1,4) runs a second
# DFIR job while those cards are idle. The heavy queue in app.py tags the job's thread with
# lane 'B'; here its reasoner calls are rewritten to the copy and gated separately, so the two
# jobs do not serialize behind one slot. agent-30b / translate-9b also live on cards 1,4 and
# llama-swap evicts without draining in-flight requests, so a call to them first waits for
# lane B's in-flight request; while either of them is loaded, lane-B calls go to lane A instead.
LANE_B_MODEL = os.getenv("DFIR_LANE_B_MODEL", "reasoner-31b-b")
_REA_IDS = {"reasoner-31b", "react", "gemma-31b", "gemma-4-31b", "dfir-synth", "synth-dfir",
            "strong", "dfir-report"}
_LANE_B_CONFLICT_IDS = {"agent-30b", "agent", "agent-cli", "qwen3-30b-abliterated", "uncensored",
                        "translate-9b", "translate-mt", "gemma-2-9b-translate"}
_LANE_B_CONFLICT_RUNNING = {"agent-30b", "translate-9b"}
_lane_local = threading.local()
_gate_b = threading.BoundedSemaphore(1)
_running_cache = {"t": 0.0, "models": set(), "ok": False}
_running_lock = threading.Lock()


def set_thread_lane(lane) -> None:
    _lane_local.lane = lane


def thread_lane():
    return getattr(_lane_local, "lane", None)


def running_models(max_age: float = 5.0):
    """Models llama-swap reports as loaded (cached). Returns (ok, set)."""
    with _running_lock:
        if time.monotonic() - _running_cache["t"] < max_age:
            return _running_cache["ok"], set(_running_cache["models"])
    ok, models = False, set()
    try:
        p = urllib.parse.urlparse(str(LLM_URL))
        with _original_urlopen("%s://%s/running" % (p.scheme, p.netloc), timeout=3) as r:
            run = json.loads(r.read().decode("utf-8") or "{}").get("running") or []
        models = {str(m.get("model")) for m in run}
        ok = True
    except Exception:
        pass
    with _running_lock:
        _running_cache.update(t=time.monotonic(), models=models, ok=ok)
    return ok, models


def lane_b_cards_free() -> bool:
    ok, models = running_models()
    return ok and not (models & _LANE_B_CONFLICT_RUNNING)


def _req_model(req: Any) -> str:
    try:
        body = req.data if isinstance(req, urllib.request.Request) else None
        if body:
            return str(json.loads(body.decode("utf-8") if isinstance(body, bytes) else body).get("model") or "")
    except Exception:
        pass
    return ""


def _with_model(req: Any, model: str):
    body = req.data
    d = json.loads(body.decode("utf-8") if isinstance(body, bytes) else body)
    d["model"] = model
    new = urllib.request.Request(req.full_url, data=json.dumps(d).encode("utf-8"),
                                 headers=dict(req.header_items()), method=req.get_method())
    new.remove_header("Content-length")
    return new


def _lane_b_call(req: Any, args, kwargs):
    """Run one reasoner call on lane B. Returns the response, or None to fall back to lane A."""
    try:
        req_b = _with_model(req, LANE_B_MODEL)
    except Exception:
        return None
    if not _gate_b.acquire(timeout=_QUEUE_TIMEOUT):
        return None
    try:
        _log.info("LLM_QUEUE lane B acquired for %s", LANE_B_MODEL)
        return _original_urlopen(req_b, *args, **kwargs)
    except Exception as e:
        # an eviction by a direct client (Open WebUI, translate via requests) kills the call;
        # the job keeps going on lane A rather than losing the step
        _log.warning("LLM_QUEUE lane B call failed (%s), retrying on lane A", repr(e)[:120])
        with _running_lock:
            _running_cache["t"] = 0.0
        return None
    finally:
        _gate_b.release()


def queued_urlopen(req: Any, *args: Any, **kwargs: Any):
    """urlopen wrapper that queues LM Studio calls and passes other traffic through."""
    if not is_lmstudio_request(req):
        return _original_urlopen(req, *args, **kwargs)
    _hold_while_big(req)
    _model = _req_model(req)
    if thread_lane() == "B" and _model in _REA_IDS:
        if lane_b_cards_free():
            _resp = _lane_b_call(req, args, kwargs)
            if _resp is not None:
                return _resp
    _b_held = False
    if _model in _LANE_B_CONFLICT_IDS:
        # wait for lane B's in-flight call; llama-swap would kill it when it swaps this model in
        _b_held = _gate_b.acquire(timeout=_QUEUE_TIMEOUT)
        with _running_lock:
            _running_cache["t"] = 0.0
    try:
        return _queued_urlopen_a(req, *args, **kwargs)
    finally:
        if _b_held:
            _gate_b.release()


def _queued_urlopen_a(req: Any, *args: Any, **kwargs: Any):

    url = _request_url(req)
    waited_start = time.monotonic()
    _wtok = None
    try:
        _wtok = _stat_enter_wait()
    except Exception:
        _wtok = None
    acquired = _thread_gate.acquire(timeout=_QUEUE_TIMEOUT)
    if not acquired:
        try:
            if _wtok is not None:
                with _stats_lock:
                    globals()['_waiters'] = max(0, _waiters - 1)
                    _wait_started.pop(id(_wtok), None)
        except Exception:
            pass
        raise TimeoutError(f"LLM thread queue wait exceeded {_QUEUE_TIMEOUT:.0f}s")
    try:
        try:
            _stat_acquired(_wtok)
        except Exception:
            pass
        try:
            with _cross_process_slot():
                waited = time.monotonic() - waited_start
                if waited >= 1.0:
                    _log.info("LLM_QUEUE acquired after %.1fs for %s", waited, url)
                else:
                    _log.info("LLM_QUEUE acquired for %s", url)
                try:
                    return _original_urlopen(req, *args, **kwargs)
                finally:
                    _log.info("LLM_QUEUE released for %s", url)
        finally:
            try:
                _stat_released()
            except Exception:
                pass
    finally:
        _thread_gate.release()


def install_urllib_llm_queue() -> None:
    """Install the urllib guard once per process."""
    global _installed
    with _install_lock:
        if _installed:
            return
        urllib.request.urlopen = queued_urlopen
        _installed = True
        _log.info("LLM_QUEUE installed: concurrency=%s endpoints=%s lock=%s", _CONCURRENCY, sorted(_base_netlocs()), _LOCK_PATH)


install_urllib_llm_queue()
