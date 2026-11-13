"""LLM warmup probe for LM Studio-backed chat model.

After a Windows/LM Studio restart the server can be reachable before the model is
loaded, or the server can appear a bit after this backend starts.  This module
runs a small background retry loop that makes one tiny chat request so LM Studio
loads the configured model before the first analyst action hits the bot.
"""
from __future__ import annotations

import fcntl
import logging
import os
import threading
import time
from typing import Optional

_log = logging.getLogger('app')
_LOCK_PATH = os.getenv('DFIR_LLM_WARMUP_LOCK', '/tmp/dfir_llm_warmup.lock')

# None = probing/not finished, True = ready, False = last probe failed.
_llm_ready: Optional[bool] = None
_llm_last_error = ''
_llm_last_elapsed_sec: Optional[float] = None
_llm_last_checked_at = ''
_llm_attempts_done = 0
_llm_probe_running = False
_status_lock = threading.Lock()


def is_ready() -> Optional[bool]:
    with _status_lock:
        return _llm_ready


def status() -> dict:
    with _status_lock:
        return {
            'ready': _llm_ready,
            'running': _llm_probe_running,
            'attempts_done': _llm_attempts_done,
            'last_error': _llm_last_error,
            'last_elapsed_sec': _llm_last_elapsed_sec,
            'last_checked_at': _llm_last_checked_at,
        }


def _set_status(*, ready: Optional[bool], running: bool, error: str = '', elapsed: Optional[float] = None) -> None:
    global _llm_ready, _llm_last_error, _llm_last_elapsed_sec, _llm_last_checked_at, _llm_probe_running
    with _status_lock:
        _llm_ready = ready
        _llm_probe_running = running
        _llm_last_error = (error or '')[:500]
        _llm_last_elapsed_sec = round(elapsed, 1) if elapsed is not None else None
        _llm_last_checked_at = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def _increment_attempts() -> int:
    global _llm_attempts_done
    with _status_lock:
        _llm_attempts_done += 1
        return _llm_attempts_done


def run_llm_smoke(timeout: int = 45) -> dict:
    """Run a real tiny chat completion and require non-empty content.

    `/v1/models` is not enough: LM Studio can list models while inference is
    hung, unloaded, or returning empty reasoning-only responses.  This smoke is
    the product-level truth for "AI usable right now".
    """
    from core.config import LLM_MODEL, LLM_FAST_MODEL, LLM_URL
    from core.http_utils import llm_chat

    # Warm the FAST chat model (the resident default), NOT the strong 120B. With
    # on-demand swapping, pinging 120B here would force it co-resident with the 20b
    # (they don't both fit) → 120B spills to CPU. The 120B loads on its first report.
    _warm_model = LLM_FAST_MODEL or LLM_MODEL
    t0 = time.monotonic()
    content = llm_chat(
        LLM_URL,
        _warm_model,
        [{'role': 'user', 'content': 'Reply exactly OK'}],
        max_tokens=int(os.getenv('DFIR_LLM_SMOKE_MAX_TOKENS', '256')),
        temperature=0.0,
        timeout=timeout,
        reasoning_effort=os.getenv('DFIR_LLM_SMOKE_REASONING_EFFORT', 'low'),
    )
    elapsed = time.monotonic() - t0
    content = str(content or '').strip()
    if not content:
        raise RuntimeError('llm_smoke_empty_content')
    return {'ok': True, 'content': content[:80], 'elapsed_sec': round(elapsed, 1), 'url': LLM_URL}


def _run_single_probe(timeout: int) -> float:
    result = run_llm_smoke(timeout=timeout)
    return float(result.get('elapsed_sec') or 0.0)


def _warmup_worker(force: bool = False) -> None:
    """Run retrying warmup loop. Cross-process lock avoids duplicate probes."""
    try:
        lock_fd = open(_LOCK_PATH, 'a')
        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, BlockingIOError):
        _log.info('[warmup] another worker already claimed the AI probe slot; skipping')
        return

    try:
        from core.config import LLM_WARMUP_ATTEMPTS, LLM_WARMUP_RETRY_DELAY, LLM_WARMUP_TIMEOUT
        from telegram.notify import _tg_send_admin

        with _status_lock:
            already_ready = _llm_ready is True
        if already_ready and not force:
            _log.info('[warmup] AI backend already marked ready; skipping')
            return

        _set_status(ready=None, running=True)
        attempts = max(1, int(LLM_WARMUP_ATTEMPTS or 1))
        delay = max(1, int(LLM_WARMUP_RETRY_DELAY or 1))
        timeout = max(5, int(LLM_WARMUP_TIMEOUT or 30))

        last_exc = None
        for idx in range(1, attempts + 1):
            attempt_no = _increment_attempts()
            try:
                _log.info('[warmup] probing AI backend attempt %s/%s', idx, attempts)
                elapsed = _run_single_probe(timeout)
                _set_status(ready=True, running=False, elapsed=elapsed)
                _log.info('[warmup] AI backend ready in %.1fs attempt=%s total_attempts=%s', elapsed, idx, attempt_no)
                # announce only the FIRST successful warmup of this process, and never
                # on a force re-warm (model swap) — those are not a 'bot start'.
                if not force and not getattr(_warmup_worker, '_announced', False):
                    _warmup_worker._announced = True
                    _tg_send_admin(f'✅ Бот запущено. AI-бекенд готовий до роботи ({elapsed:.0f}с).')
                else:
                    _log.info('[warmup] AI ready (force=%s) — startup notice already sent, suppressing', force)
                return
            except Exception as exc:
                last_exc = exc
                _set_status(ready=False, running=True, error=str(exc))
                _log.warning('[warmup] AI backend not ready attempt %s/%s: %s', idx, attempts, exc)
                if idx < attempts:
                    time.sleep(delay)

        _set_status(ready=False, running=False, error=str(last_exc or 'warmup failed'))
        try:
            _tg_send_admin('⚠️ Бот запущено. AI-бекенд поки не відповідає — перевірте LM Studio.')
        except Exception:
            pass
    finally:
        try:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
            lock_fd.close()
        except Exception:
            pass


def schedule_warmup_probe(force: bool = False) -> bool:
    """Safe to call from each Gunicorn worker; only one process probes.

    Returns True when a local daemon thread was scheduled.
    """
    try:
        from core.config import LLM_WARMUP_ENABLED
        if not LLM_WARMUP_ENABLED and not force:
            _log.info('[warmup] disabled by config')
            return False
        threading.Thread(target=_warmup_worker, kwargs={'force': force}, daemon=True, name='llm-warmup').start()
        return True
    except Exception as exc:
        _log.debug('[warmup] schedule failed: %s', exc)
        return False
