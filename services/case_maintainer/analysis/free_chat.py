"""Free uncensored AI chat for allowed Telegram users (agent-30b).

A Telegram front-end to the LLM: allowed users chat in Telegram, each exchange is
kept in a per-user sliding context window and mirrored to an audit log. WebUI
mirroring (per-TG-user account) is added in a later phase; this module is the
safe, self-contained core (ACL + context + LLM + log).
Reuses: core.config.PG_DSN, core.http_utils.llm_chat, the resident agent-30b model.
General DFIR chat and case Q&A are untouched.
"""
import os
import socket
import json
import logging
import psycopg2
from psycopg2.extras import Json

from core.config import PG_DSN
from core.http_utils import llm_chat

_log = logging.getLogger('free_chat')

LLM_URL = os.getenv('DFIR_LLM_URL', 'http://192.168.100.1:1234')
# Модель чату НЕ успадковується від моделі міркування: DFIR_REACT_MODEL
# вказує на reasoner-31b, і кожне повідомлення чату тягло перемикання
# моделі, яке не вкладалось у таймаут (виміряно 26.09).
FREE_CHAT_MODEL = os.getenv('DFIR_FREECHAT_MODEL', 'agent-30b')
LLM_TIMEOUT = int(os.getenv('DFIR_FREECHAT_TIMEOUT', '600'))
MAX_TURNS = int(os.getenv('DFIR_FREECHAT_MAX_TURNS', '12'))          # sliding window (user+assistant msgs)
MAX_CTX_CHARS = int(os.getenv('DFIR_FREECHAT_MAX_CTX_CHARS', '12000'))  # ~ token budget guard
MAX_TOKENS = int(os.getenv('DFIR_FREECHAT_MAX_TOKENS', '2000'))
RATE_PER_HOUR = int(os.getenv('DFIR_FREECHAT_RATE_HOUR', '40'))
SYS_PROMPT = os.getenv(
    'DFIR_FREECHAT_SYSTEM',
    'Ти корисний асистент. Відповідай українською, чітко й по суті, без зайвих застережень.')


def _conn():
    c = psycopg2.connect(PG_DSN)
    c.autocommit = True
    return c


# ── ACL ────────────────────────────────────────────────────────────────────
def is_allowed(tg_id) -> bool:
    try:
        with _conn() as c, c.cursor() as cur:
            cur.execute("SELECT active FROM bot_free_chat_acl WHERE tg_id=%s", (int(tg_id),))
            r = cur.fetchone()
            return bool(r) and bool(r[0])
    except Exception as e:
        _log.error("is_allowed err: %s", repr(e)[:120])
        return False


def grant(tg_id, display_name, admin_id):
    with _conn() as c, c.cursor() as cur:
        cur.execute("""INSERT INTO bot_free_chat_acl(tg_id, display_name, active, granted_by)
                       VALUES(%s,%s,true,%s)
                       ON CONFLICT (tg_id) DO UPDATE SET display_name=EXCLUDED.display_name,
                         active=true, granted_by=EXCLUDED.granted_by, granted_at=now()""",
                    (int(tg_id), (display_name or '').strip()[:120], int(admin_id) if admin_id else None))
    return True


def revoke(tg_id):
    with _conn() as c, c.cursor() as cur:
        cur.execute("UPDATE bot_free_chat_acl SET active=false WHERE tg_id=%s", (int(tg_id),))
    return True


def list_acl():
    with _conn() as c, c.cursor() as cur:
        cur.execute("""SELECT tg_id, display_name, active, granted_at FROM bot_free_chat_acl
                       ORDER BY active DESC, granted_at DESC""")
        return [{'tg_id': r[0], 'name': r[1], 'active': r[2], 'granted_at': str(r[3])}
                for r in cur.fetchall()]


def display_name_for(tg_id) -> str:
    try:
        with _conn() as c, c.cursor() as cur:
            cur.execute("SELECT display_name FROM bot_free_chat_acl WHERE tg_id=%s", (int(tg_id),))
            r = cur.fetchone()
            return (r[0] if r and r[0] else '') or ('TG %s' % tg_id)
    except Exception:
        return 'TG %s' % tg_id


# ── context + rate ──────────────────────────────────────────────────────────
def _load_history(tg_id):
    with _conn() as c, c.cursor() as cur:
        cur.execute("SELECT history FROM bot_free_chat_sessions WHERE tg_id=%s", (int(tg_id),))
        r = cur.fetchone()
    return (r[0] if r and r[0] else []) or []


def _save_history(tg_id, history):
    with _conn() as c, c.cursor() as cur:
        cur.execute("""INSERT INTO bot_free_chat_sessions(tg_id, history, updated_at)
                       VALUES(%s,%s,now())
                       ON CONFLICT (tg_id) DO UPDATE SET history=EXCLUDED.history, updated_at=now()""",
                    (int(tg_id), Json(history)))


def _trim(history):
    """Sliding window: keep the last MAX_TURNS messages AND stay under MAX_CTX_CHARS."""
    h = history[-MAX_TURNS:]
    while h and sum(len(m.get('content', '')) for m in h) > MAX_CTX_CHARS and len(h) > 2:
        h = h[2:]  # drop the oldest user+assistant pair
    return h


def _rate_ok(tg_id) -> bool:
    try:
        with _conn() as c, c.cursor() as cur:
            cur.execute("SELECT count(*) FROM bot_free_chat_log WHERE tg_id=%s AND ts > now() - interval '1 hour'",
                        (int(tg_id),))
            return cur.fetchone()[0] < RATE_PER_HOUR
    except Exception:
        return True


def reset(tg_id):
    with _conn() as c, c.cursor() as cur:
        cur.execute("DELETE FROM bot_free_chat_sessions WHERE tg_id=%s", (int(tg_id),))
    return True


# ── main entry ──────────────────────────────────────────────────────────────
def handle_message(tg_id, text):
    """Returns dict {ok, answer|reason}. Checks ACL + rate, runs agent-30b with the
    user's sliding context, persists history + audit log."""
    text = (text or '').strip()
    if not text:
        return {'ok': False, 'reason': 'empty'}
    if not is_allowed(tg_id):
        return {'ok': False, 'reason': 'not_allowed'}
    if not _rate_ok(tg_id):
        return {'ok': False, 'reason': 'rate_limited'}

    history = _load_history(tg_id)
    history.append({'role': 'user', 'content': text})
    history = _trim(history)

    messages = [{'role': 'system', 'content': SYS_PROMPT}] + \
               [{'role': m['role'], 'content': m['content']} for m in history]
    try:
        answer = llm_chat(LLM_URL, FREE_CHAT_MODEL, messages,
                          max_tokens=MAX_TOKENS, temperature=0.6,
                          timeout=LLM_TIMEOUT)
    except Exception as e:
        # Таймаут — це майже завжди завантаження моделі, а не поломка. Розрізняємо,
        # щоб користувач бачив «зачекай», а не «помилка».
        if isinstance(e, (socket.timeout, TimeoutError)) or 'timed out' in repr(e):
            _log.warning("модель %s не відповіла за %s с (імовірно вантажиться)",
                         FREE_CHAT_MODEL, LLM_TIMEOUT)
            return {'ok': False, 'reason': 'model_loading'}
        _log.error("llm err: %s", repr(e)[:150])
        return {'ok': False, 'reason': 'llm_error'}
    answer = (answer or '').strip()
    if not answer:
        return {'ok': False, 'reason': 'empty_answer'}

    history.append({'role': 'assistant', 'content': answer})
    _save_history(tg_id, _trim(history))
    name = display_name_for(tg_id)
    try:
        with _conn() as c, c.cursor() as cur:
            cur.execute("""INSERT INTO bot_free_chat_log(tg_id, display_name, question, answer)
                           VALUES(%s,%s,%s,%s)""", (int(tg_id), name, text, answer))
    except Exception as e:
        _log.error("log err: %s", repr(e)[:120])
    # WebUI mirror hook (phase 2) — best-effort, never blocks the reply
    try:
        from analysis.free_chat_webui import mirror_exchange
        mirror_exchange(tg_id, name, text, answer)
    except Exception:
        pass
    return {'ok': True, 'answer': answer}
