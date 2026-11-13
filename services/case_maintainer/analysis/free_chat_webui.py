"""Mirror Telegram «🔓 Чат ШІ» conversations into Open WebUI (free-chat phase 2).

Why: the owner authorises users in Telegram, but Open WebUI showed nothing of them —
`analysis.free_chat` has always called `mirror_exchange`, yet this module never existed,
so the import failed and the `except: pass` around it hid that (2026-08-01).

Layout the owner asked for (2026-08-01): a «Telegram» parent folder in the OWNER's admin
account, one SUB-FOLDER per Telegram user, and inside it one chat per conversation
(a new conversation starts after a gap of DFIR_WEBUI_SESSION_GAP_H hours, or when the
user resets the bot session). Folders are also created for authorised users who have not
written yet, so the owner sees everyone he granted access to.

Deleting is real: every mirrored chat is registered in bot_free_chat_mirror, and when ALL
of a user's chats are gone from Open WebUI the sweeper purges that user's bot-side history
(sessions + transcript). The ACL row is never touched — deleting history is not revoking
access.

Everything here is best-effort: a mirror failure must never break the Telegram reply.
"""
import json
import logging
import os
import sqlite3
import time
import uuid

_log = logging.getLogger(__name__)

WEBUI_DB = os.getenv('DFIR_WEBUI_DB', '/webui_data/webui.db')
ROOT_FOLDER = os.getenv('DFIR_WEBUI_TG_FOLDER', 'Telegram')
MIRROR_MODEL = os.getenv('DFIR_FREECHAT_MODEL', os.getenv('DFIR_REACT_MODEL', 'agent-30b'))
SESSION_GAP_MS = int(float(os.getenv('DFIR_WEBUI_SESSION_GAP_H', '6')) * 3600 * 1000)
_TIMEOUT = 15.0


# ------------------------------------------------------------------ plumbing ---

def _conn():
    c = sqlite3.connect(WEBUI_DB, timeout=_TIMEOUT)
    c.execute('PRAGMA busy_timeout=15000')
    return c


def _now_s():
    return int(time.time())


def _now_ms():
    return int(time.time() * 1000)


def _admin_id(c):
    """The account the mirrored chats belong to: the first admin (the owner)."""
    r = c.execute("SELECT id FROM user WHERE role='admin' ORDER BY created_at LIMIT 1").fetchone()
    return r[0] if r else None


def _folder(c, user_id, name, parent_id=None):
    """Get-or-create a folder by (user, name, parent)."""
    if parent_id is None:
        r = c.execute('SELECT id FROM folder WHERE user_id=? AND name=? AND parent_id IS NULL '
                      'LIMIT 1', (user_id, name)).fetchone()
    else:
        r = c.execute('SELECT id FROM folder WHERE user_id=? AND name=? AND parent_id=? LIMIT 1',
                      (user_id, name, parent_id)).fetchone()
    if r:
        return r[0]
    fid = str(uuid.uuid4())
    now = _now_s()
    c.execute('INSERT INTO folder(id, parent_id, user_id, name, items, meta, is_expanded, '
              'created_at, updated_at, data) VALUES(?,?,?,?,?,?,?,?,?,?)',
              (fid, parent_id, user_id, name, json.dumps({}), json.dumps({}), 1, now, now,
               json.dumps({})))
    return fid


def _user_folder(c, user_id, tg_id, display_name):
    """«Telegram» / «<name> · <tg_id>» — one sub-folder per Telegram user."""
    root = _folder(c, user_id, ROOT_FOLDER)
    label = '%s · %s' % ((display_name or 'Користувач').strip()[:40], tg_id)
    # a renamed user keeps the folder that already carries their tg_id
    for fid, nm in c.execute('SELECT id, name FROM folder WHERE user_id=? AND parent_id=?',
                             (user_id, root)):
        if str(nm).rsplit('· ', 1)[-1].strip() == str(tg_id):
            if nm != label:
                c.execute('UPDATE folder SET name=?, updated_at=? WHERE id=?',
                          (label, _now_s(), fid))
            return fid
    return _folder(c, user_id, label, root)


def _meta(raw):
    try:
        return json.loads(raw) if isinstance(raw, str) else (raw or {})
    except Exception:
        return {}


# --------------------------------------------------------------- chat writing ---

def _msg(role, content, parent, ts_ms):
    return {'id': str(uuid.uuid4()), 'parentId': parent, 'childrenIds': [], 'role': role,
            'content': content, 'timestamp': ts_ms, 'models': [MIRROR_MODEL]}


def _append(blob, question, answer, ts_ms):
    """Append one Q/A turn to Open WebUI's chat JSON, keeping its history graph valid."""
    d = json.loads(blob) if isinstance(blob, str) else dict(blob or {})
    hist = d.setdefault('history', {'messages': {}, 'currentId': None})
    hmsgs = hist.setdefault('messages', {})
    parent = hist.get('currentId')

    q = _msg('user', question, parent, ts_ms)
    a = _msg('assistant', answer, q['id'], ts_ms + 1)
    q['childrenIds'] = [a['id']]
    if parent and parent in hmsgs:
        hmsgs[parent].setdefault('childrenIds', []).append(q['id'])

    hmsgs[q['id']] = q
    hmsgs[a['id']] = a
    hist['currentId'] = a['id']
    d['messages'] = d.get('messages', []) + [dict(q), dict(a)]
    d.setdefault('models', [MIRROR_MODEL])
    d.setdefault('files', [])
    d.setdefault('tags', [])
    d['timestamp'] = ts_ms
    return d


def _title(question, ts_ms):
    """Name the conversation after its opening question, like WebUI does."""
    t = ' '.join(str(question or '').split())[:48].strip()
    if not t:
        t = time.strftime('Розмова %Y-%m-%d %H:%M', time.localtime((ts_ms or _now_ms()) / 1000))
    return t


def _open_chat(c, user_id, tg_id, ts_ms):
    """The user's still-open conversation: their newest mirrored chat, unless the gap
    since its last turn exceeds the session window (then a new conversation starts)."""
    best = None
    for cid, meta, blob, upd in c.execute(
            'SELECT id, meta, chat, updated_at FROM chat WHERE user_id=?', (user_id,)):
        m = _meta(meta)
        if str(m.get('tg_id') or '') != str(tg_id):
            continue
        last = int(m.get('last_ts') or (upd or 0) * 1000)
        if best is None or last > best[2]:
            best = (cid, blob, last)
    if not best:
        return None
    if ts_ms - best[2] > SESSION_GAP_MS:
        return None                      # long silence -> this is a new conversation
    return best[0], best[1]


def mirror_exchange(tg_id, display_name, question, answer, ts_ms=None):
    """Mirror one Telegram Q/A turn. Never raises."""
    try:
        if not question or not answer:
            return False
        ts_ms = int(ts_ms or _now_ms())
        with _conn() as c:
            uid = _admin_id(c)
            if not uid:
                _log.warning('[webui-mirror] no admin user in Open WebUI — skipped')
                return False
            fid = _user_folder(c, uid, tg_id, display_name)
            meta = json.dumps({'tg_id': str(tg_id), 'source': 'telegram_free_chat',
                               'last_ts': ts_ms})
            now = int(ts_ms / 1000)      # the turn's own time, not import time
            found = _open_chat(c, uid, tg_id, ts_ms)
            if found:
                cid, blob = found
                d = _append(blob, question, answer, ts_ms)
                d.setdefault('id', cid)
                c.execute('UPDATE chat SET chat=?, updated_at=?, meta=?, folder_id=? WHERE id=?',
                          (json.dumps(d, ensure_ascii=False), now, meta, fid, cid))
            else:
                cid = str(uuid.uuid4())
                title = _title(question, ts_ms)
                d = _append({'id': cid, 'title': title}, question, answer, ts_ms)
                d['id'] = cid
                d['title'] = title
                c.execute(
                    'INSERT INTO chat(id, user_id, title, chat, created_at, updated_at, '
                    'share_id, archived, pinned, meta, folder_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                    (cid, uid, title, json.dumps(d, ensure_ascii=False), now, now, None, 0, 0,
                     meta, fid))
        _remember_mirror(tg_id, cid)
        return True
    except Exception as e:
        _log.warning('[webui-mirror] failed for tg_id=%s: %s', tg_id, repr(e)[:160])
        return False


def ensure_user_folders():
    """Create a folder for every authorised Telegram user, so the owner sees everyone he
    granted access to — including those who have not written yet."""
    made = []
    try:
        with _pg() as pg, pg.cursor() as cur:
            cur.execute('SELECT tg_id, display_name FROM bot_free_chat_acl WHERE active')
            users = cur.fetchall()
        with _conn() as c:
            uid = _admin_id(c)
            if not uid:
                return made
            for tg, name in users:
                _user_folder(c, uid, tg, name)
                made.append(int(tg))
    except Exception as e:
        _log.warning('[webui-mirror] ensure_user_folders: %s', repr(e)[:140])
    return made


# ---------------------------------------------------------------- delete-forever ---

_DDL = """CREATE TABLE IF NOT EXISTS bot_free_chat_mirror(
    chat_id   TEXT PRIMARY KEY,
    tg_id     BIGINT NOT NULL,
    mirrored_at TIMESTAMPTZ DEFAULT now())"""


def _pg():
    import psycopg2
    from core.config import PG_DSN
    return psycopg2.connect(PG_DSN)


def _remember_mirror(tg_id, chat_id):
    """Note every WebUI chat that holds this user's history, so deletions are detectable."""
    try:
        with _pg() as pg, pg.cursor() as cur:
            cur.execute(_DDL)
            cur.execute('INSERT INTO bot_free_chat_mirror(chat_id, tg_id) VALUES(%s,%s) '
                        'ON CONFLICT (chat_id) DO UPDATE SET mirrored_at=now()',
                        (str(chat_id), int(tg_id)))
    except Exception as e:
        _log.warning('[webui-mirror] remember failed: %s', repr(e)[:120])


def sweep_deleted(purge=True):
    """Chats the owner deleted in the browser are dropped from the register; once ALL of a
    user's chats are gone, their bot-side history is purged too — so 'delete' really means
    forever. Safe: if the WebUI DB cannot be read, nothing is purged."""
    purged = []
    try:
        with _conn() as c:
            if not c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='chat'"
                             ).fetchone():
                return purged
            live = {r[0] for r in c.execute('SELECT id FROM chat')}
        with _pg() as pg, pg.cursor() as cur:
            cur.execute(_DDL)
            cur.execute('SELECT chat_id, tg_id FROM bot_free_chat_mirror')
            rows = cur.fetchall()
            gone_by_user = {}
            for chat_id, tg_id in rows:
                gone_by_user.setdefault(int(tg_id), []).append(chat_id in live)
            for tg_id, flags in gone_by_user.items():
                if any(flags):
                    continue                      # at least one conversation still kept
                purged.append(int(tg_id))
                if purge:
                    cur.execute('DELETE FROM bot_free_chat_sessions WHERE tg_id=%s', (tg_id,))
                    cur.execute('DELETE FROM bot_free_chat_log WHERE tg_id=%s', (tg_id,))
                    cur.execute('DELETE FROM bot_free_chat_mirror WHERE tg_id=%s', (tg_id,))
            if purge:
                cur.execute('DELETE FROM bot_free_chat_mirror WHERE chat_id <> ALL(%s)',
                            (list(live) or [''],))
        if purged:
            _log.info('[webui-mirror] purged bot-side history for %s (deleted in WebUI)', purged)
    except Exception as e:
        _log.warning('[webui-mirror] sweep failed: %s', repr(e)[:140])
    return purged


# ----------------------------------------------------------------------- backfill ---

def backfill(limit=20000):
    """Replay bot_free_chat_log into the mirror, splitting into conversations on a gap
    bigger than the session window. Idempotent — turns already mirrored are skipped by
    timestamp."""
    with _pg() as pg, pg.cursor() as cur:
        cur.execute('SELECT tg_id, display_name, question, answer, ts FROM bot_free_chat_log '
                    'ORDER BY ts LIMIT %s', (limit,))
        rows = cur.fetchall()
    cutoff = {}
    with _conn() as c:
        uid = _admin_id(c)
        if uid:
            for cid, meta in c.execute('SELECT id, meta FROM chat WHERE user_id=?', (uid,)):
                m = _meta(meta)
                if m.get('tg_id'):
                    tg = str(m['tg_id'])
                    cutoff[tg] = max(cutoff.get(tg, 0), int(m.get('last_ts') or 0))
    done = skipped = 0
    for tg, name, q, a, ts in rows:
        ms = int(ts.timestamp() * 1000) if ts else _now_ms()
        if ms <= cutoff.get(str(tg), 0):
            skipped += 1
            continue
        if mirror_exchange(tg, name, q, a, ms):
            done += 1
            cutoff[str(tg)] = ms
        else:
            skipped += 1
    ensure_user_folders()
    return {'mirrored': done, 'skipped': skipped, 'total': len(rows)}
