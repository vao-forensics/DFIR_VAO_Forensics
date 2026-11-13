#!/usr/bin/env python3
"""DFIR «Комунікації» extractor — runs at COLLECTION time (bundled in the collector).

Scans collected artifacts and emits a single `Communications/messengers.csv` matching
the bot's communications_v1 contract (platform, source_kind, self_account, contact_id,
contact_name, direction, msg_ts, message_text, thread_id, attachment, source_artifact,
confidence). stdlib-only (works in a PyInstaller Windows build, no external deps).

Phase 2a: SQLite-based desktop messengers (Viber; extendable to Skype/WhatsApp/Signal-
if-decrypted) + Telegram Desktop tdata IDENTIFIERS. Web Telegram/WhatsApp (browser
IndexedDB LevelDB) come in Phase 2b once we validate against a real sample.

The SQLite extractor is SCHEMA-ADAPTIVE (introspects tables/columns) so it tolerates
version differences instead of hard-coding one schema.
"""
import os
import re
import csv
import glob
import json
import sqlite3
import struct
import datetime as dt

CONTRACT = ['platform', 'source_kind', 'self_account', 'contact_id', 'contact_name',
            'direction', 'msg_ts', 'message_text', 'thread_id', 'attachment',
            'source_artifact', 'confidence']


# ── helpers ──────────────────────────────────────────────────────────────────
def _open_ro(path):
    """Open a SQLite DB read-only + immutable (never touch the evidence file)."""
    uri = 'file:%s?mode=ro&immutable=1' % os.path.abspath(path).replace('?', '%3f')
    return sqlite3.connect(uri, uri=True, timeout=5)


def _tables(cur):
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return [r[0] for r in cur.fetchall()]


def _cols(cur, table):
    try:
        cur.execute('PRAGMA table_info("%s")' % table.replace('"', ''))
        return [r[1] for r in cur.fetchall()]
    except Exception:
        return []


def _find(cols, *patterns):
    """First column whose name matches any regex pattern (case-insensitive)."""
    for pat in patterns:
        rx = re.compile(pat, re.I)
        for c in cols:
            if rx.search(c):
                return c
    return None


def _to_iso(v):
    """Best-effort timestamp → ISO-8601 UTC. Handles epoch s / ms / µs and strings."""
    if v is None or v == '':
        return None
    try:
        if isinstance(v, (int, float)) or (isinstance(v, str) and re.fullmatch(r'\d{9,19}', v.strip())):
            n = int(v)
            if n > 1e17:      # microseconds
                n //= 1000000
            elif n > 1e14:    # 100-ns or µs-ish
                n //= 1000000
            elif n > 1e12:    # milliseconds
                n //= 1000
            # else already seconds
            if 946684800 <= n <= 4102444800:   # 2000-01-01 .. 2100-01-01
                return dt.datetime.utcfromtimestamp(n).strftime('%Y-%m-%dT%H:%M:%SZ')
            return None
        s = str(v).strip()
        s = s.replace('/', '-').replace('T', ' ')[:19]
        d = dt.datetime.fromisoformat(s)
        return d.strftime('%Y-%m-%dT%H:%M:%SZ')
    except Exception:
        return None


def _dir(v):
    """Normalise a direction/outgoing/send-type column value → in/out/unknown."""
    if v is None:
        return 'unknown'
    s = str(v).strip().lower()
    if s in ('1', 'true', 'out', 'outgoing', 'sent', 'send'):
        return 'out'
    if s in ('0', 'false', 'in', 'incoming', 'received', 'recv'):
        return 'in'
    return 'unknown'


# ── generic schema-adaptive SQLite messenger extractor ───────────────────────
def parse_sqlite_messenger(db_path, platform):
    """Introspect a messenger SQLite DB and pull messages into contract rows.
    Returns list[dict]. Best-effort + version-tolerant."""
    rows = []
    try:
        con = _open_ro(db_path)
        cur = con.cursor()
    except Exception:
        return rows
    src = os.path.basename(db_path)
    tables = _tables(cur)

    # build a contact_id → name map from any contacts-like table
    name_by_id = {}
    for t in tables:
        if not re.search(r'contact|user|peer|member|buddies', t, re.I):
            continue
        cols = _cols(cur, t)
        idc = _find(cols, r'^_?id$', r'contact.?id', r'^id', r'number', r'jid')
        namec = _find(cols, r'display.?name', r'^name$', r'nick', r'first.?name', r'title', r'number')
        if not idc or not namec:
            continue
        try:
            cur.execute('SELECT "%s","%s" FROM "%s"' % (idc, namec, t))
            for i, nm in cur.fetchall():
                if i is not None and nm:
                    name_by_id.setdefault(str(i), str(nm))
        except Exception:
            pass

    # find message tables + extract
    for t in tables:
        if not re.search(r'message|\bchat\b|conversation|event', t, re.I):
            continue
        cols = _cols(cur, t)
        bodyc = _find(cols, r'^body$', r'message.?text', r'\btext\b', r'content', r'caption', r'\bbody\b')
        if not bodyc:
            continue
        tsc = _find(cols, r'time.?stamp', r'\bdate\b', r'created', r'\btime\b', r'sort.?id')
        dirc = _find(cols, r'send.?type', r'outgoing', r'from.?me', r'is.?out', r'direction', r'\btype\b')
        contactc = _find(cols, r'contact.?id', r'conversation.?id', r'chat.?id', r'peer', r'sender', r'address', r'number', r'jid')
        attc = _find(cols, r'attach', r'media', r'file.?name', r'\bfile\b')
        sel = [c for c in (bodyc, tsc, dirc, contactc, attc) if c]
        try:
            cur.execute('SELECT %s FROM "%s"' % (','.join('"%s"' % c for c in sel), t))
        except Exception:
            continue
        idx = {c: i for i, c in enumerate(sel)}
        for r in cur.fetchall():
            body = r[idx[bodyc]] if bodyc in idx else None
            if body is None or str(body).strip() == '':
                continue
            cid = str(r[idx[contactc]]) if contactc in idx and r[idx[contactc]] is not None else None
            rows.append({
                'platform': platform, 'source_kind': 'desktop',
                'self_account': None,
                'contact_id': cid,
                'contact_name': name_by_id.get(cid) if cid else None,
                'direction': _dir(r[idx[dirc]]) if dirc in idx else 'unknown',
                'msg_ts': _to_iso(r[idx[tsc]]) if tsc in idx else None,
                'message_text': str(body),
                'thread_id': cid,
                'attachment': (str(r[idx[attc]]) if attc in idx and r[idx[attc]] else None),
                'source_artifact': src,
                'confidence': 'high',
            })
    try:
        con.close()
    except Exception:
        pass
    return rows


# ── Telegram Desktop tdata — IDENTIFIERS only (account ids), Phase 2a ─────────
def parse_tdata_identifiers(tdata_dir):
    """Best-effort: surface Telegram Desktop account identifiers present in tdata
    (the numeric user-id encoded in the account map file name / usertag). Full
    message decryption is Phase 2b (needs the local key + no-passcode). Returns rows
    with self_account set + a marker message so the section shows the account exists."""
    rows = []
    try:
        entries = os.listdir(tdata_dir)
    except Exception:
        return rows
    # tdata account folders: 16-hex-uppercase dirs; usertag files 'usertag' etc.
    acc_dirs = [e for e in entries if re.fullmatch(r'[0-9A-F]{16}', e)]
    has_key = any(e in ('key_datas', 'key_data') for e in entries)
    for a in acc_dirs or (['<default>'] if has_key else []):
        rows.append({
            'platform': 'telegram', 'source_kind': 'desktop',
            'self_account': 'tdata account %s' % a,
            'contact_id': None, 'contact_name': None, 'direction': 'unknown',
            'msg_ts': None,
            'message_text': ('[Telegram Desktop встановлено; акаунт присутній у tdata. '
                             'Розшифрування переписки — етап 2b, потрібен локальний ключ без passcode.]'),
            'thread_id': None, 'attachment': None,
            'source_artifact': 'tdata/%s' % a, 'confidence': 'medium',
        })
    return rows


# ── strings/regex SWEEP («collect everything to the max») ────────────────────
# For web Telegram/WhatsApp (browser IndexedDB/localStorage LevelDB) + tdata, a full
# schema deserialiser needs vendored libs + a validated sample. A strings sweep,
# instead, robustly recovers ALL readable identifiers + text fragments even from
# EXPIRED/cached sessions — the pragmatic «grep -aoE» approach. Emits identifier
# rows (phones/@usernames/emails) + low-confidence message-text fragments.
import re as _re2

_RX_PHONE = _re2.compile(r'(?<!\d)\+?\d[\d][\d\-\s]{6,14}\d(?!\d)')
# negative lookbehind for email-local chars so the «@gmail» of an email isn't a username
_RX_USER = _re2.compile(r'(?<![A-Za-z0-9._%+\-])@[A-Za-z][A-Za-z0-9_]{4,31}')
_RX_EMAIL = _re2.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
# a readable message-like run: letters (Latin/Cyrillic) + spaces, 12..300 chars
_RX_MSG = _re2.compile(r'[A-Za-zА-Яа-яІіЇїЄєҐґ][A-Za-zА-Яа-яІіЇїЄєҐґ0-9 ,.!?;:\'"()\-–—…]{11,299}')
_NOISE_MSG = _re2.compile(r'^(https?://|[A-Za-z]:\\|/[a-z]+/|[A-Za-z0-9+/=]{40,}$)|'
                          r'function|prototype|webpack|indexedDB|chrome-extension|'
                          r'\.(js|css|png|json|woff|svg)\b', _re2.I)


def _decoded_text(data):
    """Yield readable text decoded as UTF-8 and UTF-16-LE (covers Chromium V8 strings
    which are frequently UTF-16), ignoring undecodable bytes."""
    yield data.decode('utf-8', 'ignore')
    yield data.decode('utf-16-le', 'ignore')


def sweep_artifact(path, platform, source_kind, max_bytes=48 * 1024 * 1024):
    """Regex sweep one file → contract rows (identifiers + text fragments)."""
    rows = []
    try:
        if os.path.getsize(path) > max_bytes:
            return rows
        with open(path, 'rb') as f:
            data = f.read()
    except Exception:
        return rows
    src = os.path.basename(os.path.dirname(path)) + '/' + os.path.basename(path)
    phones, users, emails, frags = set(), set(), set(), []
    for txt in _decoded_text(data):
        phones.update(m.strip() for m in _RX_PHONE.findall(txt))
        users.update(_RX_USER.findall(txt))
        emails.update(_RX_EMAIL.findall(txt))
        for m in _RX_MSG.findall(txt):
            s = m.strip()
            if len(s) >= 12 and ' ' in s and not _NOISE_MSG.search(s):
                frags.append(s)
    # normalise phones (keep those with 9..15 digits)
    phones = {p for p in phones if 9 <= len(_re2.sub(r'\D', '', p)) <= 15}
    ident = {'phones': sorted(phones)[:200], 'usernames': sorted(users)[:200],
             'emails': sorted(emails)[:200]}
    # one identifier row per distinct contact-ish value (shows up as a contact)
    for p in ident['phones']:
        rows.append({'platform': platform, 'source_kind': source_kind, 'self_account': None,
                     'contact_id': p, 'contact_name': p, 'direction': 'unknown', 'msg_ts': None,
                     'message_text': '[номер відновлено зі strings-sweep кешу]',
                     'thread_id': None, 'attachment': None, 'source_artifact': src, 'confidence': 'medium'})
    for u in ident['usernames']:
        rows.append({'platform': platform, 'source_kind': source_kind, 'self_account': None,
                     'contact_id': u, 'contact_name': u, 'direction': 'unknown', 'msg_ts': None,
                     'message_text': '[юзернейм відновлено зі strings-sweep кешу]',
                     'thread_id': None, 'attachment': None, 'source_artifact': src, 'confidence': 'medium'})
    for e in ident['emails']:
        rows.append({'platform': platform, 'source_kind': source_kind, 'self_account': None,
                     'contact_id': e, 'contact_name': e, 'direction': 'unknown', 'msg_ts': None,
                     'message_text': '[пошта відновлена зі strings-sweep кешу]',
                     'thread_id': None, 'attachment': None, 'source_artifact': src, 'confidence': 'medium'})
    # de-duplicated text fragments (low confidence — order/authorship not reconstructed)
    seen = set()
    for s in frags:
        k = s.lower()[:80]
        if k in seen:
            continue
        seen.add(k)
        rows.append({'platform': platform, 'source_kind': source_kind, 'self_account': None,
                     'contact_id': None, 'contact_name': '(фрагменти кешу)', 'direction': 'unknown',
                     'msg_ts': None, 'message_text': s[:400], 'thread_id': None, 'attachment': None,
                     'source_artifact': src, 'confidence': 'low'})
        if len(seen) >= 500:
            break
    return rows


def sweep_tree(root, path_glob, platform, source_kind):
    """Sweep every file matching a recursive glob under root."""
    rows = []
    for p in glob.glob(os.path.join(root, '**', path_glob), recursive=True):
        if os.path.isfile(p):
            rows += sweep_artifact(p, platform, source_kind)
    return rows


# ── artifact discovery + driver ──────────────────────────────────────────────
def discover_and_parse(root):
    """Walk a collected-artifact root, run the applicable extractors, return rows."""
    rows = []
    # Viber desktop: %APPDATA%\ViberPC\<phone>\viber.db
    for db in glob.glob(os.path.join(root, '**', 'viber.db'), recursive=True):
        rows += parse_sqlite_messenger(db, 'viber')
    # Skype (main.db) — same adaptive path
    for db in glob.glob(os.path.join(root, '**', 'main.db'), recursive=True):
        if 'skype' in db.lower():
            rows += parse_sqlite_messenger(db, 'skype')
    # Telegram Desktop tdata identifiers (structural) + strings sweep
    for td in glob.glob(os.path.join(root, '**', 'tdata'), recursive=True):
        if os.path.isdir(td):
            rows += parse_tdata_identifiers(td)
            rows += sweep_tree(td, '*', 'telegram', 'desktop')
    # web Telegram / WhatsApp — strings sweep over browser IndexedDB + Local Storage
    # LevelDB (recovers identifiers + fragments even from expired/cached sessions).
    for pat, plat in (('*web.telegram.org*', 'telegram'), ('*telegram*', 'telegram'),
                      ('*web.whatsapp.com*', 'whatsapp'), ('*whatsapp*', 'whatsapp')):
        for d in glob.glob(os.path.join(root, '**', pat), recursive=True):
            if os.path.isdir(d):
                for ext in ('*.ldb', '*.log', 'LOG', 'CURRENT'):
                    rows += sweep_tree(d, ext, plat, 'web')
    # de-duplicate (overlapping globs / repeated strings across .ldb + .log)
    _seen, _uniq = set(), []
    for r in rows:
        k = (r.get('platform'), r.get('source_kind'), r.get('contact_id'),
             r.get('contact_name'), r.get('message_text'))
        if k in _seen:
            continue
        _seen.add(k)
        _uniq.append(r)
    return _uniq


def write_csv(rows, out_dir):
    os.makedirs(os.path.join(out_dir, 'Communications'), exist_ok=True)
    out = os.path.join(out_dir, 'Communications', 'messengers.csv')
    with open(out, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=CONTRACT, extrasaction='ignore')
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return out, len(rows)


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('root', help='collected-artifact root to scan')
    ap.add_argument('out', help='output dir (Communications/messengers.csv written under it)')
    a = ap.parse_args()
    rr = discover_and_parse(a.root)
    p, n = write_csv(rr, a.out)
    print('wrote %s (%d rows)' % (p, n))
