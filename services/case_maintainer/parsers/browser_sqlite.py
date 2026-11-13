# -*- coding: utf-8 -*-
"""Raw browser-history SQLite parser (Chrome/Edge/Chromium 'History', Firefox
'places.sqlite').

Emits the SAME ``(parser_family, payload)`` tuples as
``forensic.hindsight_record_to_fallback`` so the EXISTING raw_fallback_v2 browser
consumers (agent_tools.get_browser_downloads / get_browser_activity) pick it up
with zero new consumer code.

WHY: a STANDARD KAPE collection grabs the raw ``History`` SQLite (Targets only, no
Hindsight module), so before this, browser history/downloads never reached the DB
unless the custom collector's Hindsight step produced JSONL. This closes that gap.
Pure/defensive: never raises to the caller; returns [] on any problem.
"""
import os
import sqlite3
from datetime import datetime, timezone

_CHROME_EPOCH_OFFSET = 11644473600  # seconds between 1601-01-01 and 1970-01-01


def _chrome_ts(v):
    """Chromium WebKit time (microseconds since 1601-01-01 UTC) -> ISO8601 Z."""
    try:
        v = int(v)
        if v <= 0:
            return None
        return datetime.fromtimestamp(v / 1_000_000 - _CHROME_EPOCH_OFFSET,
                                      tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    except Exception:
        return None


def _ff_ts(v):
    """Firefox PRTime (microseconds since 1970-01-01 UTC) -> ISO8601 Z."""
    try:
        v = int(v)
        if v <= 0:
            return None
        return datetime.fromtimestamp(v / 1_000_000, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    except Exception:
        return None


def is_browser_history_file(rel_path):
    """Return 'chromium' | 'firefox' | None for a zip member path."""
    p = str(rel_path).replace('\\', '/').lower()
    base = p.rsplit('/', 1)[-1]
    if base == 'places.sqlite':
        return 'firefox'
    # Chrome/Edge/Chromium/Brave/Opera/Yandex store history in a file literally
    # named 'History' (no extension). Require a browser-ish path to avoid matching
    # unrelated files named 'history'.
    if base == 'history' and any(b in p for b in (
            'chrome', 'edge', 'chromium', 'brave', 'opera', 'yandex', 'user data', 'user_data')):
        return 'chromium'
    return None


def _looks_sqlite(path):
    try:
        with open(path, 'rb') as f:
            return f.read(16).startswith(b'SQLite format 3')
    except Exception:
        return False


def _open_ro(path):
    """Open read-only; prefer normal RO (replays -wal if present), fall back to
    immutable (ignores locks / a missing -wal)."""
    try:
        con = sqlite3.connect('file:%s?mode=ro' % path, uri=True, timeout=5)
        con.execute('SELECT 1')
        return con
    except Exception:
        return sqlite3.connect('file:%s?immutable=1' % path, uri=True, timeout=5)


def _tables(con):
    try:
        return {r[0].lower() for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    except Exception:
        return set()


def parse_chromium(path, limit=20000):
    out = []
    if not _looks_sqlite(path):
        return out
    try:
        con = _open_ro(path)
    except Exception:
        return out
    try:
        tabs = _tables(con)
        if 'urls' in tabs:
            try:
                for url, title, vc, lvt in con.execute(
                        "SELECT url,title,visit_count,last_visit_time FROM urls "
                        "ORDER BY last_visit_time DESC LIMIT %d" % int(limit)):
                    if not url:
                        continue
                    out.append(('browser_history', {
                        'url': str(url), 'title': str(title or ''),
                        'visit_count': str(vc or 0),
                        'last_visit_time': _chrome_ts(lvt) or ''}))
            except Exception:
                pass
        if 'downloads' in tabs:
            try:
                for tp, cp, st, et, rb, tb, taburl, refurl in con.execute(
                        "SELECT target_path,current_path,start_time,end_time,"
                        "received_bytes,total_bytes,tab_url,tab_referrer_url FROM downloads "
                        "ORDER BY start_time DESC LIMIT %d" % int(limit)):
                    tp = tp or cp
                    payload = {}
                    if taburl:
                        payload['url'] = str(taburl)
                    if tp:
                        payload['target_path'] = str(tp)
                        payload['current_path'] = str(cp or tp)
                        payload['filename'] = str(tp).replace('\\', '/').rstrip('/').split('/')[-1]
                    if refurl:
                        payload['referrer'] = str(refurl)
                    if rb:
                        payload['received_bytes'] = str(rb)
                    if tb:
                        payload['total_bytes'] = str(tb)
                    ets = _chrome_ts(et) or _chrome_ts(st)
                    if ets:
                        payload['end_time'] = ets
                        payload['start_time'] = _chrome_ts(st) or ets
                    if payload.get('url') or payload.get('target_path'):
                        out.append(('browser_downloads', payload))
            except Exception:
                pass
    finally:
        try:
            con.close()
        except Exception:
            pass
    return out


def parse_firefox(path, limit=20000):
    out = []
    if not _looks_sqlite(path):
        return out
    try:
        con = _open_ro(path)
    except Exception:
        return out
    try:
        tabs = _tables(con)
        if 'moz_places' in tabs:
            try:
                for url, title, vc, lvd in con.execute(
                        "SELECT url,title,visit_count,last_visit_date FROM moz_places "
                        "WHERE url IS NOT NULL ORDER BY last_visit_date DESC LIMIT %d" % int(limit)):
                    if not url:
                        continue
                    out.append(('browser_history', {
                        'url': str(url), 'title': str(title or ''),
                        'visit_count': str(vc or 0),
                        'last_visit_time': _ff_ts(lvd) or ''}))
            except Exception:
                pass
    finally:
        try:
            con.close()
        except Exception:
            pass
    return out


def parse_file(path, kind):
    """kind is the value from is_browser_history_file(); returns list of
    (parser_family, payload) tuples. Never raises."""
    try:
        if kind == 'firefox':
            return parse_firefox(path)
        return parse_chromium(path)
    except Exception:
        return []
