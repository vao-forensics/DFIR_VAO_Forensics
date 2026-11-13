# -*- coding: utf-8 -*-
"""Known-good reference: is this file part of a clean Windows, and what do the hash
databases say about it?

The owner's complaint was that the bot calls legitimate software a virus and has nowhere to
check. The reference material was already on disk — 1.1 GB of it — and nothing in the
analysis path opened it:

    /data/case_library/_hashdb/vanilla_paths.sqlite   2438646 stock Windows paths,
                                                     1017129 file names, 530720 directories
    /data/case_library/_hashdb/hashlookup-full.bloom  CIRCL known-GOOD (includes NSRL)
    /data/case_library/_hashdb/known_bad.sqlite       MalwareBazaar known-BAD

threat_detect.py, reshape.py and chat.py each referenced them zero times. The two callers
that did (hashes.csv at ingest, autoruns_triage) are fed by artefacts no existing case has.

This module is the single door to that material. It never raises: a missing database means
"unknown", never "malicious", because an absent reference must not create evidence.

The vanilla index stores blake2b-8 digests of lowercased strings — same scheme as
analysis/autoruns_triage.py, which built it.
"""
import hashlib
import os
import sqlite3
import threading

HASHDB_DIR = os.environ.get("DFIR_HASHDB_DIR", "/data/case_library/_hashdb")
VANILLA = os.path.join(HASHDB_DIR, "vanilla_paths.sqlite")
KNOWN_BAD = os.path.join(HASHDB_DIR, "known_bad.sqlite")

_LOCK = threading.Lock()
_CONN = {}


def _digest(s):
    return hashlib.blake2b(str(s or '').lower().encode('utf-8', 'replace'),
                           digest_size=8).digest()


def _conn(path):
    """One read-only connection per path per thread-safe cache; None when absent."""
    if not os.path.exists(path):
        return None
    with _LOCK:
        c = _CONN.get(path)
        if c is None:
            try:
                c = sqlite3.connect('file:%s?mode=ro' % path, uri=True,
                                    check_same_thread=False)
                _CONN[path] = c
            except Exception:
                return None
        return c


def _has(table, value):
    """True / False / None — None means the check could not run.

    An absent reference must never be reported as a clean verdict; that is the same rule
    analysis/autoruns_triage.py follows, and the column name (`fp`) comes from there too."""
    c = _conn(VANILLA)
    if c is None or not value:
        return None
    try:
        cur = c.execute('SELECT 1 FROM %s WHERE fp=? LIMIT 1' % table, (_digest(value),))
        return cur.fetchone() is not None
    except Exception:
        return None


def is_vanilla_name(name):
    """Does a file with this NAME ship with a clean Windows?"""
    n = str(name or '').replace('/', chr(92)).rsplit(chr(92), 1)[-1].strip()
    return _has('vname', n) if n else False


def is_vanilla_path(path):
    """Does this exact full path exist in a clean Windows?"""
    p = str(path or '').strip().replace('/', chr(92))
    if not p:
        return False
    # the index stores paths without a drive letter prefix in most builds; try both
    return _has('vpath', p) or _has('vpath', p.split(':', 1)[-1].lstrip(chr(92)))


def is_vanilla_dir(path):
    """Is the containing DIRECTORY part of a clean Windows?"""
    p = str(path or '').strip().replace('/', chr(92))
    d = p.rsplit(chr(92), 1)[0] if chr(92) in p else ''
    return _has('vdir', d) if d else False


def known_bad_hash(h):
    """MalwareBazaar verdict for a hash; False when the database is absent."""
    c = _conn(KNOWN_BAD)
    hv = str(h or '').strip().lower()
    if c is None or len(hv) < 32:
        return False
    for col in ('sha256', 'sha1', 'md5'):
        try:
            cur = c.execute('SELECT 1 FROM hashes WHERE %s=? LIMIT 1' % col, (hv,))
            if cur.fetchone():
                return True
        except Exception:
            continue
    return False


def verdict(path=None, name=None, sha256=None):
    """A single, honest verdict for one file.

    Returns dict(known_bad, vanilla, why) — `vanilla` True only when the reference
    actually contains it, so 'unknown' is never reported as 'clean'."""
    out = {'known_bad': False, 'vanilla': False, 'why': ''}
    if sha256 and known_bad_hash(sha256):
        out['known_bad'] = True
        out['why'] = 'хеш є у базі відомого шкідливого ПЗ (MalwareBazaar)'
        return out
    if path and is_vanilla_path(path):
        out['vanilla'] = True
        out['why'] = 'точний шлях є в еталоні чистої Windows'
    elif name and is_vanilla_name(name):
        out['vanilla'] = True
        out['why'] = 'імʼя файлу є в еталоні чистої Windows (шлях не збігся — перевірити)'
    return out


def status():
    """What reference material is actually available right now."""
    return {
        'vanilla': os.path.exists(VANILLA),
        'known_bad': os.path.exists(KNOWN_BAD),
        'bloom': os.path.exists(os.path.join(HASHDB_DIR, 'hashlookup-full.bloom')),
    }
