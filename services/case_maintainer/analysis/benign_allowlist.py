"""Known-benign software that must NOT be picked as the initial-access ENTRY POINT
(updaters, OS telemetry, signed gov/vendor helpers). DEMOTE-only: matched candidates get a
heavy score penalty in the entry-point picker (reports/reshape._ia_scored) so they never win,
but they REMAIN in the timeline/data — nothing is hidden — and this is NEVER applied to
behavior-based threat detection. Sources merged: _SEED (below) + env DFIR_BENIGN_ENTRY_EXTRA
(comma/pipe regex fragments) + approved rows in DB table benign_allowlist_v1 (admin-managed
via the bot). DB rows are cached 60s so new patterns take effect without a restart. Any DB
error or bad regex is skipped -> the scorer never crashes."""
import os, re, time

_SEED = [
    r'eusignweb', r'\beusign', r'filecoauth', r'onedrive\.sync', r'onedrivelauncher',
    r'onedrivesetup', r'onedrivestandalone', r'filesyncconfig',
    r'googleupdate', r'edgeupdate', r'edgewebview', r'msedge.*update',
    r'adobearm', r'armsvc', r'acrotray', r'jusched', r'jucheck',
    r'mousocoreworker', r'usoclient', r'waasmedic', r'tiworker',
]

_CACHE = {'re': None, 'ts': 0.0}
_CACHE_TTL = 60.0


def _env_frags():
    frags = []
    extra = os.getenv('DFIR_BENIGN_ENTRY_EXTRA', '') or ''
    for x in re.split(r'[|,]', extra):
        x = x.strip()
        if x:
            frags.append(x if any(c in x for c in '\\.[](){}*+?^$') else re.escape(x))
    return frags


def _db_frags():
    frags = []
    try:
        import psycopg2
        try:
            from core.config import PG_DSN
        except Exception:
            try:
                from config import PG_DSN
            except Exception:
                PG_DSN = os.getenv('PG_DSN') or ''
        if not PG_DSN:
            return frags
        with psycopg2.connect(PG_DSN, connect_timeout=4) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("SET statement_timeout='4s'")
                cur.execute("SELECT pattern, coalesce(is_regex,false) FROM benign_allowlist_v1 WHERE approved IS TRUE")
                for pat, is_rx in cur.fetchall():
                    pat = str(pat or '').strip()
                    if not pat:
                        continue
                    if is_rx:
                        try:
                            re.compile(pat)
                            frags.append(pat)
                        except Exception:
                            continue
                    else:
                        frags.append(re.escape(pat))
    except Exception:
        return []
    return frags


def _build():
    frags = list(_SEED) + _env_frags() + _db_frags()
    try:
        return re.compile('(' + '|'.join(frags) + ')', re.I)
    except Exception:
        return re.compile('(' + '|'.join(_SEED) + ')', re.I)


def _get_re():
    now = time.time()
    if _CACHE['re'] is None or (now - _CACHE['ts']) > _CACHE_TTL:
        try:
            _CACHE['re'] = _build()
        except Exception:
            if _CACHE['re'] is None:
                _CACHE['re'] = re.compile('(' + '|'.join(_SEED) + ')', re.I)
        _CACHE['ts'] = now
    return _CACHE['re']


BENIGN_ENTRY_RE = _get_re()


def is_benign_entry(name_and_path):
    """True if the exe name/path is a known-benign updater/telemetry -> demote as entry.
    Never raises. Merges _SEED + env + approved DB rows (60s cache)."""
    try:
        return bool(_get_re().search(str(name_and_path or '').lower()))
    except Exception:
        return False
