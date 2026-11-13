"""Paths the collector DECLARED about itself — read them, subtract exactly those.

Our collector adds two Defender exclusions of its own (the work root that holds the
output archives, and its temporary toolkit folder) and writes both into
`_collector_self.txt` at the root of the output archive:

    # paths THIS collector added to Defender exclusions (not attacker activity)
    C:\\DFIR_Triage
    C:\\Users\\u\\AppData\\Local\\Temp\\DFIRTriage_a1b2c3

The same two exclusions are also collected AS EVIDENCE (live\\defender_exclusions.csv,
PowerShell_Defender_Exclusions), so without this file the report accuses the attacker
of weakening Defender when it was our own tool. See INTEGRATION_CONTRACT.md §2 п.1.

DELIBERATELY NARROW. Only what the file literally names is subtracted, by exact path
match (renderer) or literal substring (command lines). A wider rule has already cost
us once: a broad filter swallowed a `svchost.exe` sitting on a user's desktop, i.e.
real evidence. Therefore:
  * a line must be an absolute Windows path (`X:\\...`), else it subtracts nothing;
  * a bare drive root or a bare system root (C:\\Windows, C:\\Users, C:\\Program Files…)
    is REFUSED even if the file names it — no single declaration may blank a whole tree;
  * a case with no such file yields an empty set and changes nothing.
"""

import os
import re

try:
    import psycopg2
    from psycopg2.extras import Json  # noqa: F401  (re-exported for callers)
except Exception:  # pragma: no cover - psycopg2 always present in the service image
    psycopg2 = None

PG_DSN = os.environ.get('PG_DSN', '')

_BS = chr(92)

# absolute local Windows path with at least one component under the drive root
_ABS_RX = re.compile(r'^[a-z]:' + re.escape(_BS) + r'[^' + re.escape(_BS) + r']')

# roots nobody may declare away: subtracting these would hide whole trees of evidence
_TOO_BROAD = {
    'c:' + _BS + 'windows',
    'c:' + _BS + 'windows' + _BS + 'system32',
    'c:' + _BS + 'users',
    'c:' + _BS + 'programdata',
    'c:' + _BS + 'program files',
    'c:' + _BS + 'program files (x86)',
    'c:' + _BS + 'temp',
    'c:' + _BS + 'perflogs',
}

_MIN_LEN = 8  # 'c:\\a' style stubs are refused; 'C:\\DFIR_Triage' passes


def normalize(value):
    """lowercase, unify separators, drop quotes and a trailing separator.

    Returns '' for anything that is not a usable absolute Windows path."""
    s = (value or '').strip().strip('"').strip("'").strip()
    if not s:
        return ''
    s = s.replace('/', _BS).lower()
    while s.endswith(_BS):
        s = s[:-1]
    if len(s) < _MIN_LEN:
        return ''
    if not _ABS_RX.match(s):
        return ''
    if s in _TOO_BROAD:
        return ''
    return s


def declared_self_paths(case_key, conn=None):
    """Set of normalized paths the collector declared for THIS case (may be empty)."""
    out = set()
    if not case_key:
        return out
    rows = []
    try:
        if conn is not None:
            cur = conn.cursor()
            cur.execute("""SELECT payload FROM raw_fallback_v2
                           WHERE case_key=%s AND parser_family='collector_self'
                           LIMIT 200""", (case_key,))
            rows = cur.fetchall()
        else:
            if psycopg2 is None:
                return out
            with psycopg2.connect(PG_DSN) as c:
                c.autocommit = True
                cur = c.cursor()
                cur.execute("SET statement_timeout='5000'")
                cur.execute("""SELECT payload FROM raw_fallback_v2
                               WHERE case_key=%s AND parser_family='collector_self'
                               LIMIT 200""", (case_key,))
                rows = cur.fetchall()
    except Exception:
        return out
    for (p,) in rows:
        try:
            n = normalize((p or {}).get('path'))
        except Exception:
            continue
        if n:
            out.add(n)
    return out


def is_declared(value, declared):
    """Exact path match (after normalization) against the declared set."""
    if not declared:
        return False
    n = normalize(value)
    return bool(n) and n in declared


def contains_declared(text, declared):
    """True when a free-form string (a command line) literally names a declared path."""
    if not declared or not text:
        return False
    t = str(text).replace('/', _BS).lower()
    for d in declared:
        if d in t:
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# WHICH COLLECTOR MADE THIS ARCHIVE, AND IS THE EXECUTION EVIDENCE THERE AT ALL
#
# Collector v4.5 (2026-09-05) restored Prefetch and ShimCache, which v4.4 lost, and
# began declaring itself in the comments of _collector_self.txt. Case case_08
# (collected 2026-09-07 with a build older than that) arrived with zero Prefetch and
# zero ShimCache rows, and the bot wrote a 524-line report over it without ever saying
# that two of the three execution-artefact sources were missing. These two readers let
# the report say it. See docs/COLLECTOR_VERSION_GATE_2026-09-09.md.
# ─────────────────────────────────────────────────────────────────────────────

MIN_GOOD_VERSION = (4, 5)


def _rows(case_key, conn, family, limit=50):
    """raw_fallback_v2 payloads of one parser_family for a case (never raises)."""
    if not case_key:
        return []
    sql = ("SELECT payload FROM raw_fallback_v2 WHERE case_key=%s "
           "AND parser_family=%s LIMIT " + str(int(limit)))
    try:
        if conn is not None:
            cur = conn.cursor()
            cur.execute(sql, (case_key, family))
            return [r[0] for r in cur.fetchall()]
        if psycopg2 is None:
            return []
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            cur.execute("SET statement_timeout='5000'")
            cur.execute(sql, (case_key, family))
            return [r[0] for r in cur.fetchall()]
    except Exception:
        return []


def collector_meta(case_key, conn=None):
    """Everything the collector declared about itself: {'collector_version': '4.5', ...}.

    Empty for any archive made before v4.5, which declared nothing."""
    out = {}
    for p in _rows(case_key, conn, 'collector_self_meta'):
        try:
            k = ((p or {}).get('key') or '').strip().lower()
            v = ((p or {}).get('value') or '').strip()
        except Exception:
            continue
        if k and v:
            out[k] = v
    return out


def version_tuple(value):
    """'v4.5' / '4.5.1' / '4.5 (2026-09-05)' -> (4, 5) / (4, 5, 1). () when unreadable."""
    m = re.search(r'(\d+)(?:[.](\d+))?(?:[.](\d+))?', (value or '').strip().lstrip('vV'))
    if not m:
        return ()
    return tuple(int(g) for g in m.groups() if g is not None)


def collector_version(case_key, conn=None):
    """The declared collector version as a string, or None when the archive declares none.

    None does NOT mean "unknown build" - it means "older than v4.5", because declaring
    the version is itself a v4.5 feature."""
    return collector_meta(case_key, conn).get('collector_version') or None


def exec_artifact_gap(case_key, conn=None):
    """Is this case blind to program execution, and can we name the reason?

    Returns a dict: counts per source, `degraded` when BOTH Prefetch and ShimCache are
    absent, `stale_collector` when the archive declares no version (pre-v4.5) or one
    below MIN_GOOD_VERSION, and a ready Ukrainian `warning` line for the report (None
    when there is nothing to warn about).

    The count test stands on its own: it catches a future v4.5+ build that breaks the
    same way, which a version test alone would wave through."""
    counts = {'prefetch': 0, 'shimcache': 0, 'amcache': 0}
    ver = collector_version(case_key, conn)
    sql = ("SELECT count(*) FILTER (WHERE source_file ~* 'PECmd'), "
           "count(*) FILTER (WHERE source_file ~* 'AppCompatCache'), "
           "count(*) FILTER (WHERE source_file ~* 'Amcache') "
           "FROM program_exec_v2 WHERE case_key=%s")
    try:
        if conn is not None:
            cur = conn.cursor()
            cur.execute(sql, (case_key,))
            r = cur.fetchone()
        elif psycopg2 is not None:
            with psycopg2.connect(PG_DSN) as c:
                c.autocommit = True
                cur = c.cursor()
                cur.execute("SET statement_timeout='15000'")
                cur.execute(sql, (case_key,))
                r = cur.fetchone()
        else:
            r = None
        if r:
            counts = {'prefetch': int(r[0] or 0), 'shimcache': int(r[1] or 0),
                      'amcache': int(r[2] or 0)}
    except Exception:
        pass

    vt = version_tuple(ver)
    stale = (not vt) or (vt < MIN_GOOD_VERSION)
    degraded = counts['prefetch'] == 0 and counts['shimcache'] == 0

    warning = None
    if degraded:
        warning = ('⚠️ **Артефактів запуску майже немає:** Prefetch — 0 записів, ShimCache — 0 записів'
                   + ' (Amcache — ' + str(counts['amcache']) + ').'
                   + ' Причина — одна з двох: або збирач їх не зібрав (архів'
                   + (' версії ' + ver if ver else ' без позначки версії, тобто старіший за v4.5')
                   + '), або їх зібрано, але парсер не зміг прочитати формат нової Windows'
                   + ' (PECmd не знає Prefetch v31, AppCompatCacheParser падає на ShimCache'
                   + ' Windows 11 build 26200 — кейс case_08).'
                   + ' Висновки про те, що і коли запускалося, спираються лише на Amcache'
                   + ' і є неповними: перевірте сирі .pf у зібраному архіві вручну.')
    elif ver and vt and vt < MIN_GOOD_VERSION:
        # the archive names its own build and it is one we know loses artefacts
        warning = ('⚠️ **Збирач застарілий (версія ' + ver + ').** Ця версія втрачала'
                   + ' Prefetch і ShimCache; для наступних зборів візьміть актуальний збирач.')
    elif counts['shimcache'] == 0 and counts['prefetch'] > 0:
        # ShimCache exists on every live Windows box - its absence is a collection gap,
        # unlike Prefetch, which administrators legitimately switch off
        warning = ('⚠️ **ShimCache відсутній** — частину слідів запуску не зібрано;'
                   + ' врахуйте це у висновках про те, що запускалося на машині.')

    return {'version': ver, 'version_tuple': vt, 'stale_collector': bool(stale),
            'degraded': bool(degraded), 'counts': counts, 'warning': warning}


def parse_self_meta(line):
    """One comment line of _collector_self.txt -> (key, value), or ('', '') if it is prose.

    Collector v4.5 (pybuild/v4/Steps.cs SelfDeclaration) writes exactly:

        # paths THIS collector added to Defender exclusions (not attacker activity)
        # collector_version: v4.5 (2026-09-05)
        # collector_started: 2026-09-07 10:48:16 (local)
        # collector_started_utc: 2026-09-07 07:48:16
        # collector_host: DESKTOP-UVO9455

    Only keys beginning with `collector_` are data; the prose first line is not. The value
    keeps its own colons, so a timestamp survives intact."""
    t = (line or '').strip()
    if not t.startswith('#'):
        return ('', '')
    body = t.lstrip('#').strip()
    k = ''
    v = ''
    for sep in (':', '='):
        if sep in body:
            k, v = body.split(sep, 1)
            break
    else:
        parts = body.split(None, 1)
        if len(parts) == 2:
            k, v = parts[0], parts[1]
    k = k.strip().lower()
    v = v.strip()
    if k.startswith('collector_') and v and len(k) <= 40:
        return (k, v[:200])
    return ('', '')


def declared_started_at(case_key, conn=None):
    """The collector's own start time as an aware datetime, or None.

    Prefers `collector_started_utc` (unambiguous); falls back to the local-time line,
    which is read as naive and left to the caller's own tz handling."""
    meta = collector_meta(case_key, conn)
    raw = (meta.get('collector_started_utc') or '').strip()
    utc = True
    if not raw:
        raw = (meta.get('collector_started') or '').strip()
        utc = False
    if not raw:
        return None
    m = re.search(r'(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})', raw)
    if not m:
        return None
    try:
        from datetime import datetime, timezone
        dt = datetime(*[int(g) for g in m.groups()])
        return dt.replace(tzinfo=timezone.utc) if utc else dt
    except Exception:
        return None
