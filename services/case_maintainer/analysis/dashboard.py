"""DFIR admin dashboard — one live snapshot for the Telegram admin button.

Everything is gathered LIVE per call, nothing hardcoded: cases come from the DB,
containers/disk/cpu from the host-stats helper, GPU from the host agent. So a new
case/container tomorrow shows up, a deleted one disappears, on its own.

Sources:
  * PostgreSQL (dfir_logs)             — cases, rows, IOCs, overlap, learning, jobs
  * host-stats helper 172.18.0.1:8096  — RAM/CPU/df, docker list+sizes, case dir sizes
  * GPU agent :8788 (Windows host)     — per-GPU temp/util/VRAM

Returns (text, parse_mode) — text is an HTML <pre> block so Telegram keeps the
tables aligned in a monospace font.
"""
import html
import json
import os
import re
import time
import urllib.request

import psycopg2
from core.config import PG_DSN

try:
    from core.config import WINDOWS_AGENT_URL, WINDOWS_AGENT_TOKEN
except Exception:
    WINDOWS_AGENT_URL, WINDOWS_AGENT_TOKEN = '', ''

HOSTSTATS_URL = os.getenv('DFIR_HOSTSTATS_URL', 'http://172.18.0.1:8096/hoststats')
_GPU_CANDIDATES = [u for u in [
    WINDOWS_AGENT_URL, 'http://192.168.100.1:8788', 'http://192.168.134.1:8788',
    os.environ.get('DFIR_WINDOWS_AGENT_URL', 'http://192.168.100.1:8788')] if u]

_CACHE = {'ts': 0.0, 'text': '', 'pm': 'HTML'}
_CACHE_TTL = 25.0


# ---------- tiny formatters ----------
def _n(x):
    """1690428 -> 1.69M ; 94200 -> 94.2K ; 138 -> 138"""
    x = float(x or 0)
    for div, suf in ((1e9, 'B'), (1e6, 'M'), (1e3, 'K')):
        if x >= div:
            v = x / div
            s = ('%.2f' % v) if v < 10 else ('%.1f' % v)
            return s.rstrip('0').rstrip('.') + suf
    return str(int(x))


def _sz(b):
    """bytes -> 112M / 1.2G"""
    b = float(b or 0)
    if b >= 1e9:
        return ('%.1f' % (b / 1e9)).rstrip('0').rstrip('.') + 'G'
    return '%dM' % round(b / 1e6)


def _gb(b):
    return '%.1f' % ((b or 0) / 1e9)


def _http_json(url, timeout=8, token=''):
    req = urllib.request.Request(url)
    if token:
        req.add_header('X-DFIR-Token', token)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _hoststats():
    try:
        return _http_json(HOSTSTATS_URL, timeout=30)
    except Exception:
        return {}


def _gpu():
    for u in _GPU_CANDIDATES:
        try:
            return _http_json(u.rstrip('/') + '/gpu/json', timeout=8, token=WINDOWS_AGENT_TOKEN)
        except Exception:
            continue
    return {}


# ---------- container port/mem/img parsing ----------
def _port(ports):
    """'0.0.0.0:3000->8080/tcp,...' -> '3000' ; '127.0.0.1:5433->..' -> '5433*' ;
    '8787/tcp' -> 'i' (internal only) ; '' -> '-'"""
    if not ports:
        return '-'
    m = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)->', ports)
    if m:
        return m.group(2) + ('*' if m.group(1).startswith('127.') else '')
    m = re.search(r'(\d+)/tcp', ports)
    return (m.group(1) + 'i') if m else '-'


def _memshort(mem):
    """'53.68MiB / 33.51GiB' -> '54M'"""
    m = re.match(r'\s*([\d.]+)\s*([KMG])i?B', mem or '')
    if not m:
        return '?'
    v = float(m.group(1))
    return '%d%s' % (round(v), m.group(2))


def _imgsize(size):
    """'6MB (virtual 139MB)' -> '139M' ; '387MB (virtual 672MB)' -> '672M'"""
    m = re.search(r'virtual\s+([\d.]+)\s*([KMG])B', size or '')
    if not m:
        m = re.match(r'\s*([\d.]+)\s*([KMG])B', size or '')
    if not m:
        return '?'
    return ('%.1f' % float(m.group(1))).rstrip('0').rstrip('.') + m.group(2)


def _mem_bytes(mem):
    m = re.match(r'\s*([\d.]+)\s*([KMG])i?B', mem or '')
    if not m:
        return 0
    return float(m.group(1)) * {'K': 1e3, 'M': 1e6, 'G': 1e9}[m.group(2)]


# ---------- DB gatherers (each defensive) ----------
def _q(cur, sql, args=None):
    cur.execute(sql, args or ())
    return cur.fetchall()


def _cases_rows(cur):
    try:
        cur.execute("SET statement_timeout='30s'")
        return _q(cur, """
            WITH ev AS (SELECT case_key,count(*) n FROM event_logs_v2 GROUP BY 1),
                 pe AS (SELECT case_key,count(*) n FROM program_exec_v2 GROUP BY 1),
                 br AS (SELECT case_key,count(*) n FROM browser_provenance_v1 GROUP BY 1),
                 io AS (SELECT case_key,count(*) n FROM case_iocs GROUP BY 1),
                 gf AS (SELECT case_key,count(*) n FROM dfir_golden_facts_v1 GROUP BY 1)
            SELECT c.case_key, COALESCE(ev.n,0),COALESCE(pe.n,0),COALESCE(br.n,0),
                   COALESCE(io.n,0),COALESCE(gf.n,0)
            FROM (SELECT DISTINCT case_key FROM event_logs_v2 WHERE case_key<>'file') c
            LEFT JOIN ev USING(case_key) LEFT JOIN pe USING(case_key)
            LEFT JOIN br USING(case_key) LEFT JOIN io USING(case_key) LEFT JOIN gf USING(case_key)
            ORDER BY 2 DESC""")
    except Exception:
        return []


def _ioc_counts(cur):
    try:
        return dict((t, c) for t, c in _q(cur,
            "SELECT ioc_type,count(*) FROM case_iocs GROUP BY 1"))
    except Exception:
        return {}


def _shared(cur):
    """Indicators present in >=2 cases, with the case count — computed straight from
    case_iocs (same source as the chat 'спільні IOC' answer) so the numbers match."""
    try:
        return _q(cur, """
            SELECT ioc_type, ioc_norm, count(DISTINCT case_key) c
            FROM case_iocs WHERE case_key <> 'file'
              AND ioc_norm IS NOT NULL AND ioc_norm <> ''
            GROUP BY 1,2 HAVING count(DISTINCT case_key) >= 2
            ORDER BY c DESC, 1""")
    except Exception:
        return []


def _case_label(ck):
    """'case_22' -> '09.02 case_51...'"""
    m = re.match(r'(\d{2})_(\d{2})_\d{4}_?(.*)', ck or '')
    if m:
        rest = m.group(3).replace('_', ' ').strip()
        return ('%s.%s %s' % (m.group(1), m.group(2), rest)).strip()[:21]
    return (ck or '')[:21]


def _db_size(cur):
    size, tables = '?', []
    try:
        size = _q(cur, "SELECT pg_size_pretty(pg_database_size(current_database()))")[0][0]
    except Exception:
        pass
    try:
        tables = _q(cur, "SELECT relname, pg_size_pretty(pg_total_relation_size(oid)) "
                         "FROM pg_class WHERE relkind='r' "
                         "ORDER BY pg_total_relation_size(oid) DESC LIMIT 3")
    except Exception:
        pass
    return size, tables


def _scalar(cur, sql):
    try:
        r = _q(cur, sql)
        return r[0][0] if r and r[0] and r[0][0] is not None else 0
    except Exception:
        return None


def _learning(cur):
    return {
        'qa_total': _scalar(cur, "SELECT count(*) FROM dfir_case_qa_v1"),
        'qa_conf': _scalar(cur, "SELECT count(*) FROM dfir_case_qa_v1 WHERE confidence>=0.9"),
        'cache': _scalar(cur, "SELECT count(*) FROM dfir_qa_cache_v1"),
        'cache_v': _scalar(cur, "SELECT count(*) FROM dfir_qa_cache_v1 WHERE verified"),
        'lessons': _scalar(cur, "SELECT count(*) FROM dfir_lessons_learned_v1"),
        'know': _scalar(cur, "SELECT count(*) FROM case_learnings_v1"),
        'sft': _scalar(cur, "SELECT count(*) FROM dfir_finetune_dataset_v1"),
        'fb': _scalar(cur, "SELECT count(*) FROM dfir_user_feedback_v1"),
    }


def _jobs(cur):
    stat = {}
    try:
        for s, c in _q(cur, "SELECT status,count(*) FROM dfir_run_jobs_v2 GROUP BY 1"):
            stat[s] = c
    except Exception:
        pass
    last = None
    try:
        r = _q(cur, "SELECT case_key, to_char(created_at,'DD.MM HH24:MI') "
                    "FROM dfir_run_jobs_v2 WHERE status='completed' "
                    "ORDER BY created_at DESC NULLS LAST LIMIT 1")
        if r:
            last = (r[0][0], r[0][1])
    except Exception:
        pass
    return stat, last


# ---------- renderer ----------
def build_dashboard_text(force=False):
    now = time.time()
    if not force and _CACHE['text'] and (now - _CACHE['ts']) < _CACHE_TTL:
        return _CACHE['text'], _CACHE['pm']

    hs = _hoststats()
    gpu = _gpu()

    L = []
    A = L.append
    ts = time.strftime('%d.%m.%Y %H:%M', time.localtime())
    A('📊 DFIR DASHBOARD · %s' % ts)
    A('━' * 27)

    # hardware
    mem = hs.get('mem', {}) or {}
    cpu = hs.get('cpu', {}) or {}
    disk = hs.get('disk', {}) or {}
    A('🖥 ЗАЛІЗО (VM)')
    if mem:
        A('• RAM %s / %s GB · вільно %s GB' % (
            _gb(mem.get('used')), _gb(mem.get('total')), _gb(mem.get('available'))))
    load = ' '.join(cpu.get('load', []) or [])
    if cpu:
        A('• CPU %s ядер · %s%% · load %s' % (cpu.get('cores', '?'), cpu.get('pct', '?'), load))
    if disk:
        A('• Диск %s%% · вільно %s GB' % (disk.get('pct', '?'), _gb(disk.get('free'))))
    if not hs:
        A('• (host-stats недоступний)')
    A('')

    # GPU
    gl = gpu.get('gpus', []) or []
    if gl:
        A('🎮 GPU (хост · %d карт)' % len(gl))
        for g in gl:
            tag = ' (дисплей)' if g.get('is_display') else ''
            A(' #%s %2s°C %3s%%  %.1f/%.0f GB%s' % (
                g.get('index'), int(g.get('temp_c') or 0), int(g.get('util_pct') or 0),
                (g.get('mem_used_mib') or 0) / 1024.0, (g.get('mem_total_mib') or 0) / 1024.0, tag))
    else:
        A('🎮 GPU: агент недоступний')
    A('')

    # containers
    conts = hs.get('containers', []) or []
    ddf = hs.get('docker_df', {}) or {}
    if conts:
        ram_sum = sum(_mem_bytes(c.get('mem')) for c in conts)
        A('🐳 КОНТЕЙНЕРИ · %d up · RAM ~%s GB' % (len(conts), _gb(ram_sum)))
        rows = sorted(conts, key=lambda c: -_mem_bytes(c.get('mem')))
        A(' %-16s %-6s %5s %6s' % ('Контейнер', 'Порт', 'RAM', 'Образ'))
        for c in rows:
            A(' %-16s %-6s %5s %6s' % (
                c['name'][:16], _port(c.get('ports'))[:6],
                _memshort(c.get('mem')), _imgsize(c.get('size'))))
        img = ddf.get('images', {})
        if img:
            A(' образи %s · ♻️ %s' % (img.get('size', '?'), img.get('reclaimable', '?')))
        A(' * localhost   i внутрішній')
    A('')

    # DB work
    cases_disk = hs.get('cases_disk', {}) or {}
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cr = _cases_rows(cur)
                iocc = _ioc_counts(cur)
                shared = _shared(cur)
                dbsize, dbtables = _db_size(cur)
                learn = _learning(cur)
                jstat, jlast = _jobs(cur)
    except Exception as e:
        cr, iocc, shared, dbsize, dbtables, learn, jstat, jlast = [], {}, [], '?', [], {}, {}, None

    db_keys = set(r[0] for r in cr)

    # cases header
    A('📁 КЕЙСИ · %d' % len(cr))
    comp = jstat.get('completed', 0)
    fail = jstat.get('failed', 0)
    jline = '├ Джоби %s✅' % comp + ((' / %s⚠️' % fail) if fail else '')
    if jlast:
        jline += ' · останній %s %s' % (jlast[0].split('_20')[0].replace('_', '.'), jlast[1])
    A(jline)
    # ghosts: disk dirs that are not DB cases (and not the real 6)
    ghost_all = [d for d in cases_disk if d not in db_keys and d != '_finetune']
    if ghost_all:
        gnames = ', '.join('%s %s' % ((g.split('_20')[0].replace('_', '.')[:10] or g[:10]),
                                      _sz(cases_disk[g]))
                           for g in sorted(ghost_all, key=lambda x: -cases_disk[x])[:5])
        A('└ ⚠️ %d тек-привидів на диску (не в БД): %s' % (len(ghost_all), gnames))
    A('')

    # cases table
    _fmt = ' %-21s %6s %5s %6s %3s %3s %5s'
    A(_fmt % ('Кейс', 'Події', 'Exec', 'Браузр', 'IOC', 'Gld', 'Розмір'))
    tot = [0, 0, 0, 0, 0, 0]
    for ck, ev, pe, br, io, gf in cr:
        sz = cases_disk.get(ck, 0)
        tot[0] += ev; tot[1] += pe; tot[2] += br; tot[3] += io; tot[4] += gf; tot[5] += sz
        A(_fmt % (_case_label(ck), _n(ev), _n(pe), _n(br), io, gf, _sz(sz)))
    A(' ' + '─' * 52)
    A(_fmt % ('РАЗОМ', _n(tot[0]), _n(tot[1]), _n(tot[2]), tot[3], tot[4], _sz(tot[5])))
    A('')

    # IOC
    ioc_total = sum(iocc.values())
    parts = []
    for k, lbl in [('hash_sha1', 'хеші'), ('tool_name', 'tool'), ('malware_name', 'malware'),
                   ('domain', 'домени'), ('user_account', 'акаунт'), ('public_ip', 'IP')]:
        if iocc.get(k):
            parts.append('%s %d' % (lbl, iocc[k]))
    A('🎯 IOC · %d (%s)' % (ioc_total, ' · '.join(parts)))
    if shared:
        def _sv(t, n):
            v = n or t
            return (v[:10] + '…') if (t and t.startswith('hash') and len(v) > 12) else v
        top = ' · '.join('%s ×%d' % (_sv(t, n), c) for t, n, c in shared[:6])
        A('🔗 %d спільних: %s' % (len(shared), top))
    A('')

    # DB size
    tline = ' · '.join('%s %s' % (t.replace('_v2', '').replace('_v1', ''), s) for t, s in dbtables)
    A('🗄 БАЗА %s%s' % (dbsize, ('  (' + tline + ')') if tline else ''))
    A('')

    # learning
    def _v(x):
        return '?' if x is None else x
    A('🧠 НАВЧАННЯ · Q&A %s/%s · уроків %s · знань %s' % (
        _v(learn.get('qa_conf')), _v(learn.get('qa_total')),
        _v(learn.get('lessons')), _v(learn.get('know'))))
    A('   кеш %s (verified %s) · fine-tune %s/100 · фідбек %s' % (
        _v(learn.get('cache')), _v(learn.get('cache_v')),
        _v(learn.get('sft')), _v(learn.get('fb'))))
    A('━' * 27)

    body = '\n'.join(L)
    text = '<pre>' + html.escape(body) + '</pre>'
    text = text[:4090]
    _CACHE['ts'] = now
    _CACHE['text'] = text
    _CACHE['pm'] = 'HTML'
    return text, 'HTML'
