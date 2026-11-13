# -*- coding: utf-8 -*-
"""dfir-mcp: the bot's case data as MCP tools for an analyst's agent (agent CLI), over HTTP.

Why (owner, 17.10.2026): «ботом користуватись і по CLI через Agent нашим агентом» - one brain,
two doors. Grown from the 02.10 stdio pilot (tools/agent_pilot/dfir_mcp.py), which was bound to
one case inside a throwaway container. This one is a service:

  * transport: MCP streamable HTTP at /mcp, published through the existing uploader nginx
    (http://CHANGE_ME_DFIR_LINK_IP:8080/mcp over WireGuard - the only port VPN clients may reach)
  * auth: Authorization: Bearer <token>; tokens live in /data/state/mcp_tokens.json as sha256 only,
    each with a name and the cases it may read ("*" = all; the owner). Manage with mcp_tokens.py.
  * READ-ONLY: a read-only transaction with a statement timeout; single SELECT/WITH only; password
    hash columns refused; every query must be scoped to a case the token may read
  * audit: one JSON line per call -> /data/state/mcp_audit.jsonl (who, tool, case, args, ms, ok)
"""
import contextvars
import hashlib
import json
import os
import re
import sys
import time

import psycopg2
from mcp.server.fastmcp import FastMCP

sys.path.insert(0, '/app')
PG_DSN = os.environ['PG_DSN']
TOKENS = os.environ.get('MCP_TOKENS', '/data/state/mcp_tokens.json')
AUDIT = os.environ.get('MCP_AUDIT', '/data/state/mcp_audit.jsonl')
CASES_DIR = os.environ.get('CASE_LIBRARY', '/data/case_library')
MAX_ROWS = 200
CELL = 400

_who = contextvars.ContextVar('who', default=None)   # {'name':..., 'cases': '*' | [..]}

mcp = FastMCP('dfir', host='0.0.0.0', port=8000, stateless_http=True, json_response=True)

TABLES = {
    'event_logs_v2': 'Windows event logs: event_id, event_ts, channel, provider, computer, remote_host, '
                     'target_user, logon_type, process_name, command_line, payload(jsonb), source_file',
    'program_exec_v2': 'program execution (Prefetch/Amcache/ShimCache/BAM): event_ts, executable_name, '
                       'full_path, hash_sha1, source_file, payload',
    'filesystem_v2': 'file system ($MFT/$J/LNK/JumpLists): event_ts, file_name, extension, parent_path, '
                     'action, source_file, payload',
    'srum_v2': 'SRUM resource usage incl. network bytes: event_ts, username, exe_info, payload(bytes_sent etc.)',
    'tool_alerts_v2': 'alerts of Hayabusa/Chainsaw/Sigma etc.: tool, severity, rule, event_ts, computer, '
                      'user_name, ioc_value, details',
    'browser_provenance_v1': 'browser history/downloads with Zone.Identifier: event_ts, browser, user_name, '
                             'url, domain, download_path, local_path, zone_identifier_host_url, evidence_kind',
    'raw_fallback_v2': 'other parsed artefacts (registry, tasks, services, SRUM timeline, jump lists...): '
                       'parser_family, source_file, payload(jsonb), event_ts',
    'case_iocs': 'IOCs stored for the case: ioc_type, ioc_value, source_table, event_ts, confidence',
    'system_profile_v1': 'host profile: computer_name, os_name, build, install_date_utc, timezone, users_json',
}
_FORBID = re.compile(r'\b(insert|update|delete|drop|alter|create|truncate|grant|revoke|copy|call|do|'
                     r'set|reset|vacuum|lock|listen|notify|pg_sleep|dblink|lo_\w+|pg_read\w*|pg_ls\w*|'
                     r'pg_stat_file|current_setting|set_config)\b', re.I)
_SECRET = re.compile(r'\b(ntlm|lm|nt_hash|lm_hash)\b|local_accounts|bot_users|access_|token', re.I)
_CASE_RX = re.compile(r"'(\d{2}_\d{2}_\d{4}_[^']+)'")


# ------------------------------------------------------------------ auth, scope, audit

def _load_tokens():
    try:
        return json.load(open(TOKENS, encoding='utf-8'))
    except Exception:
        return {}


def token_identity(raw):
    if not raw:
        return None
    h = hashlib.sha256(raw.encode()).hexdigest()
    t = _load_tokens().get(h)
    if not t or t.get('disabled'):
        return None
    return {'name': t.get('name', '?'), 'cases': t.get('cases', [])}


def _allowed(case_key):
    w = _who.get() or {}
    cs = w.get('cases')
    return bool(case_key) and (cs == '*' or case_key in (cs or []))


def _scope(case_key):
    case_key = str(case_key or '').strip()
    if not _allowed(case_key):
        raise PermissionError('case %r is not available to this token (see list_cases)' % case_key)
    return case_key


def _audit(tool, case_key, args, t0, ok, note=''):
    try:
        w = _who.get() or {}
        rec = {'ts': time.strftime('%Y-%m-%dT%H:%M:%S'), 'who': w.get('name'), 'tool': tool,
               'case': case_key, 'args': {k: str(v)[:300] for k, v in (args or {}).items()},
               'ms': int((time.time() - t0) * 1000), 'ok': ok}
        if note:
            rec['note'] = note[:300]
        with open(AUDIT, 'a', encoding='utf-8') as f:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')
    except Exception:
        pass


def tool(fn):
    """MCP tool with scope check + audit; errors go back to the agent as text, never a traceback."""
    def wrapper(*a, **kw):
        t0 = time.time()
        ck = kw.get('case_key', '')
        try:
            out = fn(*a, **kw)
            _audit(fn.__name__, ck, kw, t0, True)
            return out
        except PermissionError as e:
            _audit(fn.__name__, ck, kw, t0, False, str(e))
            return 'ERROR: %s' % e
        except Exception as e:
            _audit(fn.__name__, ck, kw, t0, False, '%s: %s' % (type(e).__name__, e))
            return 'ERROR: %s: %s' % (type(e).__name__, str(e)[:300])
    wrapper.__name__, wrapper.__doc__ = fn.__name__, fn.__doc__
    wrapper.__annotations__ = fn.__annotations__
    wrapper.__wrapped__ = fn
    return mcp.tool()(wrapper)


def _conn():
    c = psycopg2.connect(PG_DSN, options='-c default_transaction_read_only=on '
                                         '-c statement_timeout=60000 -c TimeZone=UTC')
    c.set_session(readonly=True, autocommit=True)
    return c


def _fmt(cols, rows):
    out = []
    for r in rows:
        d = {}
        for k, v in zip(cols, r):
            if v is None:
                continue
            s = v if isinstance(v, (int, float)) else (
                json.dumps(v, ensure_ascii=False, default=str) if isinstance(v, (dict, list)) else str(v))
            if isinstance(s, str) and len(s) > CELL:
                s = s[:CELL] + '…'
            d[k] = s
        out.append(d)
    return json.dumps(out, ensure_ascii=False, default=str)


# ------------------------------------------------------------------ tools

@tool
def list_cases() -> str:
    """Start here. The cases this token may read: case_key, when it was analysed, host name.
    `count` is the exact number of cases - quote it, do not count the list yourself.
    Pass the exact case_key to every other tool."""
    w = _who.get() or {}
    with _conn() as c, c.cursor() as cur:
        cur.execute("SELECT case_key, max(created_at) FROM dfir_run_jobs_v2 GROUP BY case_key ORDER BY 2 DESC")
        jobs = cur.fetchall()
        cur.execute("SELECT case_key, computer_name FROM system_profile_v1")
        host = dict(cur.fetchall())
    keys = [k for k, _ in jobs] + [k for k in host if k not in {j[0] for j in jobs}]
    out = [{'case_key': k, 'last_analysis': str(dict(jobs).get(k) or ''), 'host': host.get(k)}
           for k in keys if w.get('cases') == '*' or k in (w.get('cases') or [])]
    # 18.10: Qwen3.6-35B answered «50» for a 49-item list - small models miscount long lists
    return json.dumps({'count': len(out), 'cases': out}, ensure_ascii=False)


@tool
def case_overview(case_key: str) -> str:
    """Host profile, rows and time span per evidence table, and when the examiner's own collection
    started (everything after that is the examiner, not the attacker)."""
    case_key = _scope(case_key)
    res = {'case_key': case_key, 'tables': {}}
    with _conn() as c, c.cursor() as cur:
        cur.execute('SELECT computer_name, os_name, build, install_date_utc, timezone, users_json '
                    'FROM system_profile_v1 WHERE case_key=%s LIMIT 1', (case_key,))
        r = cur.fetchone()
        if r:
            res['host'] = dict(zip(['computer', 'os', 'build', 'installed_utc', 'timezone', 'users'], r))
        for t, desc in TABLES.items():
            if t in ('system_profile_v1', 'case_iocs'):
                continue
            cur.execute('SELECT count(*), min(event_ts), max(event_ts) FROM %s WHERE case_key=%%s' % t, (case_key,))
            n, a, b = cur.fetchone()
            res['tables'][t] = {'rows': n, 'from': str(a), 'to': str(b), 'about': desc}
        try:
            from analysis.own_footprint import collect_started_at
            cs = collect_started_at(case_key, c)
        except Exception:
            cs = None
        if cs:
            res['collection_started_utc'] = str(cs)
            res['note'] = ("Everything stamped AFTER collection_started_utc is the examiner's own "
                           'collection activity (collector, KAPE, 7za, Sigma rule files), not the attacker.')
    return json.dumps(res, ensure_ascii=False, default=str)


@tool
def threat_findings(case_key: str) -> str:
    """Deterministic detector findings: severity, MITRE, title, detail, key events and IOCs.
    LEADS to verify with sql_query/timeline, not the final answer."""
    case_key = _scope(case_key)
    cache = '/data/state/mcp_cache/findings_%s.json' % re.sub(r'[^\w.-]', '_', case_key)
    if os.path.isfile(cache) and time.time() - os.path.getmtime(cache) < 86400:
        return open(cache, encoding='utf-8').read()
    from analysis.threat_detect import detect_threats
    with _conn() as c:
        f = detect_threats(case_key, c) or []
    out = [{'severity': x.get('severity'), 'mitre': x.get('mitre'), 'title': x.get('title'),
            'detail': str(x.get('detail') or '')[:600], 'count': x.get('count'),
            'events': [{'ts': e.get('ts'), 'label': str(e.get('label'))[:200], 'source': e.get('source')}
                       for e in (x.get('events') or [])[:8]],
            'iocs': [{'type': i.get('type'), 'value': str(i.get('value'))[:200], 'role': i.get('role')}
                     for i in (x.get('iocs') or [])[:10]]} for x in f[:40]]
    txt = json.dumps(out, ensure_ascii=False, default=str)
    try:
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        open(cache, 'w', encoding='utf-8').write(txt)
    except Exception:
        pass
    return txt


def sql_query(case_key: str, sql: str) -> str:
    case_key = _scope(case_key)
    q = sql.strip().rstrip(';')
    if ';' in q or not re.match(r'^\s*(select|with)\b', q, re.I) or _FORBID.search(q):
        return 'ERROR: only a single read-only SELECT/WITH statement is allowed'
    if _SECRET.search(q):
        return 'ERROR: password hashes and bot account tables are not available'
    if case_key not in q:
        return "ERROR: add WHERE case_key = '%s' to the query" % case_key
    other = [k for k in _CASE_RX.findall(q) if k != case_key and not _allowed(k)]
    if other:
        return 'ERROR: case %s is not available to this token' % other[0]
    with _conn() as c, c.cursor() as cur:
        cur.execute('SELECT * FROM (%s) _q LIMIT %d' % (q, MAX_ROWS + 1))
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description]
    if not rows:
        return ('EMPTY: 0 rows. Before concluding "absent": check the table really holds this data for the '
                'case (case_overview), the value format (search_text with a fragment), and the time range.')
    more = len(rows) > MAX_ROWS
    return ('(first %d rows - refine the query)\n' % MAX_ROWS if more else '') + _fmt(cols, rows[:MAX_ROWS])


sql_query.__doc__ = ("Run ONE read-only SELECT against the case database (PostgreSQL). Always filter by "
                     "case_key. Max 200 rows, long cells cut, timestamps UTC. An empty result says EMPTY "
                     "explicitly. Tables: " + '; '.join('%s - %s' % kv for kv in TABLES.items()))
tool(sql_query)


@tool
def search_text(case_key: str, text: str, limit: int = 50) -> str:
    """Case-insensitive search of a fragment (file name, domain, user, IP, hash) across the evidence
    tables; time-sorted hits with table and source file. Use it to learn the value FORMAT first."""
    case_key = _scope(case_key)
    pat = '%' + text.replace('%', r'\%').replace('_', r'\_') + '%'
    limit = max(1, min(int(limit), 100))
    parts = [
        ("event_logs_v2", "concat_ws(' | ', event_id, channel, process_name, command_line, target_user, remote_host, payload::text)"),
        ("program_exec_v2", "concat_ws(' | ', executable_name, full_path, hash_sha1)"),
        ("filesystem_v2", "concat_ws(' | ', action, parent_path, file_name)"),
        ("browser_provenance_v1", "concat_ws(' | ', evidence_kind, url, download_path, local_path, zone_identifier_host_url)"),
        ("srum_v2", "concat_ws(' | ', username, exe_info, payload::text)"),
        ("tool_alerts_v2", "concat_ws(' | ', tool, severity, rule, details, ioc_value)"),
        ("raw_fallback_v2", "concat_ws(' | ', parser_family, payload::text)"),
    ]
    out = []
    with _conn() as c, c.cursor() as cur:
        for t, expr in parts:
            try:
                cur.execute('SELECT event_ts, %s AS hit, source_file FROM %s WHERE case_key=%%s AND %s ILIKE %%s '
                            'ORDER BY event_ts LIMIT %d' % (expr, t, expr, limit), (case_key, pat))
                out += [{'ts': str(ts), 'table': t, 'hit': str(hit)[:CELL], 'source': src}
                        for ts, hit, src in cur.fetchall()]
            except Exception as e:
                out.append({'table': t, 'error': str(e)[:150]})
    out.sort(key=lambda d: d.get('ts') or '')
    return json.dumps(out[:limit * 2], ensure_ascii=False) if out else 'EMPTY: no table contains this fragment'


@tool
def timeline(case_key: str, start_utc: str, end_utc: str, limit: int = 150) -> str:
    """Merged chronology (executions, risky files, downloads, key logon/service/task/log-clear events,
    high alerts) between two UTC timestamps like '2026-02-13 10:00'. Use around a suspicious moment."""
    case_key = _scope(case_key)
    limit = max(1, min(int(limit), 300))
    q = """
    SELECT * FROM (
      SELECT event_ts, 'exec' k, executable_name||' '||coalesce(full_path,'') d, source_file FROM program_exec_v2
        WHERE case_key=%(c)s AND event_ts BETWEEN %(a)s AND %(b)s
      UNION ALL SELECT event_ts, 'file:'||coalesce(action,''), coalesce(parent_path,'')||'\\'||coalesce(file_name,''), source_file
        FROM filesystem_v2 WHERE case_key=%(c)s AND event_ts BETWEEN %(a)s AND %(b)s
        AND coalesce(extension,'') ~* '^\\.?(exe|dll|ps1|bat|cmd|vbs|js|hta|zip|rar|7z|iso|lnk|msi|scr)$'
      UNION ALL SELECT event_ts, 'browser:'||coalesce(evidence_kind,''), coalesce(url,'')||' '||coalesce(download_path,''), source_file
        FROM browser_provenance_v1 WHERE case_key=%(c)s AND event_ts BETWEEN %(a)s AND %(b)s
      UNION ALL SELECT event_ts, 'evt:'||event_id, concat_ws(' ', channel, target_user, logon_type, remote_host, process_name, left(command_line,200)), source_file
        FROM event_logs_v2 WHERE case_key=%(c)s AND event_ts BETWEEN %(a)s AND %(b)s
        AND event_id IN (4624,4625,4648,4672,4688,4697,4698,4720,4732,7045,1102,104,1116,1117,5001,4104,21,22,24,25,1149)
      UNION ALL SELECT event_ts, 'alert:'||coalesce(tool,''), coalesce(severity,'')||' '||coalesce(rule,''), source_file
        FROM tool_alerts_v2 WHERE case_key=%(c)s AND event_ts BETWEEN %(a)s AND %(b)s AND severity IN ('high','critical')
    ) x ORDER BY event_ts LIMIT %(n)s"""
    with _conn() as c, c.cursor() as cur:
        cur.execute(q, {'c': case_key, 'a': start_utc, 'b': end_utc, 'n': limit})
        rows = cur.fetchall()
    return _fmt(['ts', 'kind', 'what', 'source'], rows) if rows else 'EMPTY: nothing in this window'


@tool
def case_report(case_key: str, max_chars: int = 30000) -> str:
    """The bot's latest final report for the case (the text the client got), cut to max_chars.
    Use it to see the bot's verdict and reasoning, then challenge it with the data tools."""
    case_key = _scope(case_key)
    d = os.path.join(CASES_DIR, case_key, 'reports')
    try:
        files = [os.path.join(d, f) for f in os.listdir(d) if f.startswith('case_report_') and f.endswith('.txt')]
    except FileNotFoundError:
        files = []
    if not files:
        return 'EMPTY: no final report stored for this case yet'
    p = max(files, key=os.path.getmtime)
    txt = open(p, encoding='utf-8', errors='replace').read()
    max_chars = max(1000, min(int(max_chars), 120000))
    head = '[report %s, %s, %d chars]\n' % (os.path.basename(p), time.strftime('%Y-%m-%d %H:%M', time.localtime(os.path.getmtime(p))), len(txt))
    return head + txt[:max_chars] + ('\n…(cut)' if len(txt) > max_chars else '')


# ------------------------------------------------------------------ HTTP app with bearer auth

def build_app():
    app = mcp.streamable_http_app()

    async def auth(scope, receive, send):
        if scope['type'] == 'http':
            hdr = dict(scope.get('headers') or [])
            raw = hdr.get(b'authorization', b'').decode('latin-1')
            ident = token_identity(raw[7:].strip() if raw.lower().startswith('bearer ') else '')
            if scope.get('path', '').rstrip('/') == '/health':
                body = b'{"ok":true,"service":"dfir-mcp"}'
                await send({'type': 'http.response.start', 'status': 200,
                            'headers': [(b'content-type', b'application/json')]})
                await send({'type': 'http.response.body', 'body': body})
                return
            if not ident:
                await send({'type': 'http.response.start', 'status': 401,
                            'headers': [(b'content-type', b'application/json'),
                                        (b'www-authenticate', b'Bearer')]})
                await send({'type': 'http.response.body', 'body': b'{"error":"bad or missing token"}'})
                return
            tok = _who.set(ident)
            try:
                return await app(scope, receive, send)
            finally:
                _who.reset(tok)
        return await app(scope, receive, send)
    return auth


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(build_app(), host='0.0.0.0', port=8000, log_level='warning')
