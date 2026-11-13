"""Agent tool implementations — forensic data retrieval functions called by the DFIR agent loop.

Each _agent_tool_* function is self-contained: takes case_key + params, queries PostgreSQL,
returns a string result for the LLM to reason about.
"""
import os
import json
import re
import sys
import time
import uuid
import traceback as _tb
import logging
from datetime import datetime, timezone, timedelta

import psycopg2

from core.config import (
    PG_DSN, QDRANT_URL, EMBED_URL, EMBED_MODEL, TEXT_COLL_PRIMARY, EID_ATTACK_MAP,
)
from core.http_utils import http_json as _http_json
from analysis import salience as _S
# The pipeline's own footprint (collector staging folder, dfp_ probes, vao_collector, our
# tools after the collector started). Every tool answer passes through strip_own_lines in
# the dispatcher, so the model never reads KAPE/7za at 12:51 as the attacker's collection.
try:
    from analysis.own_footprint import is_own as _own_is_own, strip_own_lines as _own_strip
except Exception:  # pragma: no cover
    def _own_is_own(text, ts=None, case_key=None, conn=None, declared=None):
        return False

    def _own_strip(text, case_key=None, conn=None):
        return text
from psycopg2.extras import Json

_log = logging.getLogger('app')

def _ensure_agent_learnings_table():
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.dfir_agent_learnings (
                    id SERIAL PRIMARY KEY,
                    case_key TEXT,
                    job_id TEXT,
                    attack_family TEXT,
                    tool_sequence TEXT[],
                    effective_keywords TEXT[],
                    report_quality_score FLOAT DEFAULT 0,
                    report_len INT DEFAULT 0,
                    summary TEXT,
                    created_at TIMESTAMPTZ DEFAULT now()
                )
            """)
            conn.commit()

def _load_agent_learnings(case_key):
    """Load previous successful learnings to inject into system prompt."""
    try:
        _ensure_agent_learnings_table()
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT attack_family, effective_keywords, summary, report_quality_score
                    FROM dfir_agent_learnings
                    WHERE case_key != %s AND report_quality_score > 0
                    ORDER BY created_at DESC LIMIT 5
                """, (case_key,))
                rows = cur.fetchall()
        if not rows:
            return ""
        parts = ["ДОСВІД З ПОПЕРЕДНІХ АНАЛІЗІВ (використовуй як орієнтир):"]
        for family, keywords, summary, score in rows:
            kw = ', '.join((keywords or [])[:5])
            parts.append(f"• [{family or 'unknown'}] ключові слова: {kw} | {(summary or '')[:120]}")
        return '\n'.join(parts)
    except Exception:
        return ""


def _save_agent_learnings(case_key, job_id, called_tools_dict, final_report):
    """Save what worked in this analysis for future reference."""
    try:
        # Extract tool sequence (unique, in order of first call)
        tool_seq = list(dict.fromkeys(t for t, _ in called_tools_dict.keys()))
        # Extract keywords from search_events calls
        keywords = [
            json.loads(a).get('keyword', '') for t, a in called_tools_dict.keys()
            if t == 'search_events' and json.loads(a).get('keyword')
        ]
        # Detect attack family from report text
        report_lower = final_report.lower()
        family = 'unknown'
        if 'ngrok' in report_lower: family = 'ngrok_tunnel'
        elif 'ransomware' in report_lower or 'ransomwar' in report_lower: family = 'ransomware'
        elif 'rdp' in report_lower and 'wrapper' in report_lower: family = 'rdp_wrapper'
        elif 'mimikatz' in report_lower: family = 'credential_dump'
        elif 'anydesk' in report_lower or 'teamviewer' in report_lower: family = 'remote_access_tool'
        elif 'phishing' in report_lower: family = 'phishing'
        # Quality score: rough heuristic based on report length and structure
        score = min(10.0, round(len(final_report) / 400, 1))
        if '##' in final_report: score = min(10.0, score + 1)
        if 'хронологія' in report_lower or 'chronolog' in report_lower: score = min(10.0, score + 1)
        # Short summary (first 200 chars of report)
        summary = final_report.strip()[:200].replace('\n', ' ')
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO dfir_agent_learnings
                        (case_key, job_id, attack_family, tool_sequence, effective_keywords,
                         report_quality_score, report_len, summary)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                """, (case_key, job_id, family, tool_seq, keywords,
                      score, len(final_report), summary))
        _log.error(f"[agent] learnings saved: family={family} score={score} tools={tool_seq}")
    except Exception as e:
        _log.error(f"[agent] learnings save error: {e}")


def _sync_iocs_to_pg(case_key):
    """Sync IOCs from Qdrant kb_iocs → PostgreSQL case_iocs + compute ioc_overlap."""
    try:
        qdrant = QDRANT_URL.rstrip('/')
        # Check collection exists before scrolling
        try:
            _http_json('GET', f"{qdrant}/collections/kb_iocs", timeout=10)
        except Exception:
            return  # kb_iocs collection doesn't exist, skip
        # Scroll all IOCs for this case from Qdrant
        offset = None
        all_iocs = []
        while True:
            body = {'limit': 200, 'with_payload': True, 'with_vector': False,
                    'filter': {'must': [{'key': 'case_key', 'match': {'value': case_key}}]}}
            if offset:
                body['offset'] = offset
            r = _http_json('POST', f"{qdrant}/collections/kb_iocs/points/scroll", body=body, timeout=30)
            pts = ((r or {}).get('result') or {}).get('points') or []
            all_iocs.extend(pts)
            next_offset = ((r or {}).get('result') or {}).get('next_page_offset')
            if not next_offset or not pts:
                break
            offset = next_offset

        if not all_iocs:
            return

        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # Upsert IOCs
                for pt in all_iocs:
                    pay = pt.get('payload', {})
                    ioc_type = str(pay.get('ioc_type', 'unknown'))[:60]
                    ioc_value = str(pay.get('ioc_value', ''))[:500]
                    ioc_norm = str(pay.get('ioc_value_norm', ioc_value.lower()))[:500]
                    source = str(pay.get('source', 'report'))[:120]
                    if not ioc_value:
                        continue
                    cur.execute("""
                        INSERT INTO case_iocs (case_key, ioc_type, ioc_value, ioc_norm, source_table)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (case_key, ioc_type, ioc_norm) DO NOTHING
                    """, (case_key, ioc_type, ioc_value, ioc_norm, source))

                # Compute ioc_overlap: find other cases sharing same IOC
                cur.execute("""
                    INSERT INTO ioc_overlap (case_a, case_b, ioc_type, ioc_norm)
                    SELECT a.case_key, b.case_key, a.ioc_type, a.ioc_norm
                    FROM case_iocs a
                    JOIN case_iocs b ON a.ioc_norm = b.ioc_norm
                        AND a.ioc_type = b.ioc_type
                        AND a.case_key != b.case_key
                        AND a.case_key = %s
                    ON CONFLICT (case_a, case_b, ioc_type, ioc_norm) DO NOTHING
                """, (case_key,))
        _log.error(f"[agent] synced {len(all_iocs)} IOCs to PG for {case_key}")
    except Exception as e:
        _log.error(f"[agent] ioc sync error: {e}")


# Row caps below are scaled by DFIR_ROW_SCALE (default 1.0 = unchanged). The raw caps
# were sized for small triage sets; the largest case here holds 406k event rows, so a
# few dozen rows per tool is a tighter ceiling on what the model can see than any
# character budget. Defaults bind once at import, which is why scaling them is enough.
_ROW_SCALE = max(1.0, float(os.getenv('DFIR_ROW_SCALE', '1')))

def _agent_tool_search_iocs_across_cases(ioc_value, ioc_type=None):
    """Find IOC matches across all cases in PostgreSQL."""
    try:
        ioc_norm = str(ioc_value).strip().lower()[:500]
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                if ioc_type:
                    cur.execute("""
                        SELECT case_key, ioc_type, ioc_value, source_table, created_at
                        FROM case_iocs
                        WHERE ioc_norm = %s AND ioc_type = %s
                        ORDER BY created_at DESC LIMIT 20
                    """, (ioc_norm, ioc_type))
                else:
                    cur.execute("""
                        SELECT case_key, ioc_type, ioc_value, source_table, created_at
                        FROM case_iocs
                        WHERE ioc_norm = %s
                        ORDER BY created_at DESC LIMIT 20
                    """, (ioc_norm,))
                rows = cur.fetchall()
        if not rows:
            return f"IOC '{ioc_value}' не знайдено в жодному іншому кейсі."
        lines = [f"IOC '{ioc_value}' знайдено в {len(rows)} кейсах:"]
        for case_key, itype, ival, src, ts in rows:
            lines.append(f"  • {case_key} | type={itype} | source={src or '?'}")
        return '\n'.join(lines)
    except Exception as e:
        return f"IOC cross-case search error: {e}"


def _agent_tool_get_system_profile(case_key):
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT computer_name, os_name, build, install_date_utc,
                           timezone, utc_offset, last_shutdown_utc, users_json
                    FROM system_profile_v1 WHERE case_key=%s LIMIT 1
                """, (case_key,))
                r = cur.fetchone()
        if not r:
            return "Системний профіль не знайдено."
        keys = ['computer_name','os_name','build','install_date_utc','timezone','utc_offset','last_shutdown_utc','users']
        d = dict(zip(keys, r))
        lines = [f"Хост: {d['computer_name']}", f"ОС: {d['os_name']} build {d['build']}",
                 f"Встановлено: {d['install_date_utc']}", f"Часовий пояс: {d['timezone']} {d['utc_offset']}",
                 f"Останнє вимкнення: {d['last_shutdown_utc']}"]
        if d.get('users'):
            try:
                users = json.loads(d['users']) if isinstance(d['users'], str) else d['users']
                for u in (users or [])[:5]:
                    lines.append(f"  Користувач: {u.get('username')} | sid={u.get('sid')} | last_login={u.get('last_login_utc')}")
            except Exception: pass
        return '\n'.join(lines)
    except Exception as e:
        return f"ERROR: {e}"

def _agent_tool_get_top_alerts(case_key, tool=None, severity=None, limit=int(30 * _ROW_SCALE)):
    limit = min(int(limit or 30), 50)
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                params = [case_key]
                where = ["case_key=%s"]
                if tool: where.append("tool=%s"); params.append(tool)
                if severity: where.append("severity=%s"); params.append(severity)
                cur.execute(f"""
                    SELECT tool, severity, rule, event_ts, computer, ioc_value, details
                    FROM tool_alerts_v2
                    WHERE {' AND '.join(where)}
                    ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
                             event_ts DESC NULLS LAST
                    LIMIT %s
                """, params + [limit])
                rows = cur.fetchall()
        if not rows: return "Детекцій не знайдено."
        out = []
        for r in rows:
            ts = r[3].isoformat() if r[3] else 'n/a'
            det = str(r[6] or '')[:120]
            out.append(f"[{r[1]}] {r[0]} | {r[2]} | {ts} | host={r[4]} | ioc={r[5]} | {det}")
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"

def _agent_tool_search_events(case_key, keyword, event_id=None, limit=int(30 * _ROW_SCALE)):
    limit = min(int(limit or 30), 50)
    pat = f'%{keyword}%'
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # Search event_logs_v2
                extra = "AND event_id=%s" if event_id else ""
                params = [case_key, pat, pat, pat, pat]
                if event_id: params.append(int(event_id))
                params.append(limit)
                cur.execute(f"""
                    SELECT event_ts, event_id, channel, target_user, remote_host,
                           process_name, command_line, source_file, payload
                    FROM event_logs_v2
                    WHERE case_key=%s {extra} AND (
                        coalesce(command_line,'') ILIKE %s OR
                        coalesce(process_name,'') ILIKE %s OR
                        coalesce(remote_host,'') ILIKE %s OR
                        payload::text ILIKE %s
                    )
                    ORDER BY event_ts DESC NULLS LAST LIMIT %s
                """, params)
                rows = cur.fetchall()
                # Also search raw_fallback_v2 forensictimeline
                cur.execute("""
                    SELECT payload->>'DateTime', payload->>'Description',
                           payload->>'DataPath', payload->>'DataDetails', source_file
                    FROM raw_fallback_v2
                    WHERE case_key=%s AND parser_family='forensictimeline'
                      AND payload::text ILIKE %s
                    ORDER BY payload->>'DateTime' DESC NULLS LAST LIMIT %s
                """, (case_key, pat, min(limit, 20)))
                tl_rows = cur.fetchall()
        out = []
        if rows:
            for r in rows:
                ts = r[0].isoformat() if r[0] else 'n/a'
                cmd = str(r[6] or '')[:150]
                p = r[8] if isinstance(r[8], dict) else {}
                if not cmd.strip():
                    payload_hint = str(p.get('PayloadData1') or p.get('PayloadData2') or p.get('ScriptBlockText') or '')[:150]
                    cmd = payload_hint
                extra = ''
                if r[1] == 4624 and p.get('PayloadData1'):
                    extra = f" | target={str(p.get('PayloadData1',''))[:80]}"
                out.append(f"{ts} | EID={r[1]} | {r[2]} | user={r[3]} | host={r[4]} | proc={r[5]} | cmd={cmd}{extra} | src={r[7]}")
        if tl_rows:
            out.append(f"\n--- Forensic Timeline ({len(tl_rows)} hits) ---")
            for r in tl_rows:
                out.append(f"{r[0]} | {r[1]} | {r[2]} | {r[3]} | src={r[4]}")
        if not out:
            return f"Подій з '{keyword}' не знайдено."
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"

def _agent_tool_get_filesystem_artifacts(case_key, pattern, limit=int(30 * _ROW_SCALE)):
    limit = min(int(limit or 30), 50)
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT event_ts, file_name, extension, parent_path, action, source_file
                    FROM filesystem_v2
                    WHERE case_key=%s AND file_name ILIKE %s
                    ORDER BY event_ts DESC NULLS LAST LIMIT %s
                """, (case_key, pattern, limit))
                rows = cur.fetchall()
        if not rows: return f"Файлів за шаблоном '{pattern}' не знайдено."
        out = []
        for r in rows:
            ts = r[0].isoformat() if r[0] else 'n/a'
            out.append(f"{ts} | {r[1]}.{r[2]} | path={r[3]} | action={r[4]} | src={r[5]}")
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"

def _agent_tool_get_registry_persistence(case_key, keyword=None, limit=int(30 * _ROW_SCALE)):
    limit = min(int(limit or 30), 50)
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                params = [case_key]
                kw_clause = ""
                if keyword:
                    kw_clause = "AND (payload->>'ValueData' ILIKE %s OR payload->>'KeyPath' ILIKE %s)"
                    params += [f'%{keyword}%', f'%{keyword}%']
                params.append(limit)
                cur.execute(f"""
                    SELECT payload->>'KeyPath', payload->>'ValueName',
                           payload->>'ValueData', payload->>'Category', source_file
                    FROM raw_fallback_v2
                    WHERE case_key=%s AND parser_family='registry' {kw_clause}
                    LIMIT %s
                """, params)
                rows = cur.fetchall()
        if not rows: return "Registry ASEP записів не знайдено."
        out = []
        for r in rows:
            val = str(r[2] or '')[:120]
            out.append(f"[{r[3]}] {r[0]} | {r[1]} = {val}")
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"

def _agent_tool_get_logon_activity(case_key, limit=int(30 * _ROW_SCALE)):
    limit = min(int(limit or 30), 50)
    import datetime as _dt_la, re as _re_la
    atk_start = '2025-01-01'
    try:
        m_ck = _re_la.match(r'^(\d{2})_(\d{2})_(\d{4})', case_key)
        if m_ck:
            try:
                ck_date = _dt_la.date(int(m_ck.group(3)), int(m_ck.group(2)), int(m_ck.group(1)))
                atk_start = (ck_date - _dt_la.timedelta(days=180)).strftime('%Y-%m-%d')
            except ValueError:
                pass
    except Exception:
        pass
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # Refine atk_start using first 2026 trigger
                cur.execute("""
                    SELECT MIN(event_ts) FROM case_trigger_hits_v2
                    WHERE case_key=%s AND event_ts >= '2026-01-01' AND event_ts < '2030-01-01'
                      AND trigger NOT IN ('hosturl=','referrerurl=','word.exe','excel.exe','mspaint.exe')
                """, (case_key,))
                t2026 = cur.fetchone()[0]
                if t2026:
                    atk_start = (t2026 - _dt_la.timedelta(days=30)).strftime('%Y-%m-%d')
                cur.execute("""
                    SELECT event_ts, event_id, target_user, remote_host,
                           logon_type, computer, source_file, payload
                    FROM (
                        SELECT DISTINCT ON (date_trunc('second', event_ts), event_id, LOWER(COALESCE(target_user,'')))
                               event_ts, event_id, target_user, remote_host,
                               logon_type, computer, source_file, payload
                        FROM event_logs_v2
                        WHERE case_key=%s AND event_ts >= %s
                          AND event_id IN (4624,4625,4634,4647,4648,4720,4722,4723,4724,4725,4726,4738,4778,4779,4800,4801,1149,21,24,25)
                        ORDER BY date_trunc('second', event_ts), event_id, LOWER(COALESCE(target_user,''))
                    ) deduped
                    ORDER BY
                      CASE event_id WHEN 4720 THEN 0 WHEN 4726 THEN 0
                                    WHEN 4722 THEN 0 WHEN 4724 THEN 0
                                    WHEN 1149 THEN 1
                                    WHEN 4624 THEN
                                      CASE WHEN logon_type ILIKE '%%remote%%' OR logon_type ILIKE '%%rdp%%' OR logon_type='10' THEN 1 ELSE 3 END
                                    WHEN 21 THEN
                                      CASE WHEN LOWER(COALESCE(remote_host,''))='local' OR remote_host='' OR remote_host IS NULL THEN 4 ELSE 1 END
                                    WHEN 4625 THEN 2
                                    WHEN 4738 THEN 1
                                    ELSE 3 END,
                      event_ts ASC
                    LIMIT %s
                """, (case_key, atk_start, limit))
                rows = cur.fetchall()
        if not rows: return "Logon подій не знайдено."
        _eid_desc = {4624:'Logon',4625:'Failed Logon',4634:'Logoff',4647:'Logoff',
                     4648:'Explicit Creds',4720:'User Created',4722:'User Enabled',
                     4725:'User Disabled',4726:'User Deleted',4738:'User Changed',
                     4778:'Session Reconnect',4779:'Session Disconnect',
                     1149:'RDP Auth',21:'RDP Logon',24:'RDP Disconnect',25:'RDP Reconnect'}
        import re as _re
        seen_4720 = set()
        out = []
        for r in rows:
            ts = r[0].isoformat()[:19] if r[0] else 'n/a'
            eid = r[1]
            desc = _eid_desc.get(eid, f'EID={eid}')
            src = str(r[3] or '').strip()
            subject_user = str(r[2] or '').strip()
            payload = r[7] if isinstance(r[7], dict) else {}
            # For EID 4720/4726: extract CREATED/DELETED account from PayloadData1
            target_account = subject_user
            if eid in (4720, 4726, 4722, 4724, 4738):
                pd1 = str(payload.get('PayloadData1') or '')
                m = _re.search(r'Target:\s*([^\(]+(?:\([^\)]+\))?)', pd1)
                if m:
                    target_account = m.group(1).strip()
                    dedup_key = (ts[:16], eid, target_account[:30])
                    if dedup_key in seen_4720:
                        continue
                    seen_4720.add(dedup_key)
            flag = (' *** НОВИЙ АКАУНТ ***' if eid == 4720
                    else ' *** ВИДАЛЕНО ***' if eid == 4726
                    else ' [RDP]' if eid in (21, 1149) else '')
            logon_type_str = f" | type={r[4]}" if r[4] else ''
            out.append(f"{ts} | {desc}{flag} | account={target_account} | by={subject_user if eid in (4720,4726) else ''} | from={src}{logon_type_str} | {r[6]}")

        def _logon_rank(line):
            """Що вирішує справу у журналі входів: керування акаунтами, потім входи
            із зовнішньої адреси, потім іменований акаунт, і аж потім сесійний шум
            з порожнім акаунтом. Всередині рангу порядок лишається хронологічним."""
            try:
                if _S.tier(line) <= _S.SUSPECT:
                    return 0
                src_part = line.split('| from=')[-1] if '| from=' in line else ''
                if _S.is_public_ip(src_part):
                    return 1
                acc = line.split('| account=')[-1].split('|')[0] if '| account=' in line else ''
                return 2 if acc.strip().strip('\\') else 3
            except Exception:
                return 2
        out = sorted(out, key=_logon_rank)
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"

def _agent_tool_get_hayabusa(case_key, min_level=None, limit=int(30 * _ROW_SCALE)):
    limit = min(int(limit or 30), 50)
    # Hayabusa writes 'crit'/'high'/'med'/'low'/'info' — normalise aliases
    _norm = {'critical':'crit','crit':'crit','high':'high','medium':'med','med':'med',
             'low':'low','informational':'info','info':'info'}
    level_order = {'crit':1,'high':2,'med':3,'low':4,'info':5}
    min_key = _norm.get(str(min_level or 'high').lower(), 'high')
    min_rank = level_order.get(min_key, 2)
    allowed = [k for k, v in level_order.items() if v <= min_rank]
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT severity, rule, event_ts, computer, ioc_value, details
                    FROM tool_alerts_v2
                    WHERE case_key=%s AND tool='hayabusa'
                      AND lower(coalesce(severity,'med')) = ANY(%s)
                    ORDER BY CASE lower(coalesce(severity,'med'))
                        WHEN 'crit' THEN 1 WHEN 'high' THEN 2 WHEN 'med' THEN 3 ELSE 4 END,
                        event_ts DESC NULLS LAST
                    LIMIT %s
                """, (case_key, allowed, limit))
                rows = cur.fetchall()
        if not rows: return "Hayabusa детекцій не знайдено."
        out = []
        for r in rows:
            ts = r[2].isoformat() if r[2] else 'n/a'
            det = str(r[5] or '')[:120]
            out.append(f"[{r[0]}] {r[1]} | {ts} | {r[3]} | {det}")
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"

def _ensure_agent_case_notes_table():
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS agent_case_notes (
                        note_id bigserial PRIMARY KEY,
                        case_key text NOT NULL,
                        note_type text,
                        confidence text,
                        summary text NOT NULL,
                        sources text[],
                        detail jsonb,
                        created_at timestamptz DEFAULT now()
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_acn_case ON agent_case_notes(case_key)")
                # KB table for cross-case learnings
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS agent_kb (
                        kb_id bigserial PRIMARY KEY,
                        attack_family text,
                        technique text,
                        lesson text NOT NULL,
                        example_case text,
                        keywords text[],
                        created_at timestamptz DEFAULT now()
                    )
                """)
                conn.commit()
    except Exception:
        try: conn.rollback()
        except: pass
        pass

def _agent_tool_save_finding(case_key, finding_type, summary, sources=None, confidence='medium', detail=None):
    """Save a structured finding to investigation memory (agent_case_notes).
    Call this every time you confirm something important: initial_access, persistence, ioc, lateral_movement.
    These notes persist and help build the final report. Sources = list of tables/files that confirm this.
    """
    try:
        _ensure_agent_case_notes_table()
        src_list = sources if isinstance(sources, list) else ([sources] if sources else [])
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO agent_case_notes (case_key, note_type, confidence, summary, sources, detail)
                    VALUES (%s,%s,%s,%s,%s,%s)
                """, (case_key, finding_type, confidence, summary, src_list, Json(detail or {})))
                conn.commit()
        return f"OK: [{finding_type}/{confidence}] {summary}"
    except Exception as e:
        return f"ERROR: {e}"

def _agent_tool_get_saved_findings(case_key):
    """Load all saved findings for this case. Call at start to resume investigation, or before writing report."""
    try:
        _ensure_agent_case_notes_table()
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT note_type, confidence, summary, sources, created_at
                    FROM agent_case_notes WHERE case_key=%s ORDER BY created_at
                """, (case_key,))
                rows = cur.fetchall()
        if not rows:
            return "Збережених знахідок немає."
        out = [f"=== ЗБЕРЕЖЕНІ ЗНАХІДКИ для {case_key} ==="]
        for ntype, conf, summary, sources, ts in rows:
            src = ', '.join(sources or [])
            out.append(f"[{ntype}/{conf}] {summary}")
            if src:
                out.append(f"  Джерела: {src}")
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"

def _agent_tool_get_download_artifacts(case_key, since=None, limit=int(40 * _ROW_SCALE)):
    """Zone.Identifier з MFT — ГОЛОВНЕ для знаходження initial access.
    Показує звідки кожен файл був завантажений: HostUrl (пряме посилання) + ReferrerUrl (сторінка звідки).
    Підозрілі: ZIP/EXE/VBS/BAT з незвичних джерел. Також показує файли з Downloads/Temp/AppData.

    Обидві секції впорядковані за важливістю (analysis/salience.py): виконувані файли
    й скрипти вгорі, поштові вкладення нижче, решта — в кінці. Причина — вивід сягає
    35 541 символа при зрізі на 4000: на 03_07_case_47 усі 100 рядків секції browser
    downloads були одним і тим самим вкладенням `.jpg.asice.zip` з gmail.
    """
    limit = min(int(limit or 40), 80)
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                params = [case_key]
                since_clause = ""
                if since:
                    since_clause = "AND event_ts >= %s::timestamptz"
                    params.append(since)
                params.append(limit)
                host_re = r'HostUrl=([^\r\n]+)'
                ref_re  = r'ReferrerUrl=([^\r\n]+)'
                q_params = [host_re, ref_re, case_key]
                since_sql = ""
                if since:
                    since_sql = "AND event_ts >= %s::timestamptz"
                    q_params.append(since)
                q_params.append(limit)
                # Default: if no since filter, exclude legit notary domains to reduce noise
                legit_domain_filter = ""
                if not since:
                    legit_domain_filter = """
                      AND NOT (
                        payload->>'zone_id' ILIKE '%%zakon.rada.gov.ua%%'
                        OR payload->>'zone_id' ILIKE '%%minjust.gov.ua%%'
                        OR payload->>'zone_id' ILIKE '%%justice-km.gov.ua%%'
                        OR payload->>'zone_id' ILIKE '%%iit.com.ua%%'
                        OR payload->>'zone_id' ILIKE '%%nais.gov.ua%%'
                        OR payload->>'zone_id' ILIKE '%%drive.google.com%%'
                        OR payload->>'zone_id' ILIKE '%%takeout-download%%'
                      )
                    """
                cur.execute(f"""
                    SELECT
                        event_ts,
                        file_name,
                        parent_path,
                        (regexp_match(payload->>'zone_id', %s))[1] AS host_url,
                        (regexp_match(payload->>'zone_id', %s))[1] AS referrer,
                        payload->>'file_size' AS fsize
                    FROM filesystem_v2
                    WHERE case_key=%s
                      AND payload->>'zone_id' ILIKE '%%HostUrl%%'
                      {since_sql}
                      {legit_domain_filter}
                    ORDER BY
                      -- Suspicious archives first: ZIP/EXE/RAR from non-MS/non-google domains
                      CASE WHEN lower(file_name) ~ '\\.(zip|rar|7z|exe|msi|js|vbs|bat|ps1)' THEN 0 ELSE 1 END ASC,
                      -- Then most recent first (incident window at top)
                      event_ts DESC
                    LIMIT %s
                """, q_params)
                rows = cur.fetchall()
        # Also get browser_downloads from raw_fallback_v2
        br_rows = []
        try:
            with psycopg2.connect(PG_DSN) as _bc:
                with _bc.cursor() as _bcur:
                    # First try: suspicious exe/archive/script files from last 3 years (DESC for recent first)
                    _bcur.execute("""
                        SELECT payload->>'end_time', payload->>'target_path', payload->>'current_path', payload->>'url', payload->>'filename', payload->>'total_bytes'
                        FROM raw_fallback_v2
                        WHERE case_key=%s AND parser_family='browser_downloads'
                          AND (payload->>'target_path' ~* '\\.(exe|zip|rar|7z|msi|js|vbs|bat|ps1|docm|xlsm|cmd)'
                               OR payload->>'url' ~* '(mail\\.|attach|download|transfer|fex\\.net|ukr\\.net|swisstransfer|wetransfer|mega\\.nz|gofile|pixeldrain)')
                          AND payload->>'end_time' > '2023-01-01'
                        ORDER BY payload->>'end_time' DESC LIMIT 40
                    """, (case_key,))
                    for r in _bcur.fetchall():
                        br_rows.append(r)
                    # If nothing recent, fallback to all time
                    if not br_rows:
                        _bcur.execute("""
                            SELECT payload->>'end_time', payload->>'target_path', payload->>'current_path', payload->>'url', payload->>'filename', payload->>'total_bytes'
                            FROM raw_fallback_v2
                            WHERE case_key=%s AND parser_family='browser_downloads'
                              AND (payload->>'target_path' ~* '\\.(exe|zip|rar|7z|msi|js|vbs|bat|ps1|docm|xlsm|cmd)'
                                   OR payload->>'url' ~* '(mail\\.|attach|download|transfer|fex\\.net|ukr\\.net)')
                            ORDER BY payload->>'end_time' DESC LIMIT 30
                        """, (case_key,))
                        for r in _bcur.fetchall():
                            br_rows.append(r)
        except Exception:
            try: conn.rollback()
            except: pass
            pass

        if not rows and not br_rows:
            return "Zone.Identifier та browser_downloads записів не знайдено."
        # Suspicious domains to highlight
        SUSPICIOUS_DOMAINS = ['swisstransfer','wetransfer','gofile','mega.nz','onionshare','temp.sh','file.io','anonfiles','sendspace','zippyshare','mediafire','sendgb','mail.ukr.net','fex.net','ukr.net/attach']
        suspicious_rows = []
        normal_rows = []
        for row in rows:
            url_low = str(row[3] or '').lower()
            fname_low = str(row[1] or '').lower()
            is_susp = (any(d in url_low for d in SUSPICIOUS_DOMAINS) or
                       any(fname_low.endswith(e) for e in ['.zip','.rar','.7z','.exe','.msi','.js','.vbs','.bat','.ps1']))
            (suspicious_rows if is_susp else normal_rows).append(row)
        ordered_rows = suspicious_rows + normal_rows
        out = []
        if br_rows:
            out.append("=== BROWSER DOWNLOADS (raw_fallback_v2) ===")
            _sec = []
            for r in br_rows:
                ts = str(r[0] or 'n/a')[:19]
                path = str(r[1] or r[2] or 'n/a').replace('\\','/')
                url = str(r[3] or 'n/a')[:100]
                fname = str(r[4] or path.split('/')[-1])[:60]
                flag = " *** ПОШТА/FILE-SHARE ***" if any(d in url.lower() for d in SUSPICIOUS_DOMAINS) else ""
                _sec.append(f"{ts} | {fname} | {url}{flag}")
            out.extend(_S.sort_lines(_sec, downloaded=True))
            out.append("")
        if ordered_rows:
            out.append("=== ZONE.IDENTIFIER (filesystem_v2) ===")
        # Групами по 2-3 рядки: файл + HostUrl + Referrer не можна роз'єднувати
        # сортуванням, інакше посилання від'єднаються від своїх файлів.
        _groups = []
        for event_ts, file_name, parent_path, host_url, referrer, fsize in ordered_rows:
            ts = event_ts.isoformat()[:19].replace('T',' ') if event_ts else 'n/a'
            url = str(host_url or '').strip()
            ref = str(referrer or '').strip()
            fname = str(file_name or '').replace(':Zone.Identifier','')
            sz = f" [{fsize}b]" if fsize else ""
            flag = " *** ПІДОЗРІЛИЙ ***" if any(d in url.lower() for d in SUSPICIOUS_DOMAINS) else ""
            _grp = [f"{ts} | {fname}{sz}{flag}", f"  HostUrl: {url}"]
            if ref:
                _grp.append(f"  Referrer: {ref}")
            _groups.append(_grp)
        for _grp in _S.sort_groups(_groups, downloaded=True):
            out.extend(_grp)
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"

_FORENSIC_TOOL_NAMES = frozenset({
    'ftk imager.exe','ftkimager.exe','oxydetective.exe','oxygen forensics.exe',
    'orbital.exe','clamav_orbital.exe','velociraptor.exe','kape.exe','gkape.exe',
    'autopsy.exe','autopsy64.exe','pecmd.exe','lecmd.exe','jlecmd.exe','sbecmd.exe',
    'amcacheparser.exe','appcompatcacheparser.exe','recmd.exe','mftecmd.exe',
    'evtxecmd.exe','rbcmd.exe','srumecmd.exe','wxtcmd.exe','hayabusa.exe',
    'chainsaw.exe','thor.exe','thor64.exe','loki.exe','dumpit.exe','winpmem.exe',
    'magnetprocesscapture.exe','magnetramcapture.exe','encase.exe','winhex.exe',
    'densityscout.exe','capa.exe','tsk_recover.exe','ewfacquire.exe','isobuster.exe',
})
_FORENSIC_PATH_MARKERS = (
    '\\ftk imager', '\\oxygen forensics', '\\cisco\\orbital', '\\velociraptor',
    '\\kape\\', '\\eztools', '\\zimmerman', '\\autopsy', '\\magnet forensics',
    '\\thor', '\\hayabusa', '\\chainsaw',
)
_BENIGN_DOC_NAMES = frozenset({
    'readme.txt','readme.md','readme','readme.rst','license.txt',
    'changelog.txt','copying','copying.txt','third_party_notices.txt',
})
def _is_benign_artifact(file_name, parent_path):
    fn = str(file_name or '').strip().lower(); pp = str(parent_path or '').strip().lower()
    if fn in _FORENSIC_TOOL_NAMES or fn in _BENIGN_DOC_NAMES: return True
    if any(m in pp for m in _FORENSIC_PATH_MARKERS): return True
    if _own_is_own(pp + chr(92) + fn): return True
    # Legit installed-software folders: files INSIDE banking crypto libs (BarsCryptor,
    # DBO Soft, IIT/Avtor, websigner) or analyst tools are software components, NOT
    # attacker artifacts. Systematic false-positive filter (all suspicious sections).
    _BENIGN_SW = ('barscryptor', 'dbo soft', 'dbo_soft', 'websigner', 'iit_avtor',
                  'punto', 'foxit', 'x-ways', 'routerscan', 'greenfish', 'passware',
                  'networkminer', 'cryptolibs')
    if any(m in pp for m in _BENIGN_SW) or any(m in fn for m in _BENIGN_SW): return True
    return False


def _agent_tool_get_suspicious_executables(case_key, limit=int(50 * _ROW_SCALE)):
    """EXE/DLL/VBS/BAT у нестандартних місцях: Public, Temp, AppData, Downloads.
    Критично: виявляє дроппери із ZIP-архівів та відомий малвар по trigger_catalog_v1.

    Рядки в кожній секції впорядковані за важливістю (analysis/salience.py), бо вивід
    ріжеться до 4000 символів: інструменти атакувальника вгорі, службовий шум Windows
    унизу. У межах одного рангу порядок хронологічний, як і був.
    """
    limit = min(int(limit or 50), 200)
    # Load known-malware patterns from trigger catalog (exe/dll/dat/script file names)
    KNOWN_MALWARE = set()
    try:
        with psycopg2.connect(PG_DSN) as _c:
            with _c.cursor() as _cur:
                _cur.execute("""
                    SELECT lower(trigger_text) FROM trigger_catalog_v1
                    WHERE enabled=true
                      AND (
                        lower(trigger_text) ~ '\\.(exe|dll|vbs|bat|ps1|cmd|dat|log|ini)$'
                        OR lower(trigger_text) LIKE '%malware%'
                        OR lower(trigger_text) LIKE '%keylog%'
                        OR lower(trigger_text) LIKE '%mimikatz%'
                        OR lower(trigger_text) LIKE '%rutserv%'
                        OR lower(trigger_text) LIKE '%rfusclient%'
                        OR lower(trigger_text) LIKE '%litemanager%'
                        OR lower(trigger_text) LIKE '%nrserver%'
                        OR lower(trigger_text) LIKE '%ngrok%'
                        OR lower(trigger_text) LIKE '%anydesk%'
                      )
                    LIMIT 300
                """)
                KNOWN_MALWARE = {r[0] for r in _cur.fetchall()}
    except Exception:
        try: conn.rollback()
        except: pass
        pass
    # Fallback hardcoded set if catalog is empty
    if not KNOWN_MALWARE:
        KNOWN_MALWARE = {'msedgex.exe', 'edit.dll', 'start.vbs', 'ng.bat', 'ngrok.exe',
                         'try.exe', 'gcapi.dll', 'anydesk.exe', 'ng.cmd', 'mimikatz.exe',
                         'rutserv.exe', 'rfusclient.exe', 'rutview.exe', 'install.log',
                         'lmnoipserver.exe', 'nrcontrol.exe', 'nrserver.exe',
                         'logs.dat', 'keylogger.exe', 'kl.exe',
                         'rdpwinst.exe', 'rdpwrap.dll', 'rdpwrap.ini'}
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # Priority 1: KNOWN_MALWARE files regardless of path
                cur.execute("""
                    SELECT DISTINCT ON (lower(file_name), coalesce(parent_path,''))
                        event_ts, file_name, parent_path,
                        payload->>'file_size' AS fsize, source_file
                    FROM filesystem_v2
                    WHERE case_key=%s
                      AND lower(file_name) = ANY(%s)
                      AND action = 'MFT'
                    ORDER BY lower(file_name), coalesce(parent_path,''), event_ts ASC
                    LIMIT 50
                """, (case_key, list(KNOWN_MALWARE)))
                malware_rows = cur.fetchall()

                # Priority 2: EXE/DLL/VBS in unusual locations (Public, Users, ProgramData root)
                cur.execute("""
                    SELECT DISTINCT ON (lower(file_name), coalesce(parent_path,''))
                        event_ts, file_name, parent_path,
                        payload->>'file_size' AS fsize, source_file
                    FROM filesystem_v2
                    WHERE case_key=%s
                      AND lower(file_name) ~ '\\.(exe|dll|vbs|bat|ps1|cmd)$'
                      AND lower(coalesce(parent_path,'')) ~ '(\\\\users\\\\public|\\\\programdata|\\\\users\\\\[^\\\\]+\\\\documents|\\\\users\\\\[^\\\\]+\\\\desktop)'
                      AND lower(file_name) != ALL(%s)
                      AND action = 'MFT'
                    ORDER BY lower(file_name), coalesce(parent_path,''), event_ts ASC
                    LIMIT %s
                """, (case_key, list(KNOWN_MALWARE), limit))
                other_rows = cur.fetchall()

                # Priority 3: masqueraded system files (system32.exe outside System32, etc.)
                cur.execute("""
                    SELECT DISTINCT ON (lower(file_name), coalesce(parent_path,''))
                        event_ts, file_name, parent_path,
                        payload->>'file_size' AS fsize, source_file
                    FROM filesystem_v2
                    WHERE case_key=%s
                      AND lower(file_name) IN ('system32.exe','svchost32.exe','lsass32.exe','explorer32.exe','csrss32.exe')
                      AND action = 'MFT'
                    ORDER BY lower(file_name), coalesce(parent_path,''), event_ts ASC
                    LIMIT 20
                """, (case_key,))
                masked_rows = cur.fetchall()

                # Priority 4: keylogger data files in unusual paths
                # Exclude zero-size files (MFT orphan entries) and Windows system paths (WinSxS, servicing, PathUnknown)
                cur.execute("""
                    SELECT DISTINCT ON (lower(file_name), coalesce(parent_path,''))
                        event_ts, file_name, parent_path,
                        payload->>'file_size' AS fsize, source_file
                    FROM filesystem_v2
                    WHERE case_key=%s
                      AND (
                        lower(file_name) LIKE '%%keylog%%'
                        OR lower(file_name) LIKE '%%logs.dat'
                        OR lower(coalesce(parent_path,'')) LIKE '%%\\\\rvc%%'
                        OR lower(coalesce(parent_path,'')) LIKE '%%\\\\keylog%%'
                      )
                      AND action = 'MFT'
                      AND COALESCE((payload->>'file_size')::bigint, 0) > 0
                      AND lower(coalesce(parent_path,'')) NOT LIKE '%%\\\\winsxs%%'
                      AND lower(coalesce(parent_path,'')) NOT LIKE '%%\\\\servicing%%'
                      AND lower(coalesce(parent_path,'')) NOT LIKE '%%pathunknown%%'
                    ORDER BY lower(file_name), coalesce(parent_path,''), event_ts ASC
                    LIMIT 10
                """, (case_key,))
                keylog_rows = cur.fetchall()

                # Priority 5: AppCompatCache / Amcache / Prefetch from program_exec_v2
                # Catches EXE from Temp, Downloads, suspicious paths that were run
                cur.execute(r"""
                    SELECT event_ts, executable_name, full_path, min(source_file) AS source_file
                    FROM program_exec_v2
                    WHERE case_key=%s
                      AND lower(coalesce(full_path,'')||' '||coalesce(executable_name,'')) ~
                          '(\\\\temp\\\\|\\\\downloads?\\\\|\\\\programdata\\\\|\\\\appdata\\\\roaming\\\\|\\\\users\\\\public\\\\|\\\\intel\\\\|\\\\windows\\\\temp\\\\)'
                      AND lower(coalesce(full_path,'')||' '||coalesce(executable_name,'')) ~ '\\.(exe|dll|bat|vbs|ps1|cmd|msi)(\\s|$)'
                    GROUP BY 1, 2, 3
                    ORDER BY event_ts ASC, min(row_id) ASC
                    LIMIT %s
                """, (case_key, min(limit, 60)))
                exec_rows = cur.fetchall()

        malware_rows = [r for r in malware_rows if not _is_benign_artifact(r[1], r[2])]
        other_rows   = [r for r in other_rows   if not _is_benign_artifact(r[1], r[2])]
        masked_rows  = [r for r in masked_rows  if not _is_benign_artifact(r[1], r[2])]
        keylog_rows  = [r for r in keylog_rows  if not _is_benign_artifact(r[1], r[2])]
        exec_rows    = [r for r in exec_rows    if not _is_benign_artifact(r[1], r[2])
                        and not _own_is_own((r[2] or '') + ' ' + (r[1] or ''), ts=r[0], case_key=case_key)]
        out = []
        if keylog_rows:
            out.append("=== !!! КЕЙЛОГЕР АРТЕФАКТИ ===")
            _sec = []
            for r in sorted(keylog_rows, key=lambda x: x[0] or __import__('datetime').datetime.min):
                ts = r[0].isoformat()[:19].replace('T', ' ') if r[0] else 'n/a'
                fsize = f" [{r[3]}b]" if r[3] else ''
                _sec.append(f"{ts} | KEYLOGGER {r[1]}{fsize} | path={r[2]} | src={r[4]}")
            out.extend(_S.sort_lines(_sec))
        if masked_rows:
            out.append("=== !!! МАСКУВАННЯ ПІД СИСТЕМНІ ФАЙЛИ ===")
            _sec = []
            for r in sorted(masked_rows, key=lambda x: x[0] or __import__('datetime').datetime.min):
                ts = r[0].isoformat()[:19].replace('T', ' ') if r[0] else 'n/a'
                fsize = f" [{r[3]}b]" if r[3] else ''
                _sec.append(f"{ts} | MASKED {r[1]}{fsize} | path={r[2]}")
            out.extend(_S.sort_lines(_sec))
        if malware_rows:
            out.append("=== ВІДОМІ MALWARE/TOOL ФАЙЛИ ===")
            _sec = []
            for r in sorted(malware_rows, key=lambda x: x[0] or __import__('datetime').datetime.min):
                ts = r[0].isoformat()[:19].replace('T', ' ') if r[0] else 'n/a'
                fsize = f" [{r[3]}b]" if r[3] else ''
                _sec.append(f"{ts} | !!! {r[1]}{fsize} | path={r[2]}")
            out.extend(_S.sort_lines(_sec))
        if other_rows:
            out.append("=== ПІДОЗРІЛІ EXE/DLL/VBS В НЕСТАНДАРТНИХ МІСЦЯХ ===")
            _sec = []
            for r in sorted(other_rows, key=lambda x: x[0] or __import__('datetime').datetime.min):
                ts = r[0].isoformat()[:19].replace('T', ' ') if r[0] else 'n/a'
                fsize = f" [{r[3]}b]" if r[3] else ''
                _sec.append(f"{ts} | {r[1]}{fsize} | path={r[2]}")
            out.extend(_S.sort_lines(_sec))
        if exec_rows:
            out.append("=== AppCompatCache/Amcache/Prefetch — EXE З ПІДОЗРІЛИХ ШЛЯХІВ ===")
            _sec = []
            for r in sorted(exec_rows, key=lambda x: x[0] or __import__('datetime').datetime.min):
                ts = r[0].isoformat()[:19].replace('T', ' ') if r[0] else 'n/a'
                path = r[2] or r[1] or ''
                _sec.append(f"{ts} | {path} | src={r[3]}")
            out.extend(_S.sort_lines(_sec))
        if not out:
            return "Підозрілих виконуваних файлів не знайдено."
        return '\n'.join(out)
    except Exception as e:
        import traceback as _tb
        _log.error(f"[get_suspicious_executables] ERROR: {e}\n{_tb.format_exc()}")
        return f"ERROR: {e}"

def _agent_tool_get_srum_network_traffic(case_key, limit=int(30 * _ROW_SCALE)):
    """Мережева активність по SRUM: скільки байт відправив/отримав кожен процес по днях.
    Виявляє C2-трафік (RMS, LiteManager, ngrok) і великі exfil/download потоки.
    Поля payload: bytes_tx/bytes_sent (відправлено), bytes_rx/bytes_recv (отримано), profile/app_id (процес).
    """
    limit = min(int(limit or 30), 100)
    RAT_KEYWORDS = {'rms', 'rutserv', 'rfusclient', 'litemanager', 'nrserver', 'nrcontrol',
                    'lmnoip', 'ngrok', 'anydesk', 'teamviewer', 'ammyy', 'radmin', 'remotemanip'}
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # Detect which byte field names exist in this case's payload
                cur.execute("""
                    SELECT DISTINCT jsonb_object_keys(payload) FROM srum_v2 WHERE case_key=%s LIMIT 50
                """, (case_key,))
                all_keys = {r[0] for r in cur.fetchall()}

                if not all_keys:
                    return "SRUM: даних немає для цього кейсу."

                # Determine field names
                sent_field = 'bytes_tx' if 'bytes_tx' in all_keys else ('bytes_sent' if 'bytes_sent' in all_keys else None)
                recv_field = 'bytes_rx' if 'bytes_rx' in all_keys else ('bytes_recv' if 'bytes_recv' in all_keys else None)
                app_field  = 'profile' if 'profile' in all_keys else ('app_id' if 'app_id' in all_keys else None)

                if sent_field and recv_field:
                    # Aggregate by day + app (if app_field exists)
                    if app_field:
                        cur.execute(f"""
                            SELECT date_trunc('day', event_ts)::date AS day,
                                   payload->%s AS app,
                                   SUM((payload->>%s)::bigint) AS sent,
                                   SUM((payload->>%s)::bigint) AS recv
                            FROM srum_v2
                            WHERE case_key=%s
                              AND payload->>%s IS NOT NULL
                              AND ((payload->>%s)::bigint > 0 OR (payload->>%s)::bigint > 0)
                            GROUP BY day, app
                            ORDER BY (SUM((payload->>%s)::bigint)+SUM((payload->>%s)::bigint)) DESC
                            LIMIT %s
                        """, (app_field, sent_field, recv_field, case_key, app_field, sent_field, recv_field, sent_field, recv_field, limit))
                    else:
                        cur.execute(f"""
                            SELECT date_trunc('day', event_ts)::date AS day,
                                   NULL AS app,
                                   SUM((payload->>%s)::bigint) AS sent,
                                   SUM((payload->>%s)::bigint) AS recv
                            FROM srum_v2
                            WHERE case_key=%s
                              AND ((payload->>%s)::bigint > 0 OR (payload->>%s)::bigint > 0)
                            GROUP BY day
                            ORDER BY (SUM((payload->>%s)::bigint)+SUM((payload->>%s)::bigint)) DESC
                            LIMIT %s
                        """, (sent_field, recv_field, case_key, sent_field, recv_field, sent_field, recv_field, limit))
                    rows = cur.fetchall()
                else:
                    return f"SRUM: невідома структура payload. Поля: {', '.join(sorted(all_keys))}"

        if not rows:
            return "SRUM мережева активність: трафік 0 або даних немає."

        has_app = any(r[1] for r in rows)
        out = ["=== SRUM МЕРЕЖЕВА АКТИВНІСТЬ ==="]
        if not has_app:
            out.append("(назви процесів не збережені — показано денні totals)")
        out.append(f"{'День':<12} {'Sent MB':>9} {'Recv MB':>9} {'Total MB':>9} {'Процес':<50}")
        out.append('-' * 95)

        suspicious = []
        for r in rows:
            day = str(r[0])
            app = (r[1] or '(all)').strip()
            sent_mb = round((int(r[2]) if r[2] else 0) / 1048576, 2)
            recv_mb = round((int(r[3]) if r[3] else 0) / 1048576, 2)
            total_mb = sent_mb + recv_mb
            app_lower = app.lower()
            is_rat = any(k in app_lower for k in RAT_KEYWORDS)
            flag = ' !!!' if is_rat else ''
            out.append(f"{day:<12} {sent_mb:>9.2f} {recv_mb:>9.2f} {total_mb:>9.2f} {app[:50]}{flag}")
            if is_rat:
                suspicious.append((app, total_mb, day))

        if suspicious:
            out.append('')
            out.append("=== !!! ПІДОЗРІЛІ ПРОЦЕСИ (RAT/TUNNEL) ===")
            for app, total_mb, day in suspicious:
                out.append(f"  {app} — {total_mb:.2f} MB ({day})")

        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"


def _agent_tool_get_context_window(case_key, timestamp, hours_before=6, hours_after=6):
    """Всі події ±N годин навколо вказаного timestamp з усіх таблиць.
    Критично для реконструкції attack chain: що було ДО і ПІСЛЯ підозрілої події.
    """
    import re as _re
    m = _re.search(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2})', str(timestamp or ''))
    if not m:
        return "ERROR: вкажи timestamp у форматі YYYY-MM-DD HH:MM"
    ts_str = m.group(1).replace('T', ' ')
    try:
        hours_before = float(hours_before or 6)
        hours_after  = float(hours_after  or 6)
    except Exception:
        hours_before = hours_after = 6.0

    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                out = [f"=== КОНТЕКСТ ±{hours_before}h/{hours_after}h НАВКОЛО {ts_str} ==="]

                # event_logs_v2
                cur.execute("""
                    SELECT event_ts, event_id, channel, process_name, command_line, remote_host, source_file
                    FROM event_logs_v2
                    WHERE case_key=%s
                      AND event_ts BETWEEN %s::timestamptz - make_interval(hours=>(%s)::int)
                                      AND %s::timestamptz + make_interval(hours=>(%s)::int)
                    ORDER BY event_ts ASC LIMIT 30
                """, (case_key, ts_str, hours_before, ts_str, hours_after))
                rows = cur.fetchall()
                if rows:
                    out.append(f"\n[event_logs_v2] {len(rows)} подій:")
                    for r in rows:
                        ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                        out.append(f"  {ts} | EID={r[1]} | {(r[2] or '')[:40]} | proc={r[3] or ''} | cmd={str(r[4] or '')[:80]} | host={r[5] or ''}")

                # filesystem_v2
                cur.execute("""
                    SELECT event_ts, file_name, parent_path, payload->>'file_size', source_file
                    FROM filesystem_v2
                    WHERE case_key=%s
                      AND event_ts BETWEEN %s::timestamptz - make_interval(hours=>(%s)::int)
                                      AND %s::timestamptz + make_interval(hours=>(%s)::int)
                    ORDER BY event_ts ASC LIMIT 20
                """, (case_key, ts_str, hours_before, ts_str, hours_after))
                rows = cur.fetchall()
                if rows:
                    out.append(f"\n[filesystem_v2] {len(rows)} файлів:")
                    for r in rows:
                        ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                        out.append(f"  {ts} | {r[1]} | {r[2]} | sz={r[3]} | src={r[4]}")

                # program_exec_v2
                cur.execute("""
                    SELECT event_ts, executable_name, full_path,
                           min(hash_sha1) AS hash_sha1, min(source_file) AS source_file
                    FROM program_exec_v2
                    WHERE case_key=%s
                      AND event_ts BETWEEN %s::timestamptz - make_interval(hours=>(%s)::int)
                                      AND %s::timestamptz + make_interval(hours=>(%s)::int)
                    GROUP BY 1, 2, 3
                    ORDER BY event_ts ASC, min(row_id) ASC LIMIT 20
                """, (case_key, ts_str, hours_before, ts_str, hours_after))
                rows = cur.fetchall()
                if rows:
                    out.append(f"\n[program_exec_v2] {len(rows)} спостережень (унікальні файл+шлях+час):")
                    for r in rows:
                        ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                        out.append(f"  {ts} | {r[1]} | {str(r[2] or '')[:80]} | sha1={r[3] or ''}")

                # tool_alerts_v2
                cur.execute("""
                    SELECT event_ts, severity, rule, details, source_file
                    FROM tool_alerts_v2
                    WHERE case_key=%s
                      AND event_ts BETWEEN %s::timestamptz - make_interval(hours=>(%s)::int)
                                      AND %s::timestamptz + make_interval(hours=>(%s)::int)
                    ORDER BY event_ts ASC LIMIT 15
                """, (case_key, ts_str, hours_before, ts_str, hours_after))
                rows = cur.fetchall()
                if rows:
                    out.append(f"\n[tool_alerts_v2] {len(rows)} алертів:")
                    for r in rows:
                        ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                        out.append(f"  {ts} | {r[1]} | {r[2]} | {str(r[3] or '')[:100]}")

                if len(out) == 1:
                    return f"Подій у вікні ±{hours_before}h/{hours_after}h навколо {ts_str} не знайдено."
                return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"


def _agent_tool_pivot(case_key, ioc_value, limit=int(30 * _ROW_SCALE)):
    """Pivot по IOC: шукає IP/хеш/домен/ім'я файлу в УСІХ таблицях.
    Використовуй коли знайшов підозрілий артефакт — pivot покаже всі пов'язані сліди.
    """
    val = str(ioc_value or '').strip()
    if len(val) < 3:
        return "ERROR: ioc_value занадто короткий"
    limit = min(int(limit or 30), 100)
    pat = f"%{val}%"

    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                out = [f"=== PIVOT: {val!r} — пошук по всіх таблицях ==="]

                # event_logs_v2
                cur.execute("""
                    SELECT event_ts, event_id, process_name, command_line, remote_host, source_file
                    FROM event_logs_v2
                    WHERE case_key=%s AND (
                        coalesce(command_line,'') ILIKE %s OR coalesce(process_name,'') ILIKE %s OR
                        coalesce(remote_host,'') ILIKE %s OR payload::text ILIKE %s
                    ) ORDER BY event_ts ASC LIMIT %s
                """, (case_key, pat, pat, pat, pat, limit))
                rows = cur.fetchall()
                if rows:
                    out.append(f"\n[event_logs_v2] {len(rows)} hits:")
                    for r in rows:
                        ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                        out.append(f"  {ts} EID={r[1]} proc={r[2]} cmd={str(r[3] or '')[:100]} host={r[4] or ''} [{r[5]}]")

                # filesystem_v2
                cur.execute("""
                    SELECT event_ts, file_name, parent_path, payload->>'file_size', source_file
                    FROM filesystem_v2
                    WHERE case_key=%s AND (
                        coalesce(file_name,'') ILIKE %s OR coalesce(parent_path,'') ILIKE %s OR payload::text ILIKE %s
                    ) ORDER BY event_ts ASC LIMIT %s
                """, (case_key, pat, pat, pat, limit))
                rows = cur.fetchall()
                if rows:
                    out.append(f"\n[filesystem_v2] {len(rows)} hits:")
                    for r in rows:
                        ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                        out.append(f"  {ts} {r[1]} path={r[2]} sz={r[3]} [{r[4]}]")

                # program_exec_v2
                cur.execute("""
                    SELECT event_ts, executable_name, full_path,
                           min(hash_sha1) AS hash_sha1, min(source_file) AS source_file
                    FROM program_exec_v2
                    WHERE case_key=%s AND (
                        coalesce(executable_name,'') ILIKE %s OR coalesce(full_path,'') ILIKE %s OR
                        coalesce(hash_sha1,'') ILIKE %s OR payload::text ILIKE %s
                    )
                    GROUP BY 1, 2, 3
                    ORDER BY event_ts ASC, min(row_id) ASC LIMIT %s
                """, (case_key, pat, pat, pat, pat, limit))
                rows = cur.fetchall()
                if rows:
                    out.append(f"\n[program_exec_v2] {len(rows)} спостережень (унікальні файл+шлях+час):")
                    for r in rows:
                        ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                        out.append(f"  {ts} {r[1]} path={str(r[2] or '')[:80]} sha1={r[3] or ''} [{r[4]}]")

                # raw_fallback_v2
                cur.execute("""
                    SELECT source_file, payload::text FROM raw_fallback_v2
                    WHERE case_key=%s AND payload::text ILIKE %s
                    ORDER BY row_id ASC LIMIT %s
                """, (case_key, pat, limit))
                rows = cur.fetchall()
                if rows:
                    out.append(f"\n[raw_fallback_v2] {len(rows)} hits:")
                    for r in rows:
                        txt = str(r[1] or '')
                        idx = txt.lower().find(val.lower())
                        if idx >= 0:
                            start = max(0, idx-50); end = min(len(txt), idx+len(val)+100)
                            ctx = txt[start:end]
                        else:
                            ctx = txt[:150]
                        out.append(f"  [{r[0]}] ...{ctx}...")

                # tool_alerts_v2
                cur.execute("""
                    SELECT event_ts, severity, rule, details, source_file
                    FROM tool_alerts_v2
                    WHERE case_key=%s AND (
                        coalesce(rule,'') ILIKE %s OR coalesce(details,'') ILIKE %s OR
                        coalesce(ioc_value,'') ILIKE %s OR payload::text ILIKE %s
                    ) ORDER BY event_ts ASC LIMIT %s
                """, (case_key, pat, pat, pat, pat, limit))
                rows = cur.fetchall()
                if rows:
                    out.append(f"\n[tool_alerts_v2] {len(rows)} hits:")
                    for r in rows:
                        ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                        out.append(f"  {ts} [{r[1]}] {r[2]} | {str(r[3] or '')[:120]}")

                # Cross-case search. All three limits below sat on unordered queries,
                # so the cases that survived were whatever the planner returned first and
                # there were too few of them: measured against the live base, `powershell`
                # qualifies on 10 other cases in event_logs and 10 in program_exec and 5
                # of each were shown, `anydesk` on 7 program_exec cases and 5 were shown,
                # `rdp` on 10 event_log cases and 5 were shown. The trigger query also
                # SELECTed artifact_family and snippet that nothing ever read, and the
                # DISTINCT over them multiplied 5 cases into 31 rows that then had to fit
                # under LIMIT 10. Order by case_key so one pivot always yields one answer,
                # lift the cap above the whole case library, and say so if it is still hit.
                cur.execute("""
                    SELECT DISTINCT case_key, trigger
                    FROM case_trigger_hits_v2
                    WHERE case_key != %s AND (lower(trigger) ILIKE %s OR lower(snippet) ILIKE %s)
                    ORDER BY case_key, trigger LIMIT %s
                """, (case_key, pat, pat, _CROSS_CASE_LIMIT))
                other = cur.fetchall()
                _cross_capped = len(other) >= _CROSS_CASE_LIMIT
                cross_hits = {}
                for r in other:
                    cross_hits.setdefault(r[0], []).append(f'trigger:{r[1]}')
                # Cross-case search: event_logs + program_exec
                cur.execute("""
                    SELECT DISTINCT case_key FROM event_logs_v2
                    WHERE case_key!=%s AND (coalesce(command_line,'') ILIKE %s OR coalesce(remote_host,'') ILIKE %s OR payload::text ILIKE %s)
                    ORDER BY case_key LIMIT %s
                """, (case_key, pat, pat, pat, _CROSS_CASE_LIMIT))
                _rows = cur.fetchall()
                _cross_capped = _cross_capped or len(_rows) >= _CROSS_CASE_LIMIT
                for (ck,) in _rows:
                    cross_hits.setdefault(ck, []).append('event_logs')
                cur.execute("""
                    SELECT DISTINCT case_key FROM program_exec_v2
                    WHERE case_key!=%s AND (coalesce(full_path,'') ILIKE %s OR coalesce(hash_sha1,'') ILIKE %s)
                    ORDER BY case_key LIMIT %s
                """, (case_key, pat, pat, _CROSS_CASE_LIMIT))
                _rows = cur.fetchall()
                _cross_capped = _cross_capped or len(_rows) >= _CROSS_CASE_LIMIT
                for (ck,) in _rows:
                    cross_hits.setdefault(ck, []).append('program_exec')
                if cross_hits:
                    # Built here but printed at the TOP: chat.py cuts this tool at 4000
                    # chars, and measured on the live base the block began at char 4193
                    # for anydesk, 11675 for powershell and 22613 for rdp - the loudest
                    # signal the pivot produces never once reached the model.
                    _cross = [f"\n[!!! ЗНАЙДЕНО В ІНШИХ КЕЙСАХ ({len(cross_hits)}) — можлива спільна атака]"]
                    if _cross_capped:
                        _cross.append(f"  (перелік обрізано на {_CROSS_CASE_LIMIT} — справ може бути більше)")
                    for ck in sorted(cross_hits):
                        _cross.append(f"  {ck}: {', '.join(dict.fromkeys(cross_hits[ck]))}")
                    out[1:1] = _cross

                if len(out) == 1:
                    return f"Pivot {val!r}: нічого не знайдено в жодній таблиці."
                return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"


def _agent_tool_get_log_gaps(case_key, min_gap_hours=2):
    """Знаходить розриви (gaps) в хронології event_logs — індикатор очищення логів.
    Розрив > N годин при наявній активності до/після = підозрілий.
    Також перевіряє Event ID 1102/104 (audit log cleared).
    """
    min_gap = float(min_gap_hours or 2)
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                out = []

                # Check explicit log clearing events
                cur.execute("""
                    SELECT event_ts, event_id, channel, process_name, source_file
                    FROM event_logs_v2
                    WHERE case_key=%s AND (
                          (event_id=1102 AND channel ILIKE %s) OR
                          (event_id=517  AND channel ILIKE %s) OR
                          (event_id=104  AND (channel ILIKE %s OR channel ILIKE %s)
                                         AND coalesce(provider,'') ILIKE %s)
                      )
                    ORDER BY event_ts ASC
                """, (case_key, '%Security%', '%Security%', '%System%', '%Eventlog%', '%Eventlog%'))
                # EID 104 is also a smart-card reader driver message (WudfUsbccidDriver, 388 rows on
                # case_50): only the Eventlog provider's 104 is «log cleared» (detector rule since 07.2026)
                clears = cur.fetchall()
                if clears:
                    out.append(f"=== !!! ОЧИЩЕННЯ ЖУРНАЛУ ПОДІЙ ({len(clears)} events) ===")
                    for r in clears:
                        ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                        out.append(f"  {ts} | EID={r[1]} | {r[2]} | {r[3] or ''} | [{r[4]}]")

                # Find chronological gaps
                cur.execute("""
                    SELECT event_ts FROM event_logs_v2
                    WHERE case_key=%s AND event_ts IS NOT NULL
                    ORDER BY event_ts ASC
                """, (case_key,))
                times = [r[0] for r in cur.fetchall()]

                gaps = []
                for i in range(1, len(times)):
                    gap_h = (times[i] - times[i-1]).total_seconds() / 3600
                    if gap_h >= min_gap:
                        gaps.append((times[i-1], times[i], gap_h))

                if gaps:
                    out.append(f"\n=== РОЗРИВИ В ХРОНОЛОГІЇ (>{min_gap}h) ===")
                    out.append(f"{'Від':<22} {'До':<22} {'Розрив'}")
                    out.append('-' * 55)
                    for g_from, g_to, g_h in sorted(gaps, key=lambda x: -x[2])[:20]:
                        out.append(f"  {g_from.isoformat()[:19]}  →  {g_to.isoformat()[:19]}  ({g_h:.1f}h)")

                    # Flag gaps that overlap with known trigger hits
                    cur.execute("""
                        SELECT min(event_ts), max(event_ts) FROM case_trigger_hits_v2
                        WHERE case_key=%s AND event_ts IS NOT NULL
                    """, (case_key,))
                    hit_range = cur.fetchone()
                    if hit_range and hit_range[0]:
                        incident_start = hit_range[0]
                        incident_end   = hit_range[1]
                        incident_gaps  = [g for g in gaps if g[0] >= incident_start and g[1] <= incident_end]
                        if incident_gaps:
                            out.append(f"\n  !!! {len(incident_gaps)} розривів всередині вікна інциденту — можливе видалення слідів!")

                if not out:
                    out.append(f"Розривів >{min_gap}h і очищення логів не виявлено.")

                return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"


def _agent_tool_get_attack_phases(case_key):
    """Кластеризація тригерів по часових фазах атаки (MITRE ATT&CK).
    Розбиває хронологію на фази: Initial Access → Execution → Persistence → C2 → Exfil.
    """
    PHASE_LABELS = {
        'Initial Access':  {'download','phish','browser','pixeldrain','swisstransfer','zone.identifier','rar','zip','archive','doc','xls'},
        'Execution':       {'.exe','.vbs','.bat','.ps1','.cmd','powershell','wscript','cscript','mshta','rundll32','regsvr32','cmd.exe'},
        'Persistence':     {'registry','run key','startup','service','scheduled','task','asep','autorun','lnk'},
        'C2 / RAT':        {'rutserv','rfusclient','remote manipulator','ngrok','anydesk','litemanager','nrserver','nrcontrol','teamviewer','rdp','tunnel'},
        'Collection':      {'keylog','logs.dat','rvc','screenshot','clipboard','credential','password','chrome','browser'},
        'Exfiltration':    {'swisstransfer','transfer.sh','upload','mega.nz','dropbox','ftp','sftp','exfil','send'},
        'Defense Evasion': {'event cleared','1102','tamper','delete log','wevtutil','clear','disable'},
    }
    PHASE_GAP_HOURS = 3

    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT DISTINCT ON (trigger, artifact_family)
                        trigger, artifact_family, event_ts, snippet
                    FROM case_trigger_hits_v2
                    WHERE case_key=%s AND event_ts IS NOT NULL
                    ORDER BY trigger, artifact_family, event_ts ASC
                """, (case_key,))
                hits = sorted(cur.fetchall(), key=lambda r: r[2])

        if not hits:
            return "Тригерів з timestamp не знайдено — запустіть trigger scan."

        # Build time clusters
        clusters = []
        cur_cluster = {'start': hits[0][2], 'end': hits[0][2], 'hits': [hits[0]]}
        for h in hits[1:]:
            ts = h[2]
            gap_h = (ts - cur_cluster['end']).total_seconds() / 3600
            if gap_h > PHASE_GAP_HOURS:
                clusters.append(cur_cluster)
                cur_cluster = {'start': ts, 'end': ts, 'hits': [h]}
            else:
                cur_cluster['end'] = ts
                cur_cluster['hits'].append(h)
        clusters.append(cur_cluster)

        out = [f"=== ФАЗИ АТАКИ ({len(clusters)} кластерів, gap>{PHASE_GAP_HOURS}h) ===\n"]
        for i, cl in enumerate(clusters, 1):
            combined = ' '.join(
                (h[0] + ' ' + (h[3] or '')).lower() for h in cl['hits']
            )
            matched = [lbl for lbl, kw in PHASE_LABELS.items() if any(k in combined for k in kw)]
            phase_label = ' + '.join(matched) if matched else 'Unknown Activity'

            dur_h = (cl['end'] - cl['start']).total_seconds() / 3600
            out.append(f"── Фаза {i}: {phase_label}")
            out.append(f"   Час: {cl['start'].isoformat()[:19]} → {cl['end'].isoformat()[:19]} ({dur_h:.1f}h)")
            out.append(f"   Тригерів: {len(cl['hits'])}")

            # Show top 5 triggers in this phase
            trig_summary = {}
            for h in cl['hits']:
                trig_summary[h[0]] = trig_summary.get(h[0], 0) + 1
            top_trigs = sorted(trig_summary.items(), key=lambda x: -x[1])[:5]
            out.append(f"   Ключові: {', '.join(f'{t}({c})' for t,c in top_trigs)}")

            # Show best snippet
            snips = [h[3] for h in cl['hits'] if h[3] and len(h[3]) > 20]
            if snips:
                out.append(f"   Контекст: {snips[0][:200]}")
            out.append('')

        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"


def _pd1_clean(pd1):
    """Strip PowerShell script boilerplate (# Copyright, :: ====, separators, MS
    headers) from a PayloadData1 blob so it does not pollute timeline / IOC output."""
    if not pd1:
        return ''
    keep = []
    for _l in str(pd1).replace(chr(13), chr(10)).split(chr(10)):
        _l = _l.strip()
        if not _l:
            continue
        _ll = _l.lower()
        if _l[0] in '#=:':
            continue
        if 'copyright' in _ll or 'all rights reserved' in _ll or 'microsoft corporation' in _ll:
            continue
        if len(_l) >= 6 and all(_c in '=-_:.# ' for _c in _l):
            continue
        keep.append(_l)
    return ' '.join(keep).strip()


def _agent_tool_get_full_timeline(case_key, limit=int(60 * _ROW_SCALE)):
    """Збирає повну хронологію атаки з усіх таблиць — program_exec, event_logs, downloads, registry, triggers.
    Автоматично визначає дату початку атаки на основі перших тригер-хітів."""
    import re as _rz
    events = []
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # Determine attack period from case_key date (format: DD_MM_YYYY_...)
                import datetime as _dt, re as _re_ck
                atk_start = '2025-01-01'  # default fallback
                m_ck = _re_ck.match(r'^(\d{2})_(\d{2})_(\d{4})', case_key)
                if m_ck:
                    try:
                        ck_date = _dt.date(int(m_ck.group(3)), int(m_ck.group(2)), int(m_ck.group(1)))
                        # Go back 6 months from case creation date to capture the attack
                        atk_start = (ck_date - _dt.timedelta(days=180)).strftime('%Y-%m-%d')
                    except ValueError:
                        pass
                # Also validate using actual trigger data: if attack triggers exist in 2026, use 2026-01-01
                cur.execute("""
                    SELECT MIN(event_ts) FROM case_trigger_hits_v2
                    WHERE case_key=%s AND event_ts >= '2026-01-01' AND event_ts < '2030-01-01'
                      AND trigger NOT IN ('hosturl=','referrerurl=','word.exe','excel.exe','mspaint.exe')
                """, (case_key,))
                trigger_2026 = cur.fetchone()[0]
                if trigger_2026:
                    atk_start = (trigger_2026 - _dt.timedelta(days=30)).strftime('%Y-%m-%d')

                # 1. Suspicious executables — filter by SUSPICIOUS PATHS (paths stored lowercase)
                # Malware runs from: temp, downloads, public, appdata\roaming, root C:\, programdata
                # Exclude Chrome/Edge updaters (C:\WINDOWS\SystemTemp\, Microsoft\Temp\)
                cur.execute("""
                    SELECT event_ts, executable_name, full_path, min(source_file) AS source_file
                    FROM program_exec_v2
                    WHERE case_key=%s AND event_ts >= %s
                      AND (
                        lower(full_path) LIKE '%%temp%%'
                        OR lower(full_path) LIKE '%%downloads%%'
                        OR lower(full_path) LIKE '%%public%%'
                        OR lower(full_path) LIKE '%%appdata%%roaming%%'
                        OR lower(full_path) LIKE '%%programdata%%'
                        OR lower(executable_name) ~ '(rustdesk|psexec|anydesk|ngrok|rutserv|rfusclient|rdpwinst|mimikatz|cobalt|meterpreter|nltest|procdump|rclone|litemanager|teamviewer)'
                        OR lower(full_path) ~ '^[a-z]:\\\\[^\\\\]+\\.exe$'
                      )
                      AND lower(full_path) NOT LIKE '%%systemtemp%%'
                      AND lower(full_path) NOT LIKE '%%googleupdater%%'
                      AND lower(full_path) NOT LIKE '%%updater_chrome%%'
                      AND lower(full_path) NOT LIKE '%%microsoftedgeupdate%%'
                      AND lower(full_path) NOT LIKE '%%.opera%%'
                      AND lower(full_path) NOT LIKE '%%windows defender%%'
                      AND executable_name NOT ILIKE '%%websigner%%'
                      AND executable_name NOT ILIKE '%%BarsCryptor%%'
                      AND executable_name NOT ILIKE '%%EUSign%%'
                      AND executable_name NOT ILIKE '%%dismhost%%'
                      AND executable_name NOT ILIKE '%%WhatsApp%%'
                      AND executable_name NOT ILIKE '%%updater%%'
                      AND executable_name NOT ILIKE '%%MpCmdRun%%'
                      AND executable_name NOT ILIKE '%%NisSrv%%'
                      AND executable_name NOT ILIKE '%%MsMpEng%%'
                      AND executable_name NOT ILIKE '%%MpDefender%%'
                      AND executable_name NOT ILIKE '%%chimera%%'
                      AND executable_name NOT ILIKE '%%qualcommedl%%'
                      AND executable_name NOT ILIKE '%%yihome%%'
                      AND executable_name NOT ILIKE '%%bittorrent%%'
                      AND executable_name NOT ILIKE '%%utorrent%%'
                      AND executable_name NOT ILIKE '%%qbittorrent%%'
                    GROUP BY 1, 2, 3
                    ORDER BY event_ts ASC, min(row_id) ASC LIMIT 50
                """, (case_key, atk_start))
                for row in cur.fetchall():
                    ts, exe, path, src = row
                    sfam = 'Prefetch' if 'PECmd' in (src or '') else ('Amcache' if 'Amcache' in (src or '') else 'Shimcache')
                    events.append((ts, f'program_exec_v2/{sfam}', f'Запуск: {exe}', (path or '')[:120]))

                # RAT/attack tools by NAME — ALWAYS include (key evidence; must not be
                # buried by benign downloads + the ASC LIMIT. RustDesk/psexec were in
                # Program Files/scripts + beyond pos 50 -> the whole attack was missed).
                cur.execute("""
                    SELECT event_ts, executable_name, full_path, min(source_file) AS source_file
                    FROM program_exec_v2 WHERE case_key=%s
                      AND lower(executable_name) ~ '(rustdesk|psexec|anydesk|ngrok|rutserv|rfusclient|rdpwinst|mimikatz|cobalt|meterpreter|nltest|procdump|rclone|litemanager|teamviewer|atera|screenconnect)'
                    GROUP BY 1, 2, 3
                    ORDER BY event_ts DESC, min(row_id) ASC LIMIT 25
                """, (case_key,))
                for row in cur.fetchall():
                    ts, exe, path, src = row
                    events.append((ts, 'program_exec_v2/RAT', f'⚠️ Інструмент віддаленого доступу/атаки: {exe}', (path or '')[:120]))

                # 2. Key Windows Event IDs (filtered)
                EID_DESC = {
                    4624: 'Успішний вхід', 4625: 'Невдалий вхід', 4720: 'Новий аккаунт',
                    4726: 'Видалення аккаунту', 4732: 'Додано до групи', 4698: 'Завдання у планувальнику',
                    4697: 'Нова служба', 7045: 'Нова служба (SCM)', 1102: 'Логи очищено',
                    104: 'Логи очищено (System)', 5001: 'Defender вимкнено', 5007: 'Конфіг Defender змінено',
                    1116: 'Defender: виявлено', 1117: 'Defender: дія', 1011: 'Defender: malware quarantine',
                    4688: 'Запуск процесу (EID 4688)', 4104: 'PowerShell скрипт', 4648: 'Явний вхід',
                    4719: 'Аудит змінено', 4616: 'Час системи змінено',
                }
                cur.execute("""
                    SELECT event_ts, event_id, target_user, logon_type,
                           payload->>'PayloadData1', remote_host, source_file
                    FROM event_logs_v2
                    WHERE case_key=%s AND event_ts >= %s
                      AND (
                          (event_id IN (4625,4720,4726,4732,4698,4697,4688,4719,4616) AND channel ILIKE '%%Security%%')
                          OR (event_id=7045 AND channel ILIKE '%%System%%')
                          OR (event_id=1102 AND (channel ILIKE '%%Security%%' OR channel ILIKE '%%RDPClient%%'))
                          OR (event_id=104  AND (channel ILIKE '%%System%%' OR channel ILIKE '%%Eventlog%%'))
                          OR (event_id IN (5001,5007,1116,1117,1011) AND channel ILIKE '%%Windows Defender%%')
                          OR (event_id=4104 AND channel ILIKE '%%PowerShell%%')
                      )
                      AND NOT (event_id=4688 AND (
                               LOWER(COALESCE(process_name,'')) LIKE '%%system32%%'
                               OR TRIM(LOWER(COALESCE(process_name,''))) IN ('registry','')
                               OR process_name IS NULL))
                    ORDER BY event_ts ASC LIMIT 80
                """, (case_key, atk_start))
                for row in cur.fetchall():
                    ts, eid, user, ltype, pd1, rhost, src = row
                    # Skip machine accounts (end with $) for non-critical EIDs
                    if user and user.endswith('$') and eid not in (4720, 4732, 4726):
                        continue
                    # EID 1011: skip if no malware name
                    if eid == 1011 and not pd1:
                        continue
                    # EID 1102 in RDPClient channel = RDP connection (not log clear!)
                    if eid == 1102 and 'RDPClient' in (src or ''):
                        if not pd1:  # no IP = skip noise
                            continue
                        desc = 'RDP з\'єднання (C2)'
                        det = [pd1[:100]] if pd1 else []
                        events.append((ts, f'event_logs_v2/EID 1102 RDPClient', desc, '; '.join(det)[:120]))
                        continue
                    # EID 5007 (Defender config): only attack-relevant changes (exclusions, disable)
                    if eid == 5007:
                        pd1_low = (pd1 or '').lower()
                        if not any(k in pd1_low for k in ('exclusion', 'disable', 'tamper', 'behavior', 'realtime', 'ioav')):
                            continue  # skip hash/ECS config noise
                        det_val = (pd1 or '')[:80]
                        events.append((ts, f'event_logs_v2/EID 5007', 'Defender bypass/exclusion', det_val))
                        continue
                    desc = EID_DESC.get(eid, f'EID {eid}')
                    det = []
                    if user and not user.endswith('$'): det.append(f'user={user}')
                    _pdc = _pd1_clean(pd1)
                    if _pdc: det.append(_pdc[:80])
                    if rhost and rhost not in ('-:-', '127.0.0.1', '::1'):
                        det.append(f'from={rhost}')
                    events.append((ts, f'event_logs_v2/EID {eid}', desc, '; '.join(det)[:120]))

                # 2b. Successful RDP logons (logon_type='10') only
                cur.execute("""
                    SELECT event_ts, target_user, remote_host, payload->>'PayloadData1'
                    FROM event_logs_v2
                    WHERE case_key=%s AND event_ts >= %s AND event_id=4624 AND logon_type='10'
                    ORDER BY event_ts ASC LIMIT 20
                """, (case_key, atk_start))
                for row in cur.fetchall():
                    ts, user, rhost, pd1 = row
                    det = []
                    if user: det.append(f'user={user}')
                    if rhost and rhost not in ('-:-', '127.0.0.1'): det.append(f'від={rhost}')
                    events.append((ts, 'event_logs_v2/EID 4624', 'RDP вхід (type=10)', '; '.join(det)[:100]))

                # 3. Browser downloads (suspicious)
                cur.execute("""
                    SELECT (payload->>'end_time')::timestamptz, payload->>'filename',
                           payload->>'target_path', payload->>'url'
                    FROM raw_fallback_v2
                    WHERE case_key=%s AND parser_family='browser_downloads'
                      AND payload->>'end_time' >= %s
                      AND (payload->>'target_path' ILIKE '%%.exe'
                           OR payload->>'target_path' ILIKE '%%.zip'
                           OR payload->>'target_path' ILIKE '%%.rar'
                           OR payload->>'target_path' ILIKE '%%.7z'
                           OR payload->>'url' ~* '(swisstransfer|pixeldrain|mega|ukr\\.net|fex\\.net|wetransfer|gofile|transfer\\.sh)')
                    ORDER BY payload->>'end_time' ASC LIMIT 20
                """, (case_key, atk_start))
                for row in cur.fetchall():
                    ts, fname, tpath, url = row
                    if ts:
                        events.append((ts, 'browser_downloads', f'Завантаження: {fname or tpath or "?"}',
                                       f'url={url[:80] if url else ""}'))

                # 4. Zone.Identifier
                cur.execute("""
                    SELECT event_ts, file_name, payload->>'zone_id'
                    FROM filesystem_v2
                    WHERE case_key=%s AND extension='identifier'
                      AND payload->>'zone_id' ILIKE '%%HostUrl%%'
                      AND event_ts >= %s
                    ORDER BY event_ts ASC LIMIT 20
                """, (case_key, atk_start))
                for row in cur.fetchall():
                    ts, fname, zone = row
                    url = ''
                    if zone:
                        m = _rz.search(r'HostUrl=([^\r\n]+)', zone)
                        if m: url = m.group(1)[:80]
                    events.append((ts, 'filesystem_v2/Zone.Identifier', f'Web завантаження: {fname}', url))

                # 5. Registry persistence (Run keys, Services)
                cur.execute("""
                    SELECT (payload->>'timestamp')::timestamptz, payload->>'KeyPath',
                           payload->>'ValueName', payload->>'ValueData'
                    FROM raw_fallback_v2
                    WHERE case_key=%s AND parser_family='registry'
                      AND (payload->>'KeyPath' ILIKE '%%\\\\Run%%' OR payload->>'KeyPath' ILIKE '%%\\\\Services%%'
                           OR payload->>'KeyPath' ILIKE '%%RunOnce%%')
                      AND payload->>'timestamp' >= %s
                      AND payload->>'ValueData' IS NOT NULL
                    ORDER BY payload->>'timestamp' ASC LIMIT 15
                """, (case_key, atk_start))
                for row in cur.fetchall():
                    ts, kpath, vname, vdata = row
                    if ts and vdata:
                        events.append((ts, 'registry/Run key', f'Persistence: {vname or "?"}',
                                       (vdata or '')[:100]))

    except Exception as e:
        return f'ERROR get_full_timeline: {e}'

    if not events:
        return 'Подій не знайдено. Перевірте case_key або запустіть trigger scan.'

    events = [(ts, src, desc, det) for ts, src, desc, det in events if ts is not None]
    events.sort(key=lambda x: x[0])

    # Deduplicate: same source+event within 3 seconds; limit high-noise EIDs
    deduped = []
    prev_key = (None, None)
    prev_ts = None
    eid_counts = {}  # limit high-noise EID types
    _HIGH_NOISE_LIMIT = {'EID 5007': 8, 'EID 4616': 5, 'EID 104': 8, 'EID 4688': 5}
    for ts, src, desc, det in events:
        key = (src, desc[:40])
        if key == prev_key and prev_ts and (ts - prev_ts).total_seconds() < 3:
            continue
        # Limit high-noise event types
        eid_tag = next((k for k in _HIGH_NOISE_LIMIT if k in src), None)
        if eid_tag:
            eid_counts[eid_tag] = eid_counts.get(eid_tag, 0) + 1
            if eid_counts[eid_tag] > _HIGH_NOISE_LIMIT[eid_tag]:
                continue
        deduped.append((ts, src, desc, det))
        prev_key = key
        prev_ts = ts

    lines = [f'=== ПОВНА ХРОНОЛОГІЯ АТАКИ ({len(deduped)} подій, від {deduped[0][0].strftime("%Y-%m-%d")}) ===',
             '| Час (UTC+2) | Джерело / EID | Подія | Деталі |',
             '|---|---|---|---|']
    for ts, src, desc, det in deduped[:limit]:
        ts_str = ts.strftime('%Y-%m-%d %H:%M:%S')
        lines.append(f'| {ts_str} | {src} | {desc} | {det} |')

    if len(deduped) > limit:
        lines.append(f'⚠️ Показано {limit} з {len(deduped)} подій. Для деталей по фазі — використовуй run_sql з фільтром дати.')

    return '\n'.join(lines)


def _agent_tool_compare_cases(case_key):
    """Порівнює тригери поточного кейсу з усіма попередніми кейсами.
    Виявляє однакові IOC, інструменти, патерни — наприклад: той самий ngrok + RMS = серійний зловмисник.
    """
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # Get current case triggers
                cur.execute("""
                    SELECT DISTINCT trigger FROM case_trigger_hits_v2
                    WHERE case_key=%s AND trigger NOT LIKE '\\_\\_%%'
                """, (case_key,))
                my_triggers = {r[0].lower() for r in cur.fetchall()}

                if not my_triggers:
                    return "Поточний кейс не має тригерів — запустіть trigger scan."

                # Find matches in other cases
                cur.execute("""
                    SELECT case_key, trigger, min(event_ts) as first_seen, count(*) as hits
                    FROM case_trigger_hits_v2
                    WHERE case_key != %s
                      AND lower(trigger) = ANY(%s)
                      AND trigger NOT LIKE '\\_\\_%%'
                    GROUP BY case_key, trigger
                    ORDER BY case_key, min(event_ts)
                """, (case_key, list(my_triggers)))
                matches = cur.fetchall()

                if not matches:
                    return f"Спільних тригерів з іншими кейсами не знайдено (перевірено {len(my_triggers)} тригерів)."

                # Group by other case_key
                from collections import defaultdict
                by_case = defaultdict(list)
                for m_case, m_trig, m_ts, m_hits in matches:
                    by_case[m_case].append((m_trig, m_ts, m_hits))

                out = [f"=== ПЕРЕТИН З ІНШИМИ КЕЙСАМИ ===",
                       f"Поточний кейс: {case_key}",
                       f"Тригерів у кейсі: {len(my_triggers)}\n"]

                for other_case, shared in sorted(by_case.items(), key=lambda x: -len(x[1])):
                    out.append(f"── {other_case}: {len(shared)} спільних тригерів")
                    for trig, ts, hits in sorted(shared, key=lambda x: -x[2])[:8]:
                        ts_str = ts.isoformat()[:10] if ts else 'n/a'
                        out.append(f"   • {trig} (hits={hits}, first={ts_str})")

                return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"


def _agent_tool_get_user_timeline(case_key, username=None, limit=int(60 * _ROW_SCALE)):
    """Повна хронологія дій конкретного користувача: logon, файли, процеси, мережа.
    Якщо username не вказано — показує всіх користувачів і їх активність.
    """
    limit = min(int(limit or 60), 200)
    pat = f"%{username}%" if username else None

    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # Find users if not specified
                if not username:
                    cur.execute("""
                        SELECT DISTINCT target_user FROM event_logs_v2
                        WHERE case_key=%s AND target_user IS NOT NULL AND target_user != ''
                          AND lower(target_user) NOT IN ('system','local service','network service','')
                        ORDER BY target_user LIMIT 20
                    """, (case_key,))
                    users = [r[0] for r in cur.fetchall()]
                    if not users:
                        return "Користувачів не знайдено в event_logs_v2."
                    return f"Знайдено користувачів: {', '.join(users)}\nВикличте get_user_timeline з конкретним username."

                events = []

                # Logon/logoff events
                cur.execute("""
                    SELECT event_ts, event_id, channel, remote_host, source_file
                    FROM event_logs_v2
                    WHERE case_key=%s AND target_user ILIKE %s
                      AND event_id IN (4624,4625,4634,4647,4648,4672,4776,4779)
                    ORDER BY event_ts ASC LIMIT %s
                """, (case_key, pat, limit))
                for r in cur.fetchall():
                    ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                    eid_labels = {4624:'LOGON',4625:'LOGON_FAIL',4634:'LOGOFF',4647:'LOGOFF',
                                  4648:'LOGON_EXPLICIT',4672:'PRIV_LOGON',4776:'CRED_VALIDATE',4779:'SESSION_DISCONNECT'}
                    label = eid_labels.get(r[1], f'EID={r[1]}')
                    events.append((r[0], f"[AUTH] {label} host={r[3] or 'local'} [{r[4]}]"))

                # Process execution by user
                cur.execute("""
                    SELECT event_ts, event_id, process_name, command_line, source_file
                    FROM event_logs_v2
                    WHERE case_key=%s AND target_user ILIKE %s AND event_id=4688
                    ORDER BY event_ts ASC LIMIT %s
                """, (case_key, pat, limit))
                for r in cur.fetchall():
                    ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                    events.append((r[0], f"[EXEC] {r[2]} cmd={str(r[3] or '')[:100]}"))

                # Files in user profile
                cur.execute("""
                    SELECT event_ts, file_name, parent_path, source_file
                    FROM filesystem_v2
                    WHERE case_key=%s AND lower(coalesce(parent_path,'')) ILIKE %s
                    ORDER BY event_ts ASC LIMIT %s
                """, (case_key, f"%users%{(username or '').lower()}%", limit // 2))
                for r in cur.fetchall():
                    if r[0]:
                        events.append((r[0], f"[FILE] {r[1]} path={r[2]}"))

                if not events:
                    return f"Активності користувача {username!r} не знайдено."

                events.sort(key=lambda x: x[0])
                out = [f"=== ХРОНОЛОГІЯ КОРИСТУВАЧА: {username} ({len(events)} подій) ==="]
                for ts_dt, desc in events:
                    ts = ts_dt.isoformat()[:19] if ts_dt else 'n/a'
                    out.append(f"  {ts} | {desc}")

                return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"


def _agent_tool_get_case_triggers(case_key, limit=int(50 * _ROW_SCALE)):
    """Grep результати по базі тригерів (threat intel накопичений з практики).
    Повертає:
    - вікно зараження: перший і останній хіт по часу
    - список хітів, упорядкований за важливістю (analysis/salience.py); у межах
      одного рангу — event_ts ASC, тож відкат назад від першого хіта працює як раніше
    - топ тригерів по кількості хітів

    МЕТОДОЛОГІЯ: знайди first_ts → це ~початок зараження.
    Потім шукай що було ДО first_ts щоб знайти initial access.
    """
    limit = min(int(limit or 50), 100)
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                NOISE_TRIGGERS = (
                    'zone.identifier','zoneid=','referrerurl=','hosturl=',
                    'chrome.exe','iexplore.exe','firefox.exe','edge.exe',
                )
                TS_HARD_MIN = "'2015-01-01'::timestamptz"
                TS_MAX_ABS  = "'2030-01-01'::timestamptz"

                # Find max observed ts to compute dynamic cluster window (last 3 years)
                cur.execute("""
                    SELECT max(event_ts) FROM case_trigger_hits_v2
                    WHERE case_key=%s AND event_ts IS NOT NULL
                """, (case_key,))
                max_ts_row = cur.fetchone()
                max_ts = max_ts_row[0] if max_ts_row else None

                # Cluster window: last 3 years from latest hit (captures attack, excludes ancient noise)
                if max_ts:
                    cur.execute(f"""
                        SELECT
                            min(event_ts), max(event_ts), count(*), count(DISTINCT trigger)
                        FROM case_trigger_hits_v2
                        WHERE case_key=%s AND event_ts IS NOT NULL
                          AND event_ts >= (%s::timestamptz - interval '3 years')
                          AND event_ts <= {TS_MAX_ABS}
                          AND artifact_family IN ('eventlog','program_exec','tool_alerts_v2')
                          AND trigger NOT IN %s
                    """, (case_key, max_ts, NOISE_TRIGGERS))
                    window = cur.fetchone()
                else:
                    window = None

                # Fallback: all families, last 5 years
                if not window or not window[0]:
                    cur.execute(f"""
                        SELECT min(event_ts), max(event_ts), count(*), count(DISTINCT trigger)
                        FROM case_trigger_hits_v2
                        WHERE case_key=%s AND event_ts IS NOT NULL
                          AND event_ts BETWEEN {TS_HARD_MIN} AND {TS_MAX_ABS}
                          AND trigger NOT IN %s
                    """, (case_key, NOISE_TRIGGERS))
                    window = cur.fetchone()

                cluster_min = window[0] if window else None
                cluster_max = window[1] if window else None

                # Get OS install date to exclude first-day noise (OS setup artifacts)
                os_install_cutoff = None
                try:
                    cur.execute("""
                        SELECT install_date_utc FROM system_profile_v1
                        WHERE case_key=%s LIMIT 1
                    """, (case_key,))
                    inst_row = cur.fetchone()
                    if inst_row and inst_row[0]:
                        import re as _re2
                        m = _re2.match(r'(\d{4}-\d{2}-\d{2})', str(inst_row[0]))
                        if m:
                            os_install_cutoff = f"'{m.group(1)}'::date + interval '2 days'"
                except Exception:
                    conn.rollback()

                effective_min = f"GREATEST(%s, {os_install_cutoff})" if os_install_cutoff else '%s'

                # Top triggers — unique (trigger, artifact_family) with first/last occurrence
                cur.execute(f"""
                    SELECT trigger, artifact_family,
                           min(event_ts) AS first_seen, max(event_ts) AS last_seen
                    FROM case_trigger_hits_v2
                    WHERE case_key=%s AND event_ts IS NOT NULL
                      AND event_ts BETWEEN {effective_min} AND {TS_MAX_ABS}
                      AND trigger NOT IN %s
                    GROUP BY trigger, artifact_family
                    ORDER BY min(event_ts) ASC
                    LIMIT 30
                """, (case_key, cluster_min or '2015-01-01', NOISE_TRIGGERS))
                top = cur.fetchall()

                # Chronological hits — DISTINCT per (trigger, artifact_family) to avoid duplicates
                cur.execute(f"""
                    SELECT DISTINCT ON (trigger, artifact_family)
                        trigger, artifact_family, event_ts, snippet
                    FROM case_trigger_hits_v2
                    WHERE case_key=%s AND event_ts IS NOT NULL
                      AND event_ts BETWEEN {effective_min} AND {TS_MAX_ABS}
                      AND trigger NOT IN %s
                    ORDER BY trigger, artifact_family, event_ts ASC
                    LIMIT %s
                """, (case_key, cluster_min or '2015-01-01', NOISE_TRIGGERS, limit * 3))
                # Re-sort by time after dedup
                chrono = sorted(cur.fetchall(), key=lambda r: r[2])

        chrono = chrono[:limit]  # apply limit after dedup+resort
        if not chrono and not top:
            return "Тригерів не знайдено."

        out = []

        # Summary header
        from datetime import datetime as _dt2, timezone as _tz2, timedelta as _td2
        _now = _dt2.now(_tz2.utc)
        _incident_cutoff = _now - _td2(days=365)  # triggers older than 1 year = background noise

        if window and window[0]:
            first_hit = window[0].isoformat() if window[0] else 'невідомо'
            last_hit = window[1].isoformat() if window[1] else 'невідомо'
            # Find the most recent trigger to use as reference for "incident start"
            recent_hits = [r for r in (top or []) if r[2] and r[2] >= _incident_cutoff]
            incident_first = recent_hits[0][2].isoformat()[:16] if recent_hits else None
            out.append(f"=== ВІКНО ЗАРАЖЕННЯ ===")
            if incident_first:
                out.append(f"Перший ІНЦИДЕНТНИЙ тригер (останні 12 міс): {incident_first}")
            out.append(f"Перший тригер (всього, включно з фоном): {first_hit}")
            out.append(f"Останній тригер: {last_hit}")
            out.append(f"Всього хітів: {window[2]} | Унікальних тригерів: {window[3]}")
            out.append(f"УВАГА: тригери старіше 12 місяців від last_hit — ФОНОВИЙ ШУМ, не початок інциденту!")
            out.append(f"→ Шукай initial access ДО {incident_first or first_hit}")
            out.append("")

        # Top triggers
        if top:
            _hdr_at = len(out)
            out.append("=== ТРИГЕРИ ЗА ВАЖЛИВІСТЮ (у межах рангу — хронологічно) ===")
            _sec = []
            # Whatever the hits section below is going to repeat is dropped from here: it says
            # the same thing there WITH a path, so keeping both spends a third of the 4000-char
            # budget saying it twice. Measured overlap ran from 22 of 22 rows down to 2 of 8,
            # which is why this is a per-row test and not a decision to delete the section.
            # A background-noise trigger always stays: that tag is a judgement the hits section
            # never makes, and losing it would let old background read as part of the incident.
            _below = {(str(t), str(f)) for t, f, _e, _s in (chrono or [])}
            for trigger, family, first_seen, last_seen in top:
                fs = first_seen.isoformat()[:16].replace('T',' ') if first_seen else 'n/a'
                ls = last_seen.isoformat()[:16].replace('T',' ') if last_seen else ''
                span = f" → {ls}" if ls and ls != fs else ""
                is_noise = first_seen and first_seen < _incident_cutoff
                noise_tag = " [BACKGROUND-NOISE]" if is_noise else ""
                if not is_noise and (str(trigger), str(family)) in _below:
                    continue
                _sec.append(f"  {fs}{span} | [{family}] {trigger}{noise_tag}")
            if _sec:
                out.extend(_S.sort_lines(_sec))
                out.append("")
            else:
                # everything here was repeated below with a path: drop the empty header too,
                # so the model is not handed a section that says nothing
                del out[_hdr_at:]

        # Chronological earliest hits
        if chrono:
            out.append("=== ХІТИ ТРИГЕРІВ ЗА ВАЖЛИВІСТЮ (у межах рангу — від найранішого) ===")
            _sec = []
            for trigger, family, event_ts, snippet in chrono:
                ts = event_ts.isoformat() if event_ts else 'n/a'
                snip = str(snippet or '')[:60]
                _sec.append(f"{ts} | [{family}] {trigger} | {snip}")
            out.extend(_S.sort_lines(_sec))

        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"

# ── запасне джерело хронології ───────────────────────────────────────────────────────
# Виміряно по бібліотеці 2026-08-16: сімʼя `forensictimeline` є лише в 4 справах з 11 —
# ForensicTimeliner додали в збирач пізніше за решту архівів. На 7 справах цей інструмент,
# який у власному docstring зветься «основним джерелом виявлення», відповідав
# «записів не знайдено», хоча поруч лежало 1819–4444 рядки `program_exec_v2` зі справжнім
# часом і 170 тис.–800 тис. рядків `event_logs_v2`.
#
# Три правила, які тут важать більше за обсяг:
#  1) вмикається ЛИШЕ коли сімʼї в справі НЕМАЄ (перевірка наявності, а не порожнього
#     результату) — інакше `keyword=` без збігів на здоровій справі почав би раптом
#     віддавати program_exec замість чесного «записів не знайдено»;
#  2) тип часу підписується: з трьох джерел «запуску» лише Prefetch означає запуск,
#     Amcache — першу появу файлу, ShimCache — час самого файлу;
#  3) що саме потрапить у 40 рядків, вирішує analysis/salience.py, а не випадковий зріз.

# шматок імені CSV → (підпис артефакту, ЯКИЙ це час)
# Підписи часу — ті самі рядки, які вже друкує звіт (reports/reshape.py:_WHEN_KIND_LABEL):
# модель не має вчити два словники синонімів для однієї речі.
_TL_FB_EXEC_KIND = (
    ('appcompatcache', 'ShimCache', 'час файлу, НЕ запуску'),
    ('pecmd',          'Prefetch',  'запуск'),
    ('prefetch',       'Prefetch',  'запуск'),
    ('amcache',        'Amcache',   'перша поява файлу'),
)

_TL_FB_EID_DESC = {
    4625: 'Невдалий вхід', 4720: 'Новий обліковий запис', 4726: 'Видалення облікового запису',
    4732: 'Додано до групи', 4698: 'Завдання у планувальнику', 4697: 'Нова служба',
    4688: 'Запуск процесу', 4719: 'Політику аудиту змінено', 4616: 'Час системи змінено',
    7045: 'Нова служба (SCM)', 1102: 'Журнал Security очищено', 104: 'Журнал очищено (System)',
    5001: 'Defender: захист вимкнено', 5007: 'Defender: конфігурацію змінено',
    1116: 'Defender: виявлено загрозу', 1117: 'Defender: вжито дію',
    1011: 'Defender: карантин', 4104: 'PowerShell: блок скрипта',
}
# Один EID уміє зʼїсти весь вивід: на 06_02_case_58_NGROK лише EID 5007 дає 6367 подій
# проти 111 подій 7045. Стеля на EID — та сама ідея, що в _agent_tool_get_full_timeline.
_TL_FB_EID_CAP = 8

_TL_FB_FS_EXT = ('exe', 'dll', 'scr', 'com', 'pif', 'ps1', 'bat', 'cmd', 'vbs', 'js',
                 'hta', 'msi', 'jar', 'lnk', 'iso', 'img', 'rar', '7z', 'zip')

# Теки, де атакувальник тримає файли. Подвійний зворотний слеш — навмисно: у LIKE
# зворотний слеш сам є символом екранування, тож `%\users%` шукало б просто «users».
_TL_FB_FS_DIRS = [
    r'%\\users\\public%', r'%\\appdata\\roaming%', r'%\\appdata\\local\\temp%',
    r'%\\windows\\temp%', r'%\\downloads%', r'%\\programdata%',
    r'%\\desktop%', r'%\\documents%', r'%\\perflogs%',
]
# ...окрім теки Recent: це ярлики документів, які Windows створює на кожне відкриття файлу
# людиною. Розширення `.lnk` у `\AppData\Roaming` дає їм ранг «підозріло», і виміряно, що
# вони займали 20 рядків із 40 на 20_05_case_58 і 18 із 40 на 06_02_NGROK — тобто
# хронологія атаки складалася зі списку нотаріальних документів.
_TL_FB_FS_DIR_SKIP = r'%\\microsoft\\windows\\recent%'


def _tl_fallback_timeline(cur, case_key, keyword=None, artifact=None, limit=40):
    """Хронологія з program_exec_v2 + event_logs_v2 + filesystem_v2 — коли ForensicTimeliner
    у справі відсутній. Формат рядка той самий: `час | [артефакт] | опис | шлях`.

    Кандидати з кожного джерела беруться НАЙНОВІШІ (`ORDER BY event_ts DESC`), а не
    найраніші: архів знімають за дні після інциденту, а «найраніші» — це рівно та помилка,
    яку виправив коміт a9d18b4 (усі 40 рядків пішли на файлові часи 2003–2009 років).
    Далі salience вирішує, ЩО з кандидатів увійде, і аж на друці порядок стає
    хронологічним — заглушки (час до 2000 року або його відсутність) у кінець.
    """
    want = str(artifact or '').strip().lower()
    kw = '%' + str(keyword) + '%' if keyword else None
    cands = []

    def _wanted(label):
        return (not want) or (want in label.lower())

    def _add(src, ts, label, eid_str, descr, path):
        ph = 1 if (ts is None or ts.year < 2000) else 0
        ts_txt = ts.strftime('%Y-%m-%d %H:%M:%S') if ts else 'n/a'
        line = '%s | [%s]%s | %s | %s' % (ts_txt, label, eid_str, descr, str(path or '')[:120])
        try:
            ep = ts.timestamp() if ts else 0.0
        except Exception:
            ep = 0.0
        cands.append((_S.tier(line), ph, ep, line, src))

    def _base(p):
        s = str(p or '').replace('/', '\\')
        return s.split('\\')[-1] or s

    # 1) Сліди запуску: ShimCache / Amcache / Prefetch — з підписом типу часу
    if any(_wanted(lbl) for _, lbl, _ in _TL_FB_EXEC_KIND) or _wanted('ProgramExec'):
        q = ['SELECT event_ts, executable_name, full_path, source_file FROM program_exec_v2',
             'WHERE case_key=%s']
        p = [case_key]
        if kw:
            q.append('AND (executable_name ILIKE %s OR full_path ILIKE %s OR source_file ILIKE %s)')
            p += [kw, kw, kw]
        q.append('ORDER BY event_ts DESC NULLS LAST, row_id ASC LIMIT 4000')
        cur.execute(' '.join(q), p)
        for ts, exe, path, src in cur.fetchall():
            label, kind = 'ProgramExec', ''
            s = str(src or '').lower()
            for frag, lbl, knd in _TL_FB_EXEC_KIND:
                if frag in s:
                    label, kind = lbl, knd
                    break
            if not _wanted(label):
                continue
            nm = _base(exe or path) or '?'
            _add('exec', ts, label, '', ('%s: %s' % (kind, nm)) if kind else nm, path or exe)

    # 2) Журнали подій — набір EID узято з _agent_tool_get_full_timeline (той самий файл,
    #    ~рядок 1570) слово в слово і свідомо НЕ винесено у спільну константу: правити той
    #    інструмент означало б змінити ще й його вивід, а це окрема регресія.
    #    EID 4624 тут немає навмисно — 4600+ подій на справу, і входами вже опікується
    #    _agent_tool_get_logon_activity.
    if _wanted('EventLog'):
        q = ["""SELECT event_ts, event_id, target_user, remote_host, process_name, command_line
                FROM event_logs_v2 WHERE case_key=%s
                  AND (
                      (event_id IN (4625,4720,4726,4732,4698,4697,4688,4719,4616) AND channel ILIKE '%%Security%%')
                      OR (event_id=7045 AND channel ILIKE '%%System%%')
                      OR (event_id=1102 AND (channel ILIKE '%%Security%%' OR channel ILIKE '%%RDPClient%%'))
                      OR (event_id=104  AND (channel ILIKE '%%System%%' OR channel ILIKE '%%Eventlog%%'))
                      OR (event_id IN (5001,5007,1116,1117,1011) AND channel ILIKE '%%Windows Defender%%')
                      OR (event_id=4104 AND channel ILIKE '%%PowerShell%%')
                  )
                  AND NOT (event_id=4688 AND (
                           LOWER(COALESCE(process_name,'')) LIKE '%%system32%%'
                           OR TRIM(LOWER(COALESCE(process_name,''))) IN ('registry','')
                           OR process_name IS NULL))"""]
        p = [case_key]
        if kw:
            q.append("""AND (COALESCE(process_name,'') ILIKE %s OR COALESCE(command_line,'') ILIKE %s
                             OR COALESCE(target_user,'') ILIKE %s OR COALESCE(remote_host,'') ILIKE %s)""")
            p += [kw, kw, kw, kw]
        q.append('ORDER BY event_ts DESC NULLS LAST, row_id ASC LIMIT 800')
        cur.execute(' '.join(q), p)
        eid_seen = {}
        for ts, eid, user, rhost, pname, cmd in cur.fetchall():
            eid_seen[eid] = eid_seen.get(eid, 0) + 1
            if eid_seen[eid] > _TL_FB_EID_CAP:
                continue
            det = [x for x in (('user=' + str(user)) if user else None,
                               ('from=' + str(rhost)) if rhost and str(rhost) != '-' else None,
                               str(cmd or pname or '')[:80] or None) if x]
            _add('evt', ts, 'EventLog', ' EID=%s' % eid,
                 _TL_FB_EID_DESC.get(eid, 'Подія %s' % eid), ' '.join(det))

    # 3) Файлова система — лише виконувані/архівні розширення в теках, де атакувальник
    #    тримає файли. Рядки $J свідомо не беремо: у них `parent_path` порожній (виміряно),
    #    тож salience не має за чим їх судити, а їх 19 тис. на справу.
    if _wanted('MFT') or _wanted('USN'):
        q = ['SELECT event_ts, file_name, parent_path, action FROM filesystem_v2',
             'WHERE case_key=%s',
             "AND lower(COALESCE(extension,'')) = ANY(%s)",
             "AND lower(COALESCE(parent_path,'')) LIKE ANY(%s)",
             "AND lower(COALESCE(parent_path,'')) NOT LIKE %s"]
        p = [case_key, list(_TL_FB_FS_EXT), list(_TL_FB_FS_DIRS), _TL_FB_FS_DIR_SKIP]
        if kw:
            q.append("AND (COALESCE(file_name,'') ILIKE %s OR COALESCE(parent_path,'') ILIKE %s)")
            p += [kw, kw]
        q.append('ORDER BY event_ts DESC NULLS LAST, row_id ASC LIMIT 600')
        cur.execute(' '.join(q), p)
        for ts, fname, parent, action in cur.fetchall():
            act = str(action or '')
            label = 'MFT' if act == 'MFT' else 'USN'
            if not _wanted(label):
                continue
            # MFT.event_ts = Created0x10 (parsers/forensic.py:map_fs_mft) — це створення
            # файлу, а не його запуск; USN несе причину зміни у самому `action`.
            descr = (('створення файлу (MFT): %s' % (fname or '?')) if act == 'MFT'
                     else ('%s: %s' % (act[:40], fname or '?')))
            full = str(parent or '').rstrip('\\')
            full = (full + '\\' + str(fname or '')) if full else str(fname or '')
            _add('fs', ts, label, '', descr, full)

    if not cands:
        return ('ForensicTimeliner: записів не знайдено. Запасні джерела (program_exec_v2, '
                'event_logs_v2, filesystem_v2) теж порожні за цим фільтром.')

    # відбір: ранг важливості → справжній час перед заглушкою → найновіше
    cands.sort(key=lambda x: (x[0], x[1], -x[2]))

    # Одне джерело не сміє забрати весь вивід. Виміряно до квоти: файлова система давала
    # 33 рядки з 40 на 22_07_case_56 і 25 з 40 на трьох інших справах, а журнали подій —
    # 0 рядків на 6 справах із 7, хоч саме там лежать встановлення служб (7045), спрацювання
    # Defender (1116) і очищення журналів (1102). Спершу кожне джерело отримує свою третину,
    # решту місць добирає загальний рейтинг.
    quota = max(1, limit // 3)
    seen, picked, taken = set(), [], {}
    def _take(row, cap=None):
        _tier, ph, ep, line, src = row
        if line in seen:          # два однакові CSV в архіві дають той самий рядок двічі
            return False          # (13_08_case_66: два AppCompatCache з різницею 4 с)
        if cap is not None and taken.get(src, 0) >= cap:
            return False
        seen.add(line)
        taken[src] = taken.get(src, 0) + 1
        picked.append((ph, ep, line))
        return True

    for row in cands:
        if len(picked) >= limit:
            break
        _take(row, cap=quota)
    for row in cands:
        if len(picked) >= limit:
            break
        _take(row)
    picked.sort(key=lambda x: (x[0], x[1]))   # друк: заглушки в кінець, решта хронологічно

    head = ('ForensicTimeliner у цій справі відсутній — хронологію зібрано з program_exec_v2, '
            'event_logs_v2 і filesystem_v2: %d рядків із %d кандидатів (відбір за важливістю, '
            'друк хронологічний). Тип часу підписано: «запуск» — Prefetch, «перша поява файлу» — '
            'Amcache, «час файлу, НЕ запуску» — ShimCache, «створення файлу» — MFT.'
            % (len(picked), len(cands)))
    return '\n'.join([head] + [ln for _ph, _ep, ln in picked])


def _agent_tool_get_forensic_timeline(case_key, keyword=None, artifact=None, limit=int(40 * _ROW_SCALE)):
    """Query ForensicTimeliner — pre-aggregated timeline of all forensically interesting events.
    This is the primary discovery source: covers LNK, JumpLists, Event Logs, MFT, Prefetch, Amcache, Shellbags.

    Якщо ForensicTimeliner у справі не ганяли (4 архіви з 11 його мають), хронологія
    збирається із `program_exec_v2`, `event_logs_v2` і `filesystem_v2` —
    див. `_tl_fallback_timeline`. Формат рядка однаковий в обох гілках.
    """
    limit = min(int(limit or 40), 80)
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # Перемикач — НАЯВНІСТЬ сімʼї, а не порожній результат запиту: інакше
                # `keyword=` без збігів на справі з ForensicTimeliner почав би віддавати
                # program_exec замість чесного «записів не знайдено», тобто змінилася б
                # поведінка там, де ламати нічого не треба.
                cur.execute("""SELECT 1 FROM raw_fallback_v2
                               WHERE case_key=%s AND parser_family='forensictimeline' LIMIT 1""",
                            (case_key,))
                if cur.fetchone() is None:
                    return _tl_fallback_timeline(cur, case_key, keyword, artifact, limit)
                params = [case_key]
                where = ["case_key=%s AND parser_family='forensictimeline'"]
                if artifact:
                    where.append("payload->>'ArtifactName' ILIKE %s")
                    params.append(f'%{artifact}%')
                if keyword:
                    where.append("payload::text ILIKE %s")
                    params.append(f'%{keyword}%')
                params.append(limit)
                cur.execute(f"""
                    SELECT
                        payload->>'DateTime' AS dt,
                        payload->>'ArtifactName' AS artifact,
                        payload->>'Description' AS descr,
                        payload->>'DataPath' AS data_path,
                        payload->>'EventId' AS eid
                    FROM raw_fallback_v2
                    WHERE {' AND '.join(where)}
                    -- Placeholders LAST. ShimCache/LNK/JumpLists write 1980-01-01 when they
                    -- have no real time, and plain ascending order handed all 40 slots to them:
                    -- 32 of 40 on 20_07_case_43, with not one real timestamp in the output.
                    -- row_id breaks ties, and a timeline is nothing but ties: this case has
                    -- 10-14 thousand groups of rows sharing a timestamp to the second, so
                    -- DateTime alone left Postgres free to pick any of them. Measured on the
                    -- unchanged code: 5 runs, 4-5 different outputs on 3 of the 4 cases that
                    -- have this artefact. Found by the fallback agent, which could not prove
                    -- "byte-identical" and said so instead of loosening its own check.
                    ORDER BY (coalesce(payload->>'DateTime','') < '2000') ASC,
                             (payload->>'DateTime') ASC NULLS LAST,
                             row_id ASC
                    LIMIT %s
                """, params)
                rows = cur.fetchall()
        if not rows:
            return "ForensicTimeliner: записів не знайдено."
        out = []
        for dt, artifact_name, descr, data_path, eid in rows:
            # Trim datetime to readable format
            ts = (dt or 'n/a')[:19].replace('T', ' ')
            path_short = str(data_path or '')[:120]
            eid_str = f" EID={eid}" if eid else ""
            out.append(f"{ts} | [{artifact_name}]{eid_str} | {descr} | {path_short}")
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"

def _agent_tool_get_browser_downloads(case_key, limit=int(30 * _ROW_SCALE)):
    limit = min(int(limit or 30), 50)
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # browser_provenance_v1 has event_ts / download_path / local_path / user_name; the
                # old column names (visit_ts, file_path, profile_user) never existed, so this tool
                # answered "ERROR" on every call until 24.10.2026. The MOTW host URL fills a
                # download row that carries no URL of its own.
                cur.execute("""
                    SELECT event_ts,
                           COALESCE(NULLIF(url,''), zone_identifier_host_url),
                           COALESCE(NULLIF(referrer_url,''), zone_identifier_referrer_url),
                           regexp_replace(COALESCE(NULLIF(download_path,''), local_path, ''), '^.*[\\\\/]', ''),
                           COALESCE(NULLIF(download_path,''), local_path),
                           browser, COALESCE(NULLIF(user_name,''), profile_name), source_file
                    FROM browser_provenance_v1
                    WHERE case_key=%s
                      AND COALESCE(NULLIF(url,''), NULLIF(zone_identifier_host_url,''),
                                   NULLIF(download_path,''), NULLIF(local_path,'')) IS NOT NULL
                    ORDER BY (COALESCE(NULLIF(url,''), NULLIF(zone_identifier_host_url,'')) IS NULL),
                             event_ts DESC NULLS LAST LIMIT %s
                """, (case_key, limit))
                rows = cur.fetchall()
        if not rows:
            return "Даних браузера не знайдено."
        out = []
        for r in rows:
            ts = r[0].isoformat() if r[0] else 'n/a'
            url = str(r[1] or '')[:120]
            ref = str(r[2] or '')[:80]
            fname = str(r[3] or '')
            fpath = str(r[4] or '')[:80]
            out.append(f"{ts} | browser={r[5]} | user={r[6]} | file={fname} | url={url} | ref={ref} | path={fpath}")
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"

def _agent_tool_get_browser_activity(case_key, limit=int(50 * _ROW_SCALE)):
    """Attacker/user browser history and downloads from WebBrowsers CSVs.
    Повертає Edge/Chrome history (URL, title, visit time) і downloads — критично для victim journey."""
    limit = min(int(limit or 50), 200)
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # History: url, title, visit_count, last_visit_time
                cur.execute("""
                    SELECT parser_family, payload
                    FROM raw_fallback_v2
                    WHERE case_key=%s AND parser_family IN ('browser_history','browser_downloads','browser_searches','browser_misc')
                    ORDER BY
                        CASE parser_family
                            WHEN 'browser_downloads' THEN 0
                            WHEN 'browser_history' THEN 1
                            ELSE 2
                        END,
                        row_id ASC
                    LIMIT %s
                """, (case_key, limit))
                rows = cur.fetchall()
        if not rows:
            return "Даних браузера не знайдено."
        out = []
        for family, payload in rows:
            if isinstance(payload, dict):
                p = payload
            elif isinstance(payload, str):
                try: p = json.loads(payload)
                except Exception: p = {}
            else:
                p = {}
            p.pop('SourceFile', None)
            line_parts = [f"[{family}]"]
            for k in ('url', 'title', 'last_visit_time', 'visit_count',
                      'current_path', 'target_path', 'start_time', 'end_time',
                      'received_bytes', 'total_bytes', 'mime_type',
                      'term', 'keyword_id'):
                v = p.get(k) or p.get(k.replace('_',' '))
                if v: line_parts.append(f"{k}={str(v)[:150]}")
            out.append(' | '.join(line_parts))
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"

def _agent_tool_get_thor_file_hashes(case_key, keyword=None, limit=int(50 * _ROW_SCALE)):
    """MD5 хеші файлів із системи (THOR files_md5s.csv).
    Дозволяє перевірити конкретний файл, знайти зловмисні EXE/DLL/ZIP."""
    limit = min(int(limit or 50), 500)
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                if keyword:
                    cur.execute("""
                        SELECT payload FROM raw_fallback_v2
                        WHERE case_key=%s AND parser_family='thor_file_hashes'
                          AND payload::text ILIKE %s
                        ORDER BY row_id LIMIT %s
                    """, (case_key, f'%{keyword}%', limit))
                else:
                    cur.execute("""
                        SELECT payload FROM raw_fallback_v2
                        WHERE case_key=%s AND parser_family='thor_file_hashes'
                        ORDER BY
                            CASE WHEN payload->>'path' ILIKE '%\\\\temp\\\\%'
                                   OR payload->>'path' ILIKE '%\\\\appdata\\\\%'
                                   OR payload->>'path' ILIKE '%\\\\downloads\\\\%'
                                   OR payload->>'file_name' ~ '\\.(exe|dll|ps1|vbs|bat|js|zip|rar)$'
                            THEN 0 ELSE 1 END ASC,
                            row_id LIMIT %s
                    """, (case_key, limit))
                rows = cur.fetchall()
        if not rows:
            return "THOR MD5 хешів не знайдено. Можливо, файли не були реінгесті після оновлення."
        out = []
        for (p,) in rows:
            if isinstance(p, dict):
                out.append(f"md5={p.get('md5','')} | size={p.get('size','')} | {p.get('path','')}")
        return '\n'.join(out[:limit])
    except Exception as e:
        return f"ERROR: {e}"

def _agent_tool_get_regripper_data(case_key, keyword=None, limit=int(30 * _ROW_SCALE)):
    """Regripper artifacts: OS info, accounts (SAM), services, remote tools.
    Пріоритет: samparse (акаунти+хеші), os_info, timezone, shutdown, services, software.
    """
    limit = min(int(limit or 30), 60)
    # Priority plugins to show in full first
    PRIORITY_PLUGINS = ['samparse', 'compname', 'winver', 'timezone', 'shutdown', 'lastlogon',
                        'logon_xp', 'services', 'autoruns', 'appcompatcache', 'prefetch',
                        'networkcards', 'wifi', 'wireless', 'wlan']
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                params = [case_key]
                kw_clause = ""
                if keyword:
                    kw_clause = "AND payload::text ILIKE %s"
                    params.append(f'%{keyword}%')
                params.append(limit)
                cur.execute(f"""
                    SELECT parser_family, source_file, payload,
                           CASE WHEN lower(payload->>'plugin') = ANY(%s) THEN 0 ELSE 1 END as prio
                    FROM raw_fallback_v2
                    WHERE case_key=%s AND parser_family LIKE 'regripper%%' {kw_clause}
                    ORDER BY prio, parser_family, row_id LIMIT %s
                """, [PRIORITY_PLUGINS] + params)
                rows = cur.fetchall()
        if not rows:
            return "RegRipper даних не знайдено."
        out = []
        for r in rows:
            plugin = r[2].get('plugin', '') if isinstance(r[2], dict) else ''
            text = r[2].get('text', '') if isinstance(r[2], dict) else str(r[2] or '')
            # Priority plugins get full text, others get 500 chars
            is_prio = plugin.lower() in PRIORITY_PLUGINS
            preview = text[:3000] if is_prio else text[:500]
            out.append(f"[{r[0]}|{plugin}] {r[1]}\n{preview}")
        return '\n---\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"

def _agent_tool_get_sensitive_secrets(case_key):
    """Витягує чутливі артефакти: ngrok токени, AnyDesk ID, Wi-Fi credentials,
    збережені паролі/токени у конфігах — критично для розуміння масштабу компрометації."""
    results = []
    # NOTE: all %pattern% in ILIKE must be %% to avoid psycopg2 treating them as params
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # 1. ngrok authtoken from raw_fallback
                try:
                    cur.execute("""
                        SELECT source_file, substr(payload::text, 1, 500)
                        FROM raw_fallback_v2
                        WHERE case_key=%s AND (
                            payload::text ILIKE '%%authtoken%%'
                            OR payload::text ILIKE '%%ngrok%%token%%'
                            OR payload::text ILIKE '%%ngrok%%yml%%'
                        ) AND payload::text NOT ILIKE '%%XblAuthToken%%'
                        LIMIT 5
                    """, (case_key,))
                    for row in cur.fetchall():
                        results.append(f"[ngrok_token] src={row[0]}\n  {row[1][:300]}")
                except Exception: conn.rollback()

                # 2. ngrok token from event_logs command lines
                try:
                    cur.execute("""
                        SELECT event_ts, command_line, source_file
                        FROM event_logs_v2
                        WHERE case_key=%s AND (
                            command_line ILIKE '%%authtoken%%'
                            OR command_line ILIKE '%%ngrok%%token%%'
                            OR command_line ILIKE '%%ngrok%%config%%'
                        )
                        ORDER BY event_ts ASC LIMIT 5
                    """, (case_key,))
                    for row in cur.fetchall():
                        ts = row[0].isoformat()[:19] if row[0] else 'n/a'
                        results.append(f"[ngrok_cmd] {ts} | {(row[1] or '')[:400]} | src={row[2]}")
                except Exception: conn.rollback()

                # 3. AnyDesk ID
                try:
                    cur.execute("""
                        SELECT source_file, substr(payload::text, 1, 400)
                        FROM raw_fallback_v2
                        WHERE case_key=%s AND (
                            payload->>'plugin' ILIKE '%%anydesk%%'
                            OR (payload::text ILIKE '%%anydesk%%' AND payload::text ILIKE '%%client%%id%%')
                        )
                        LIMIT 5
                    """, (case_key,))
                    for row in cur.fetchall():
                        results.append(f"[anydesk_id] src={row[0]}\n  {row[1][:300]}")
                except Exception: conn.rollback()

                # 4. Wi-Fi credentials
                try:
                    cur.execute("""
                        SELECT source_file, substr(coalesce(payload->>'text',''), 1, 2000)
                        FROM raw_fallback_v2
                        WHERE case_key=%s AND (
                            payload->>'plugin' ILIKE '%%wifi%%'
                            OR payload->>'plugin' ILIKE '%%wlan%%'
                            OR payload->>'plugin' ILIKE '%%wireless%%'
                            OR (payload->>'text' ILIKE '%%WPA%%' AND payload->>'text' ILIKE '%%SSID%%')
                            OR payload->>'text' ILIKE '%%keyMaterial%%'
                        )
                        LIMIT 5
                    """, (case_key,))
                    for row in cur.fetchall():
                        if row[1]:
                            results.append(f"[wifi_creds] src={row[0]}\n  {row[1][:1000]}")
                except Exception: conn.rollback()

                # 5. ngrok/RDPWrap config files in filesystem
                try:
                    cur.execute("""
                        SELECT event_ts, file_name, parent_path, payload->>'file_size' as sz
                        FROM filesystem_v2
                        WHERE case_key=%s AND (
                            lower(file_name) IN ('ngrok.yml','ngrok.yaml','ng.bat','rdpwrap.ini','autoupdate.bat')
                            OR (lower(file_name) LIKE '%%ngrok%%' AND lower(file_name) LIKE '%%.yml%%')
                        )
                        ORDER BY event_ts ASC LIMIT 10
                    """, (case_key,))
                    for row in cur.fetchall():
                        ts = row[0].isoformat()[:19] if row[0] else 'n/a'
                        results.append(f"[config_file] {ts} | {row[1]} | {row[2]} | size={row[3]}")
                except Exception: conn.rollback()

                # 6. Credential harvesting commands
                try:
                    cur.execute("""
                        SELECT event_ts, process_name, command_line, source_file
                        FROM event_logs_v2
                        WHERE case_key=%s AND (
                            command_line ILIKE '%%credential%%'
                            OR command_line ILIKE '%%mimikatz%%'
                            OR command_line ILIKE '%%lazagne%%'
                            OR command_line ILIKE '%%sekurlsa%%'
                        )
                        ORDER BY event_ts ASC LIMIT 5
                    """, (case_key,))
                    for row in cur.fetchall():
                        ts = row[0].isoformat()[:19] if row[0] else 'n/a'
                        results.append(f"[cred_harvest] {ts} | {row[1]} | {_pd1_clean(row[2])[:300]}")
                except Exception: conn.rollback()

    except Exception as e:
        return f"ERROR: {e}"

    if not results:
        return "Секретів/токенів/Wi-Fi credentials не знайдено в БД."
    return '\n\n'.join(results)


def _agent_tool_search_reports(case_key, query):
    """Search PDF expert reports in Qdrant kb_reports collection.
    Use when SQL DB has insufficient data or user asks about expert findings.
    Returns relevant chunks from uploaded PDF forensic reports.
    """
    if not query or len(query.strip()) < 3:
        return 'ERROR: query required'
    # HYBRID: if the query IS an indicator (IP/domain/hash/email) → exact lookup over
    # case_iocs + report chunks first (semantic RAG is weak on exact tokens).
    _hybrid = ''
    try:
        from app import _hybrid_report_search as _hrs
        _hybrid = _hrs(case_key, query) or ''
    except Exception:
        _hybrid = ''
    qdrant = QDRANT_URL.rstrip('/')
    embed_url = EMBED_URL.rstrip('/')
    embed_model = EMBED_MODEL
    try:
        # Get embedding for query
        emb_resp = _http_json('POST', f'{embed_url}/v1/embeddings',
                              body={'model': embed_model, 'input': query}, timeout=30)
        vector = (emb_resp.get('data') or [{}])[0].get('embedding')
        if not vector:
            return 'ERROR: не вдалось отримати embedding'
        # Search kb_reports
        search_body = {
            'vector': vector,
            'limit': 5,
            'with_payload': True,
            'score_threshold': 0.3,
        }
        # 02.10.2026: every kb_reports point carries case_key; without this filter the chat of one
        # case quoted the expert PDF reports of other clients
        if case_key:
            search_body['filter'] = {'must': [{'key': 'case_key', 'match': {'value': case_key}}]}
        result = _http_json('POST', f'{qdrant}/collections/kb_reports/points/search',
                            body=search_body, timeout=30)
        points = result.get('result') or []
        if not points:
            return _hybrid if _hybrid else 'kb_reports: нічого не знайдено для цього запиту.'
        out = ([_hybrid, ''] if _hybrid else []) + [f'=== ЗНАХІДКИ З PDF ЗВІТІВ (запит: {query[:60]}) ===']
        for p in points:
            pl = p.get('payload', {})
            src = pl.get('source_file', pl.get('file_name', '?'))[:50]
            text = pl.get('text', pl.get('content', ''))[:400]
            score = round(p.get('score', 0), 2)
            out.append(f'\n[{src}] score={score}:\n{text}')
        return '\n'.join(out)
    except Exception as e:
        return (_hybrid + '\n' if _hybrid else '') + f'ERROR search_reports: {e}'


_sql_schema_hint_cache = {}


def sql_schema_hint():
    """Compact `table(col,col,...)` listing of the allowlisted tables that really exist.

    Built from information_schema and cached per process: a hardcoded list would drift
    from the database the first time a parser adds a column, and the model would go back
    to guessing. Only tables present in the DB are listed, so the model is never pointed
    at an allowlisted table that no parser has created yet.

    Why this exists: measured on job e445d30f the agent burned 3 of its 11 tool calls
    discovering that event_logs_v2 has event_ts and not event_time.
    """
    if _sql_schema_hint_cache.get('txt'):
        return _sql_schema_hint_cache['txt']
    try:
        import psycopg2 as _pg
        with _pg.connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT table_name, column_name FROM information_schema.columns "
                    "WHERE table_schema='public' AND table_name = ANY(%s) "
                    "ORDER BY table_name, ordinal_position",
                    (sorted(_SQL_ALLOWLIST_TABLES),))
                cols = {}
                for _t, _c in cur.fetchall():
                    cols.setdefault(_t, []).append(_c)
        txt = chr(10).join('%s(%s)' % (t, ','.join(cols[t])) for t in sorted(cols))
        txt += (chr(10) + 'УВАГА: payload - це jsonb. Для пошуку тексту в ньому пиши '
                          'payload::text ILIKE ... , а не payload LIKE ...')
    except Exception as _e:
        _log.error('[schema_hint] failed: %s' % _e)
        txt = ''
    _sql_schema_hint_cache['txt'] = txt
    return txt


_SQL_ALLOWLIST_TABLES = frozenset([
    'event_logs_v2', 'filesystem_v2', 'program_exec_v2', 'srum_v2',
    'tool_alerts_v2', 'raw_fallback_v2', 'system_profile_v1',
    'case_iocs', 'trigger_results_v2', 'dfir_eval_answers_v1',
    'dfir_eval_questions_v1', 'browser_downloads_v2', 'browser_history_v2',
    'regripper_v2', 'shellbags_v2', 'lnk_v2', 'thor_file_hashes_v2',
    'cases', 'ingest_files',
])
_SQL_FORBIDDEN_KEYWORDS = frozenset([
    'drop', 'delete', 'insert', 'update', 'truncate', 'create', 'alter',
    'grant', 'revoke', 'copy', 'vacuum', 'reindex', 'cluster', 'pg_read_file',
    'pg_execute_server_program', 'pg_reload_conf', 'pg_terminate_backend',
    # Postgres can read the filesystem of its own container as well. The connection is a
    # superuser one, and a read-only transaction does not stop a read - so the functions
    # that read files and directories are named here explicitly (added 2026-09-18 while
    # answering "can the LLM pull files off our machines?").
    'pg_read_binary_file', 'pg_ls_dir', 'pg_stat_file', 'pg_ls_waldir',
    'pg_ls_logdir', 'pg_ls_tmpdir', 'lo_import', 'lo_export', 'dblink',
    'dblink_exec', 'pg_file_read', 'pg_logdir_ls', 'pg_authid', 'pg_shadow',
])

_CASE_TABS_CACHE = {'t': 0.0, 'v': frozenset()}


def _case_data_tables():
    """Every public table that has a case_key column (refreshed every 10 min)."""
    import time as _t
    if _CASE_TABS_CACHE['v'] and _t.time() - _CASE_TABS_CACHE['t'] < 600:
        return _CASE_TABS_CACHE['v']
    try:
        with psycopg2.connect(PG_DSN) as _c:
            with _c.cursor() as _cu:
                _cu.execute("SELECT DISTINCT table_name FROM information_schema.columns "
                            "WHERE table_schema='public' AND column_name='case_key'")
                _CASE_TABS_CACHE['v'] = frozenset(r[0] for r in _cu.fetchall())
                _CASE_TABS_CACHE['t'] = _t.time()
    except Exception:
        pass
    return _CASE_TABS_CACHE['v'] or frozenset(_SQL_ALLOWLIST_TABLES)


def scope_sql_to_case(q_str, case_key):
    """(query, error). CASE SCOPE (02.10.2026): every case-data table the query mentions is shadowed
    by a CTE holding only this case's rows, so UNION parts, subqueries, comma joins and a foreign
    case_key literal all see this case and nothing else. Schema-qualified names would bypass the
    shadow and are refused, as are case-data tables outside the allowlist and Postgres system
    functions (the server can read its own files)."""
    case_key_sql = str(case_key or '').replace("'", "''")
    _ql = str(q_str or '').lower()
    if re.search(r'\b(public|pg_catalog|information_schema|pg_temp\w*)\s*"?\s*\.', _ql) or re.search(r'"\s*\.\s*"', _ql):
        return q_str, 'звертайтесь до таблиць без схеми (public./pg_catalog. заборонені)'
    _tok = set(re.findall(r'[a-z_][a-z0-9_]*', _ql))
    _case_tabs = _case_data_tables()
    _foreign = sorted((_tok & _case_tabs) - set(_SQL_ALLOWLIST_TABLES))
    if _foreign:
        return q_str, 'таблиці недоступні агенту: %s' % ', '.join(_foreign[:5])
    if re.search(r'\b(pg_\w+|dblink\w*|lo_\w+|current_setting|set_config|query_to_xml\w*)\s*\(', _ql) and not re.search(r'\bpg_typeof\s*\(', _ql):
        return q_str, 'системні функції Postgres недоступні агенту'
    _shadow = sorted(_tok & _case_tabs & set(_SQL_ALLOWLIST_TABLES))
    if _shadow:
        q_str = 'WITH ' + ', '.join(
            '%s AS NOT MATERIALIZED (SELECT * FROM public.%s WHERE case_key=\'%s\')' % (t, t, case_key_sql)
            for t in _shadow) + ' ' + q_str
    return q_str, None


def _agent_tool_run_sql(case_key, query):
    """Execute SELECT-only query via a read-only DB connection."""
    q_str = str(query or '').strip()
    q_str = re.sub(r"->>\s*''(\w+)''", r"->>'\1'", q_str)  # repair LLM doubled jsonb quotes
    # payload is jsonb; `payload LIKE '%x%'` has no operator. The model cannot know that
    # from a column list, so cast rather than hand back a syntax error.
    q_str = re.sub(r"(?i)\bpayload\s+(NOT\s+)?(I?LIKE|~~)\b",
                   lambda m: "payload::text " + (m.group(1) or "") + m.group(2), q_str)
    case_key_sql = str(case_key or '').replace("'", "''")
    # The tool catalog documents the filter as `case_key=<this>`, and the model does
    # exactly that - measured on job c8c2a012, two of three SQL calls died on
    # `syntax error at or near "<"`. The placeholder is ours, so resolve it here instead
    # of spending the model's calls on it. Any quoting the model added is absorbed too.
    q_str = re.sub(r"""(?i)(['"]?)<\s*(this|case[_ ]?key|case)\s*>\1""",
                   "'" + case_key_sql + "'", q_str)
    if not q_str.upper().startswith('SELECT'):
        return 'ERROR: тільки SELECT запити дозволені'
    if len(q_str) > 3000:
        return 'ERROR: запит занадто довгий (max 3000 chars)'
    tokens = set(re.split(r'\W+', q_str.lower()))
    bad = tokens & _SQL_FORBIDDEN_KEYWORDS
    if bad:
        return f'ERROR: заборонені ключові слова: {bad}'
    q_str, _scope_err = scope_sql_to_case(q_str, case_key)
    if _scope_err:
        return 'ERROR: ' + _scope_err
    if 'limit' not in q_str.lower():
        q_str += ' LIMIT 30'
    try:
        # Use autocommit=False + read-only transaction for extra safety
        conn = psycopg2.connect(PG_DSN)
        try:
            conn.autocommit = False
            conn.set_session(readonly=True)
            with conn.cursor() as cur:
                cur.execute(q_str)
                rows = cur.fetchall()
                cols = [d[0] for d in cur.description] if cur.description else []
        finally:
            conn.rollback()
            conn.close()
        if not rows:
            return "Результат порожній."
        out = [' | '.join(str(c) for c in cols)]
        for r in rows[:40]:
            out.append(' | '.join(str(v)[:80] for v in r))
        return '\n'.join(out)
    except Exception as e:
        return f"SQL ERROR: {e}"


# Runs FIRST inside the child, before anything the model wrote. An audit hook cannot be
# uninstalled, and it sees operations at the interpreter level rather than as source text,
# so it is not defeated by spelling `open` differently.
_SCRIPT_SANDBOX_HEADER = (
    "import sys as _s, os as _o, sysconfig as _sc\n"
    "_ALLOW = ('/tmp/',)\n"
    "_LIB = tuple(p for p in (_sc.get_paths().get('stdlib'), _sc.get_paths().get('purelib'),\n"
    "                         _sc.get_paths().get('platlib'), _s.prefix, _s.base_prefix) if p)\n"
    "def _audit(event, args):\n"
    "    if event in ('open', 'os.open'):\n"
    "        p = args[0]\n"
    "        if not isinstance(p, str):\n"
    "            return\n"
    "        full = _o.path.realpath(p)\n"
    "        if full.startswith(_ALLOW) or full.startswith(_LIB):\n"
    "            return\n"
    "        raise PermissionError('sandbox: читання поза /tmp заборонено: ' + p)\n"
    "    if event in ('os.listdir', 'os.scandir'):\n"
    "        p = args[0] if args and isinstance(args[0], str) else '/'\n"
    "        full = _o.path.realpath(p)\n"
    "        if not (full.startswith(_ALLOW) or full.startswith(_LIB)):\n"
    "            raise PermissionError('sandbox: перелік теки заборонено: ' + p)\n"
    "    if event.startswith(('subprocess.', 'os.exec', 'os.spawn', 'os.posix_spawn',\n"
    "                         'ctypes.', 'os.system', 'winreg.')):\n"
    "        raise PermissionError('sandbox: заборонена операція ' + event)\n"
    "_s.addaudithook(_audit)\n"
    "del _audit\n"
)

_UNPRIV_NAMES = ('nobody', 'daemon')


def _unpriv_ids():
    """(uid, gid) of an account with no privileges, or None if there is none to use.

    None means the caller must refuse to run. Running analysis scripts as root is what made
    the private key readable in the first place; if we cannot drop that, we do not execute.
    """
    try:
        import pwd
    except Exception:
        return None
    for name in _UNPRIV_NAMES:
        try:
            e = pwd.getpwnam(name)
            if e.pw_uid > 0:
                return e.pw_uid, e.pw_gid
        except KeyError:
            continue
        except Exception:
            return None
    return None


def _agent_tool_run_temp_script(case_key, script_code, description=''):
    """Execute a temporary Python script for forensic analysis. READ-ONLY: no network, no file writes outside /tmp."""
    import subprocess, tempfile, os, re

    code = str(script_code or '').strip()
    if not code:
        return 'ERROR: порожній скрипт'
    if len(code) > 8000:
        return 'ERROR: скрипт занадто довгий (max 8000 chars)'

    # Safety: block dangerous operations
    forbidden_patterns = [
        r'\bos\.system\b', r'\bsubprocess\.(Popen|run|call|check_output)\b',
        r'\bshutil\.(rmtree|move|copy)\b', r'\bopen\s*\(.*["\']w["\']',
        r'\bimport\s+socket\b', r'\burllib\b', r'\brequests\b',
        r'\beval\s*\(', r'\bexec\s*\(',
        r'\bos\.(remove|unlink|rename|makedirs|mkdir)\b',
        r'__import__', r'importlib\.import_module',
    ]
    for pat in forbidden_patterns:
        if re.search(pat, code):
            return f'ERROR: заборонена операція ({pat})'

    # Inject PG_DSN and case_key as constants
    header = (
        _SCRIPT_SANDBOX_HEADER +
        "import psycopg2, json, re, datetime, collections\n"
        f"PG_DSN = {PG_DSN!r}\n"
        f"CASE_KEY = {case_key!r}\n"
        "def pg_query(sql, params=None):\n"
        "    with psycopg2.connect(PG_DSN) as c:\n"
        "        with c.cursor() as cur:\n"
        "            cur.execute(sql, params)\n"
        "            cols = [d[0] for d in cur.description] if cur.description else []\n"
        "            return [dict(zip(cols, r)) for r in cur.fetchall()]\n\n"
    )
    full_code = header + code

    # The real control is not the pattern list above - patterns are guessable and
    # bypassable. It is that this script does not run as root, so the private key (600,
    # root) and everything else that is not world-readable is simply unreadable to it.
    unpriv = _unpriv_ids()
    if unpriv is None:
        return ('ERROR: не можу знизити права для запуску скрипта - виконання скасовано. '
                'Це захист: скрипт не має працювати від root.')
    uid, gid = unpriv

    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', prefix='dfir_tmp_',
                                         dir='/tmp', delete=False, encoding='utf-8') as f:
            f.write(full_code)
            tmp_path = f.name
        os.chmod(tmp_path, 0o644)      # the unprivileged child has to be able to read it

        result = subprocess.run(
            [sys.executable or 'python3', tmp_path],
            capture_output=True, text=True, timeout=30, cwd='/tmp',
            user=uid, group=gid,
            env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/tmp',
                 'PYTHONDONTWRITEBYTECODE': '1'}
        )
        os.unlink(tmp_path)

        stdout = (result.stdout or '')[:2000]
        stderr = (result.stderr or '')[:500]
        if result.returncode != 0:
            return f"SCRIPT ERROR (rc={result.returncode}):\n{stderr}\n{stdout}"
        return stdout if stdout else '(порожній вивід)'
    except subprocess.TimeoutExpired:
        try: os.unlink(tmp_path)
        except Exception: pass
        return 'ERROR: скрипт перевищив час виконання (30s)'
    except Exception as e:
        return f'ERROR: {e}'


def _agent_tool_search_knowledge_base(query):
    """Semantic search in DFIR knowledge base (books/methodology)."""
    try:
        qdrant = QDRANT_URL.rstrip('/')
        embed_url = EMBED_URL.rstrip('/')
        embed_model = EMBED_MODEL
        collection = TEXT_COLL_PRIMARY

        emb_resp = _http_json('POST', f"{embed_url}/v1/embeddings",
                              body={'model': embed_model, 'input': query}, timeout=60)
        vec = ((emb_resp or {}).get('data') or [{}])[0].get('embedding')
        if not vec:
            return "Не вдалося отримати embedding для пошуку."

        # books-only filter: kb_text holds books (case_key=LESSONS) + a few stray
        # case-PDF chunks; restrict book-RAG to books (quality + privacy: case
        # evidence must NOT surface as general knowledge).
        result = _http_json('POST', f"{qdrant}/collections/{collection}/points/search",
                            body={'vector': vec, 'limit': 5, 'with_payload': True,
                                  'filter': {'must': [{'key': 'case_key', 'match': {'value': 'LESSONS'}}]}}, timeout=30)
        hits = (result or {}).get('result') or []
        if not hits:
            return "Нічого не знайдено в базі знань."

        out = []
        for h in hits:
            payload = h.get('payload', {})
            text = str(payload.get('text', payload.get('chunk', '')))[:600]
            src = payload.get('source_file', '')
            score = round(h.get('score', 0), 3)
            out.append(f"[score={score} | {src}]\n{text}")
        return '\n\n'.join(out)
    except Exception as e:
        return f"KB search error: {e}"

def _agent_tool_get_defender_events(case_key, limit=int(40 * _ROW_SCALE)):
    """EID 1116/1118/1119/1120/5001/5007/5010/5012/5013 — Defender detections + tampering."""
    limit = min(int(limit or 40), 80)
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT event_ts, event_id, target_user, computer, command_line, process_name, source_file, payload
                    FROM event_logs_v2
                    WHERE case_key=%s
                      AND event_id IN (1008,1009,1011,1013,1116,1117,1118,1119,1120,1121,1122,5001,5004,5007,5010,5012,5013,5100,5101)
                      AND channel ILIKE '%%Windows Defender%%'
                    ORDER BY event_ts ASC NULLS LAST
                    LIMIT %s
                """, (case_key, limit))
                rows = cur.fetchall()
        _desc = {
            1008:'Malware action taken', 1009:'Malware quarantined', 1011:'Malware removed from quarantine',
            1013:'Malware history deleted',
            1116:'Malware detected', 1117:'Malware action taken', 1118:'Remediation started',
            1119:'Remediation succeeded', 1120:'Remediation failed', 1121:'BAFS action taken',
            1122:'BAFS action not taken', 5001:'Defender disabled', 5004:'Defender disabled',
            5007:'Config/exclusions changed', 5010:'Protection disabled', 5012:'Protection disabled',
            5013:'Protection disabled', 5100:'Antimalware platform expiring', 5101:'Platform expired'
        }
        if not rows:
            # fallback: search tool_alerts_v2 for defender-related alerts
            with psycopg2.connect(PG_DSN) as conn:
                conn.autocommit = True
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT event_ts, rule, severity, details, ioc_value
                        FROM tool_alerts_v2
                        WHERE case_key=%s AND (lower(rule) LIKE '%%defender%%' OR lower(rule) LIKE '%%malware%%'
                              OR lower(rule) LIKE '%%tamper%%' OR lower(rule) LIKE '%%exclusion%%')
                        ORDER BY event_ts ASC NULLS LAST LIMIT %s
                    """, (case_key, limit))
                    rows2 = cur.fetchall()
            if not rows2: return "Defender/AV подій не знайдено."
            return '\n'.join(f"{r[0].isoformat()[:19] if r[0] else 'n/a'} | {r[1]} [{r[2]}] | {str(r[3] or '')[:150]} | ioc={r[4] or ''}" for r in rows2)
        out = []
        for r in rows:
            ts = r[0].isoformat()[:19] if r[0] else 'n/a'
            eid = r[1]
            desc = _desc.get(eid, f'EID={eid}')
            p = r[7] if isinstance(r[7], dict) else {}
            threat = p.get('ThreatName') or p.get('Threat Name') or p.get('PayloadData1') or ''
            path = p.get('Path') or p.get('FilePath') or p.get('PayloadData2') or ''
            action = p.get('Action') or p.get('PayloadData3') or ''
            user = r[2] or p.get('UserName') or ''
            flag = ' !!! TAMPER !!!' if eid in (5001,5004,5007,5010,5012,5013) else ''
            out.append(f"{ts} | {desc}{flag} | EID={eid} | threat={str(threat)[:80]} | path={str(path)[:100]} | action={action} | user={user} | {r[6]}")
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"


def _agent_tool_get_powershell_events(case_key, limit=int(40 * _ROW_SCALE)):
    """EID 4104/4103/400/403 + suspicious PowerShell: -enc, IEX, DownloadString, Add-MpPreference."""
    limit = min(int(limit or 40), 80)
    _SUSP_PS = ['encodedcommand','-enc ','iex ','invoke-expression','downloadstring','frombase64string',
                'webclient','invoke-webrequest','add-mppreference','set-mppreference','bypass',
                'hidden','windowstyle','noprofile','noexit','cmd /c','wscript','cscript','mshta',
                'rundll32','regsvr32','rclone','psexec','sdelete','7z.exe','7za.exe']
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # EID 4104 = script block logging; also search payload for hidden PS commands (EID 400/403)
                cur.execute("""
                    SELECT event_ts, event_id, target_user, computer, command_line, process_name, source_file, payload
                    FROM event_logs_v2
                    WHERE case_key=%s
                      AND event_id IN (4103,4104,400,403,4688)
                      AND (lower(coalesce(command_line,'')) LIKE ANY(%s)
                           OR lower(coalesce(process_name,'')) LIKE ANY(%s)
                           OR lower(payload::text) LIKE ANY(%s))
                    ORDER BY event_ts ASC NULLS LAST
                    LIMIT %s
                """, (case_key,
                      [f'%%{k}%%' for k in _SUSP_PS],
                      ['%%powershell%%','%%pwsh%%'],
                      [f'%%{k}%%' for k in _SUSP_PS],
                      limit))
                rows = cur.fetchall()
        if not rows: return "Підозрілих PowerShell подій не знайдено."
        _eid_desc = {4104:'PS ScriptBlock',4103:'PS Module',400:'PS Start',403:'PS Stop',4688:'Process Created'}
        out = []
        for r in rows:
            ts = r[0].isoformat()[:19] if r[0] else 'n/a'
            eid = r[1]
            cmd = str(r[4] or '')[:200]
            p = r[7] if isinstance(r[7], dict) else {}
            script = str(p.get('ScriptBlockText') or p.get('PayloadData1') or '')[:200]
            content = _pd1_clean(script if script else cmd)
            _cl = content.lower()
            if (len(content.strip()) < 8 or 'cmdletization' in _cl or '#requires -version' in _cl
                    or ('set-strictmode' in _cl and 'microsoft.powershell' in _cl)):
                continue  # Microsoft PS module auto-generated boilerplate — not an attacker script
            out.append(f"{ts} | {_eid_desc.get(eid,f'EID={eid}')} | user={r[2] or ''} | {content} | {r[6]}")
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"


def _agent_tool_get_persistence_events(case_key, limit=int(40 * _ROW_SCALE)):
    """EID 4698/4699/4700/4701/4702/4697/7045/7040 — task/service persistence."""
    limit = min(int(limit or 40), 80)
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT event_ts, event_id, target_user, computer, command_line, process_name, source_file, payload
                    FROM event_logs_v2
                    WHERE case_key=%s
                      AND event_id IN (4697,4698,4699,4700,4701,4702,7045,7040,7035,7036,106)
                    ORDER BY event_ts ASC NULLS LAST
                    LIMIT %s
                """, (case_key, limit))
                rows = cur.fetchall()
        _desc = {
            4697:'Service installed', 4698:'Task created', 4699:'Task deleted',
            4700:'Task enabled', 4701:'Task disabled', 4702:'Task updated',
            7045:'Service installed (System)', 7040:'Service start type changed',
            7035:'Service control sent', 7036:'Service state changed', 106:'Task registered'
        }
        if not rows: return "Persistence подій не знайдено."
        out = []
        for r in rows:
            ts = r[0].isoformat()[:19] if r[0] else 'n/a'
            eid = r[1]
            p = r[7] if isinstance(r[7], dict) else {}
            name = p.get('ServiceName') or p.get('TaskName') or p.get('PayloadData1') or r[5] or ''
            path = p.get('ImagePath') or p.get('CommandLine') or p.get('PayloadData2') or r[4] or ''
            acct = p.get('AccountName') or p.get('SubjectUserName') or r[2] or ''
            flag = ' !!! PERSISTENCE !!!' if eid in (4698,4697,7045,4702) else ''
            out.append(f"{ts} | {_desc.get(eid,f'EID={eid}')}{flag} | name={str(name)[:80]} | path={str(path)[:120]} | acct={acct} | {r[6]}")
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"


def _agent_tool_get_tampering_events(case_key, limit=int(40 * _ROW_SCALE)):
    """EID 1100/1102/104/4719/4907/4616/1074/5001/5007 — log clearing, audit policy, time change."""
    limit = min(int(limit or 40), 80)
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT event_ts, event_id, target_user, computer, command_line, process_name, source_file, payload
                    FROM event_logs_v2
                    WHERE case_key=%s
                      AND (
                          (event_id IN (1100,1102,4719,4907,4616) AND channel ILIKE '%%Security%%')
                          OR (event_id IN (104,1074) AND (channel ILIKE '%%System%%' OR channel ILIKE '%%Eventlog%%'))
                          OR (event_id IN (5001,5007) AND channel ILIKE '%%Windows Defender%%')
                      )
                    ORDER BY event_ts ASC NULLS LAST
                    LIMIT %s
                """, (case_key, limit))
                rows = cur.fetchall()
        _desc = {
            1100:'EventLog service shutdown', 1102:'Security log cleared !!!',
            104:'System log cleared !!!', 4719:'Audit policy changed',
            4907:'Audit settings changed', 4616:'System time changed',
            1074:'Shutdown/Restart', 5001:'Defender disabled !!!', 5007:'Defender config changed'
        }
        if not rows: return "Tampering/evasion подій не знайдено."
        out = []
        for r in rows:
            ts = r[0].isoformat()[:19] if r[0] else 'n/a'
            eid = r[1]
            p = r[7] if isinstance(r[7], dict) else {}
            user = p.get('SubjectUserName') or r[2] or ''
            channel = p.get('Channel') or p.get('PayloadData1') or ''
            detail = str(p.get('PayloadData2') or p.get('NewValue') or p.get('OldValue') or '')[:100]
            out.append(f"{ts} | {_desc.get(eid,f'EID={eid}')} | user={user} | channel={channel} | {detail} | {r[6]}")
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"


def _agent_tool_get_lateral_movement(case_key, limit=int(40 * _ROW_SCALE)):
    """EID 5140/5142/5145/4771/4776/4768/4769 + type3/type10 logons — lateral movement indicators."""
    limit = min(int(limit or 40), 80)
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT event_ts, event_id, target_user, remote_host, logon_type, computer, source_file, payload
                    FROM event_logs_v2
                    WHERE case_key=%s
                      AND (
                        event_id IN (5140,5142,5145,4771,4776,4768,4769)
                        OR (event_id = 4624 AND logon_type IN (3,10))
                        OR (event_id = 4648)
                      )
                    ORDER BY event_ts ASC NULLS LAST
                    LIMIT %s
                """, (case_key, limit))
                rows = cur.fetchall()
        _desc = {
            5140:'Share accessed', 5142:'Share added', 5145:'Share access check',
            4771:'Kerberos pre-auth failed', 4776:'NTLM validation',
            4768:'Kerberos TGT', 4769:'Kerberos TGS',
            4624:'Logon (type3=Network/type10=RDP)', 4648:'Explicit credentials'
        }
        if not rows: return "Lateral movement подій не знайдено."
        out = []
        for r in rows:
            ts = r[0].isoformat()[:19] if r[0] else 'n/a'
            eid = r[1]
            p = r[7] if isinstance(r[7], dict) else {}
            share = p.get('ShareName') or p.get('ObjectName') or p.get('TargetServerName') or ''
            src_ip = str(r[3] or p.get('IpAddress') or '')
            logtype = f" type={r[4]}" if r[4] else ''
            flag = ' !!! LATERAL !!!' if eid in (5140,5145,4771,4648) else ''
            out.append(f"{ts} | {_desc.get(eid,f'EID={eid}')}{flag} | user={r[2] or ''}{logtype} | from={src_ip} | target={str(share)[:80]} | {r[6]}")
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"


def _agent_tool_get_artifacts_confirmation(case_key, limit=int(40 * _ROW_SCALE)):
    """Prefetch (extension=pf), LNK in Recent, Zone.Identifier (extension=identifier) — execution/download confirmation."""
    import json as _json
    limit = min(int(limit or 40), 80)
    out = []
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # 1. Prefetch — extension='pf' AND parent_path contains 'Prefetch'
                cur.execute("""
                    SELECT event_ts, file_name, parent_path, source_file
                    FROM filesystem_v2
                    WHERE case_key=%s
                      AND extension = 'pf'
                      AND parent_path ILIKE '%%Prefetch%%'
                      AND event_ts > '2020-01-01'
                    ORDER BY event_ts DESC NULLS LAST
                    LIMIT %s
                """, (case_key, limit // 2))
                for r in cur.fetchall():
                    ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                    out.append(f"{ts} | [Prefetch] {r[1]} | path={r[2]} | {r[3]}")

                # 2. LNK in Recent — execution/open history from shell
                cur.execute("""
                    SELECT event_ts, file_name, parent_path, source_file
                    FROM filesystem_v2
                    WHERE case_key=%s
                      AND extension = 'lnk'
                      AND parent_path ILIKE '%%Recent%%'
                      AND event_ts > '2020-01-01'
                    ORDER BY event_ts DESC NULLS LAST
                    LIMIT %s
                """, (case_key, limit // 3))
                for r in cur.fetchall():
                    ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                    out.append(f"{ts} | [LNK/Recent] {r[1]} | path={r[2]} | {r[3]}")

                # 3. Zone.Identifier — downloaded files (HostUrl/ReferrerUrl)
                cur.execute("""
                    SELECT event_ts, file_name, parent_path, payload, source_file
                    FROM filesystem_v2
                    WHERE case_key=%s
                      AND extension = 'identifier'
                      AND event_ts > '2020-01-01'
                    ORDER BY event_ts DESC NULLS LAST
                    LIMIT %s
                """, (case_key, limit // 3))
                for r in cur.fetchall():
                    ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                    payload = r[3] or {}
                    if isinstance(payload, str):
                        try: payload = _json.loads(payload)
                        except: payload = {}
                    zone_raw = payload.get('zone_id', '')
                    host_url = ''
                    ref_url = ''
                    for line in str(zone_raw).split('\n'):
                        if 'HostUrl=' in line: host_url = line.split('=', 1)[1].strip()[:100]
                        if 'ReferrerUrl=' in line: ref_url = line.split('=', 1)[1].strip()[:100]
                    url_info = f"host={host_url}" if host_url else f"ref={ref_url}" if ref_url else ''
                    out.append(f"{ts} | [Zone.Identifier] {r[1]} | {url_info} | path={r[2]} | {r[4]}")

        # Fallback: raw_fallback_v2
        if not out:
            with psycopg2.connect(PG_DSN) as conn:
                conn.autocommit = True
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT source_file, payload::text, created_at
                        FROM raw_fallback_v2
                        WHERE case_key=%s
                          AND (lower(source_file) LIKE '%%prefetch%%'
                               OR lower(source_file) LIKE '%%amcache%%'
                               OR lower(source_file) LIKE '%%lnk%%')
                        ORDER BY created_at DESC NULLS LAST
                        LIMIT %s
                    """, (case_key, limit))
                    for r in cur.fetchall():
                        raw = str(r[1])[:200] if r[1] else ''
                        out.append(f"{r[0]} | {raw}")
        if not out:
            return "Артефакти підтвердження (Prefetch/LNK/Zone.Identifier) не знайдено."
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"


def _agent_tool_get_ad_events(case_key, limit=int(40 * _ROW_SCALE)):
    """EID 4720/4722/4723/4724/4725/4726/4728/4732/4756/5136/4794 — AD/DC account/group changes."""
    limit = min(int(limit or 40), 80)
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT event_ts, event_id, target_user, computer, source_file, payload
                    FROM event_logs_v2
                    WHERE case_key=%s
                      AND event_id IN (4720,4722,4723,4724,4725,4726,4728,4729,4732,4733,
                                       4735,4737,4738,4740,4756,4757,4767,4794,5136,5137,5139,5141)
                    ORDER BY event_ts ASC NULLS LAST
                    LIMIT %s
                """, (case_key, limit))
                rows = cur.fetchall()
        _desc = {
            4720:'User created', 4722:'User enabled', 4723:'Password change attempt',
            4724:'Password reset', 4725:'User disabled', 4726:'User deleted',
            4728:'Global group member added', 4729:'Global group member removed',
            4732:'Local group member added', 4733:'Local group member removed',
            4735:'Local group changed', 4737:'Global group changed',
            4738:'User account changed', 4740:'Account locked out', 4756:'Universal group member added',
            4757:'Universal group member removed', 4767:'Account unlocked',
            4794:'DSRM password set attempt', 5136:'AD object modified',
            5137:'AD object created', 5139:'AD object moved', 5141:'AD object deleted'
        }
        if not rows: return "AD/DC подій не знайдено (або не доменний хост)."
        out = []
        for r in rows:
            ts = r[0].isoformat()[:19] if r[0] else 'n/a'
            eid = r[1]
            p = r[4] if isinstance(r[4], dict) else (r[5] if isinstance(r[5], dict) else {})
            target = p.get('TargetUserName') or p.get('SAMAccountName') or r[2] or ''
            actor = p.get('SubjectUserName') or ''
            group = p.get('TargetDomainName') or p.get('GroupName') or ''
            flag = ' !!! AD CHANGE !!!' if eid in (4720,4728,4732,4756,4794) else ''
            out.append(f"{ts} | {_desc.get(eid,f'EID={eid}')}{flag} | target={target} | actor={actor} | group={group} | {r[4]}")
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR: {e}"


# ─── 8 Deterministic Evidence Tools (dual-search: normalized + payload JSONB) ───

def _agent_tool_get_user_identity_evidence(case_key, username=''):
    """All evidence for a specific username: account events, logons, process paths.
    Searches BOTH normalized columns AND payload JSONB fields (PayloadData1, TargetUserName)."""
    if not username:
        return "username required"
    uname = username.strip().lower()
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT event_ts, event_id, target_user, remote_host,
                           payload->>'PayloadData1' as pd1,
                           payload->>'TargetUserName' as tun,
                           payload->>'SubjectUserName' as sun,
                           channel, source_file
                    FROM event_logs_v2
                    WHERE case_key=%s
                      AND (
                        lower(target_user) LIKE %s
                        OR lower(payload->>'PayloadData1') LIKE %s
                        OR lower(payload->>'TargetUserName') LIKE %s
                        OR lower(payload->>'SubjectUserName') LIKE %s
                        OR lower(payload->>'SAMAccountName') LIKE %s
                        OR lower(payload::text) LIKE %s
                      )
                    ORDER BY event_ts ASC NULLS LAST
                    LIMIT 50
                """, (case_key, f'%{uname}%', f'%{uname}%', f'%{uname}%',
                      f'%{uname}%', f'%{uname}%', f'%{uname}%'))
                logon_rows = cur.fetchall()

                cur.execute("""
                    SELECT event_ts, executable_name, full_path, min(source_file) AS source_file
                    FROM program_exec_v2
                    WHERE case_key=%s AND lower(full_path) LIKE %s
                    GROUP BY 1, 2, 3
                    ORDER BY event_ts ASC NULLS LAST, min(row_id) ASC LIMIT 20
                """, (case_key, f'%\\{uname}\\%'))
                exec_rows = cur.fetchall()

        _eid_map = {
            4624:'Logon', 4625:'Failed logon', 4647:'Logoff', 4648:'Explicit logon',
            4720:'Account created', 4722:'Account enabled', 4723:'Pwd change attempt',
            4724:'Pwd reset', 4725:'Account disabled', 4726:'Account deleted',
            4728:'Global group member added', 4732:'Local group member added',
            4733:'Local group member removed', 4738:'Account changed', 4740:'Account locked',
            4767:'Account unlocked', 4794:'DSRM pwd set'
        }
        out = [f"=== Докази для акаунту: {username} ===\n"]
        if not logon_rows and not exec_rows:
            return f"Жодних даних для акаунту '{username}' не знайдено ні в нормалізованих колонках, ні в payload."
        for r in logon_rows:
            ts = r[0].isoformat()[:19] if r[0] else 'n/a'
            eid = r[1]
            target = r[5] or r[2] or ''
            actor = r[6] or ''
            pd1 = r[4] or ''
            rhost = r[3] or ''
            out.append(f"{ts} | EID {eid} ({_eid_map.get(eid, '?')}) | target={target} | actor={actor} | ip={rhost} | pd1={pd1[:80]} | {r[7]} | {r[8]}")
        if exec_rows:
            out.append(f"\n--- Виконання з шляху користувача ---")
            for r in exec_rows:
                ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                out.append(f"{ts} | {r[1]} | {r[2]} | {r[3]}")
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR get_user_identity_evidence: {e}"


def _agent_tool_get_logon_rdp_evidence(case_key, keyword=''):
    """All RDP/remote logon events with source IPs from BOTH remote_host AND payload fields.
    EID 4624(type 10)/4625/1149/21/22/24/25/1102(RDPClient). Includes failed logons."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # RDP/network logons + failures
                cur.execute("""
                    SELECT event_ts, event_id, logon_type, target_user, remote_host,
                           payload->>'PayloadData1' as pd1,
                           payload->>'PayloadData2' as pd2,
                           payload->>'IpAddress' as ip_addr,
                           payload->>'WorkstationName' as wsname,
                           channel, source_file
                    FROM event_logs_v2
                    WHERE case_key=%s
                      AND (
                        (event_id IN (4624,4625,4648) AND logon_type IN ('10','3'))
                        OR event_id IN (1149, 21, 22, 24, 25, 40, 4778, 4779)
                        OR (event_id=1102 AND channel ILIKE '%%RDPClient%%')
                      )
                    ORDER BY event_ts ASC NULLS LAST
                    LIMIT 60
                """, (case_key,))
                rows = cur.fetchall()

        if not rows:
            return "Жодних RDP/мережевих сесій не знайдено."

        _eid_map = {
            4624:'Logon', 4625:'Failed logon', 4648:'Explicit logon',
            1149:'RDP auth', 21:'RDP logon', 22:'RDP logon', 24:'RDP reconnect',
            25:'RDP reconnect', 40:'RDP disconnect', 4778:'Session reconnect',
            4779:'Session disconnect', 1102:'RDP connection IP (RDPClient)'
        }
        out = ["=== RDP / Мережеві сесії ===\n"]
        kw = keyword.strip().lower() if keyword else ''
        for r in rows:
            ts = r[0].isoformat()[:19] if r[0] else 'n/a'
            eid = r[1]
            ltype = r[2] or ''
            tuser = r[3] or ''
            # get best IP: remote_host > IpAddress > PayloadData1 > PayloadData2
            ip = r[4] or r[7] or ''
            pd1 = r[5] or ''
            if not ip and 'Address:' in pd1:
                ip = pd1.split('Address:')[-1].strip().split()[0]
            pd2 = r[6] or ''
            ws = r[8] or ''
            ch = r[9] or ''
            sf = r[10] or ''
            line = f"{ts} | EID {eid} ({_eid_map.get(eid, '?')}) | type={ltype} | user={tuser} | ip={ip} | ws={ws} | pd1={pd1[:60]} | {sf}"
            if kw and kw not in line.lower():
                continue
            out.append(line)
        if len(out) == 1:
            return f"Немає RDP подій, що відповідають фільтру '{keyword}'."
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR get_logon_rdp_evidence: {e}"


def _agent_tool_get_ioc_evidence(case_key):
    """Comprehensive IOC sweep across ALL tables. Finds: suspicious executables, known RAT/malware
    tools (ngrok/rdpwrap/7za/fiddler/rms/litemanager/nott/try.exe/start.vbs etc.),
    browser downloads, Zone.Identifier URLs, shellbag unusual paths.
    Searches BOTH normalized columns AND payload JSONB fields."""
    # '7za' is deliberately absent: a generic archiver, and the one our collector ships in
    # its staging folder. An archiver is evidence only with a path or a command line.
    _MALWARE_KEYWORDS = [
        'ngrok', 'rdpwrap', 'rdpwinst', 'fiddler', 'trustcert',
        'nott.exe', 'not.exe', 'try.exe', 'start.vbs', 'rms.exe', 'rfusclient',
        'rutserv', 'litemanager', 'radmin', 'ammyy', 'anydesk', 'teamviewer',
        'rdc_man', 'mimikatz', 'meterpreter', 'cobalt', 'netcat', 'nc.exe',
        'psexec', 'wce.exe', 'procdump', 'nanodump', 'wmiexec', 'atera',
        'screenconnect', 'netsupport', 'edit_test', 'run.exe', 'upd2.exe',
        'sys32.exe', 'system32.exe', 'win64.exe', 'svchost32'
    ]
    _SUSPICIOUS_PATHS = [
        '%\\\\temp\\\\%', '%\\\\downloads\\\\%', '%\\public\\documents\\%',
        '%\\appdata\\roaming\\%', '%\\appdata\\local\\temp\\%',
        'c:\\%\\users\\public\\%', 'c:\\programdata\\%'
    ]
    try:
        out = ["=== Комплексний IOC Sweep ===\n"]
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # 1. Known malware tool names in program_exec_v2
                kw_conditions = ' OR '.join([f"lower(executable_name) LIKE %s OR lower(full_path) LIKE %s"
                                              for _ in _MALWARE_KEYWORDS])
                kw_params = []
                for kw in _MALWARE_KEYWORDS:
                    kw_params += [f'%{kw}%', f'%{kw}%']
                cur.execute(f"""
                    SELECT event_ts, executable_name, full_path, min(source_file) AS source_file
                    FROM program_exec_v2
                    WHERE case_key=%s AND ({kw_conditions})
                    GROUP BY 1, 2, 3
                    ORDER BY event_ts ASC NULLS LAST, min(row_id) ASC LIMIT 40
                """, [case_key] + kw_params)
                exec_hits = cur.fetchall()
                if exec_hits:
                    out.append("--- Відомі RAT/Malware інструменти (program_exec_v2) ---")
                    for r in exec_hits:
                        ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                        out.append(f"  {ts} | {r[1]} | {r[2]} | {r[3]}")

                # 2. Suspicious path executions (not known-legit)
                path_conditions = ' OR '.join([f"lower(full_path) LIKE %s" for _ in _SUSPICIOUS_PATHS])
                path_params = list(_SUSPICIOUS_PATHS)
                cur.execute(f"""
                    SELECT event_ts, executable_name, full_path, min(source_file) AS source_file
                    FROM program_exec_v2
                    WHERE case_key=%s AND ({path_conditions})
                      AND lower(executable_name) NOT LIKE '%%google%%'
                      AND lower(executable_name) NOT LIKE '%%microsoft%%'
                      AND lower(executable_name) NOT LIKE '%%windows%%'
                      AND lower(executable_name) NOT LIKE '%%websigner%%'
                      AND lower(executable_name) NOT LIKE '%%barscrip%%'
                      AND lower(executable_name) NOT LIKE '%%eusign%%'
                      AND lower(executable_name) NOT LIKE '%%whatsapp%%'
                      AND lower(executable_name) NOT LIKE '%%dismhost%%'
                    GROUP BY 1, 2, 3
                    ORDER BY event_ts ASC NULLS LAST, min(row_id) ASC LIMIT 30
                """, [case_key] + path_params)
                path_hits = cur.fetchall()
                if path_hits:
                    out.append("\n--- EXE з підозрілих шляхів (program_exec_v2) ---")
                    for r in path_hits:
                        ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                        out.append(f"  {ts} | {r[1]} | {r[2]} | {r[3]}")

                # 3. Malware in event_logs_v2 payload::text
                kw_payload_conditions = ' OR '.join([f"lower(payload::text) LIKE %s" for _ in _MALWARE_KEYWORDS[:15]])
                kw_payload_params = [f'%{kw}%' for kw in _MALWARE_KEYWORDS[:15]]
                cur.execute(f"""
                    SELECT event_ts, event_id, payload->>'PayloadData1', payload->>'PayloadData2', source_file
                    FROM event_logs_v2
                    WHERE case_key=%s AND ({kw_payload_conditions})
                    ORDER BY event_ts ASC NULLS LAST LIMIT 20
                """, [case_key] + kw_payload_params)
                evlog_hits = cur.fetchall()
                if evlog_hits:
                    out.append("\n--- Malware у Event Logs payload ---")
                    for r in evlog_hits:
                        ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                        out.append(f"  {ts} | EID {r[1]} | pd1={str(r[2] or '')[:80]} | pd2={str(r[3] or '')[:60]} | {r[4]}")

                # 4. Browser downloads (raw_fallback_v2)
                cur.execute("""
                    SELECT payload->>'start_time', payload->>'filename',
                           payload->>'target_path', payload->>'url', source_file
                    FROM raw_fallback_v2
                    WHERE case_key=%s AND parser_family='browser_downloads'
                      AND (
                        lower(payload->>'filename') LIKE '%%.exe%%'
                        OR lower(payload->>'filename') LIKE '%%.zip%%'
                        OR lower(payload->>'filename') LIKE '%%.rar%%'
                        OR lower(payload->>'filename') LIKE '%%.7z%%'
                        OR lower(payload->>'url') LIKE '%%swisstransfer%%'
                        OR lower(payload->>'url') LIKE '%%pixeldrain%%'
                        OR lower(payload->>'url') LIKE '%%fex.net%%'
                        OR lower(payload->>'url') LIKE '%%wetransfer%%'
                        OR lower(payload->>'url') LIKE '%%mega.nz%%'
                        OR lower(payload->>'url') LIKE '%%ukr.net%%'
                        OR lower(payload->>'url') LIKE '%%gofile%%'
                      )
                    ORDER BY (payload->>'start_time') ASC NULLS LAST LIMIT 20
                """, (case_key,))
                dl_hits = cur.fetchall()
                if dl_hits:
                    out.append("\n--- Підозрілі завантаження (browser_downloads) ---")
                    for r in dl_hits:
                        out.append(f"  {r[0] or 'n/a'} | {r[1] or 'n/a'} | {r[2] or 'n/a'} | url={str(r[3] or '')[:80]} | {r[4]}")

                # 5. Zone.Identifier external URLs
                cur.execute("""
                    SELECT event_ts, file_name, payload->>'zone_id', source_file
                    FROM filesystem_v2
                    WHERE case_key=%s
                      AND extension='identifier'
                      AND payload->>'zone_id' ILIKE '%%HostUrl%%'
                      AND (
                        lower(file_name) LIKE '%%.exe%%'
                        OR lower(file_name) LIKE '%%.zip%%'
                        OR lower(file_name) LIKE '%%.rar%%'
                        OR lower(file_name) LIKE '%%.7z%%'
                        OR lower(payload->>'zone_id') LIKE '%%swisstransfer%%'
                        OR lower(payload->>'zone_id') LIKE '%%pixeldrain%%'
                        OR lower(payload->>'zone_id') LIKE '%%fex.net%%'
                        OR lower(payload->>'zone_id') LIKE '%%wetransfer%%'
                        OR lower(payload->>'zone_id') LIKE '%%mega.nz%%'
                        OR lower(payload->>'zone_id') LIKE '%%ukr.net%%'
                        OR lower(payload->>'zone_id') LIKE '%%gofile%%'
                        OR lower(payload->>'zone_id') LIKE '%%ngrok%%'
                      )
                    ORDER BY event_ts ASC NULLS LAST LIMIT 20
                """, (case_key,))
                zone_hits = cur.fetchall()
                if zone_hits:
                    out.append("\n--- Zone.Identifier (джерело завантаження) ---")
                    for r in zone_hits:
                        ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                        zone = str(r[2] or '')
                        host = ''
                        for line in zone.split('\n'):
                            if 'HostUrl' in line:
                                host = line.strip()
                        out.append(f"  {ts} | {r[1]} | {host[:100]} | {r[3]}")

                # 6. Unusual shellbag paths (external drives, USB)
                cur.execute("""
                    SELECT payload->>'AbsolutePath', payload->>'LastWriteTime'
                    FROM raw_fallback_v2
                    WHERE case_key=%s AND parser_family='shellbags'
                      AND (
                        payload->>'AbsolutePath' LIKE 'D:\\\\%%'
                        OR payload->>'AbsolutePath' LIKE 'E:\\\\%%'
                        OR payload->>'AbsolutePath' LIKE 'F:\\\\%%'
                        OR payload->>'AbsolutePath' LIKE 'G:\\\\%%'
                        OR lower(payload->>'AbsolutePath') LIKE '%%usb%%'
                        OR lower(payload->>'AbsolutePath') LIKE '%%removable%%'
                        OR lower(payload->>'AbsolutePath') LIKE '%%desktop%%\\\\%%'
                      )
                      AND payload->>'AbsolutePath' NOT ILIKE '%%Windows%%'
                    ORDER BY payload->>'LastWriteTime' DESC NULLS LAST LIMIT 20
                """, (case_key,))
                sb_hits = cur.fetchall()
                if sb_hits:
                    out.append("\n--- Незвичайні Shellbag шляхи (зовнішні диски/USB/Desktop) ---")
                    for r in sb_hits:
                        out.append(f"  {r[1] or 'n/a'} | {r[0] or 'n/a'}")

        if len(out) == 1:
            return "IOC Sweep: нічого підозрілого не знайдено в жодній таблиці."
        total = sum(1 for line in out if line.startswith('  '))
        out.insert(1, f"Знайдено {total} IOC-артефактів у {len([l for l in out if l.startswith('---')])} категоріях.\n")
        return '\n'.join(out)
    except Exception as e:
        import traceback as _tb2
        return f"ERROR get_ioc_evidence: {e}\n{_tb2.format_exc()[:500]}"


# cross-case pivot: above the size of the whole case library on purpose, so
# the cap is a safety net and not a silent sampler of it.
_CROSS_CASE_LIMIT = 60


# per-bucket quota for the registry persistence tool: Run/RunOnce and
# Winlogon must never be crowded out by the thousands of service rows.
_REG_PERSIST_PER_BUCKET = 25


def _agent_tool_get_persistence_evidence(case_key, keyword=''):
    """Persistence mechanisms: scheduled tasks (EID 4698), services (7045/4697),
    registry Run keys. Searches BOTH normalized columns AND payload JSONB."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # Scheduled tasks
                kw_filter = ''
                kw_params = []
                if keyword:
                    kw_filter = "AND (lower(payload::text) LIKE %s OR lower(process_name) LIKE %s)"
                    kw_params = [f'%{keyword.lower()}%', f'%{keyword.lower()}%']
                cur.execute(f"""
                    SELECT event_ts, event_id,
                           payload->>'PayloadData1' as pd1,
                           payload->>'PayloadData2' as pd2,
                           payload->>'PayloadData3' as pd3,
                           payload->>'TaskName' as taskname,
                           process_name, source_file
                    FROM event_logs_v2
                    WHERE case_key=%s
                      AND event_id IN (4698,4699,4700,4701,4702,4697,7045,7040,7035,7036,106)
                      {kw_filter}
                    ORDER BY event_ts ASC NULLS LAST LIMIT 40
                """, [case_key] + kw_params)
                task_rows = cur.fetchall()

                # Registry autostart / persistence (RECmd) + RegRipper text.
                # Measured on the live base before rewriting this: the old arm demanded a
                # path separator AFTER "Run", but RECmd writes an autostart key as a LEAF
                # path that ENDS in "Run" -- so it matched 0 of the 410 rows whose KeyPath
                # contains "Run", and this tool had never once returned a real autostart
                # value. It also ordered by payload->>'timestamp', a key present on 0 of
                # 478701 registry rows (RECmd names it LastWriteTimestamp), and its
                # services arm pulled 40481 firewall-rule rows on one case, of which an
                # arbitrary 30 got printed. Selection now runs off RECmd's own ASEP labels
                # and leaf-anchored regexes -- no LIKE, so no backslash-escape trap.
                reg_kw_filter = ''
                reg_kw_params = []
                if keyword:
                    reg_kw_filter = "AND lower(payload::text) LIKE %s"
                    reg_kw_params = [f'%{keyword.lower()}%']
                cur.execute(f"""
                    WITH cand AS (
                        SELECT payload->>'KeyPath' AS kp,
                               payload->>'ValueName' AS vn,
                               coalesce(payload->>'ValueData', payload->>'ValueData2') AS vd,
                               coalesce(payload->>'LastWriteTimestamp',
                                        payload->>'Timestamp') AS ts,
                               source_file AS sf,
                               payload->>'Description' AS descr,
                               CASE
                                 WHEN payload->>'Description' ~* '^run'
                                   OR payload->>'KeyPath' ~* '(run|runonce|runservices|runservicesonce|run32)$'
                                   THEN 1
                                 WHEN payload->>'Description' ~* '^(winlogon|logonui|startup programs)'
                                   OR payload->>'KeyPath' ~* '(winlogon|image file execution options)'
                                   THEN 2
                                 WHEN payload->>'Description' ~* '^services (imagepath|objectname|displayname)'
                                   THEN 3
                                 ELSE 9 END AS rnk
                        FROM raw_fallback_v2
                        WHERE case_key=%s AND parser_family='registry'
                          AND (payload->>'Description' ILIKE 'Run%%'
                               OR payload->>'Description' ILIKE '%%Winlogon%%'
                               OR payload->>'Description' ILIKE 'LogonUI'
                               OR payload->>'Description' ILIKE 'Startup Programs'
                               OR payload->>'Description' ILIKE 'Services ImagePath'
                               OR payload->>'Description' ILIKE 'Services ObjectName'
                               OR payload->>'Description' ILIKE 'Services DisplayName'
                               OR payload->>'KeyPath' ILIKE '%%Run'
                               OR payload->>'KeyPath' ILIKE '%%RunOnce'
                               OR payload->>'KeyPath' ILIKE '%%Image File Execution Options%%')
                          {reg_kw_filter}
                    ), dedup AS (
                        -- RECmd runs several batch files over the same hives, so one
                        -- autostart value arrives 3x with only the source CSV differing;
                        -- on the biggest case that inflated Run/RunOnce from 21 to 61.
                        SELECT DISTINCT ON (rnk, kp, vn, vd) *
                        FROM cand WHERE rnk < 9
                        ORDER BY rnk, kp, vn, vd, sf
                    ), ranked AS (
                        SELECT dedup.*,
                               row_number() OVER (PARTITION BY rnk
                                                  ORDER BY ts DESC NULLS LAST, kp, vn) AS rn,
                               count(*) OVER (PARTITION BY rnk) AS tot
                        FROM dedup
                    )
                    SELECT kp, vn, vd, ts, sf, descr, rnk, rn, tot
                    FROM ranked WHERE rn <= {_REG_PERSIST_PER_BUCKET}
                    ORDER BY rnk ASC, rn ASC
                """, [case_key] + reg_kw_params)
                reg_rows = cur.fetchall()

                # RegRipper is free TEXT, not columns: its rows carry hive/plugin/text and
                # never a KeyPath, so the query above cannot see them. Measured value is
                # thin -- 844 rows on 2 cases, both of which already hold rich RECmd data,
                # and 595 of those rows are pure "not found" boilerplate -- so it stays a
                # secondary source: persistence plugins only, boilerplate stripped.
                cur.execute("""
                    SELECT payload->>'hive', payload->>'plugin', payload->>'text'
                    FROM raw_fallback_v2
                    WHERE case_key=%s AND parser_family LIKE 'regripper%%'
                      AND payload->>'plugin' IN (
                          'run','runonce','runservices','services','svc','svcdll','winlogon',
                          'imagefile','appinitdlls','load','schedtasks','tasks','runvirtual',
                          'userinit','startup','logon','appkeys','cmdproc','profiler')
                    ORDER BY payload->>'plugin', payload->>'hive', payload->>'text'
                """, (case_key,))
                rr_rows = cur.fetchall()

        _eid_map = {
            4698:'Scheduled task created', 4699:'Scheduled task deleted',
            4700:'Scheduled task enabled', 4701:'Scheduled task disabled',
            4702:'Scheduled task updated', 4697:'Service installed',
            7045:'New service installed', 7040:'Service config changed',
            7035:'Service start/stop', 7036:'Service state change', 106:'Task registered'
        }
        out = ["=== Persistence Artifacts ===\n"]
        _RANK_LABEL = {1: 'Run / RunOnce (автозапуск)',
                       2: 'Winlogon / Image File Execution Options',
                       3: 'Служби (ImagePath / ObjectName / DisplayName)'}
        if reg_rows:
            out.append("\n--- Реєстр: точки закріплення (RECmd) ---")
            _cur_rank = None
            for kp, vn, vd, ts, sf, descr, rnk, rn, tot in reg_rows:
                if rnk != _cur_rank:
                    _cur_rank = rnk
                    _shown = min(int(tot or 0), _REG_PERSIST_PER_BUCKET)
                    _sfx = (f' — показано {_shown} із {tot}' if int(tot or 0) > _shown
                            else f' ({tot})')
                    out.append(f"  [{_RANK_LABEL.get(rnk, '?')}{_sfx}]")
                out.append(f"    {ts or 'n/a'} | {kp or ''} | "
                           f"{vn or ''}={(vd or '')[:120]} | {descr or ''} | {sf}")
        if rr_rows:
            _rr = []
            for hive, plugin, text in rr_rows:
                # line 0 is "plugin v.YYYYMMDD", line 1 the plugin description
                for s in str(text or '').split('\n')[2:]:
                    s = s.strip()
                    if (not s or s.startswith('---') or s.startswith('*')
                            or s.lower().endswith('not found.')
                            or s.lower().startswith('lastwrite time')
                            or s.lower().startswith('analysis tip')):
                        continue
                    _rr.append(f"    [{hive or '?'}/{plugin or '?'}] {s[:160]}")
            _rr = list(dict.fromkeys(_rr))[:40]
            if _rr:
                out.append("\n--- Реєстр: RegRipper (текстовий вивід плагінів закріплення) ---")
                out.extend(_rr)
        if task_rows:
            out.append("--- Event Logs (tasks/services) ---")
            for r in task_rows:
                ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                eid = r[1]
                pd1 = r[2] or ''
                pd2 = r[3] or ''
                taskname = r[5] or r[6] or ''
                out.append(f"  {ts} | EID {eid} ({_eid_map.get(eid, '?')}) | name={taskname[:60]} | pd1={pd1[:80]} | pd2={pd2[:60]} | {r[7]}")
        if len(out) == 1:
            return f"Persistence artifacts: нічого не знайдено{(' для «' + keyword + '»') if keyword else ''}."
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR get_persistence_evidence: {e}"


def _agent_tool_get_process_file_evidence(case_key, keyword=''):
    """Process/file execution evidence: searches program_exec_v2 AND EID 4688 CommandLine
    in BOTH normalized process_name/command_line columns AND payload JSONB (PayloadData1/2).
    This is the payload-fallback tool for process questions."""
    if not keyword:
        return "keyword required (e.g. process name, path fragment, hash)"
    kw = keyword.strip().lower()
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT event_ts, executable_name, full_path,
                           min(hash_sha1) AS hash_sha1, min(source_file) AS source_file
                    FROM program_exec_v2
                    WHERE case_key=%s
                      AND (lower(executable_name) LIKE %s OR lower(full_path) LIKE %s OR hash_sha1 ILIKE %s)
                    GROUP BY 1, 2, 3
                    ORDER BY event_ts ASC NULLS LAST, min(row_id) ASC LIMIT 30
                """, (case_key, f'%{kw}%', f'%{kw}%', f'%{kw}%'))
                exec_rows = cur.fetchall()

                # EID 4688 + 4104 via normalized AND payload
                cur.execute("""
                    SELECT event_ts, event_id, process_name, command_line,
                           payload->>'PayloadData1' as pd1,
                           payload->>'PayloadData2' as pd2,
                           payload->>'NewProcessName' as npn,
                           payload->>'CommandLine' as cmdline_payload,
                           source_file
                    FROM event_logs_v2
                    WHERE case_key=%s
                      AND event_id IN (4688, 4104, 4103, 400, 403)
                      AND (
                        lower(process_name) LIKE %s
                        OR lower(command_line) LIKE %s
                        OR lower(payload->>'PayloadData1') LIKE %s
                        OR lower(payload->>'PayloadData2') LIKE %s
                        OR lower(payload->>'NewProcessName') LIKE %s
                        OR lower(payload->>'CommandLine') LIKE %s
                        OR lower(payload::text) LIKE %s
                      )
                    ORDER BY event_ts ASC NULLS LAST LIMIT 30
                """, (case_key, f'%{kw}%', f'%{kw}%', f'%{kw}%',
                      f'%{kw}%', f'%{kw}%', f'%{kw}%', f'%{kw}%'))
                evlog_rows = cur.fetchall()

        out = [f"=== Процеси/файли для: {keyword} ===\n"]
        if exec_rows:
            out.append("--- program_exec_v2 (Prefetch/Amcache/ShimCache) ---")
            for r in exec_rows:
                ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                out.append(f"  {ts} | {r[1]} | {r[2]} | sha1={r[3] or 'n/a'} | {r[4]}")
        if evlog_rows:
            out.append("\n--- Event Logs EID 4688/4104 (normalized + payload) ---")
            for r in evlog_rows:
                ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                eid = r[1]
                pname = r[6] or r[2] or ''
                cmdline = r[7] or r[3] or ''
                pd1 = r[4] or ''
                out.append(f"  {ts} | EID {eid} | proc={pname[:60]} | cmd={cmdline[:80]} | pd1={pd1[:60]} | {r[8]}")
        if len(out) == 1:
            return f"Жодних процесів/файлів для '{keyword}' не знайдено (ні normalized, ні payload)."
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR get_process_file_evidence: {e}"


def _agent_tool_get_initial_access_evidence(case_key):
    """First contact evidence: browser downloads + Zone.Identifier + LNK + first suspicious exec.
    Combines all download/delivery artifacts in chronological order."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # Browser downloads (raw_fallback_v2)
                cur.execute("""
                    SELECT payload->>'start_time' as ts, payload->>'filename',
                           payload->>'target_path', payload->>'url', source_file
                    FROM raw_fallback_v2
                    WHERE case_key=%s AND parser_family='browser_downloads'
                    ORDER BY payload->>'start_time' ASC NULLS LAST LIMIT 30
                """, (case_key,))
                dl_rows = cur.fetchall()

                # Zone.Identifier from filesystem_v2
                cur.execute("""
                    SELECT event_ts, file_name, payload->>'zone_id', source_file
                    FROM filesystem_v2
                    WHERE case_key=%s
                      AND extension='identifier'
                      AND payload->>'zone_id' ILIKE '%%HostUrl%%'
                    ORDER BY event_ts ASC NULLS LAST LIMIT 30
                """, (case_key,))
                zone_rows = cur.fetchall()

                # LNK files
                cur.execute("""
                    SELECT payload->>'SourceCreated', payload->>'LocalPath',
                           payload->>'TargetCreated', source_file
                    FROM raw_fallback_v2
                    WHERE case_key=%s AND parser_family='lnk'
                      AND payload->>'LocalPath' NOT ILIKE '%%system32%%'
                      AND payload->>'LocalPath' NOT ILIKE '%%Program Files%%'
                    ORDER BY payload->>'SourceCreated' ASC NULLS LAST LIMIT 20
                """, (case_key,))
                lnk_rows = cur.fetchall()

                # First suspicious executable
                cur.execute("""
                    SELECT event_ts, executable_name, full_path, min(source_file) AS source_file
                    FROM program_exec_v2
                    WHERE case_key=%s
                      AND (
                        lower(full_path) LIKE '%%\\\\downloads\\\\%%'
                        OR lower(full_path) LIKE '%%\\\\temp\\\\%%'
                        OR lower(full_path) LIKE '%%\\\\public\\\\%%'
                        OR lower(full_path) LIKE '%%\\\\appdata\\\\roaming\\\\%%'
                        OR lower(full_path) LIKE '%%\\\\appdata\\\\local\\\\%%'
                      )
                      AND lower(executable_name) NOT LIKE '%%google%%'
                      AND lower(executable_name) NOT LIKE '%%microsoft%%'
                      AND lower(executable_name) NOT LIKE '%%windows%%'
                      AND lower(executable_name) NOT LIKE '%%websigner%%'
                      AND lower(executable_name) NOT LIKE '%%barscrip%%'
                      AND lower(executable_name) NOT LIKE '%%eusign%%'
                    GROUP BY 1, 2, 3
                    ORDER BY event_ts ASC NULLS LAST, min(row_id) ASC LIMIT 20
                """, (case_key,))
                first_exec = cur.fetchall()

                # RDP / remote logon — the vector the tool was previously blind to (EID 1149
                # TerminalServices connect, 4624 remote-interactive; 4625 = brute-force bursts).
                cur.execute("""
                    SELECT event_ts, event_id,
                           coalesce(payload->>'IpAddress', payload->>'Source Network Address', ''), logon_type
                    FROM event_logs_v2 WHERE case_key=%s
                      AND (event_id=1149
                           OR (event_id=4624 AND (logon_type ILIKE '%%remote interactive%%'
                                                  OR logon_type ILIKE '%%RDP%%' OR logon_type='10')))
                    ORDER BY event_ts ASC NULLS LAST LIMIT 15
                """, (case_key,))
                rdp_rows = cur.fetchall()
                cur.execute("SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id=4625", (case_key,))
                brute = cur.fetchone()[0]

                # Email / phishing delivery — .eml/.msg messages + suspicious attachments in mail dirs.
                cur.execute("""
                    SELECT event_ts, file_name, parent_path FROM filesystem_v2 WHERE case_key=%s
                      AND (lower(file_name) LIKE '%%.eml' OR lower(file_name) LIKE '%%.msg'
                           OR (lower(parent_path) ~ '(outlook|\\mail\\|attachments)'
                               AND lower(file_name) ~ '\\.(zip|rar|7z|js|vbs|docm|xlsm|iso|img|lnk|exe|scr)$'))
                    ORDER BY event_ts DESC NULLS LAST LIMIT 15
                """, (case_key,))
                email_rows = cur.fetchall()

        out = ["=== Initial Access Evidence ===\n"]
        if dl_rows:
            out.append("--- Browser Downloads (raw_fallback_v2) ---")
            for r in dl_rows:
                out.append(f"  {r[0] or 'n/a'} | {r[1] or 'n/a'} | {r[2] or 'n/a'} | url={str(r[3] or '')[:80]} | {r[4]}")
        if zone_rows:
            out.append("\n--- Zone.Identifier (HostUrl = джерело завантаження) ---")
            for r in zone_rows:
                ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                zone = str(r[2] or '')
                host = next((l.strip() for l in zone.split('\n') if 'HostUrl' in l), zone[:100])
                out.append(f"  {ts} | {r[1]} | {host} | {r[3]}")
        if lnk_rows:
            out.append("\n--- LNK файли (ярлики) ---")
            for r in lnk_rows:
                out.append(f"  created={r[0] or 'n/a'} | path={r[1] or 'n/a'} | target_created={r[2] or 'n/a'} | {r[3]}")
        if first_exec:
            out.append("\n--- Перше підозріле виконання (program_exec_v2) ---")
            for r in first_exec:
                ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                out.append(f"  {ts} | {r[1]} | {r[2]} | {r[3]}")
        if rdp_rows:
            out.append("\n--- RDP / віддалений вхід (ВЕКТОР ДОСТУПУ) ---")
            for r in rdp_rows:
                ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                lbl = 'EID1149 TS-connect' if r[1] == 1149 else 'EID4624 RDP-logon'
                out.append(f"  {ts} | {lbl} | src_ip={r[2] or '?'} | {r[3] or ''}")
            if brute and brute > 20:
                out.append(f"  ⚠ {brute}× EID4625 невдалих входів — можливий RDP-брутфорс")
        if email_rows:
            out.append("\n--- Email / фішинг-доставка (.eml/.msg + вкладення) ---")
            for r in email_rows:
                ts = r[0].isoformat()[:19] if r[0] else 'n/a'
                out.append(f"  {ts} | {r[1]} | {str(r[2] or '')[:80]}")
        if len(out) == 1:
            # zero-data guard: empty case => ingestion problem, not a forensic conclusion
            with psycopg2.connect(PG_DSN) as _c2:
                with _c2.cursor() as _cu:
                    _cu.execute("SELECT (SELECT count(*) FROM event_logs_v2 WHERE case_key=%s)"
                                " + (SELECT count(*) FROM filesystem_v2 WHERE case_key=%s)",
                                (case_key, case_key))
                    _tot = _cu.fetchone()[0]
            if not _tot:
                return ("Initial Access: у кейсі НЕМАЄ даних (0 подій, 0 файлів) — ingest не "
                        "завершився або логи видалені. Це не форензік-висновок, а брак даних. "
                        "Перезалий логи кейсу.")
            return ("Initial Access: явних артефактів доставки (завантаження/RDP/email) не знайдено "
                    "у наявних даних. Перевір browser_history / run_sql або розшир вікно пошуку.")
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR get_initial_access_evidence: {e}"


def _agent_tool_get_defender_evidence(case_key):
    """Defender events: EID 1116(detect)/1117(action)/1011(quarantine_remove)/1008/1009/5001/5007.
    Searches BOTH normalized columns AND payload->>'PayloadData1' for malware names.
    Returns malware names, action taken, paths, timestamps."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT event_ts, event_id,
                           payload->>'PayloadData1' as pd1,
                           payload->>'PayloadData2' as pd2,
                           payload->>'PayloadData3' as pd3,
                           payload->>'ThreatName' as threat,
                           payload->>'Path' as fpath,
                           payload->>'Action' as action,
                           channel, source_file
                    FROM event_logs_v2
                    WHERE case_key=%s
                      AND event_id IN (1116,1117,1011,1008,1009,5001,5007,5010,5012,5013)
                    ORDER BY event_ts ASC NULLS LAST LIMIT 60
                """, (case_key,))
                rows = cur.fetchall()

        _eid_map = {
            1116:'Defender DETECTED', 1117:'Defender ACTION TAKEN',
            1011:'Removed from quarantine (CRITICAL!)', 1008:'Scan failed',
            1009:'Quarantine action', 5001:'Defender DISABLED',
            5007:'Defender config changed (exclusion?)', 5010:'Realtime protection disabled',
            5012:'Defender disabled', 5013:'Defender tampered'
        }
        out = ["=== Windows Defender Events ===\n"]
        if not rows:
            return "Windows Defender events (EID 1116/1117/1011/5001/5007): не знайдено."
        for r in rows:
            ts = r[0].isoformat()[:19] if r[0] else 'n/a'
            eid = r[1]
            pd1 = r[2] or ''
            pd2 = r[3] or ''
            threat = r[5] or ''
            fpath = r[6] or ''
            action = r[7] or ''
            # Extract malware name from pd1 if not in threat field
            if not threat and 'Malware' in pd1:
                threat = pd1.split('\n')[0][:80] if '\n' in pd1 else pd1[:80]
            flag = ' ⚠️' if eid in (1116, 1117, 1011, 5001, 5007) else ''
            out.append(f"{ts} | EID {eid}{flag} | {_eid_map.get(eid, '?')} | malware={threat or pd1[:60]} | path={fpath or pd2[:60]} | action={action} | {r[9]}")
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR get_defender_evidence: {e}"


def _agent_tool_get_tampering_evidence(case_key):
    """Evidence tampering / log clearing / Defender disable / timestamp changes.
    EID 1102(log clear in Security)/104(System log cleared)/4719(audit policy)/
    4907(audit settings)/4616(time changed)/1074(shutdown).
    NOTE: EID 1102 in RDPClient channel = RDP connection (NOT log clear!).
    Returns chronological tamper timeline."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT event_ts, event_id, channel,
                           payload->>'PayloadData1' as pd1,
                           payload->>'PayloadData2' as pd2,
                           payload->>'SubjectUserName' as actor,
                           payload->>'OldTime' as old_time,
                           payload->>'NewTime' as new_time,
                           source_file
                    FROM event_logs_v2
                    WHERE case_key=%s
                      AND (
                        (event_id=1102 AND channel NOT ILIKE '%%RDPClient%%')
                        OR event_id IN (104, 4719, 4907, 4616, 1074, 4647)
                        OR (event_id=5007 AND (
                          payload->>'PayloadData1' ILIKE '%%exclusion%%'
                          OR payload->>'PayloadData1' ILIKE '%%disable%%'
                          OR payload->>'PayloadData1' ILIKE '%%0x0%%'
                        ))
                      )
                    ORDER BY event_ts ASC NULLS LAST LIMIT 40
                """, (case_key,))
                rows = cur.fetchall()

        _eid_map = {
            1102:'Log cleared (Security)', 104:'Log cleared (System)',
            4719:'Audit policy changed', 4907:'Audit settings changed',
            4616:'System time changed', 1074:'Shutdown/Restart', 4647:'User logoff',
            5007:'Defender exclusion/disable'
        }
        out = ["=== Tampering / Anti-Forensics Evidence ===\n"]
        if not rows:
            return "Tampering events: не знайдено (логи не очищувались, час не змінювався)."
        for r in rows:
            ts = r[0].isoformat()[:19] if r[0] else 'n/a'
            eid = r[1]
            ch = r[2] or ''
            pd1 = r[3] or ''
            actor = r[5] or ''
            old_t = r[6] or ''
            new_t = r[7] or ''
            flag = ' 🚨' if eid in (1102, 104, 4719) else ''
            extra = ''
            if eid == 4616 and (old_t or new_t):
                extra = f" | old={old_t} → new={new_t}"
            out.append(f"{ts} | EID {eid}{flag} | {_eid_map.get(eid, '?')} | actor={actor} | pd1={pd1[:80]}{extra} | {ch} | {r[8]}")
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR get_tampering_evidence: {e}"


# ─── End deterministic evidence tools ───


def _agent_tool_backtrace(case_key, anchor_ts, days_back=14, days_forward=3):
    """Search all tables for delivery/initial access events N days before an anchor timestamp.
    Used when first known events are late-phase (log clearing, RDP, tampering).
    Searches: Zone.Identifier, browser downloads, EML/mail artifacts, MFT new files, Prefetch early exec."""
    try:
        from datetime import datetime, timedelta, timezone
        ts_from = '2000-01-01'
        ts_to = '2099-12-31'
        if anchor_ts and str(anchor_ts).strip():
            try:
                _ats = str(anchor_ts).strip().replace(' ', 'T')
                if '+' not in _ats and _ats.count('-') < 4:
                    _ats += '+00:00'
                anchor = datetime.fromisoformat(_ats)
            except Exception:
                try:
                    anchor = datetime.strptime(str(anchor_ts).strip()[:19], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
                except Exception:
                    anchor = None
            if anchor:
                ts_from = (anchor - timedelta(days=int(days_back or 14))).isoformat()
                ts_to = (anchor + timedelta(days=int(days_forward or 3))).isoformat()
        # Collect structured entries: (datetime_obj, entry_type, text)
        entries = []  # list of [dt, etype, text]

        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # 1. Zone.Identifier — only entries with actual HostUrl (internet downloads), suspicious files first
                cur.execute("""
                    SELECT event_ts, file_name, parent_path, payload
                    FROM filesystem_v2
                    WHERE case_key=%s AND extension = 'identifier'
                      AND payload->>'zone_id' ILIKE '%%HostUrl%%'
                      AND event_ts BETWEEN %s AND %s
                    ORDER BY
                      CASE WHEN lower(file_name) ~ '[.](rar|zip|7z|exe|msi|js|vbs|bat|ps1)' THEN 0 ELSE 1 END ASC,
                      event_ts DESC LIMIT 20
                """, (case_key, ts_from, ts_to))
                for r in cur.fetchall():
                    p = r[3] if isinstance(r[3], dict) else {}
                    if isinstance(p, str):
                        try: p = __import__('json').loads(p)
                        except: p = {}
                    zone_raw = p.get('zone_id', '')
                    host_url = ref_url = ''
                    for line in str(zone_raw).split('\n'):
                        if 'HostUrl=' in line: host_url = line.split('=', 1)[1].strip()[:120]
                        if 'ReferrerUrl=' in line: ref_url = line.split('=', 1)[1].strip()[:80]
                    url = host_url or ref_url or ''
                    flag = ' *** ПІДОЗРІЛИЙ ***' if any(d in url.lower() for d in ['mail.ukr','fex.net','mail.','attach','wetransfer','mega.nz']) else ''
                    entries.append([r[0], 'zone', f"[Zone.Identifier] {r[0].isoformat()[:19] if r[0] else 'n/a'} | {r[1]}{flag} | url={url}"])
                # 2. Browser downloads (by source_file name) — skip, covered by 5c
                # 3. New EXE/RAR/ZIP files in MFT — exclude WinSxS/system paths
                cur.execute("""
                    SELECT event_ts, file_name, parent_path, source_file
                    FROM filesystem_v2
                    WHERE case_key=%s
                      AND lower(extension) IN ('exe','rar','zip','7z','vbs','bat','ps1','msi','jar')
                      AND event_ts BETWEEN %s AND %s
                      AND (parent_path ILIKE '%%\\\\Users\\\\%%\\\\Download%%'
                           OR parent_path ILIKE '%%\\\\Users\\\\%%\\\\Desktop%%'
                           OR parent_path ILIKE '%%\\\\Users\\\\%%\\\\AppData\\\\Local\\\\Temp%%'
                           OR parent_path ILIKE '%%\\\\Users\\\\Public\\\\%%')
                      AND NOT parent_path ILIKE '%%WinSxS%%'
                      AND NOT parent_path ILIKE '%%InFlight%%'
                    ORDER BY event_ts DESC LIMIT 20
                """, (case_key, ts_from, ts_to))
                for r in cur.fetchall():
                    entries.append([r[0], 'mft', f"[MFT] {r[0].isoformat()[:19] if r[0] else 'n/a'} | {r[1]} | path={r[2]} | {r[3]}"])
                # 4. LNK in Recent (recently opened files — strong execution indicator)
                cur.execute("""
                    SELECT event_ts, file_name, parent_path, source_file
                    FROM filesystem_v2
                    WHERE case_key=%s
                      AND extension = 'lnk'
                      AND parent_path ILIKE '%%Recent%%'
                      AND event_ts BETWEEN %s AND %s
                    ORDER BY event_ts DESC LIMIT 20
                """, (case_key, ts_from, ts_to))
                for r in cur.fetchall():
                    entries.append([r[0], 'lnk', f"[LNK/Recent] {r[0].isoformat()[:19] if r[0] else 'n/a'} | {r[1]} | path={r[2]} | {r[3]}"])
                # 5. Prefetch files (newest first)
                cur.execute("""
                    SELECT event_ts, file_name, parent_path, source_file
                    FROM filesystem_v2
                    WHERE case_key=%s
                      AND extension = 'pf'
                      AND parent_path ILIKE '%%Prefetch%%'
                      AND event_ts BETWEEN %s AND %s
                    ORDER BY event_ts DESC LIMIT 20
                """, (case_key, ts_from, ts_to))
                for r in cur.fetchall():
                    entries.append([r[0], 'prefetch_fs', f"[Prefetch] {r[0].isoformat()[:19] if r[0] else 'n/a'} | {r[1]} | {r[3]}"])
                # 5b. AppCompat/Amcache/Prefetch — suspicious user paths, exclude Intel/system dirs
                cur.execute("""
                    SELECT event_ts, executable_name, full_path, min(source_file) AS source_file
                    FROM program_exec_v2
                    WHERE case_key=%s
                      AND event_ts BETWEEN %s AND %s
                      AND lower(coalesce(full_path,'')||' '||coalesce(executable_name,'')) ~
                          '(\\\\temp\\\\|\\\\downloads?\\\\|\\\\programdata\\\\(?!microsoft|usos|windowsapps)|\\\\appdata\\\\roaming\\\\|\\\\users\\\\public\\\\|\\\\recycle\\.bin\\\\)'
                    GROUP BY 1, 2, 3
                    ORDER BY event_ts DESC, min(row_id) ASC LIMIT 30
                """, (case_key, ts_from, ts_to))
                for r in cur.fetchall():
                    ts_str = r[0].isoformat()[:19] if r[0] else 'n/a'
                    path = r[2] or r[1] or ''
                    entries.append([r[0], 'appcompat', f"[AppCompat/Prefetch] {ts_str} | {path} | src={r[3]}"])

                # 5c. Browser downloads from raw_fallback_v2 — suspicious archives/exes
                cur.execute("""
                    SELECT payload->>'end_time', payload->>'target_path', payload->>'url', payload->>'filename'
                    FROM raw_fallback_v2
                    WHERE case_key=%s AND parser_family='browser_downloads'
                      AND (payload->>'target_path' ~* '[.](exe|zip|rar|7z|msi|js|vbs|bat|ps1|docm)'
                           OR payload->>'filename' ~* '[.](exe|zip|rar|7z|msi|js|vbs|bat|ps1)'
                           OR payload->>'url' ~* '(mail[.][^/]|attach|fex[.]net|ukr[.]net)')
                    ORDER BY payload->>'end_time' DESC LIMIT 20
                """, (case_key,))
                for r in cur.fetchall():
                    ts_str = str(r[0] or 'n/a')[:19]
                    path = str(r[1] or 'n/a').replace('\\','/')
                    url = str(r[2] or '')[:100]
                    fname = str(r[3] or path.split('/')[-1])[:60]
                    try:
                        from datetime import datetime
                        _dt = datetime.fromisoformat(str(r[0]).strip()) if r[0] else None
                    except: _dt = None
                    entries.append([_dt, 'browser', f"[BrowserDL] {ts_str} | {fname} | url={url}"])

                # 5d. LNK files from raw_fallback_v2 — use TargetIDAbsolutePath (LocalPath often NULL)
                cur.execute("""
                    SELECT payload->>'SourceCreated', payload->>'TargetIDAbsolutePath',
                           payload->>'RelativePath', payload->>'LocalPath'
                    FROM raw_fallback_v2
                    WHERE case_key=%s AND parser_family='lnk'
                      AND (payload->>'RelativePath' IS NOT NULL OR payload->>'LocalPath' IS NOT NULL
                           OR payload->>'TargetIDAbsolutePath' ILIKE '%%Desktop%%'
                           OR payload->>'TargetIDAbsolutePath' ILIKE '%%рада%%'
                           OR payload->>'TargetIDAbsolutePath' ILIKE '%%договор%%'
                           OR payload->>'RelativePath' ILIKE '%%рада%%'
                           OR payload->>'RelativePath' ILIKE '%%договор%%'
                           OR payload->>'RelativePath' ILIKE '%%eula%%'
                           OR payload->>'RelativePath' ILIKE '%%бланк%%')
                    ORDER BY payload->>'SourceCreated' DESC LIMIT 20
                """, (case_key,))
                for r in cur.fetchall():
                    ts_str = str(r[0] or 'n/a')[:19]
                    path = str(r[3] or r[1] or r[2] or 'n/a').replace('\\','/')[:100]
                    rel = str(r[2] or '')[:80]
                    try:
                        from datetime import datetime
                        _dt = datetime.fromisoformat(str(r[0]).strip().replace(' ','T')) if r[0] else None
                    except: _dt = None
                    entries.append([_dt, 'lnk', f"[LNK/raw_fallback] {ts_str} | Target={path} | Rel={rel}"])

                # 5e. EML / mail artifacts in raw_fallback
                cur.execute("""
                    SELECT source_file, payload, created_at
                    FROM raw_fallback_v2
                    WHERE case_key=%s
                      AND (lower(source_file) LIKE '%%mail%%' OR lower(source_file) LIKE '%%.eml%%'
                           OR lower(source_file) LIKE '%%outlook%%' OR lower(source_file) LIKE '%%thunderbird%%')
                    ORDER BY created_at ASC LIMIT 10
                """, (case_key,))
                for r in cur.fetchall():
                    raw = str(r[1] or '')[:200]
                    entries.append([r[2], 'mail', f"[Mail/EML] {r[0]} | {raw}"])
                # 6. Early logons before the anchor
                cur.execute("""
                    SELECT event_ts, event_id, target_user, remote_host, logon_type, source_file
                    FROM event_logs_v2
                    WHERE case_key=%s AND event_id IN (4624,4625,1149,21)
                      AND event_ts BETWEEN %s AND %s
                    ORDER BY event_ts DESC LIMIT 15
                """, (case_key, ts_from, ts_to))
                for r in cur.fetchall():
                    ts_str = r[0].isoformat()[:19] if r[0] else 'n/a'
                    entries.append([r[0], 'logon', f"[Logon EID={r[1]}] {ts_str} | user={r[2] or ''} | from={r[3] or ''} | type={r[4] or ''} | {r[5]}"])

        if not entries:
            return f"Backtrace {ts_from}..{ts_to}: нічого не знайдено. Можливо, дані за цей період відсутні."

        # --- Delivery cluster scoring ---
        # Find LNK entries, then look for AppCompat/Prefetch within 60 min → CONFIRMED DELIVERY
        from datetime import timedelta as _td
        def _nt(dt):
            return dt.replace(tzinfo=None) if (dt and getattr(dt, 'tzinfo', None)) else dt
        # Legitimate domains: exec from these = not malicious
        _LEGIT_DOMAINS = ('radabank','ibank.','treasury.gov','microsoft','windows','google','chrome','update','office','adobe','java','nvidia')
        _exec_types = {'appcompat', 'prefetch_fs'}
        _lnk_entries = [(_nt(e[0]), e[2]) for e in entries if e[1] == 'lnk' and e[0]]
        confirmed = []
        for lnk_dt, lnk_text in _lnk_entries:
            _window_end = lnk_dt + _td(hours=1)
            _exec_hits = [e[2] for e in entries if e[1] in _exec_types and e[0] and lnk_dt <= _nt(e[0]) <= _window_end]
            # Filter out executions of known-legitimate programs
            _suspicious_hits = [h for h in _exec_hits if not any(d in h.lower() for d in _LEGIT_DOMAINS)]
            if _suspicious_hits:
                lnk_name = lnk_text.split('|')[1].strip() if '|' in lnk_text else lnk_text
                confirmed.append(f"!!! CONFIRMED DELIVERY: {lnk_dt.isoformat()[:19]} — {lnk_name}")
                for h in _suspicious_hits[:2]:
                    confirmed.append(f"    EXEC EVIDENCE: {h}")

        header = f"=== BACKTRACE: anchor={anchor_ts} | -{days_back}d..+{days_forward}d | {ts_from}..{ts_to} ===\n"
        if confirmed:
            header += ">>> INITIAL ACCESS CANDIDATES (LNK+EXEC cluster, use these timestamps!) <<<\n"
            header += '\n'.join(confirmed) + '\n'

        # Highlight top suspicious zone entries: mail+archive = likely initial access
        _IA_SIGNALS = ['mail.ukr', 'fex.net', 'mail.', 'attach']
        _IA_EXT = ['.rar', '.zip', '.7z', '.exe', '.js', '.vbs']
        for e in entries:
            if e[1] == 'zone' and any(d in e[2].lower() for d in _IA_SIGNALS) and any(x in e[2].lower() for x in _IA_EXT):
                e[2] = e[2] + ' <<< ЙМОВІРНИЙ INITIAL ACCESS'

        # Output: suspicious downloads first (zone + browser), then everything else
        _susp_types = {'zone', 'browser'}
        susp_entries = [e for e in entries if e[1] in _susp_types]
        other_entries = [e for e in entries if e[1] not in _susp_types]
        susp_entries.sort(key=lambda e: (_nt(e[0]) or datetime.min), reverse=True)
        other_entries.sort(key=lambda e: (_nt(e[0]) or datetime.min), reverse=True)
        out_lines = [header.rstrip()]
        if susp_entries:
            out_lines.append("=== DOWNLOADS (Zone.Identifier + BrowserDL) ===")
            out_lines.extend(e[2] for e in susp_entries)
        if other_entries:
            out_lines.append("=== OTHER ARTIFACTS (AppCompat/LNK/Logon) ===")
            out_lines.extend(e[2] for e in other_entries)
        return '\n'.join(out_lines)
    except Exception as e:
        return f"ERROR: {e}"


def _agent_tool_unwind_file(case_key, name):
    """Course 'unwind a suspicious EXE' chain for one filename: execution artefacts →
    4688 → Defender → MFT → scanner hits. Returns a cited per-file dossier."""
    nm = re.split(r'[\\/]', str(name or '').strip().strip('"').strip("'"))[-1]
    if len(nm) < 3:
        return 'ERROR: вкажи імʼя файлу (мінімум 3 символи)'
    like = '%' + nm.lower() + '%'
    out = ['ДОСЬЄ ФАЙЛУ: ' + nm]

    def _sec(cur, title, sql, fmt):
        try:
            cur.execute(sql, (case_key, like))
            rows = cur.fetchall()
        except Exception:
            return
        if rows:
            out.append(title)
            for r in rows:
                try:
                    out.append('   ' + fmt(r))
                except Exception:
                    pass
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            with c.cursor() as cur:
                _sec(cur, '• Виконання/поява (Prefetch/Amcache/ShimCache):',
                     "SELECT event_ts, full_path, hash_sha1, source_file FROM program_exec_v2 "
                     "WHERE case_key=%s AND lower(coalesce(executable_name,'')) LIKE %s ORDER BY event_ts LIMIT 12",
                     lambda r: '%s  %s  %s [%s]' % (str(r[0])[:19], (r[1] or '')[:70],
                               ('sha1:' + r[2][:16]) if r[2] else '', (r[3] or '')[:22]))
                _sec(cur, '• Запуск процесу (EID 4688):',
                     "SELECT event_ts, payload->>'ParentProcessName', target_user, left(payload->>'CommandLine',120) "
                     "FROM event_logs_v2 WHERE case_key=%s AND event_id=4688 "
                     "AND lower(coalesce(payload->>'NewProcessName','')) LIKE %s ORDER BY event_ts LIMIT 10",
                     lambda r: '%s  parent=%s  user=%s  %s' % (str(r[0])[:19], (r[1] or '?')[:24],
                               (r[2] or '?')[:20], (r[3] or '')[:70]))
                _sec(cur, '• Defender (EID 1116/1117/1118/1119):',
                     "SELECT event_ts, event_id, left(payload::text,160) FROM event_logs_v2 "
                     "WHERE case_key=%s AND event_id IN (1116,1117,1118,1119) AND lower(payload::text) LIKE %s "
                     "ORDER BY event_ts LIMIT 6",
                     lambda r: '%s  EID%s  %s' % (str(r[0])[:19], r[1], (r[2] or '')[:90]))
                _sec(cur, '• Файлова система / MFT (поява файлу):',
                     "SELECT event_ts, file_name FROM filesystem_v2 WHERE case_key=%s "
                     "AND lower(coalesce(file_name,'')) LIKE %s ORDER BY event_ts LIMIT 8",
                     lambda r: '%s  %s' % (str(r[0])[:19], (r[1] or '')[:80]))
                _sec(cur, '• Алерти сканерів (THOR/YARA/Sigma):',
                     "SELECT severity, tool, rule FROM tool_alerts_v2 WHERE case_key=%s "
                     "AND lower(coalesce(ioc_value,'')||' '||coalesce(rule,'')||' '||coalesce(source_file,'')) LIKE %s LIMIT 6",
                     lambda r: '[%s] %s: %s' % (r[0], r[1], (r[2] or '')[:70]))
    except Exception as e:
        return 'ERROR unwind_file: ' + repr(e)[:120]
    if len(out) == 1:
        return u'Файл «%s» не знайдено у артефактах виконання/файлової системи цього кейсу.' % nm
    # P5 corroboration: how many INDEPENDENT artefact classes carry this file (each '•' section)
    _classes = sum(1 for _l in out if _l.startswith(u'•'))
    if _classes >= 2:
        _tier = u'✅ CONFIRMED — підтверджено %d незалежними джерелами' % _classes
    else:
        _tier = u'⚠️ ПОТРЕБУЄ ПІДТВЕРДЖЕННЯ — лише 1 джерело (правило: для висновку треба 2-ге незалежне)'
    out.insert(1, _tier)
    return '\n'.join(out)[:4000]


# Tools whose output is not evidence text (or is the model's own notes) - never filtered.
_OWN_FILTER_PASSTHROUGH = frozenset({'finish_report', 'save_finding', 'get_saved_findings',
                                     'search_knowledge_base', 'get_system_profile', 'run_temp_script',
                                     'search_iocs_across_cases', 'compare_cases', 'get_case_learnings'})


def _execute_agent_tool(tool_name, args, case_key):
    """Dispatch a tool call and subtract the pipeline's own footprint from the answer.

    One choke point instead of sixty query functions: every evidence tool returns text
    lines, and a line naming DFIRTriage_/dfp_/vao_collector - or one of our tools after
    the collector started - is ours, not the attacker's. See analysis/own_footprint.py."""
    out = _execute_agent_tool_raw(tool_name, args, case_key)
    if tool_name in _OWN_FILTER_PASSTHROUGH or not isinstance(out, str):
        return out
    try:
        return _own_strip(out, case_key=case_key)
    except Exception:
        return out


def _execute_agent_tool_raw(tool_name, args, case_key):
    """Dispatch tool call from agent to implementation."""
    try:
        if tool_name == 'get_system_profile':
            return _agent_tool_get_system_profile(case_key)
        elif tool_name == 'get_top_alerts':
            return _agent_tool_get_top_alerts(case_key,
                tool=args.get('tool'), severity=args.get('severity'),
                limit=args.get('limit', 30))
        elif tool_name == 'search_events':
            return _agent_tool_search_events(case_key,
                keyword=args.get('keyword',''),
                event_id=args.get('event_id'),
                limit=args.get('limit', 30))
        elif tool_name == 'get_filesystem_artifacts':
            return _agent_tool_get_filesystem_artifacts(case_key,
                pattern=args.get('pattern','%'),
                limit=args.get('limit', 30))
        elif tool_name == 'get_registry_persistence':
            return _agent_tool_get_registry_persistence(case_key,
                keyword=args.get('keyword'),
                limit=args.get('limit', 30))
        elif tool_name == 'get_logon_activity':
            return _agent_tool_get_logon_activity(case_key,
                limit=args.get('limit', 30))
        elif tool_name == 'get_hayabusa_detections':
            return _agent_tool_get_hayabusa(case_key,
                min_level=args.get('min_level','high'),
                limit=args.get('limit', 30))
        elif tool_name == 'run_sql':
            return _agent_tool_run_sql(case_key, args.get('query',''))
        elif tool_name == 'unwind_file':
            return _agent_tool_unwind_file(case_key, args.get('name', '') or args.get('file', ''))
        elif tool_name == 'search_knowledge_base':
            return _agent_tool_search_knowledge_base(args.get('query', ''))
        elif tool_name == 'search_iocs_across_cases':
            return _agent_tool_search_iocs_across_cases(
                args.get('ioc_value', ''), args.get('ioc_type'))
        elif tool_name == 'get_saved_findings':
            return _agent_tool_get_saved_findings(case_key)
        elif tool_name == 'save_finding':
            return _agent_tool_save_finding(case_key,
                finding_type=args.get('finding_type','finding'),
                summary=args.get('summary',''),
                sources=args.get('sources'),
                confidence=args.get('confidence','medium'),
                detail=args.get('detail'))
        elif tool_name == 'get_download_artifacts':
            return _agent_tool_get_download_artifacts(case_key,
                since=args.get('since'), limit=args.get('limit', 40))
        elif tool_name == 'get_case_triggers':
            return _agent_tool_get_case_triggers(case_key,
                limit=args.get('limit', 40))
        elif tool_name == 'get_forensic_timeline':
            return _agent_tool_get_forensic_timeline(case_key,
                keyword=args.get('keyword'), artifact=args.get('artifact'),
                limit=args.get('limit', 40))
        elif tool_name == 'get_browser_downloads':
            return _agent_tool_get_browser_downloads(case_key,
                limit=args.get('limit', 30))
        elif tool_name == 'get_regripper_data':
            return _agent_tool_get_regripper_data(case_key,
                keyword=args.get('keyword'), limit=args.get('limit', 30))
        elif tool_name == 'get_sensitive_secrets':
            return _agent_tool_get_sensitive_secrets(case_key)
        elif tool_name == 'get_browser_activity':
            return _agent_tool_get_browser_activity(case_key,
                limit=args.get('limit', 50))
        elif tool_name == 'get_suspicious_executables':
            return _agent_tool_get_suspicious_executables(case_key,
                limit=args.get('limit', 50))
        elif tool_name == 'get_srum_network_traffic':
            return _agent_tool_get_srum_network_traffic(case_key,
                limit=args.get('limit', 30))
        elif tool_name == 'get_context_window':
            return _agent_tool_get_context_window(case_key,
                timestamp=args.get('timestamp', ''),
                hours_before=args.get('hours_before', 6),
                hours_after=args.get('hours_after', 6))
        elif tool_name == 'pivot':
            return _agent_tool_pivot(case_key,
                ioc_value=args.get('ioc_value', ''),
                limit=args.get('limit', 30))
        elif tool_name == 'get_log_gaps':
            return _agent_tool_get_log_gaps(case_key,
                min_gap_hours=args.get('min_gap_hours', 2))
        elif tool_name == 'get_attack_phases':
            return _agent_tool_get_attack_phases(case_key)
        elif tool_name == 'compare_cases':
            return _agent_tool_compare_cases(case_key)
        elif tool_name == 'get_user_timeline':
            return _agent_tool_get_user_timeline(case_key,
                username=args.get('username'),
                limit=args.get('limit', 60))
        elif tool_name == 'get_thor_file_hashes':
            return _agent_tool_get_thor_file_hashes(case_key,
                keyword=args.get('keyword'), limit=args.get('limit', 50))
        elif tool_name == 'run_temp_script':
            return _agent_tool_run_temp_script(case_key,
                script_code=args.get('script_code', ''),
                description=args.get('description', ''))
        elif tool_name == 'get_defender_events':
            return _agent_tool_get_defender_events(case_key, limit=args.get('limit', 40))
        elif tool_name == 'get_powershell_events':
            return _agent_tool_get_powershell_events(case_key, limit=args.get('limit', 40))
        elif tool_name == 'get_persistence_events':
            return _agent_tool_get_persistence_events(case_key, limit=args.get('limit', 40))
        elif tool_name == 'get_tampering_events':
            return _agent_tool_get_tampering_events(case_key, limit=args.get('limit', 40))
        elif tool_name == 'get_lateral_movement':
            return _agent_tool_get_lateral_movement(case_key, limit=args.get('limit', 40))
        elif tool_name == 'get_artifacts_confirmation':
            return _agent_tool_get_artifacts_confirmation(case_key, limit=args.get('limit', 40))
        elif tool_name == 'get_ad_events':
            return _agent_tool_get_ad_events(case_key, limit=args.get('limit', 40))
        elif tool_name == 'backtrace':
            return _agent_tool_backtrace(case_key,
                anchor_ts=args.get('anchor_ts', ''),
                days_back=args.get('days_back', 14),
                days_forward=args.get('days_forward', 3))
        elif tool_name == 'finish_report':
            return '__FINISH__:' + str(args.get('report', ''))
        else:
            return f'ERROR: невідомий інструмент {tool_name}'
    except Exception as e:
        return f'TOOL ERROR: {e}'


def _ensure_case_learnings_table():
    """Create case_learnings_v1 table for cross-case self-learning."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS public.case_learnings_v1 (
                      id bigserial PRIMARY KEY,
                      case_key text NOT NULL,
                      topic text NOT NULL,
                      finding text NOT NULL,
                      artifacts text,
                      timestamps text,
                      confidence text DEFAULT 'medium',
                      created_at timestamptz NOT NULL DEFAULT now()
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_case_learnings_topic ON public.case_learnings_v1(topic, created_at DESC)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_case_learnings_case ON public.case_learnings_v1(case_key)")
                conn.commit()
    except Exception:
        pass


def _save_case_learning(case_key, topic, finding, artifacts='', timestamps=''):
    """Save a key finding to case_learnings_v1 for cross-case learning."""
    try:
        _ensure_case_learnings_table()
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO public.case_learnings_v1(case_key, topic, finding, artifacts, timestamps)
                    VALUES (%s, %s, %s, %s, %s)
                """, (case_key, topic, finding[:2000], artifacts[:500], timestamps[:200]))
                conn.commit()
    except Exception:
        pass


def _extract_learning_facts(finding_text):
    """Extract concise key facts from a full markdown finding."""
    import re as _re_f
    facts = []
    ts = _re_f.findall(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}(?::\d{2})?', finding_text)
    if ts:
        facts.append('Час: ' + ', '.join(sorted(set(ts))[:3]))
    ips = [ip for ip in _re_f.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', finding_text)
           if not ip.startswith(('127.', '192.168.', '10.', '172.'))]
    if ips:
        facts.append('IP: ' + ', '.join(list(dict.fromkeys(ips))[:3]))
    paths = _re_f.findall(r'[A-Za-z]:\\[^\s\|,\)\"\']{5,60}', finding_text)
    if paths:
        facts.append('Файли: ' + ', '.join(list(dict.fromkeys(paths))[:3]))
    malware = _re_f.findall(r'Trojan:\w+[\w/!]+', finding_text)
    if malware:
        facts.append('Malware: ' + ', '.join(list(dict.fromkeys(malware))[:2]))
    tools = [t for t in ['ngrok', 'litemanager', 'rms', 'rutserv', 'rdpwrap', '7za', 'fiddler', 'anydesk']
             if t in finding_text.lower()]
    if tools:
        facts.append('Інструменти: ' + ', '.join(tools))
    if not facts:
        first = next((l.strip() for l in finding_text.split('\n')
                      if len(l.strip()) > 20 and '|' not in l and '#' not in l and '---' not in l), '')
        facts.append(first[:120] if first else finding_text[:120])
    return '; '.join(facts)


def _detect_similar_cases(case_key):
    """Find other cases with overlapping IOCs."""
    import re as _re_s
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("SELECT finding FROM case_learnings_v1 WHERE case_key=%s AND topic NOT LIKE '\\_%%' LIMIT 30", (case_key,))
                my_text = ' '.join(r[0] for r in cur.fetchall())
                if not my_text:
                    return ''
                my_ips = {ip for ip in _re_s.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', my_text)
                          if not ip.startswith(('127.', '192.168.', '10.', '172.'))}
                my_tools = {t for t in ['ngrok', 'litemanager', 'rms', 'rutserv', 'rdpwrap', '7za', 'fiddler', 'anydesk']
                            if t in my_text.lower()}
                my_mw = set(_re_s.findall(r'Trojan:\w+[\w/!]+', my_text))
                if not (my_ips or my_tools or my_mw):
                    return ''
                # ORDER BY: DISTINCT runs through a HashAggregate, whose output order is
                # not guaranteed; these lines reach the report and the 4000-char cut.
                cur.execute("SELECT DISTINCT case_key FROM case_learnings_v1 WHERE case_key!=%s AND topic NOT LIKE '\\_%%' ORDER BY case_key", (case_key,))
                similar = []
                for (other_key,) in cur.fetchall():
                    cur.execute("SELECT finding FROM case_learnings_v1 WHERE case_key=%s LIMIT 20", (other_key,))
                    ot = ' '.join(r[0] for r in cur.fetchall())
                    # sorted(): the sets stay the intersection tool, but iterating a set of
                    # strings follows PYTHONHASHSEED, which is fresh in every process. hits is
                    # then cut to [:3], so set order decided WHICH shared IOC got named:
                    # measured 8 different results out of 8 processes on the same database.
                    hits = ([f'IP {ip}' for ip in sorted(my_ips) if ip in ot] +
                            [f'інструмент {t}' for t in sorted(my_tools) if t in ot.lower()] +
                            [f'malware {m}' for m in sorted(my_mw) if m in ot])
                    if hits:
                        similar.append(f'  {other_key}: {", ".join(hits[:3])}')
                if similar:
                    return '\n⚠️ СХОЖІ КЕЙСИ (спільні IOC):\n' + '\n'.join(similar)
                return ''
    except Exception:
        return ''


def _agent_tool_get_case_learnings(current_case_key, topic=''):
    """Retrieve learned patterns from past cases similar to current topic.
    Returns key findings from previous investigations to accelerate analysis.

    Порядок: заголовок, блок спільних IOC, далі записи за важливістю
    (analysis/salience.py). Вивід ріже на 4 з 11 справ.
    """
    try:
        _ensure_case_learnings_table()
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                if topic:
                    cur.execute("""
                        SELECT case_key, topic, finding, artifacts, timestamps, created_at
                        FROM public.case_learnings_v1
                        WHERE case_key != %s
                          AND (topic ILIKE %s OR topic ILIKE %s OR finding ILIKE %s)
                        ORDER BY created_at DESC
                        LIMIT 10
                    """, (current_case_key, f'%{topic}%', '%' + topic.split()[0] + '%' if topic else '%', f'%{topic[:30]}%'))
                else:
                    cur.execute("""
                        SELECT case_key, topic, finding, artifacts, timestamps, created_at
                        FROM public.case_learnings_v1
                        WHERE case_key != %s
                        ORDER BY created_at DESC
                        LIMIT 15
                    """, (current_case_key,))
                rows = cur.fetchall()
        if not rows:
            return "Попередніх навчальних записів ще немає для цієї теми."
        out = ["=== ПАТТЕРНИ З ПОПЕРЕДНІХ КЕЙСІВ ==="]
        # Блок спільних IOC — те, заради чого інструмент і викликають: він стояв у самому
        # кінці й починався на 4193-му символі, тобто за межею зрізу на 4000. Тепер він
        # іде одразу за заголовком.
        similar = _detect_similar_cases(current_case_key)
        if similar:
            out.append(similar)
        _groups = []
        for case_k, top, finding, arts, ts, created in rows:
            facts = _extract_learning_facts(finding)
            _grp = [f"\n[{case_k}] {top}: {facts[:250]}"]
            if ts:
                _grp.append(f"  Час: {ts[:80]}")
            _groups.append(_grp)
        for _grp in _S.sort_groups(_groups):
            out.extend(_grp)
        return '\n'.join(out)
    except Exception as e:
        return f"ERROR get_case_learnings: {e}"

