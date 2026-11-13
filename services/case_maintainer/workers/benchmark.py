"""Benchmark worker — compare bot reports vs golden facts, generate playbooks."""
import json, os, re, time, logging, urllib.request
import psycopg2
from core.config import PG_DSN, LLM_URL, LLM_MODEL, LLM_FAST_MODEL, LLM_MAX_TOKENS, LLM_TIMEOUT, QDRANT_URL, LLM_JSON_TEMPERATURE, LLM_FAST_TEMPERATURE
from core.http_utils import http_json as _http_json, llm_chat as _llm_chat
from core.model_router import build_chat_payload
from telegram.notify import _tg_send_admin
from workers.state import _idle_worker_stop, _bg_llm_lock, _state
from workers.idle_learning import _wait_for_llm
_log = logging.getLogger('app')


def _ensure_benchmark_tables():
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS dfir_benchmark_runs_v1 (
                      id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                      case_key    TEXT NOT NULL,
                      status      TEXT NOT NULL DEFAULT 'running',
                      quality_score INT,
                      pass_count  INT DEFAULT 0,
                      fail_count  INT DEFAULT 0,
                      notes       TEXT,
                      started_at  TIMESTAMPTZ DEFAULT NOW(),
                      finished_at TIMESTAMPTZ
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS dfir_benchmark_gaps_v1 (
                      id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                      run_id      UUID NOT NULL,
                      case_key    TEXT NOT NULL,
                      gap_type    TEXT,
                      expected    TEXT,
                      bot_found   TEXT,
                      severity    TEXT DEFAULT 'medium',
                      created_at  TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS dfir_playbooks_v1 (
                      id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                      case_key        TEXT,
                      gap_type        TEXT,
                      title           TEXT,
                      checklist       JSONB DEFAULT '[]'::jsonb,
                      sql_patterns    JSONB DEFAULT '[]'::jsonb,
                      evidence_rules  JSONB DEFAULT '[]'::jsonb,
                      source_run_id   UUID,
                      times_applied   INT DEFAULT 0,
                      created_at      TIMESTAMPTZ DEFAULT NOW(),
                      updated_at      TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS dfir_golden_facts_v1 (
                      id          SERIAL PRIMARY KEY,
                      case_key    TEXT NOT NULL,
                      category    TEXT NOT NULL,
                      fact_key    TEXT NOT NULL,
                      fact_value  TEXT NOT NULL,
                      severity    TEXT DEFAULT 'high',
                      created_at  TIMESTAMPTZ DEFAULT NOW(),
                      UNIQUE(case_key, category, fact_key)
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_bmark_runs_case ON dfir_benchmark_runs_v1(case_key, started_at DESC)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_bmark_gaps_run ON dfir_benchmark_gaps_v1(run_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_playbooks_gap ON dfir_playbooks_v1(gap_type)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_golden_case ON dfir_golden_facts_v1(case_key, category)")
                conn.commit()
    except Exception as _e:
        _log.error(f"[benchmark] _ensure_benchmark_tables error: {_e}")


def _seed_golden_facts():
    """Seed golden reference facts for case_58/case_59 case."""
    facts = [
        # initial_access
        ('29_04_2026__case_58_phishing_case_59', 'initial_access', 'timestamp',       '2026-01-26 10:06:29 UTC', 'high'),
        ('29_04_2026__case_58_phishing_case_59', 'initial_access', 'vector',          'Chrome download from SwissTransfer', 'high'),
        ('29_04_2026__case_58_phishing_case_59', 'initial_access', 'first_files',     'C:\\Users\\Public\\Documents\\edit.dll, gcapi.dll, start.vbs', 'high'),
        ('29_04_2026__case_58_phishing_case_59', 'initial_access', 'payload_path',    'C:\\Users\\123\\AppData\\Roaming\\try.exe', 'high'),
        # defender
        ('29_04_2026__case_58_phishing_case_59', 'defender',       'bypass_cmd',      'PowerShell Add-MpPreference -ExclusionPath C:\\', 'high'),
        ('29_04_2026__case_58_phishing_case_59', 'defender',       'detection',       'Trojan:Win32/MpTamperBulkExcl.H', 'high'),
        # persistence
        ('29_04_2026__case_58_phishing_case_59', 'persistence',    'account_created', 'case_59', 'high'),
        ('29_04_2026__case_58_phishing_case_59', 'persistence',    'account_ts',      '2026-01-26 10:23:51 UTC', 'high'),
        ('29_04_2026__case_58_phishing_case_59', 'persistence',    'rdp_wrapper',     'rdpwinst.exe installed in C:\\Program Files\\RDP Wrapper', 'high'),
        # remote_access
        ('29_04_2026__case_58_phishing_case_59', 'remote_access',  'tools',           'RDP Wrapper + ngrok tunnel', 'high'),
        ('29_04_2026__case_58_phishing_case_59', 'remote_access',  'rdp_source_host', 'case_53', 'high'),
        ('29_04_2026__case_58_phishing_case_59', 'remote_access',  'rdp_user',        'case_59', 'high'),
        ('29_04_2026__case_58_phishing_case_59', 'remote_access',  'suspicious_host', '192.168.0.166 / DESKTOP', 'medium'),
        # ioc
        ('29_04_2026__case_58_phishing_case_59', 'ioc', 'executables',
         'ngrok.exe, rdpwinst.exe, msedgex.exe, try.exe, 7za.exe', 'high'),
        ('29_04_2026__case_58_phishing_case_59', 'ioc', 'suspicious_dlls',
         'edit.dll, gcapi.dll in C:\\Users\\Public\\Documents', 'high'),
        ('29_04_2026__case_58_phishing_case_59', 'ioc', 'script',
         'start.vbs in C:\\Users\\Public\\Documents', 'medium'),
        # also seed for original case_58 key
        ('06_02_2026_case_58_phishing_attack_NGROK_і_case_59', 'initial_access', 'timestamp',    '2026-01-26 10:06:29 UTC', 'high'),
        ('06_02_2026_case_58_phishing_attack_NGROK_і_case_59', 'initial_access', 'vector',       'Chrome download from SwissTransfer', 'high'),
        ('06_02_2026_case_58_phishing_attack_NGROK_і_case_59', 'defender',       'bypass_cmd',   'PowerShell Add-MpPreference -ExclusionPath C:\\', 'high'),
        ('06_02_2026_case_58_phishing_attack_NGROK_і_case_59', 'defender',       'detection',    'Trojan:Win32/MpTamperBulkExcl.H', 'high'),
        ('06_02_2026_case_58_phishing_attack_NGROK_і_case_59', 'persistence',    'account_created', 'case_59', 'high'),
        ('06_02_2026_case_58_phishing_attack_NGROK_і_case_59', 'persistence',    'account_ts',   '2026-01-26 10:23:51 UTC', 'high'),
        ('06_02_2026_case_58_phishing_attack_NGROK_і_case_59', 'remote_access',  'tools',        'RDP Wrapper + ngrok tunnel', 'high'),
        ('06_02_2026_case_58_phishing_attack_NGROK_і_case_59', 'remote_access',  'rdp_source_host', 'case_53', 'high'),
        ('06_02_2026_case_58_phishing_attack_NGROK_і_case_59', 'ioc', 'executables',
         'ngrok.exe, rdpwinst.exe, msedgex.exe, try.exe, 7za.exe', 'high'),
        # --- case_41: bank accountant PC, keylogger + RMS remote access ---
        ('case_25', 'initial_access', 'timestamp',
         '2026-03-11 13:05:21', 'high'),
        ('case_25', 'initial_access', 'vector',
         'Chrome download RAR from email link (fileview.ukr.net), sender raj.chaorasia@aristopharma.co.in (compromised)', 'high'),
        ('case_25', 'initial_access', 'lure_file',
         'Електронна форма Бюро економічної безпеки України №_9156.rar (25 MiB)', 'high'),
        ('case_25', 'malware', 'payload_exe',
         'Електронна форма Бюро економічної безпеки України №_9156.exe (Prefetch 2026-03-11 13:06:40)', 'critical'),
        ('case_25', 'persistence', 'autorun_exe',
         'C:\\ProgramData\\System32\\System32.exe added to autorun 2026-03-11 15:45:42', 'critical'),
        ('case_25', 'keylogger', 'tool',
         'rvc keylogger: C:\\ProgramData\\rvc\\logs.dat active 2026-03-13 to 2026-04-02', 'critical'),
        ('case_25', 'remote_access', 'tools',
         'RMS (Remote Manipulator System), LiteManager Pro 5.0, RDP Wrapper', 'high'),
        ('case_25', 'remote_access', 'rms_install',
         'RMS installed 2026-03-11 15:06:50 in C:\\Program Files (x86)\\Remote Manipulator System', 'high'),
        ('case_25', 'defender', 'quarantine_removed',
         'Trojan:Win32/Alevaul!rfn removed from quarantine 2026-03-16 11:20:31', 'high'),
        ('case_25', 'log_tampering', 'cleared_logs',
         'Security, System, PowerShell logs cleared 2026-03-16 11:19:37', 'critical'),
        ('case_25', 'credential_access', 'method',
         'Credential Manager accessed by SYSTEM 2026-03-16; password.txt used by attacker', 'critical'),
        ('case_25', 'ioc', 'rar_sha1',
         '5b7399a803a333140c76a5060b2e5c446ee29e5e (Електронна форма №_9156.rar)', 'high'),
        ('case_25', 'ioc', 'system32_sha1',
         'aaee8a00b1674262c87f7fc46d6a80930b6f35ae (C:\\ProgramData\\System32\\System32.exe)', 'critical'),
        ('case_25', 'attribution', 'country',
         'Likely China — Chinese characters in malware web panel logs', 'medium'),
    ]
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                for case_key, cat, fact_key, fact_val, sev in facts:
                    cur.execute("""
                        INSERT INTO dfir_golden_facts_v1 (case_key, category, fact_key, fact_value, severity)
                        VALUES (%s,%s,%s,%s,%s)
                        ON CONFLICT (case_key, category, fact_key) DO NOTHING
                    """, (case_key, cat, fact_key, fact_val, sev))
                conn.commit()
        _log.info("[benchmark] golden facts seeded")
    except Exception as _e:
        _log.error(f"[benchmark] _seed_golden_facts error: {_e}")


def _has_active_production_run():
    """Return True if any DFIR job is currently queued or running."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) FROM dfir_run_jobs_v2
                    WHERE status IN ('queued','running')
                    AND created_at >= NOW() - INTERVAL '2 hours'
                """)
                return cur.fetchone()[0] > 0
    except Exception:
        return False


def _benchmark_get_cases():
    """Return case_keys that have golden facts AND still have ingested data.
    (Golden facts persist after a case is deleted/archived; benchmarking those
    dead cases yields a meaningless 0/5 and pollutes playbooks — skip them.)"""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute("""SELECT DISTINCT g.case_key FROM dfir_golden_facts_v1 g
                    WHERE EXISTS (SELECT 1 FROM event_logs_v2 e WHERE e.case_key=g.case_key)
                    ORDER BY g.case_key""")
                return [r[0] for r in cur.fetchall()]
    except Exception:
        return []


def _benchmark_get_golden(case_key):
    """Return golden facts for case as structured dict."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT category, fact_key, fact_value, severity
                    FROM dfir_golden_facts_v1 WHERE case_key=%s ORDER BY category, fact_key
                """, (case_key,))
                rows = cur.fetchall()
        result = {}
        for cat, key, val, sev in rows:
            result.setdefault(cat, {})[key] = {'value': val, 'severity': sev}
        return result
    except Exception:
        return {}


def _merge_json_objects(text):
    """Pull every balanced top-level {...} out of an LLM answer and merge them.

    A greedy brace regex looks right until the model answers with TWO objects
    (one per category, or a preamble plus the payload): the match then spans
    both, json.loads dies with "Extra data", and a whole case silently scores
    zero. Scan brace depth instead, keep what parses, merge list values."""
    out = None
    depth = 0
    start = -1
    for i, ch in enumerate(text or ''):
        if ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    try:
                        obj = json.loads(text[start:i + 1])
                    except Exception:
                        obj = None
                    if isinstance(obj, dict):
                        if out is None:
                            out = {}
                        for k, v in obj.items():
                            if isinstance(v, list):
                                if not isinstance(out.get(k), list):
                                    out[k] = []
                                out[k].extend(v)
                            elif k not in out:
                                out[k] = v
                    start = -1
    return out


def _auto_extract_golden_from_report(case_key):
    """Use LLM to extract golden facts from expert PDF in kb_reports → save to dfir_golden_facts_v1."""
    try:
        # Fetch all kb_reports chunks for this case
        qdrant = QDRANT_URL
        body = json.dumps({'limit': 20, 'with_payload': True, 'with_vector': False,
            'filter': {'should': [
                {'key': 'case_key', 'match': {'value': case_key}},
                {'key': 'source_file', 'match': {'any': [case_key + '.pdf', case_key]}}
            ]}}).encode('utf-8')
        req = urllib.request.Request(f'{qdrant}/collections/kb_reports/points/scroll',
                                     data=body, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=10) as r:
            pts = json.loads(r.read().decode('utf-8', errors='ignore')).get('result', {}).get('points', [])
        if not pts:
            _log.error(f"[golden_extract] no kb_reports chunks for {case_key}")
            return 0

        text = '\n\n'.join(p.get('payload', {}).get('text', '') for p in pts if p.get('payload', {}).get('text'))[:6000]

        llm_url = LLM_URL
        model = LLM_FAST_MODEL
        prompt = f"""You are a DFIR analyst. Extract structured forensic facts from this expert report for case: {case_key}

EXPERT REPORT TEXT:
{text}

Extract ALL key facts grouped by category. Return ONLY valid JSON:
{{
  "initial_access": [{{"fact_key": "delivery_method", "fact_value": "...", "severity": "critical|high|medium"}}],
  "malware": [{{"fact_key": "malware_name", "fact_value": "...", "severity": "..."}}],
  "persistence": [{{"fact_key": "task_name", "fact_value": "...", "severity": "..."}}],
  "remote_access": [{{"fact_key": "tool", "fact_value": "...", "severity": "..."}}],
  "accounts": [{{"fact_key": "username", "fact_value": "...", "severity": "..."}}],
  "iocs": [{{"fact_key": "ioc_type:value", "fact_value": "...", "severity": "..."}}],
  "timeline": [{{"fact_key": "first_seen", "fact_value": "YYYY-MM-DD HH:MM timestamp", "severity": "high"}}],
  "defender": [{{"fact_key": "tamper_method", "fact_value": "...", "severity": "..."}}]
}}
RULES:
- Every fact_value MUST contain a concrete artefact a forensic tool can search for:
  a file name with extension, a full path, an IPv4, a domain, a hash, an account name,
  a scheduled-task/service name, a registry key or an ISO timestamp.
  A fact whose value is only prose ("malicious executable", "tunneling tool") is USELESS -
  either name the artefact or drop the fact.
- fact_key must be UNIQUE inside its category; if two facts share a kind, number them
  ("tool", "tool_2").
Extract minimum 5, maximum 30 facts total. Only real facts from the text, no hallucinations."""

        body_llm = json.dumps(build_chat_payload(
            model=model,
            messages=[{'role': 'user', 'content': prompt}],
            role='json',
            temperature=LLM_JSON_TEMPERATURE,
            max_tokens=int(os.environ.get('DFIR_BENCHMARK_EXTRACT_MAX_TOKENS', '6000')),
            stream=False,
            reasoning_effort=os.environ.get('DFIR_JSON_REASONING_EFFORT', 'low'),
        )).encode('utf-8')
        req_llm = urllib.request.Request(
            f'{llm_url.rstrip("/")}/v1/chat/completions',
            data=body_llm, headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req_llm, timeout=600) as r:
            content = json.loads(r.read().decode('utf-8', errors='ignore'))
        _msg = content['choices'][0]['message']
        text_out = (_msg.get('content') or _msg.get('reasoning_content') or _msg.get('reasoning') or '').strip()
        facts_by_cat = _merge_json_objects(text_out)
        if facts_by_cat is None:
            _log.error(f"[golden_extract] no JSON in LLM response for {case_key}: {text_out[:300]!r}")
            return 0
        saved = 0
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("DELETE FROM dfir_golden_facts_v1 WHERE case_key=%s AND severity != 'manual'", (case_key,))
                # The unique key is (case_key, category, fact_key). A grader model happily
                # returns three "tool" facts under remote_access; with ON CONFLICT DO NOTHING
                # the 2nd and 3rd vanished silently, so the yardstick lost a third of itself
                # before anyone measured anything. Number the repeats instead.
                for category, facts in facts_by_cat.items():
                    if not isinstance(facts, list):
                        continue
                    _seen = {}
                    for f in facts:
                        if not isinstance(f, dict) or not f.get('fact_key') or not f.get('fact_value'):
                            continue
                        _fk = str(f['fact_key'])[:100]
                        _seen[_fk] = _seen.get(_fk, 0) + 1
                        if _seen[_fk] > 1:
                            _fk = ('%s#%d' % (_fk, _seen[_fk]))[:100]
                        cur.execute("""INSERT INTO dfir_golden_facts_v1
                            (case_key, category, fact_key, fact_value, severity)
                            VALUES (%s,%s,%s,%s,%s)
                            ON CONFLICT DO NOTHING""",
                            (case_key, category, _fk,
                             str(f['fact_value'])[:500], str(f.get('severity','medium'))))
                        saved += 1
        _log.error(f"[golden_extract] extracted {saved} facts for {case_key}")
        return saved
    except Exception as _e:
        _log.error(f"[golden_extract] error for {case_key}: {_e}")
        return 0


def _benchmark_slice_report(full):
    """Judge-input composer. The reshaped client report is ~48KB and the
    fact-bearing sections (Q&A narrative, detections, IOC) live PAST the old
    naive [:12000] head-cut — grading collapsed to 0-2/5 the day the reshaper
    landed (avg 1.5 -> 0.5 on 07-04..07-05). Pull those sections explicitly;
    fall back to the head for short/un-reshaped reports."""
    import re as _re
    if len(full) <= 20000:
        return full
    parts, seen = [], set()
    markers = [
        (r'ПЕРША ТОЧКА ЗАРАЖЕННЯ', 3000),
        (r'ЗАГАЛЬНИЙ ВИСНОВОК', 3500),
        (r'АВТОМАТИЧНІ ДЕТЕКЦІЇ ЗАГРОЗ', 4000),
        (r'ПИТАННЯ\s*[–—-]\s*ВІДПОВІДЬ', 6000),
        (r'ХРОНОЛОГІЯ ПОДІЙ З ДОКАЗАМИ', 5000),
        (r'ІНДИКАТОРИ КОМПРОМЕТАЦІЇ', 3000),
    ]
    for pat, cap in markers:
        for m in list(_re.finditer(pat, full))[:2]:
            if m.start() in seen:
                continue
            seen.add(m.start())
            parts.append(full[m.start():m.start() + cap])
    if not parts:
        return full[:20000]
    return ('\n\n[...]\n\n'.join(parts))[:26000]


def _benchmark_get_bot_report(case_key):
    """Get latest completed job's txt_report as bot answer."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT txt_report_path, job_id FROM dfir_run_jobs_v2
                    WHERE case_key=%s AND status='completed' AND txt_report_ready=true
                    ORDER BY finished_at DESC LIMIT 1
                """, (case_key,))
                row = cur.fetchone()
        if not row:
            return None, None
        path, job_id = row
        if path and os.path.exists(path):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return _benchmark_slice_report(f.read(250000)), str(job_id)
        return None, str(job_id) if job_id else None
    except Exception:
        return None, None


def _benchmark_assemble_sql_findings(case_key):
    """Pull key forensic data from DB for this case.

    Sections are ordered so the most forensically critical data (hashes, defender
    detections, remote-access programs) appears first and survives the 2000-char
    JSON truncation applied in _benchmark_llm_compare.
    """
    findings = {}
    try:
        with psycopg2.connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                # IOCs — hash types first so they survive the 2000-char JSON truncation.
                # Expert-document sources are excluded: case_iocs also holds rows parsed
                # OUT of the expert report ('report', 'report_reclassified', 'report_llm',
                # 'report_pdf', and sources named after the .pdf/.docx itself). Handing
                # those to the judge as "what the bot found" grades the bot against its own
                # crib sheet - measured on case_30: 6 of the 20 rows
                # fed to the judge, 4 malware SHA1 and 2 domains, came from the .docx.
                cur.execute("""
                    SELECT ioc_type, ioc_value, confidence, source_ref
                    FROM case_iocs WHERE case_key=%s
                      AND coalesce(source_table,'') NOT IN
                          ('report', 'report_reclassified', 'report_llm', 'report_pdf')
                      AND coalesce(source_table,'') !~* '[.](pdf|docx|doc|md)$'
                    ORDER BY CASE ioc_type WHEN 'hash_sha1' THEN 0 WHEN 'hash_md5' THEN 1
                                           WHEN 'hash_sha256' THEN 2 ELSE 3 END, ioc_type
                    LIMIT 20
                """, (case_key,))
                findings['iocs'] = [
                    {'type': r[0], 'value': r[1], 'conf': str(r[2]), 'src': r[3]}
                    for r in cur.fetchall()
                ]
                # Defender events — EID 1011 (quarantine removal) + 1116/1117 detections
                # Uses PayloadData1 fallback to extract threat name from EvtxECmd-normalized logs
                cur.execute(r"""
                    SELECT event_ts,
                           COALESCE(
                               NULLIF(payload->>'ThreatName',''),
                               (regexp_match(payload::text, '"PayloadData1"\s*:\s*"Malware name:\s*([^"]+)"'))[1],
                               NULLIF(payload->>'PayloadData1','')
                           ) AS threat,
                           COALESCE(NULLIF(payload->>'Path',''), NULLIF(payload->>'PayloadData3','')) AS path,
                           COALESCE(NULLIF(payload->>'ActionSuccess',''), payload->>'MapDescription') AS action
                    FROM event_logs_v2
                    WHERE case_key=%s AND event_id IN (1011,1116,1117,1119,5007,5010,5012)
                    ORDER BY event_ts ASC LIMIT 10
                """, (case_key,))
                findings['defender'] = [
                    {'ts': str(r[0]), 'threat': r[1], 'path': r[2], 'action': r[3]}
                    for r in cur.fetchall()
                ]
                # Remote access programs (RAT/RMM installs captured in program_exec_v2)
                try:
                    cur.execute(r"""
                        SELECT event_ts, executable_name, full_path, hash_sha1
                        FROM program_exec_v2
                        WHERE case_key=%s
                        AND lower(full_path) ~ '(remote manipulator|rutserv|rfusclient|litemanager|anydesk|teamviewer|rdpwrap|ngrok)'
                        ORDER BY event_ts ASC LIMIT 10
                    """, (case_key,))
                    findings['remote_access_programs'] = [
                        {'ts': str(r[0]), 'exe': r[1], 'path': r[2], 'sha1': r[3]}
                        for r in cur.fetchall()
                    ]
                except Exception:
                    pass
                # Account creation
                cur.execute("""
                    SELECT event_ts, target_user,
                           payload->>'SubjectUserName' AS actor
                    FROM event_logs_v2
                    WHERE case_key=%s AND event_id=4720
                    ORDER BY event_ts ASC LIMIT 10
                """, (case_key,))
                findings['accounts_created'] = [
                    {'ts': str(r[0]), 'user': r[1], 'actor': r[2]} for r in cur.fetchall()
                ]
                # RDP logons
                cur.execute("""
                    SELECT event_ts, target_user, remote_host,
                           payload->>'WorkstationName' AS ws
                    FROM event_logs_v2
                    WHERE case_key=%s AND event_id IN (4624,4625) AND (logon_type ILIKE '%%remote interactive%%' OR logon_type ILIKE '%%RDP%%' OR logon_type='10')
                    ORDER BY event_ts ASC LIMIT 10
                """, (case_key,))
                findings['rdp_logons'] = [
                    {'ts': str(r[0]), 'user': r[1], 'ip': r[2], 'ws': r[3]}
                    for r in cur.fetchall()
                ]
                # Initial access candidates (process creation — last, often sparse)
                cur.execute("""
                    SELECT event_ts, process_name, command_line,
                           payload->>'ParentProcessName' AS parent
                    FROM event_logs_v2
                    WHERE case_key=%s AND event_id IN (4688,1)
                      AND coalesce(process_name,'') <> ''
                    ORDER BY event_ts ASC LIMIT 15
                """, (case_key,))
                findings['process_exec'] = [
                    {'ts': str(r[0]), 'proc': r[1], 'cmd': (r[2] or '')[:200], 'parent': r[3]}
                    for r in cur.fetchall()
                ]
                # File artifacts
                cur.execute("""
                    SELECT parent_path || '/' || file_name AS full_path, event_ts, payload->>'Zone' AS zone
                    FROM filesystem_v2
                    WHERE case_key=%s
                    AND (parent_path ILIKE '%%Public%%' OR parent_path ILIKE '%%Roaming%%'
                         OR file_name ILIKE '%%ngrok%%' OR file_name ILIKE '%%rdpw%%'
                         OR parent_path ILIKE '%%ngrok%%' OR parent_path ILIKE '%%rdpw%%')
                    ORDER BY event_ts ASC LIMIT 15
                """, (case_key,))
                findings['file_artifacts'] = [
                    {'path': r[0], 'ts': str(r[1]), 'zone': r[2]} for r in cur.fetchall()
                ]
    except Exception as _e:
        _log.error(f"[benchmark] _benchmark_assemble_sql_findings error: {_e}")
    return findings


def _benchmark_llm_compare(case_key, bot_report, sql_findings, golden_facts):
    """Grade the bot's coverage of EACH golden fact (per-fact pass/fail) so the
    score is REAL instead of the schema default. The old prompt handed the model a
    fillable JSON example and gpt-oss just echoed it (pass=0/fail=0/score=3). Now we
    number the golden facts and force an independent verdict per fact, then count.
    Returns the legacy dict shape consumed by _benchmark_run_case."""
    llm_url = LLM_URL
    # The fast 20b judge failed 9/10 golden facts that were VERBATIM in its input
    # (2026-07-08 bank case) — long-context grading needs the report-grade model.
    model = os.environ.get('DFIR_BENCHMARK_JUDGE_MODEL', 'reasoner-31b')

    # flatten the nested golden facts into N atomic, readable facts. The seeded
    # golden is a dict {category: {subfield: {value, severity}}}; auto-extracted
    # golden may be a list. Either way -> [{text, type, severity}].
    def _walk_values(o, vals):
        if isinstance(o, dict):
            sev = o.get('severity')
            if isinstance(o.get('value'), (str, int, float)):
                vals.append((str(o['value']), sev))
            for _k, _v in o.items():
                if _k not in ('value', 'severity'):
                    _walk_values(_v, vals)
        elif isinstance(o, list):
            for _x in o:
                _walk_values(_x, vals)
        elif isinstance(o, (str, int, float)):
            vals.append((str(o), None))

    if isinstance(golden_facts, dict):
        src = list(golden_facts.items())
    elif isinstance(golden_facts, list):
        src = [(((g.get('category') or g.get('gap_type') or g.get('fact_type') or 'fact')
                 if isinstance(g, dict) else 'fact'), g) for g in golden_facts]
    else:
        src = [('fact', golden_facts)]

    items = []
    for cat, body in src:
        vals = []
        _walk_values(body, vals)
        sev = next((sv for (_v, sv) in vals if sv), 'medium')
        if vals:
            text = '%s: %s' % (cat, ' | '.join(v for (v, _sv) in vals[:5]))
        else:
            text = '%s: %s' % (cat, json.dumps(body, ensure_ascii=False)[:200])
        items.append({'text': str(text)[:320], 'type': str(cat), 'severity': str(sev)})
    if not items:
        return None
    n_total = len(items)
    golden_list = '\n'.join('%d. %s' % (i + 1, it['text']) for i, it in enumerate(items))

    # gpt-small-20b now has a 64K context — feed the judge the real material
    # (3500-char cuts starved it down to the report header -> fake 0/5 scores).
    report_txt = (bot_report or 'NO REPORT AVAILABLE')[:16000]
    sql_txt = json.dumps(sql_findings, ensure_ascii=False, default=str)[:6000]

    prompt = (
        "You are a strict DFIR QA grader. For case %s, decide for EACH numbered "
        "golden fact whether the BOT REPORT or SQL EVIDENCE below actually covers it.\n\n"
        "GOLDEN FACTS (exactly %d):\n%s\n\n"
        "BOT REPORT:\n%s\n\nSQL EVIDENCE:\n%s\n\n"
        "Rules: verdict=\"pass\" ONLY if the bot report or SQL evidence clearly "
        "contains that specific fact; otherwise \"fail\". Judge each fact "
        "independently on the evidence shown above; do NOT invent coverage.\n"
        "Output ONLY this JSON (exactly %d verdicts, no prose, no markdown):\n"
        "{\"verdicts\":[{\"n\":1,\"verdict\":\"pass-or-fail\",\"note\":\"short where-found or why-missing\"}],"
        "\"lesson_summary\":\"one sentence on the biggest gap\"}"
    ) % (case_key, n_total, golden_list, report_txt, sql_txt, n_total)

    if _has_active_production_run():
        _log.error("[benchmark] llm_compare skipping - production run active")
        return None

    text = ''
    try:
        body = json.dumps(build_chat_payload(
            model=model,
            messages=[{'role': 'user', 'content': prompt}],
            role='json',
            temperature=LLM_FAST_TEMPERATURE,
            max_tokens=int(os.environ.get('DFIR_BENCHMARK_COMPARE_MAX_TOKENS', '5000')),
            stream=False,
            reasoning_effort='',
        )).encode('utf-8')
        import time as _t
        text = ''
        _last_err = None
        for _attempt in range(4):
            try:
                req = urllib.request.Request(
                    f'{llm_url.rstrip("/")}/v1/chat/completions',
                    data=body, headers={'Content-Type': 'application/json'})
                with urllib.request.urlopen(req, timeout=660) as r:
                    content = json.loads(r.read().decode('utf-8', errors='ignore'))
                    msg = content['choices'][0]['message']
                    text = (msg.get('content') or msg.get('reasoning') or '').strip()
                if text:
                    break
                _last_err = 'empty response'
            except Exception as _re:
                _last_err = _re
                _log.info("[benchmark] grader attempt %d failed: %s (retry)" % (_attempt + 1, _re))
            _t.sleep(8 * (_attempt + 1))  # backoff: lets llama-swap reload the model after a swap
        if not text:
            _log.error("[benchmark] grader failed after retries: %s" % _last_err)
            return None
        _log.info("[benchmark] grader raw (%d chars): %r" % (len(text), text[:200]))
        try:
            with open('/tmp/bench_llm_last.txt', 'w') as _df:
                _df.write(text)
        except Exception:
            pass
    except Exception as _e:
        _log.error("[benchmark] grader call error: %s" % _e)
        return None

    parsed = None
    tc = re.sub(r'```(?:json)?', '', text).strip()
    m = re.search(r'\{.*\}', tc, re.DOTALL)
    if m:
        raw = m.group()
        for _ in range(6):
            try:
                parsed = json.loads(raw); break
            except json.JSONDecodeError:
                raw = re.sub(r',\s*([\]}])', r'\1', raw)
                raw = re.sub(r'([\}\]])\s*\n(\s*[\{\[])', r'\1,\n\2', raw)
                raw = re.sub(r'//[^\n]*', '', raw)
                raw = re.sub(r'\bNone\b', 'null', raw)
                raw = re.sub(r'\bTrue\b', 'true', raw)
                raw = re.sub(r'\bFalse\b', 'false', raw)
    if not parsed or not isinstance(parsed.get('verdicts'), list):
        _log.error("[benchmark] grader returned no usable verdicts")
        return None

    # Score = COVERAGE over ALL N golden facts. gpt-oss is inconsistent about
    # returning a verdict for every fact, so we only trust the PASSes it asserts;
    # every fact not confirmed-pass counts as a gap. This makes the score
    # deterministic and conservative regardless of how many verdicts come back.
    passed = set()
    notes = {}
    for v in parsed['verdicts']:
        try:
            n = int(v.get('n') or 0)
        except Exception:
            n = 0
        if not (1 <= n <= n_total):
            continue
        notes[n] = str(v.get('note') or '')[:300]
        if str(v.get('verdict') or '').lower().startswith('pass'):
            passed.add(n)
    # Deterministic verbatim override: a golden fact whose distinctive token
    # (hash/date/filename — has a digit or a dot, len>=6) appears VERBATIM in the
    # judge input is a PASS even when the LLM judge overlooked it. String match
    # is exact and free; the LLM only arbitrates non-literal facts.
    _hay = ((report_txt or '') + ' ' + (sql_txt or '')).lower()
    for _i, _it in enumerate(items, 1):
        if _i in passed:
            continue
        for _t in re.split(r'[^\w./\\:№_-]+', _it['text'].lower()):
            _t = _t.strip('.:-')
            if len(_t) >= 6 and (any(_c.isdigit() for _c in _t) or '.' in _t) and _t in _hay:
                passed.add(_i)
                notes[_i] = 'verbatim match: ' + _t[:80]
                break
    pass_c = len(passed)
    fail_c = n_total - pass_c
    good = [items[i - 1]['text'][:90] for i in sorted(passed)][:6]
    gaps = [{'gap_type': items[i - 1]['type'], 'expected': items[i - 1]['text'],
             'bot_found': notes.get(i, ''), 'severity': items[i - 1]['severity'],
             'table_hint': ''}
            for i in range(1, n_total + 1) if i not in passed]
    quality = max(1, min(5, int(round(5.0 * pass_c / n_total)))) if n_total else 1
    rules = [{'title': 'Перевіряти: %s' % g['gap_type'], 'gap_type': g['gap_type'],
              'checklist': [g['expected'][:120]]}
             for g in gaps if g['severity'] in ('high', 'critical')][:6]
    return {'quality_score': quality, 'pass_count': pass_c, 'fail_count': fail_c,
            'gaps': gaps, 'good_patterns': good[:6], 'playbook_rules': rules,
            'lesson_summary': str(parsed.get('lesson_summary') or '')[:300]}

def _benchmark_save_playbooks(run_id, case_key, playbook_rules):
    """Save reusable playbooks from LLM evaluation."""
    if not playbook_rules:
        return
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                for rule in playbook_rules[:5]:
                    cur.execute("""
                        INSERT INTO dfir_playbooks_v1
                          (case_key, gap_type, title, checklist, sql_patterns, source_run_id)
                        VALUES (%s,%s,%s,%s::jsonb,%s::jsonb,%s)
                    """, (
                        case_key,
                        rule.get('gap_type', 'general'),
                        rule.get('title', '')[:200],
                        json.dumps(rule.get('checklist', [])),
                        json.dumps(rule.get('sql_patterns', [])),
                        run_id
                    ))
                conn.commit()
    except Exception as _e:
        _log.error(f"[benchmark] _benchmark_save_playbooks error: {_e}")


def _benchmark_run_case(case_key):
    """Full benchmark run for one case: SQL findings → LLM compare → save gaps + playbooks."""
    run_id = None
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO dfir_benchmark_runs_v1 (case_key, status)
                    VALUES (%s,'running') RETURNING id
                """, (case_key,))
                run_id = str(cur.fetchone()[0])
                conn.commit()

        golden = _benchmark_get_golden(case_key)
        if not golden:
            _log.error(f"[benchmark] no golden facts for {case_key}, trying auto-extract from kb_reports")
            extracted = _auto_extract_golden_from_report(case_key)
            if extracted:
                golden = _benchmark_get_golden(case_key)
            if not golden:
                _log.error(f"[benchmark] still no golden facts for {case_key}, skip")
                with psycopg2.connect(PG_DSN) as conn:
                    conn.autocommit = True
                    with conn.cursor() as cur:
                        cur.execute("UPDATE dfir_benchmark_runs_v1 SET status='skipped', notes='no_golden_facts', finished_at=NOW() WHERE id=%s", (run_id,))
                return None

        bot_report, job_id = _benchmark_get_bot_report(case_key)
        sql_findings = _benchmark_assemble_sql_findings(case_key)

        _log.info(f"[benchmark] comparing {case_key}: report={'yes' if bot_report else 'no'} sql_keys={list(sql_findings.keys())}")

        if not _bg_llm_lock.acquire(timeout=600):
            _log.info(f"[benchmark] lock timeout, skipping {case_key}")
            return None
        try:
            result = _benchmark_llm_compare(case_key, bot_report, sql_findings, golden)
        finally:
            _bg_llm_lock.release()
        if not result:
            with psycopg2.connect(PG_DSN) as conn:
                conn.autocommit = True
                with conn.cursor() as cur:
                    cur.execute("UPDATE dfir_benchmark_runs_v1 SET status='error', notes='llm_compare_failed', finished_at=NOW() WHERE id=%s", (run_id,))
            return None

        pass_c = int(result.get('pass_count') or 0)
        fail_c = int(result.get('fail_count') or 0)
        # Compute score deterministically — LLM tends to copy the schema default (3)
        # regardless of actual pass/fail, so we derive it from pass_count directly.
        score = int(round(5.0 * pass_c / (pass_c + fail_c))) if (pass_c + fail_c) > 0 else int(result.get('quality_score') or 1)
        gaps = result.get('gaps', [])
        good = result.get('good_patterns', [])
        lesson = result.get('lesson_summary', '')

        # Save gaps
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                for g in gaps[:10]:
                    cur.execute("""
                        INSERT INTO dfir_benchmark_gaps_v1
                          (run_id, case_key, gap_type, expected, bot_found, severity)
                        VALUES (%s,%s,%s,%s,%s,%s)
                    """, (
                        run_id, case_key,
                        g.get('gap_type', ''),
                        g.get('expected', '')[:500],
                        g.get('bot_found', '')[:500],
                        g.get('severity', 'medium')
                    ))
                cur.execute("""
                    UPDATE dfir_benchmark_runs_v1
                    SET status='done', quality_score=%s, pass_count=%s, fail_count=%s,
                        notes=%s, finished_at=NOW()
                    WHERE id=%s
                """, (score, pass_c, fail_c, lesson[:500], run_id))
                conn.commit()

        _benchmark_save_playbooks(run_id, case_key, result.get('playbook_rules', []))

        # Save gap lessons to dfir_lessons_learned_v1 so synthesis picks them up
        if gaps or lesson:
            try:
                from analysis.learnings import _save_lesson
                if lesson:
                    _save_lesson(case_key, 'benchmark_summary', 'gap_from_self_eval',
                                 f"[BENCHMARK SUMMARY] {lesson}", [], [], {})
                for g in gaps[:8]:
                    g_text = (
                        f"[BENCHMARK GAP] {g.get('gap_type','?')} severity={g.get('severity','?')}\n"
                        f"Expected: {g.get('expected','')[:300]}\n"
                        f"Bot found: {g.get('bot_found','') or 'nothing'}"
                    )
                    _save_lesson(case_key, g.get('gap_type', 'benchmark_gap'),
                                 'gap_from_self_eval', g_text, [], [], {})
                _log.info(f"[benchmark] saved {len(gaps)} gap lessons to dfir_lessons_learned_v1")
            except Exception as _le:
                _log.error(f"[benchmark] gap lesson save error: {_le}")

        pass_fail = 'PASS ✅' if score >= 4 else ('WARN ⚠️' if score >= 3 else 'FAIL ❌')
        gap_lines = '\n'.join(
            f"  [{g.get('severity','?').upper()}] {g.get('gap_type','?')}: {g.get('expected','')[:80]}"
            for g in gaps[:5]
        )
        good_lines = '\n'.join(f"  ✓ {x[:80]}" for x in good[:3])
        msg = (
            f"🔬 <b>Benchmark: {case_key[:40]}</b>\n"
            f"Результат: {pass_fail} (score {score}/5)\n"
            f"Pass: {pass_c} | Fail: {fail_c}\n\n"
            f"<b>Gaps знайдено:</b>\n{gap_lines or '  немає'}\n\n"
            f"<b>Правильно:</b>\n{good_lines or '  немає даних'}\n\n"
            f"<b>Висновок:</b> {lesson[:200]}\n"
            f"<b>Playbooks додано:</b> {len(result.get('playbook_rules',[]))}"
        )
        _tg_send_admin(msg)
        _log.info(f"[benchmark] done {case_key} score={score} gaps={len(gaps)} playbooks={len(result.get('playbook_rules',[]))}")
        return result

    except Exception as _e:
        _log.error(f"[benchmark] _benchmark_run_case error {case_key}: {_e}")
        if run_id:
            try:
                with psycopg2.connect(PG_DSN) as conn:
                    conn.autocommit = True
                    with conn.cursor() as cur:
                        cur.execute("UPDATE dfir_benchmark_runs_v1 SET status='error', notes=%s, finished_at=NOW() WHERE id=%s",
                                    (str(_e)[:300], run_id))
            except Exception:
                pass
        return None


def _idle_benchmark_worker():
    """Background benchmark worker: runs when idle + no active production jobs.
    Picks cases with golden facts, compares bot output, records gaps + playbooks."""
    _log.info("[benchmark] worker started")
    _idle_worker_stop.wait(120)  # cold start delay

    while not _idle_worker_stop.is_set():
        try:
            idle_secs = time.time() - _state['last_user_request_ts']
            if idle_secs < 900:
                _idle_worker_stop.wait(60)
                continue

            if _has_active_production_run():
                _log.error("[benchmark] production run active, waiting")
                _idle_worker_stop.wait(300)
                continue

            cases = _benchmark_get_cases()
            if not cases:
                _idle_worker_stop.wait(3600)
                continue

            for case_key in cases:
                if _idle_worker_stop.is_set():
                    break
                if _has_active_production_run():
                    break
                if (time.time() - _state['last_user_request_ts']) < 900:
                    break

                # Skip if benchmarked successfully in last 12h
                try:
                    with psycopg2.connect(PG_DSN) as _c:
                        with _c.cursor() as _cu:
                            _cu.execute("""
                                SELECT COUNT(*) FROM dfir_benchmark_runs_v1
                                WHERE case_key=%s AND status='done'
                                AND started_at >= NOW() - INTERVAL '12 hours'
                            """, (case_key,))
                            if _cu.fetchone()[0] > 0:
                                _log.info(f"[benchmark] skipping {case_key} (done <12h ago)")
                                continue
                except Exception:
                    pass

                if not _wait_for_llm(_idle_worker_stop, 'benchmark'):
                    break
                _log.info(f"[benchmark] starting benchmark for {case_key}")
                _benchmark_run_case(case_key)
                _idle_worker_stop.wait(300)  # пауза між кейсами

        except Exception as _e:
            _log.error(f"[benchmark] worker error: {_e}")

        _idle_worker_stop.wait(3600)  # раз на годину якщо всі кейси пройшли

    _log.error("[benchmark] worker stopped")


