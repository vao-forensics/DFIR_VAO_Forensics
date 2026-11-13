"""
DFIR idle self-improvement worker — ЕТАП 2.

Flow per case:
  1. extract_ground_truth()   — Q&A from human report in Qdrant kb_reports
  2. answer_from_logs()       — bot answers from PostgreSQL only (no PDF)
  3. evaluate_answer()        — LLM judge, score 1-5
  4. save results             — dfir_learning_runs, dfir_learning_qa_eval
  5. suggest playbook updates — dfir_playbook_suggestions (status=pending)
  6. optionally save lesson   — dfir_lessons_learned_v1 (only if not dry_run)

Config flags (all default to safe/disabled):
  DFIR_IDLE_LEARNING_ENABLED=false
  DFIR_IDLE_LEARNING_DRY_RUN=true
  DFIR_IDLE_LEARNING_MAX_CASES=1
  DFIR_IDLE_LEARNING_MAX_QUESTIONS_PER_CASE=5
  DFIR_IDLE_LEARNING_MIN_IDLE_SECONDS=900
  DFIR_IDLE_LEARNING_SLEEP_SECONDS=60
  DFIR_IDLE_LEARNING_REQUIRE_APPROVAL=true
"""
import json, logging, re, time, uuid, urllib.request
import os
try:
    import psycopg2
except ImportError:  # keep unit tests importable on hosts without DB driver
    psycopg2 = None  # type: ignore[assignment]


def _pg_connect(*args, **kwargs):
    if psycopg2 is None:
        raise RuntimeError('psycopg2 is not installed')
    return psycopg2.connect(*args, **kwargs)

from core.config import (
    PG_DSN, LLM_URL, LLM_FAST_MODEL, LLM_FAST_TIMEOUT, QDRANT_URL,
    IDLE_LEARNING_ENABLED, IDLE_LEARNING_DRY_RUN,
    IDLE_LEARNING_MAX_CASES, IDLE_LEARNING_MAX_QUESTIONS,
    IDLE_LEARNING_MIN_IDLE_SECS, IDLE_LEARNING_SLEEP_SECS,
    IDLE_LEARNING_REQUIRE_APPROVAL,
    LLM_JSON_TEMPERATURE, LLM_FAST_TEMPERATURE,
    WINDOWS_AGENT_URL, WINDOWS_AGENT_TOKEN, GPU_IDLE_THRESHOLD,
)
from analysis.learnings import _save_lesson, _has_active_production_run
from core.http_utils import gpu_host_idle
from core.model_router import build_chat_payload
from workers.state import _idle_worker_stop, _bg_llm_lock, _state

_log = logging.getLogger('app')


def _is_gpu_idle(threshold: int = None) -> bool:
    """Return True if GPU host is idle (util ≤ threshold%) or agent is unreachable."""
    thr = threshold if threshold is not None else GPU_IDLE_THRESHOLD
    idle, detail = gpu_host_idle(WINDOWS_AGENT_URL, WINDOWS_AGENT_TOKEN, thr)
    if not idle:
        _log.info(f"[self_improve] GPU busy: util={detail.get('util_pct')}% threshold={thr}%")
    return idle

# ─── Failure types (mirrors qa.py / benchmark.py) ───────────────────────────
_FAILURE_TYPES = [
    'sql_payload_gap', 'missing_table_probe', 'wrong_source_priority',
    'parser_normalization_gap', 'tool_gap', 'prompt_reasoning_gap',
    'timeline_gap', 'ioc_gap', 'report_quality_gap',
]

# Score mapping: verdict + evidence quality → 1-5
_SCORE_MAP = {
    ('correct',   True):  5,
    ('correct',   False): 4,
    ('partial',   True):  4,
    ('partial',   False): 3,
    ('wrong',     True):  2,
    ('wrong',     False): 1,
    ('no_evidence', True): 2,
    ('no_evidence', False): 1,
}


# ─── DB helpers ──────────────────────────────────────────────────────────────

def _ensure_tables():
    """Create self-improvement tables if not present (idempotent)."""
    try:
        with _pg_connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS dfir_learning_runs (
                      id SERIAL PRIMARY KEY,
                      run_id UUID DEFAULT gen_random_uuid() UNIQUE,
                      case_key TEXT NOT NULL,
                      status TEXT NOT NULL DEFAULT 'running',
                      started_at TIMESTAMPTZ DEFAULT NOW(),
                      finished_at TIMESTAMPTZ,
                      dry_run BOOLEAN DEFAULT TRUE,
                      model TEXT,
                      questions_total INT DEFAULT 0,
                      questions_answered INT DEFAULT 0,
                      avg_score FLOAT,
                      error TEXT,
                      created_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS dfir_learning_qa_eval (
                      id SERIAL PRIMARY KEY,
                      learning_run_id INT REFERENCES dfir_learning_runs(id) ON DELETE CASCADE,
                      case_key TEXT NOT NULL,
                      question TEXT NOT NULL,
                      expected_answer TEXT,
                      bot_answer TEXT,
                      score INT CHECK (score BETWEEN 1 AND 5),
                      verdict TEXT,
                      missing_evidence TEXT[] DEFAULT '{}',
                      wrong_assumption TEXT[] DEFAULT '{}',
                      evidence_tables_checked TEXT[] DEFAULT '{}',
                      evidence_refs TEXT[] DEFAULT '{}',
                      recommended_tables TEXT[] DEFAULT '{}',
                      lesson_learned TEXT,
                      suggested_playbook_update TEXT,
                      created_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS dfir_playbook_suggestions (
                      id SERIAL PRIMARY KEY,
                      case_key TEXT,
                      source_learning_run_id INT REFERENCES dfir_learning_runs(id) ON DELETE SET NULL,
                      title TEXT NOT NULL,
                      problem TEXT,
                      suggested_change TEXT NOT NULL,
                      affected_module TEXT,
                      status TEXT DEFAULT 'pending',
                      created_at TIMESTAMPTZ DEFAULT NOW(),
                      approved_at TIMESTAMPTZ,
                      applied_at TIMESTAMPTZ
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_learning_runs_case ON dfir_learning_runs(case_key, created_at DESC)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_learning_qa_run ON dfir_learning_qa_eval(learning_run_id)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_playbook_sug_status ON dfir_playbook_suggestions(status, created_at DESC)")
    except Exception as _e:
        _log.error(f"[self_improve] _ensure_tables: {_e}")


def _create_run(case_key, dry_run):
    """Insert a dfir_learning_runs row and return its id."""
    with _pg_connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO dfir_learning_runs (case_key, status, dry_run, model)
                VALUES (%s, 'running', %s, %s) RETURNING id
            """, (case_key, dry_run, LLM_FAST_MODEL))
            return cur.fetchone()[0]


def _finish_run(run_id, status, questions_total, questions_answered, avg_score, error=None):
    try:
        with _pg_connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE dfir_learning_runs
                    SET status=%s, finished_at=NOW(), questions_total=%s,
                        questions_answered=%s, avg_score=%s, error=%s
                    WHERE id=%s
                """, (status, questions_total, questions_answered,
                      avg_score, (error or '')[:500], run_id))
    except Exception as _e:
        _log.error(f"[self_improve] _finish_run error: {_e}")


# ─── ЗАДАЧА 4: Ground truth extraction ───────────────────────────────────────

def extract_ground_truth(case_key):
    """
    Find human expert report in Qdrant kb_reports and extract Q&A pairs.
    Does NOT expose the report text to the bot answering step.

    Returns:
        {case_key, source, questions: [{question, expected_answer, source_ref}],
         status: ok|empty|error, error: null}
    """
    result = {'case_key': case_key, 'source': 'kb_report', 'questions': [],
              'status': 'empty', 'error': None}
    try:
        # 1. Fetch PDF chunks from Qdrant kb_reports
        _body = json.dumps({
            'limit': 50, 'with_payload': True, 'with_vector': False,
            'filter': {'should': [
                {'key': 'case_key', 'match': {'value': case_key}},
                {'key': 'source_file', 'match': {'any': [
                    case_key + '.pdf', case_key,
                    case_key.replace('__', '_') + '.pdf',
                ]}}
            ]}
        }).encode('utf-8')
        _req = urllib.request.Request(
            f'{QDRANT_URL}/collections/kb_reports/points/scroll',
            data=_body, headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(_req, timeout=8) as _r:
            pts = json.loads(_r.read().decode('utf-8', errors='ignore')).get('result', {}).get('points', [])

        if not pts:
            # Fallback: get recent chunks and filter by case key substring
            _req2 = urllib.request.Request(
                f'{QDRANT_URL}/collections/kb_reports/points/scroll',
                data=json.dumps({'limit': 100, 'with_payload': True, 'with_vector': False}).encode(),
                headers={'Content-Type': 'application/json'}
            )
            with urllib.request.urlopen(_req2, timeout=8) as _r2:
                all_pts = json.loads(_r2.read().decode('utf-8', errors='ignore')).get('result', {}).get('points', [])
            ck_short = case_key.split('_')[-1][:10].lower()
            pts = [p for p in all_pts if
                   ck_short in (p.get('payload', {}).get('source_file', '') or '').lower() or
                   ck_short in (p.get('payload', {}).get('case_key', '') or '').lower()]

        if not pts:
            return result

        texts = [p.get('payload', {}).get('text', '') for p in pts if p.get('payload', {}).get('text')]
        source_file = pts[0].get('payload', {}).get('source_file', '') if pts else ''
        pdf_text = '\n\n'.join(texts[:30])[:12000]

        # 2. Extract Q&A from the report via LLM
        questions = _extract_qa_from_report(case_key, pdf_text, source_file)
        result['questions'] = questions
        result['source'] = source_file or 'kb_report'
        result['status'] = 'ok' if questions else 'empty'

    except Exception as _e:
        _log.error(f"[self_improve] extract_ground_truth error: {_e}")
        result['status'] = 'error'
        result['error'] = str(_e)[:300]
    return result


def _extract_qa_from_report(case_key, pdf_text, source_file):
    """
    Ask LLM to extract Q&A from expert report.
    Priority: 'Питання – Відповідь' section; fallback: key findings as pseudo-questions.
    """
    prompt = (
        f"You are a DFIR analyst. Given this expert forensic report for case {case_key}, "
        f"extract up to 10 question-answer pairs.\n\n"
        f"PRIORITY: Find any 'Питання – Відповідь', 'Q&A', or 'Висновки' section and use it directly.\n"
        f"FALLBACK: If no Q&A section, convert the key findings into questions.\n\n"
        f"EXPERT REPORT:\n{pdf_text[:8000]}\n\n"
        f"Return ONLY valid JSON array (no markdown):\n"
        f'[{{"question": "...", "expected_answer": "...", "source_ref": "{source_file}"}}]\n'
        f"Each expected_answer must be factual and come ONLY from the report text above.\n"
        f"No hallucinations. If no facts found, return []."
    )
    try:
        _body = json.dumps(build_chat_payload(
            model=LLM_FAST_MODEL,
            messages=[{'role': 'user', 'content': prompt}],
            role='json',
            temperature=LLM_JSON_TEMPERATURE,
            max_tokens=int(os.environ.get('DFIR_SELF_IMPROVE_EXTRACT_MAX_TOKENS', '1600')),
            stream=False,
            reasoning_effort=os.environ.get('DFIR_JSON_REASONING_EFFORT', 'low'),
        )).encode('utf-8')
        _req = urllib.request.Request(
            f'{LLM_URL.rstrip("/")}/v1/chat/completions',
            data=_body, headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(_req, timeout=LLM_FAST_TIMEOUT) as _r:
            content = json.loads(_r.read().decode('utf-8', errors='ignore'))
        raw = content['choices'][0]['message']['content'].strip()
        raw = re.sub(r'```(?:json)?\s*', '', raw).strip().rstrip('`')
        m = re.search(r'\[.*\]', raw, re.DOTALL)
        if not m:
            return []
        qa_list = json.loads(m.group())
        # Validate and cap
        validated = []
        for item in qa_list[:10]:
            if isinstance(item, dict) and item.get('question') and item.get('expected_answer'):
                validated.append({
                    'question': str(item['question'])[:400],
                    'expected_answer': str(item['expected_answer'])[:800],
                    'source_ref': str(item.get('source_ref', source_file))[:200],
                })
        return validated
    except Exception as _e:
        _log.error(f"[self_improve] _extract_qa_from_report error: {_e}")
        return []


# ─── ЗАДАЧА 5: Logs-first answering ──────────────────────────────────────────

def answer_from_logs(case_key, question):
    """
    Answer a forensic question using ONLY PostgreSQL artifacts for this case.
    Never uses human report text as evidence.

    Returns:
        {case_key, question, answer, confidence, evidence_tables_checked,
         evidence_refs, status: ok|no_evidence|error, error: null}
    """
    result = {
        'case_key': case_key, 'question': question, 'answer': '',
        'confidence': 'low', 'evidence_tables_checked': [],
        'evidence_refs': [], 'status': 'no_evidence', 'error': None,
    }
    try:
        # Determine relevant tables from question keywords
        tables_to_check = _select_tables_for_question(question)
        # Run SQL probes
        evidence = _probe_tables(case_key, question, tables_to_check)
        result['evidence_tables_checked'] = list(evidence.keys())
        result['evidence_refs'] = _collect_refs(evidence)

        if not any(rows for rows in evidence.values()):
            return result

        # Synthesize answer from SQL evidence using LLM
        answer, confidence = _synthesize_answer(case_key, question, evidence)
        result['answer'] = answer
        result['confidence'] = confidence
        result['status'] = 'ok' if answer else 'no_evidence'
    except Exception as _e:
        _log.error(f"[self_improve] answer_from_logs error: {_e}")
        result['status'] = 'error'
        result['error'] = str(_e)[:300]
    return result


def _select_tables_for_question(question):
    """Map question keywords to likely PostgreSQL tables."""
    q = question.lower()
    tables = []
    if any(k in q for k in ['rdp', 'logon', '4624', '4625', '1149', 'remote', 'login']):
        tables.append('event_logs_v2')
    if any(k in q for k in ['exe', 'процес', 'process', 'amcache', 'prefetch', 'запуск', 'ran']):
        tables.extend(['program_exec_v2', 'event_logs_v2'])
    if any(k in q for k in ['файл', 'file', 'download', 'завантаж', 'lnk', 'zone']):
        tables.extend(['filesystem_v2', 'browser_downloads_v1'])
    if any(k in q for k in ['defender', 'trojan', '1116', '1117', 'malware', 'threat']):
        tables.append('event_logs_v2')
    if any(k in q for k in ['persistence', 'task', 'service', '7045', '4698', 'run key', 'реєстр']):
        tables.extend(['event_logs_v2', 'raw_fallback_v2', 'filesystem_v2'])
    if any(k in q for k in ['account', '4720', 'user', 'обліков', 'case_59', 'admin']):
        tables.append('event_logs_v2')
    if any(k in q for k in ['ngrok', 'tunnel', 'c2', 'lateral', '5140', 'share']):
        tables.append('event_logs_v2')
    if any(k in q for k in ['log clear', '1102', '104', 'тамп', 'очищ']):
        tables.append('event_logs_v2')
    if any(k in q for k in ['ioc', 'hash', 'ip', 'domain', 'indicator']):
        tables.extend(['event_logs_v2', 'program_exec_v2'])
    if any(k in q for k in ['хронолог', 'timeline', 'перший', 'first']):
        tables.extend(['event_logs_v2', 'program_exec_v2', 'filesystem_v2'])
    # Default: always check event_logs_v2
    if not tables:
        tables.append('event_logs_v2')
    return list(dict.fromkeys(tables))  # unique, preserve order


def _probe_tables(case_key, question, tables):
    """Run targeted SQL probes per table, return evidence dict."""
    evidence = {}
    q = question.lower()
    try:
        with _pg_connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                for tbl in tables:
                    rows = []
                    try:
                        if tbl == 'event_logs_v2':
                            rows = _probe_event_logs(cur, case_key, q)
                        elif tbl == 'program_exec_v2':
                            rows = _probe_program_exec(cur, case_key, q)
                        elif tbl == 'filesystem_v2':
                            rows = _probe_filesystem(cur, case_key, q)
                        elif tbl == 'browser_downloads_v1':
                            rows = _probe_browser_downloads(cur, case_key)
                        elif tbl == 'raw_fallback_v2':
                            rows = _probe_raw_fallback(cur, case_key, q)
                    except Exception as _te:
                        _log.info(f"[self_improve] probe {tbl}: {_te}")
                    evidence[tbl] = rows
    except Exception as _e:
        _log.error(f"[self_improve] _probe_tables error: {_e}")
    return evidence


def _probe_event_logs(cur, case_key, q):
    # Pick relevant event_ids based on question
    eids = []
    if any(k in q for k in ['rdp', '4624', '1149', 'logon', 'remote']): eids += [4624, 4625, 1149, 21, 22, 4778]
    if any(k in q for k in ['defender', '1116', '1117', 'trojan', 'malware']): eids += [1116, 1117, 1119, 5007]
    if any(k in q for k in ['process', 'exe', '4688']): eids += [4688, 4689]
    if any(k in q for k in ['task', '4698', 'persistence']): eids += [4698, 4699, 4702]
    if any(k in q for k in ['service', '7045']): eids += [7045, 7040]
    if any(k in q for k in ['account', '4720', 'user', 'case_59']): eids += [4720, 4722, 4728, 4732]
    if any(k in q for k in ['log clear', '1102', '104']): eids += [1102, 104]
    if any(k in q for k in ['ngrok', 'tunnel', 'share', '5140', '5145']): eids += [5140, 5145, 5142]
    if any(k in q for k in ['powershell', '4103', '4104']): eids += [4103, 4104]
    if not eids:  # broad search
        cur.execute("""
            SELECT event_ts, event_id, source_file, payload
            FROM event_logs_v2 WHERE case_key=%s
            ORDER BY event_ts ASC LIMIT 20
        """, (case_key,))
    else:
        cur.execute("""
            SELECT event_ts, event_id, source_file, payload
            FROM event_logs_v2 WHERE case_key=%s AND event_id=ANY(%s)
            ORDER BY event_ts ASC LIMIT 20
        """, (case_key, eids))
    return [{'ts': str(r[0]), 'eid': r[1], 'src': r[2],
             'payload': {k: v for k, v in (r[3] or {}).items() if k in (
                 'ThreatName', 'ProcessName', 'TargetUserName', 'IpAddress',
                 'WorkstationName', 'NewProcessName', 'CommandLine', 'TaskName',
                 'ServiceName', 'SubjectUserName', 'Channel', 'ActionSuccess', 'Path')}}
            for r in cur.fetchall()]


def _probe_program_exec(cur, case_key, q):
    filters = []
    if any(k in q for k in ['exe', 'перший', 'first', 'amcache', 'prefetch']): pass
    cur.execute("""
        SELECT full_path, event_ts, source_file
        FROM program_exec_v2 WHERE case_key=%s
        AND full_path NOT ILIKE '%%\\\\Windows\\\\System32%%'
        AND full_path NOT ILIKE '%%\\\\Windows\\\\SysWOW64%%'
        AND full_path IS NOT NULL
        ORDER BY event_ts ASC NULLS LAST LIMIT 20
    """, (case_key,))
    return [{'path': r[0], 'ts': str(r[1]), 'src': r[2]} for r in cur.fetchall()]


def _probe_filesystem(cur, case_key, q):
    cur.execute("""
        SELECT full_path, event_ts, extension, payload->>'HostUrl' AS host_url
        FROM filesystem_v2 WHERE case_key=%s
        AND (extension IN ('exe','zip','rar','dll','vbs','bat','ps1','lnk') OR
             full_path ILIKE '%%Downloads%%' OR full_path ILIKE '%%Public%%' OR
             full_path ILIKE '%%Roaming%%')
        ORDER BY event_ts ASC NULLS LAST LIMIT 15
    """, (case_key,))
    return [{'path': r[0], 'ts': str(r[1]), 'ext': r[2], 'host_url': r[3]}
            for r in cur.fetchall()]


def _probe_browser_downloads(cur, case_key):
    try:
        cur.execute("""
            SELECT filename, url, start_time, target_path
            FROM browser_downloads_v1 WHERE case_key=%s
            ORDER BY start_time ASC LIMIT 15
        """, (case_key,))
        return [{'file': r[0], 'url': r[1], 'ts': str(r[2]), 'path': r[3]}
                for r in cur.fetchall()]
    except Exception:
        return []


def _probe_raw_fallback(cur, case_key, q):
    cur.execute("""
        SELECT full_path, payload->>'RegValueName' AS reg_val, event_ts
        FROM filesystem_v2 WHERE case_key=%s
        AND (full_path ILIKE '%%CurrentVersion\\\\Run%%' OR
             full_path ILIKE '%%Tasks\\\\%%' OR full_path ILIKE '%%Services\\\\%%')
        ORDER BY event_ts DESC LIMIT 10
    """, (case_key,))
    return [{'path': r[0], 'val': r[1], 'ts': str(r[2])} for r in cur.fetchall()]


def _collect_refs(evidence):
    refs = []
    for tbl, rows in evidence.items():
        for r in rows[:3]:
            ref = f"{tbl}:{r.get('ts','?')}:{r.get('eid',r.get('path',''))}"
            refs.append(ref[:120])
    return refs[:20]


def _synthesize_answer(case_key, question, evidence):
    """LLM synthesizes answer from SQL evidence only. No report text."""
    evidence_str = json.dumps(evidence, ensure_ascii=False, default=str)[:4000]
    prompt = (
        f"You are a DFIR analyst. Answer the following question for case {case_key} "
        f"using ONLY the SQL evidence below. Do not invent facts.\n\n"
        f"Question: {question}\n\n"
        f"SQL evidence from PostgreSQL:\n{evidence_str}\n\n"
        f"Answer concisely (2-5 sentences). If evidence is insufficient, say so explicitly.\n"
        f"End with: CONFIDENCE: high|medium|low"
    )
    try:
        _body = json.dumps(build_chat_payload(
            model=LLM_FAST_MODEL,
            messages=[{'role': 'user', 'content': prompt}],
            role='fast',
            temperature=LLM_FAST_TEMPERATURE,
            max_tokens=int(os.environ.get('DFIR_SELF_IMPROVE_ANSWER_MAX_TOKENS', '1200')),
            stream=False,
            reasoning_effort=os.environ.get('DFIR_SELF_IMPROVE_REASONING_EFFORT', ''),
        )).encode('utf-8')
        _req = urllib.request.Request(
            f'{LLM_URL.rstrip("/")}/v1/chat/completions',
            data=_body, headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(_req, timeout=LLM_FAST_TIMEOUT) as _r:
            content = json.loads(_r.read().decode('utf-8', errors='ignore'))
        raw = content['choices'][0]['message']['content'].strip()
        confidence = 'low'
        m_conf = re.search(r'CONFIDENCE:\s*(high|medium|low)', raw, re.I)
        if m_conf:
            confidence = m_conf.group(1).lower()
            raw = raw[:m_conf.start()].strip()
        return raw, confidence
    except Exception as _e:
        _log.error(f"[self_improve] _synthesize_answer error: {_e}")
        return '', 'low'


# ─── ЗАДАЧА 6: Evaluation ────────────────────────────────────────────────────

def evaluate_answer(case_key, question, expected_answer, bot_answer,
                    evidence_tables_checked, evidence_refs):
    """
    LLM judge: compare expected (human) vs bot answer.
    Returns score 1-5 and structured verdict.

    Score: 5=perfect, 4=correct+incomplete, 3=partial, 2=weak, 1=wrong/empty
    """
    if not bot_answer or len(bot_answer.strip()) < 20:
        return {
            'score': 1, 'verdict': 'no_evidence',
            'missing_evidence': ['Bot produced no answer'],
            'wrong_assumption': [], 'recommended_tables': ['event_logs_v2'],
            'lesson_learned': f'Bot could not answer: {question[:100]}',
            'suggested_playbook_update': 'Add SQL probe for this question category',
        }
    try:
        prompt = (
            f"DFIR QA judge. Case: {case_key}\n"
            f"Question: {question}\n\n"
            f"EXPECTED (human expert):\n{expected_answer[:600]}\n\n"
            f"BOT ANSWER (from SQL logs only):\n{bot_answer[:600]}\n\n"
            f"Tables bot checked: {', '.join(evidence_tables_checked)}\n\n"
            f"Judge the bot answer against the expert answer.\n"
            f"Return ONLY valid JSON:\n"
            f'{{"verdict":"correct|partial|wrong|no_evidence","score":1-5,'
            f'"missing_evidence":["..."],"wrong_assumption":["..."],'
            f'"recommended_tables":["..."],"lesson_learned":"...","suggested_playbook_update":"..."}}\n'
            f"score: 5=perfect, 4=correct+incomplete, 3=partial, 2=weak, 1=wrong/empty\n"
            f"No markdown. No extra text."
        )
        _body = json.dumps(build_chat_payload(
            model=LLM_FAST_MODEL,
            messages=[{'role': 'user', 'content': prompt}],
            role='json',
            temperature=LLM_JSON_TEMPERATURE,
            max_tokens=int(os.environ.get('DFIR_SELF_IMPROVE_JUDGE_MAX_TOKENS', '900')),
            stream=False,
            reasoning_effort=os.environ.get('DFIR_JSON_REASONING_EFFORT', 'low'),
        )).encode('utf-8')
        _req = urllib.request.Request(
            f'{LLM_URL.rstrip("/")}/v1/chat/completions',
            data=_body, headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(_req, timeout=LLM_FAST_TIMEOUT) as _r:
            raw = json.loads(_r.read().decode('utf-8', errors='ignore'))
        text = raw['choices'][0]['message']['content'].strip()
        text = re.sub(r'```(?:json)?\s*', '', text).strip().rstrip('`')
        m = re.search(r'\{.*\}', text, re.DOTALL)
        if not m:
            raise ValueError(f"No JSON in judge output: {text[:200]!r}")
        result = json.loads(m.group())
        # Ensure score is int 1-5
        score = max(1, min(5, int(result.get('score', 1))))
        return {
            'score': score,
            'verdict': str(result.get('verdict', 'wrong'))[:50],
            'missing_evidence': result.get('missing_evidence', [])[:5],
            'wrong_assumption': result.get('wrong_assumption', [])[:5],
            'recommended_tables': result.get('recommended_tables', [])[:5],
            'lesson_learned': str(result.get('lesson_learned', ''))[:500],
            'suggested_playbook_update': str(result.get('suggested_playbook_update', ''))[:500],
        }
    except Exception as _e:
        _log.error(f"[self_improve] evaluate_answer error: {_e}")
        return {
            'score': 1, 'verdict': 'no_evidence',
            'missing_evidence': [str(_e)[:200]],
            'wrong_assumption': [], 'recommended_tables': [],
            'lesson_learned': '', 'suggested_playbook_update': '',
        }


# ─── ЗАДАЧА 4-7: Full learning cycle ─────────────────────────────────────────

def run_learning_cycle(case_key, dry_run=True, max_questions=None):
    """
    Full self-improvement cycle for one case.
    dry_run=True: runs full eval, saves to learning tables, but does NOT write
                  lessons to dfir_lessons_learned_v1 or suggest playbooks.

    Returns: run_id or None on fatal error.
    """
    if max_questions is None:
        max_questions = IDLE_LEARNING_MAX_QUESTIONS

    _log.info(f"[self_improve] starting cycle case={case_key} dry_run={dry_run} max_q={max_questions}")
    _ensure_tables()
    run_id = _create_run(case_key, dry_run)

    scores = []
    try:
        # Step 1: Extract ground truth from human report
        gt = extract_ground_truth(case_key)
        if gt['status'] != 'ok' or not gt['questions']:
            _log.warning(f"[self_improve] no ground truth for {case_key}: {gt['status']} {gt.get('error','')}")
            _finish_run(run_id, 'skipped_no_gt', 0, 0, None,
                        f"no_ground_truth: {gt.get('error','')}")
            return run_id

        questions = gt['questions'][:max_questions]
        _log.info(f"[self_improve] {case_key}: extracted {len(questions)} questions from {gt['source']}")

        answered = 0
        for q_item in questions:
            if _idle_worker_stop.is_set():
                break
            if _has_active_production_run():
                _log.warning(f"[self_improve] production run active, pausing cycle")
                break
            if (time.time() - _state['last_user_request_ts']) < IDLE_LEARNING_MIN_IDLE_SECS:
                _log.info(f"[self_improve] user active, pausing cycle")
                break
            if not _is_gpu_idle():
                _log.info(f"[self_improve] GPU busy mid-cycle, pausing")
                break

            question = q_item['question']
            expected = q_item['expected_answer']

            # Step 2: Bot answers from logs only (no report context)
            if not _bg_llm_lock.acquire(timeout=300):
                _log.warning(f"[self_improve] LLM lock timeout, skipping question")
                continue
            try:
                ans_result = answer_from_logs(case_key, question)
            finally:
                _bg_llm_lock.release()

            bot_answer = ans_result['answer']
            tables_checked = ans_result['evidence_tables_checked']
            refs = ans_result['evidence_refs']

            # Step 3: Evaluate
            if not _bg_llm_lock.acquire(timeout=300):
                _log.warning(f"[self_improve] LLM lock timeout for eval, skipping")
                continue
            try:
                eval_result = evaluate_answer(
                    case_key, question, expected, bot_answer, tables_checked, refs
                )
            finally:
                _bg_llm_lock.release()

            score = eval_result['score']
            scores.append(score)
            answered += 1

            # Step 4: Save eval record
            _save_qa_eval(run_id, case_key, question, expected, bot_answer,
                          eval_result, tables_checked, refs)

            # Step 5: Save lesson (only if NOT dry_run)
            if not dry_run and score >= 3 and eval_result.get('lesson_learned'):
                try:
                    _save_lesson(case_key, question[:80], 'self_improve',
                                 eval_result['lesson_learned'], tables_checked, refs, {})
                except Exception as _le:
                    _log.error(f"[self_improve] _save_lesson error: {_le}")

            # Step 6: Create playbook suggestion (only if NOT dry_run and needs approval)
            if not dry_run and score <= 2 and eval_result.get('suggested_playbook_update'):
                _create_playbook_suggestion(
                    run_id, case_key, eval_result, question, IDLE_LEARNING_REQUIRE_APPROVAL
                )

            _log.info(f"[self_improve] q={question[:60]!r} score={score} verdict={eval_result['verdict']}")

        avg_score = sum(scores) / len(scores) if scores else None
        status = 'done_dry_run' if dry_run else 'done'
        _finish_run(run_id, status, len(questions), answered, avg_score)
        _log.info(f"[self_improve] cycle done case={case_key} answered={answered} avg_score={avg_score}")
        return run_id

    except Exception as _e:
        _log.error(f"[self_improve] run_learning_cycle error case={case_key}: {_e}")
        _finish_run(run_id, 'error', 0, 0, None, str(_e)[:400])
        return run_id


def _save_qa_eval(run_id, case_key, question, expected_answer, bot_answer,
                  eval_result, tables_checked, refs):
    try:
        with _pg_connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO dfir_learning_qa_eval
                      (learning_run_id, case_key, question, expected_answer, bot_answer,
                       score, verdict, missing_evidence, wrong_assumption,
                       evidence_tables_checked, evidence_refs, recommended_tables,
                       lesson_learned, suggested_playbook_update)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (
                    run_id, case_key, question[:400], expected_answer[:800], (bot_answer or '')[:800],
                    eval_result['score'], eval_result['verdict'],
                    eval_result.get('missing_evidence', []),
                    eval_result.get('wrong_assumption', []),
                    tables_checked,
                    refs,
                    eval_result.get('recommended_tables', []),
                    (eval_result.get('lesson_learned', '') or '')[:500],
                    (eval_result.get('suggested_playbook_update', '') or '')[:500],
                ))
    except Exception as _e:
        _log.error(f"[self_improve] _save_qa_eval error: {_e}")


def _create_playbook_suggestion(run_id, case_key, eval_result, question, require_approval):
    """Create a dfir_playbook_suggestions entry with status=pending."""
    try:
        title = f"[{eval_result['verdict'].upper()}] {question[:80]}"
        problem = '; '.join(eval_result.get('missing_evidence', [])[:3])
        suggested_change = eval_result.get('suggested_playbook_update', '') or ''
        affected_module = 'self_improve_worker'
        if 'sql' in suggested_change.lower():
            affected_module = 'sql_probes'
        elif 'table' in suggested_change.lower():
            affected_module = 'table_coverage'
        elif 'prompt' in suggested_change.lower():
            affected_module = 'react_prompt'

        with _pg_connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO dfir_playbook_suggestions
                      (case_key, source_learning_run_id, title, problem,
                       suggested_change, affected_module, status)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                """, (case_key, run_id, title[:200], problem[:500],
                      suggested_change[:500], affected_module, 'pending'))
        _log.info(f"[self_improve] playbook suggestion created: {title[:60]}")
    except Exception as _e:
        _log.error(f"[self_improve] _create_playbook_suggestion error: {_e}")


# ─── ЗАДАЧА 8: Admin report ───────────────────────────────────────────────────

def admin_report(run_id):
    """
    Generate a human-readable summary of a learning run.
    Returns a dict with all key metrics.
    """
    try:
        with _pg_connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute("""SELECT case_key, status, dry_run, model, questions_total,
                    questions_answered, avg_score, started_at, finished_at, error
                    FROM dfir_learning_runs WHERE id=%s""", (run_id,))
                run = cur.fetchone()
                if not run:
                    return {'error': f'run_id {run_id} not found'}
                (case_key, status, dry_run, model, q_total, q_answered,
                 avg_score, started, finished, error) = run

                cur.execute("""
                    SELECT question, score, verdict, missing_evidence, evidence_tables_checked,
                           recommended_tables, suggested_playbook_update
                    FROM dfir_learning_qa_eval WHERE learning_run_id=%s
                    ORDER BY score ASC, created_at ASC
                """, (run_id,))
                evals = cur.fetchall()

                cur.execute("""SELECT title, problem, suggested_change, status
                    FROM dfir_playbook_suggestions WHERE source_learning_run_id=%s
                """, (run_id,))
                suggestions = cur.fetchall()

        # Top-3 weakest questions
        worst = [{'question': r[0][:100], 'score': r[1], 'verdict': r[2],
                  'missing': (r[3] or [])[:2]} for r in evals[:3]]
        # Tables not checked (appeared in recommended but not checked)
        all_checked = set()
        all_recommended = set()
        for r in evals:
            all_checked.update(r[4] or [])
            all_recommended.update(r[5] or [])
        not_checked = list(all_recommended - all_checked)

        duration_s = None
        if started and finished:
            duration_s = int((finished - started).total_seconds())

        return {
            'run_id': run_id,
            'case_key': case_key,
            'status': status,
            'dry_run': dry_run,
            'model': model,
            'questions_total': q_total,
            'questions_answered': q_answered,
            'avg_score': round(avg_score, 2) if avg_score else None,
            'duration_seconds': duration_s,
            'error': error,
            'top3_worst': worst,
            'evidence_tables_not_checked': not_checked,
            'playbook_updates_proposed': len(suggestions),
            'playbook_suggestions': [
                {'title': s[0][:80], 'problem': (s[1] or '')[:120],
                 'change': (s[2] or '')[:120], 'status': s[3]}
                for s in suggestions[:5]
            ],
            'needs_approval': any(s[3] == 'pending' for s in suggestions),
        }
    except Exception as _e:
        _log.error(f"[self_improve] admin_report error: {_e}")
        return {'error': str(_e)}


# ─── ЗАДАЧА 7: Idle worker ────────────────────────────────────────────────────

def idle_self_improve_worker():
    """
    Background worker for idle self-improvement.
    Exits immediately if DFIR_IDLE_LEARNING_ENABLED=false (default).
    Runs in dry_run mode by default (DFIR_IDLE_LEARNING_DRY_RUN=true).
    Never changes production prompts. Never auto-applies playbook suggestions.
    """
    if not IDLE_LEARNING_ENABLED:
        _log.info("[self_improve] worker disabled (DFIR_IDLE_LEARNING_ENABLED=false), exiting")
        return

    _log.info(f"[self_improve] worker started dry_run={IDLE_LEARNING_DRY_RUN} "
              f"max_cases={IDLE_LEARNING_MAX_CASES} max_q={IDLE_LEARNING_MAX_QUESTIONS}")
    _ensure_tables()

    while not _idle_worker_stop.is_set():
        try:
            # Check idle condition
            idle_secs = time.time() - _state['last_user_request_ts']
            if idle_secs < IDLE_LEARNING_MIN_IDLE_SECS:
                _idle_worker_stop.wait(IDLE_LEARNING_SLEEP_SECS)
                continue

            # Check for active production runs
            if _has_active_production_run():
                _log.info("[self_improve] production run active, waiting")
                _idle_worker_stop.wait(IDLE_LEARNING_SLEEP_SECS)
                continue

            # Check GPU host is idle before consuming LLM resources
            if not _is_gpu_idle():
                _log.info("[self_improve] GPU host busy, waiting")
                _idle_worker_stop.wait(IDLE_LEARNING_SLEEP_SECS)
                continue

            # Find cases that have both logs and human reports
            cases = _find_cases_with_reports()
            if not cases:
                _idle_worker_stop.wait(3600)
                continue

            processed = 0
            for case_key in cases[:IDLE_LEARNING_MAX_CASES]:
                if _idle_worker_stop.is_set():
                    break
                if _has_active_production_run():
                    break
                if (time.time() - _state['last_user_request_ts']) < IDLE_LEARNING_MIN_IDLE_SECS:
                    break

                # Skip if already run in last 6h
                if _recently_run(case_key, hours=6):
                    _log.info(f"[self_improve] skipping {case_key} (run <6h ago)")
                    continue

                run_id = run_learning_cycle(
                    case_key,
                    dry_run=IDLE_LEARNING_DRY_RUN,
                    max_questions=IDLE_LEARNING_MAX_QUESTIONS,
                )
                if run_id:
                    report = admin_report(run_id)
                    _log.info(
                        f"[self_improve] run {run_id} done: case={case_key} "
                        f"avg_score={report.get('avg_score')} "
                        f"answered={report.get('questions_answered')}/{report.get('questions_total')} "
                        f"suggestions={report.get('playbook_updates_proposed')} "
                        f"needs_approval={report.get('needs_approval')}"
                    )
                processed += 1
                _idle_worker_stop.wait(60)  # pause between cases

        except Exception as _e:
            _log.error(f"[self_improve] worker loop error: {_e}")

        _idle_worker_stop.wait(3600 if not IDLE_LEARNING_ENABLED else IDLE_LEARNING_SLEEP_SECS)

    _log.info("[self_improve] worker stopped")


def _find_cases_with_reports():
    """Cases that have event_logs_v2 data AND kb_reports in Qdrant."""
    try:
        with _pg_connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT DISTINCT case_key FROM event_logs_v2
                    WHERE case_key IS NOT NULL LIMIT 20
                """)
                return [r[0] for r in cur.fetchall()]
    except Exception as _e:
        _log.error(f"[self_improve] _find_cases_with_reports error: {_e}")
        return []


def _recently_run(case_key, hours=6):
    try:
        with _pg_connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) FROM dfir_learning_runs
                    WHERE case_key=%s AND status NOT IN ('error','running')
                    AND created_at >= NOW() - INTERVAL '%s hours'
                """, (case_key, hours))
                return cur.fetchone()[0] > 0
    except Exception:
        return False
