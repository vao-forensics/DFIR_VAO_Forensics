"""Idle learning worker — self-eval, idle analysis, QA cache worker."""
import os
import json, time, logging, urllib.request, re
import psycopg2
from core.config import (
    PG_DSN, LLM_URL, LLM_MODEL, LLM_FAST_MODEL, LLM_MAX_TOKENS, LLM_FAST_MAX_TOKENS,
    LLM_FAST_TIMEOUT, EMBED_MODEL, QDRANT_URL,
    LLM_JSON_TEMPERATURE, LLM_FAST_TEMPERATURE,
    WINDOWS_AGENT_URL, WINDOWS_AGENT_TOKEN, GPU_IDLE_THRESHOLD,
)
from core.http_utils import http_json as _http_json, llm_chat as _llm_chat, gpu_host_idle
from core.model_router import build_chat_payload
from analysis.learnings import _save_lesson
from analysis.qa_cache import _ensure_qa_cache_table, _qa_cache_lookup, _qa_cache_save
from workers.state import _idle_worker_stop, _bg_llm_lock, _qa_case_queue, _qa_queue_lock, _state
from analysis.chat import _react_call_llm, _react_parse_action, _react_get_case_sources, _react_call_tool, _REACT_SYSTEM, _TOPIC_QUESTIONS, _detect_question_topic, _run_fast_path, _FAST_PATH_SQL

# Standard DFIR questions the idle cache-warmer pre-generates answers for.
# (was referenced but never defined -> NameError crashed qa_cache_worker every 30min)
_QA_CACHE_QUESTIONS = list(_TOPIC_QUESTIONS.values())
_log = logging.getLogger('app')


def _is_gpu_idle(threshold: int = None) -> bool:
    """Return True if GPU host is idle or agent is unreachable (fail-open)."""
    thr = threshold if threshold is not None else GPU_IDLE_THRESHOLD
    idle, detail = gpu_host_idle(WINDOWS_AGENT_URL, WINDOWS_AGENT_TOKEN, thr)
    if not idle:
        _log.info(f"[idle] GPU busy: util={detail.get('util_pct')}% threshold={thr}%")
    return idle

def _llm_is_ready(probe_timeout=8):
    """Probe LM Studio with a 1-token request. Returns True if GPU is free and responds fast."""
    # big-120b (Agent agent sessions) owns all five cards. A probe for LLM_MODEL would make
    # llama-swap evict it, and every next Agent request waited ~2 min for a reload (2026-10-01).
    try:
        with urllib.request.urlopen(LLM_URL.rstrip('/') + '/running', timeout=3) as _r:
            _running = (json.loads(_r.read().decode('utf-8') or '{}').get('running') or [])
        if any(str(m.get('model')) == 'big-120b' for m in _running):
            return False
    except Exception:
        pass
    try:
        llm_url = LLM_URL.rstrip('/') + '/v1'
        model = LLM_MODEL
        payload = json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": "1"}],
            "max_tokens": 1,
            "stream": False,
            "temperature": 0
        }).encode()
        req = urllib.request.Request(
            f"{llm_url}/chat/completions",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=probe_timeout)
        return True
    except Exception:
        return False


def _wait_for_llm(stop_event, worker_name, probe_timeout=8, wait_secs=300, max_attempts=2):
    """Block until LM Studio is ready. Returns False if still busy after all attempts."""
    for attempt in range(max_attempts):
        if _llm_is_ready(probe_timeout):
            return True
        _log.info(f"[{worker_name}] LLM busy, waiting {wait_secs}s (attempt {attempt+1}/{max_attempts})")
        stop_event.wait(wait_secs)
        if stop_event.is_set():
            return False
    if _llm_is_ready(probe_timeout):
        return True
    _log.info(f"[{worker_name}] LLM still busy after {max_attempts} attempts, skipping")
    return False


def _update_last_request_ts():
    _state['last_user_request_ts'] = time.time()


def _ensure_idle_learning_tables():
    """Create all idle learning tables if not exist."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS dfir_user_feedback_v1 (
                      id SERIAL PRIMARY KEY, case_key TEXT, question TEXT, answer TEXT,
                      intent TEXT, rating INT, feedback_text TEXT, sources_used JSONB,
                      created_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS dfir_lessons_learned_v1 (
                      id SERIAL PRIMARY KEY, case_key TEXT, intent TEXT, lesson_type TEXT,
                      lesson_text TEXT, source_tables JSONB, source_artifacts JSONB,
                      reusable_query_hints JSONB, approved_by_user BOOLEAN DEFAULT FALSE,
                      created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS dfir_self_eval_runs_v1 (
                      id SERIAL PRIMARY KEY, case_key TEXT, status TEXT,
                      started_at TIMESTAMPTZ DEFAULT NOW(), finished_at TIMESTAMPTZ,
                      coverage_score FLOAT, notes TEXT
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS dfir_self_eval_gaps_v1 (
                      id SERIAL PRIMARY KEY, self_eval_run_id INT, case_key TEXT,
                      gap_type TEXT, expected_fact TEXT, bot_found BOOLEAN DEFAULT FALSE,
                      suggested_probe TEXT, severity TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                # Report-driven QA regression tables
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS dfir_eval_questions_v1 (
                      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                      case_key TEXT NOT NULL,
                      source_report TEXT,
                      question TEXT NOT NULL,
                      expected_answer TEXT,
                      expected_facts JSONB DEFAULT '[]'::jsonb,
                      expected_sources JSONB DEFAULT '[]'::jsonb,
                      category TEXT,
                      created_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS dfir_eval_answers_v1 (
                      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                      question_id UUID NOT NULL,
                      case_key TEXT NOT NULL,
                      bot_answer TEXT,
                      tools_used JSONB DEFAULT '[]'::jsonb,
                      sql_used JSONB DEFAULT '[]'::jsonb,
                      sources_used JSONB DEFAULT '[]'::jsonb,
                      logs_first BOOLEAN DEFAULT TRUE,
                      created_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS dfir_eval_failures_v1 (
                      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                      question_id UUID NOT NULL,
                      answer_id UUID,
                      case_key TEXT NOT NULL,
                      category TEXT,
                      failure_type TEXT NOT NULL,
                      expected_fact TEXT,
                      actual_answer TEXT,
                      root_cause TEXT,
                      suggested_fix TEXT,
                      severity TEXT DEFAULT 'medium',
                      created_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS dfir_fix_candidates_v1 (
                      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                      case_key TEXT,
                      failure_type TEXT,
                      fix_area TEXT,
                      fix_prompt TEXT,
                      affected_questions JSONB DEFAULT '[]'::jsonb,
                      priority INT DEFAULT 5,
                      status TEXT DEFAULT 'proposed',
                      created_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_eval_q_case ON dfir_eval_questions_v1(case_key)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_eval_f_case ON dfir_eval_failures_v1(case_key, failure_type)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_eval_fc_type ON dfir_fix_candidates_v1(failure_type, priority)")
                conn.commit()
    except Exception as _e:
        _log.error(f"[idle] _ensure_idle_learning_tables error: {_e}")


def _ensure_idle_qdrant_collection():
    """Create dfir_lessons_learned_v1 Qdrant collection if not exists."""
    try:
        _check_req = urllib.request.Request(
            f'{QDRANT_URL}/collections/dfir_lessons_learned_v1',
            method='GET'
        )
        with urllib.request.urlopen(_check_req, timeout=5) as _r:
            _r.read()
        # Collection exists
    except urllib.error.HTTPError as _e:
        if _e.code == 404:
            # Create it
            try:
                _body = json.dumps({
                    'vectors': {'size': 4096, 'distance': 'Cosine'}
                }).encode('utf-8')
                _create_req = urllib.request.Request(
                    f'{QDRANT_URL}/collections/dfir_lessons_learned_v1',
                    data=_body,
                    headers={'Content-Type': 'application/json'},
                    method='PUT'
                )
                with urllib.request.urlopen(_create_req, timeout=10) as _r:
                    _r.read()
                _log.info("[idle] Created Qdrant collection dfir_lessons_learned_v1")
            except Exception as _ce:
                _log.error(f"[idle] Failed to create Qdrant collection: {_ce}")
    except Exception as _e:
        _log.error(f"[idle] _ensure_idle_qdrant_collection error: {_e}")



def _has_active_production_run():
    """Lazy delegate to benchmark's check. It was referenced in this module
    (qa_cache worker, kernel section) but never defined here -> NameError every
    loop iteration. Lazy import avoids the circular import (benchmark imports
    _wait_for_llm from this module)."""
    try:
        from workers.benchmark import _has_active_production_run as _bench_check
        return _bench_check()
    except Exception:
        return False


def _is_night():
    """True only inside the night window (local server time). Night-gated so idle
    learning runs when GPUs are free overnight, never during daytime work."""
    try:
        import datetime as _dt
        h = _dt.datetime.now().hour
        start = int(os.environ.get('DFIR_NIGHT_START', '1'))
        end = int(os.environ.get('DFIR_NIGHT_END', '7'))
        return (start <= h < end) if start <= end else (h >= start or h < end)
    except Exception:
        return False


def _idle_qa_cache_worker():
    """Pre-generate Q&A cache for all completed cases during idle time."""
    _log.info('[qa_cache_worker] started')
    _idle_worker_stop.wait(300)  # cold start delay

    llm_url = LLM_URL.rstrip('/') + '/v1/chat/completions'
    model = LLM_MODEL

    while not _idle_worker_stop.is_set():
        try:
            # Only run when truly idle
            idle_secs = time.time() - _state['last_user_request_ts']
            if idle_secs < 900 or not _is_night():  # night+idle gated
                _idle_worker_stop.wait(120)
                continue
            if _has_active_production_run():
                _idle_worker_stop.wait(120)
                continue

            # Get all completed cases
            with psycopg2.connect(PG_DSN) as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT DISTINCT case_key FROM dfir_run_jobs_v2
                        WHERE status='completed' ORDER BY case_key
                    """)
                    cases = [r[0] for r in cur.fetchall()]

            for case_key in cases:
                if _idle_worker_stop.is_set(): break
                if (time.time() - _state['last_user_request_ts']) < 900: break
                if _has_active_production_run(): break

                # Count existing cache entries for this case
                with psycopg2.connect(PG_DSN) as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT count(*) FROM dfir_qa_cache_v1 WHERE case_key=%s AND status='active'", (case_key,))
                        cached_count = cur.fetchone()[0]

                if cached_count >= len(_QA_CACHE_QUESTIONS):
                    continue  # already fully cached

                _log.info(f'[qa_cache_worker] pre-generating for {case_key} (have {cached_count}/{len(_QA_CACHE_QUESTIONS)})')

                for question in _QA_CACHE_QUESTIONS:
                    if _idle_worker_stop.is_set(): break
                    if (time.time() - _state['last_user_request_ts']) < 900: break
                    if _has_active_production_run(): break

                    # Skip if already cached
                    existing = _qa_cache_lookup(case_key, question)
                    if existing and existing['is_direct']:
                        continue

                    # Run ReAct to answer
                    if not _wait_for_llm(_idle_worker_stop, 'qa_cache_worker'):
                        break
                    if not _bg_llm_lock.acquire(timeout=600):
                        _log.info(f'[qa_cache_worker] lock timeout, skipping')
                        break
                    try:
                        intent = _detect_question_topic(question)
                        answer = ''
                        if intent and intent in _FAST_PATH_SQL:
                            answer = _run_fast_path(case_key, question, intent, model, llm_url) or ''
                        if answer and len(answer) > 50:
                            _qa_cache_save(case_key, question, answer, source='idle_worker', confidence=0.80)
                            _log.info(f'[qa_cache_worker] cached: {case_key} q={question[:60]!r}')
                        elif not answer:
                            _log.info(f'[qa_cache_worker] no fast path for q={question[:60]!r}, skipping')
                    except Exception as e:
                        _log.info(f'[qa_cache_worker] error: {e}')
                    finally:
                        _bg_llm_lock.release()

                    _idle_worker_stop.wait(10)

                # KERNEL (самонавчання): на простої тримати trusted-кеш (dfir_case_qa_v1)
                # свіжим — заповнити Q&A якщо нема + звірити зі звітом (corroborated→trusted).
                try:
                    if (not _idle_worker_stop.is_set()
                            and (time.time() - _state['last_user_request_ts']) >= 900
                            and not _has_active_production_run()):
                        from analysis.case_qa import run_case_qa, crosscheck_case_qa, get_case_qa
                        from core.config import LLM_FAST_MODEL
                        _fast_model = LLM_FAST_MODEL or model
                        if _bg_llm_lock.acquire(timeout=600):
                            try:
                                if not get_case_qa(case_key):
                                    run_case_qa(case_key, _fast_model, llm_url)
                                crosscheck_case_qa(case_key, _fast_model, llm_url)
                                _log.info(f'[qa_cache_worker] kernel trusted-cache refreshed: {case_key}')
                            finally:
                                _bg_llm_lock.release()
                except Exception as _ke:
                    _log.info(f'[qa_cache_worker] kernel refresh error: {_ke}')

        except Exception as e:
            _log.error(f'[qa_cache_worker] outer error: {e}')

        _idle_worker_stop.wait(1800)  # re-check every 30 min


def _seed_case_59_lesson():
    """Seed known lesson about case_59 user investigation."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM dfir_lessons_learned_v1 WHERE lesson_type='seed'")
                if cur.fetchone()[0] > 0:
                    return
                lesson = ("For questions about suspicious users (e.g. 'case_59'): "
                    "Check SAM/Security events 4720,4724,4728,4732,4624,4625,4672,1102; "
                    "RDP logs EID 1149,21,22,24,25,40; filesystem C:\\Users\\; "
                    "Amcache/Prefetch/UserAssist; Scheduled Tasks; program_exec_v2. "
                    "Do NOT start with SRUM. "
                    "For case 29_04_2026__case_58_phishing_case_59: case_59=local user SID-1003, "
                    "created 2026-02-16 12:33:13 UTC, groups=Administrators+RDP Users, "
                    "linked to RDPWrapper/ngrok/Fiddler/TrustCert.")
                cur.execute("""INSERT INTO dfir_lessons_learned_v1
                    (case_key, intent, lesson_type, lesson_text, source_tables, source_artifacts, reusable_query_hints)
                    VALUES (%s,'suspicious_users','seed',%s,'["event_logs_v2","program_exec_v2"]','[]','{}')""",
                    ('29_04_2026__case_58_phishing_case_59', lesson))
                conn.commit()
    except Exception as _e:
        _log.error(f"[idle] _seed_case_59_lesson error: {_e}")


# ─── Self-eval analysis functions (8 Windows IR categories) ──────────────────

def _idle_analyze_defender(case_key, conn):
    """Defender/AV: EID 1116/1118/1119/1120/5001/5007/5010/5012/5013."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT event_id,
                   payload->>'ThreatName' AS threat,
                   payload->>'ProcessName' AS proc,
                   COUNT(*) AS cnt,
                   MAX(event_ts) AS last_ts
            FROM event_logs_v2
            WHERE case_key=%s AND event_id IN (1116,1117,1118,1119,1120,5001,5007,5010,5012,5013,1008,1009)
            GROUP BY event_id, threat, proc
            ORDER BY last_ts DESC LIMIT 20
        """, (case_key,))
        rows = cur.fetchall()
    findings = [{'event_id': r[0], 'threat': r[1], 'proc': r[2], 'cnt': r[3], 'last_ts': str(r[4])} for r in rows]
    # Questions the bot should be able to answer
    questions = [
        f"Чи знайшов Defender загрози у кейсі {case_key}? Назви файли/трояни.",
        f"Які EID 1116/1117 (detection/action) є у {case_key}? Назви ThreatName.",
        f"Чи вимикався Defender (EID 5007) у {case_key}?"
    ]
    return {'category': 'defender_av', 'findings': findings, 'questions': questions}


def _idle_analyze_logon_rdp(case_key, conn):
    """Logon/RDP: EID 4624/4625/4634/4648/4672/1149/4778/4779/21/22/24/25/40."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT event_id,
                   payload->>'LogonType' AS logon_type,
                   payload->>'IpAddress' AS ip,
                   payload->>'TargetUserName' AS username,
                   COUNT(*) AS cnt,
                   MIN(event_ts) AS first_ts,
                   MAX(event_ts) AS last_ts
            FROM event_logs_v2
            WHERE case_key=%s AND event_id IN (4624,4625,4634,4647,4648,4672,1149,4778,4779,21,22,24,25,40)
            GROUP BY event_id, payload->>'LogonType', payload->>'IpAddress', payload->>'TargetUserName'
            ORDER BY MAX(event_ts) DESC LIMIT 25
        """, (case_key,))
        rows = cur.fetchall()
    findings = [{'event_id': r[0], 'logon_type': r[1], 'ip': r[2], 'user': r[3], 'cnt': r[4], 'first': str(r[5]), 'last': str(r[6])} for r in rows]
    # Find remote RDP IPs specifically
    rdp_ips = list({f['ip'] for f in findings if f['event_id'] in (4624, 21, 22, 1149) and f['ip'] and f['ip'] not in ('-', '', '::1', '127.0.0.1')})
    questions = [
        f"Звідки були RDP підключення до {case_key}? Назви IP-адреси та час.",
        f"Які невдалі спроби логіну (EID 4625) є у {case_key}? Хто і коли?",
        f"Чи є привілейовані сесії (EID 4672) у {case_key}? Який обліковий запис?"
    ]
    return {'category': 'logon_rdp', 'findings': findings, 'rdp_ips': rdp_ips, 'questions': questions}


def _idle_analyze_process_ps(case_key, conn):
    """Process/PS: EID 4688/4689/400/403/4103/4104 + program_exec_v2."""
    with conn.cursor() as cur:
        # Event-based process creation
        cur.execute("""
            SELECT event_id,
                   payload->>'NewProcessName' AS proc,
                   payload->>'ParentProcessName' AS parent,
                   payload->>'CommandLine' AS cmdline,
                   COUNT(*) AS cnt,
                   MIN(event_ts) AS first_ts
            FROM event_logs_v2
            WHERE case_key=%s AND event_id IN (4688,4689,400,403,4103,4104,4105,4106)
            GROUP BY event_id, proc, parent, cmdline
            ORDER BY cnt DESC LIMIT 20
        """, (case_key,))
        ev_rows = cur.fetchall()
        # Amcache/Prefetch from program_exec_v2
        cur.execute("""
            SELECT full_path, event_ts, event_ts, source_file
            FROM program_exec_v2
            WHERE case_key=%s
              AND (source_file ILIKE '%%amcache%%' OR source_file ILIKE '%%prefetch%%' OR source_file ILIKE '%%shimcache%%')
              AND full_path IS NOT NULL
              AND full_path NOT ILIKE '%%\\\\Windows\\\\System32%%'
              AND full_path NOT ILIKE '%%\\\\Windows\\\\SysWOW64%%'
            ORDER BY event_ts ASC NULLS LAST LIMIT 20
        """, (case_key,))
        exec_rows = cur.fetchall()
    findings = {
        'events': [{'event_id': r[0], 'proc': r[1], 'parent': r[2], 'cmdline': (r[3] or '')[:200], 'cnt': r[4], 'first': str(r[5])} for r in ev_rows],
        'executables': [{'path': r[0], 'first_run': str(r[1]), 'last_run': str(r[2]), 'source': r[3]} for r in exec_rows]
    }
    questions = [
        f"Які підозрілі процеси запускались у {case_key}? Назви exe та час першого запуску.",
        f"Чи є PowerShell активність (EID 4103/4104) у {case_key}? Які команди?",
        f"Який перший підозрілий exe файл з'явився у {case_key} (Amcache/Prefetch)?"
    ]
    return {'category': 'process_ps', 'findings': findings, 'questions': questions}


def _idle_analyze_persistence(case_key, conn):
    """Persistence: EID 4698/4699/4700/4701/4702/4697/7045/7040/7035/106."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT event_id,
                   COALESCE(payload->>'TaskName', payload->>'ServiceName', payload->>'ObjectName') AS name,
                   payload->>'SubjectUserName' AS user,
                   event_ts
            FROM event_logs_v2
            WHERE case_key=%s AND event_id IN (4698,4699,4700,4701,4702,4697,7045,7040,7035,7036,106)
            ORDER BY event_ts DESC LIMIT 20
        """, (case_key,))
        ev_rows = cur.fetchall()
        # Startup/Run registry via raw_fallback or filesystem
        cur.execute("""
            -- filesystem_v2 stores the path split in two; there is no full_path column,
            -- so this analysis raised on every run and its absence was then recorded as a
            -- GAP against the golden set - the bot inventing a failure it never attempted.
            SELECT (coalesce(parent_path,'')||'\\'||coalesce(file_name,'')), payload->>'RegValueName' AS reg_val, event_ts
            FROM filesystem_v2
            WHERE case_key=%s AND (
                (coalesce(parent_path,'')||'\\'||coalesce(file_name,'')) ILIKE '%%\\\\CurrentVersion\\\\Run%%'
                OR (coalesce(parent_path,'')||'\\'||coalesce(file_name,'')) ILIKE '%%\\\\Startup%%'
                OR (coalesce(parent_path,'')||'\\'||coalesce(file_name,'')) ILIKE '%%\\\\Tasks\\\\%%'
            )
            ORDER BY event_ts DESC LIMIT 10
        """, (case_key,))
        reg_rows = cur.fetchall()
    findings = {
        'events': [{'event_id': r[0], 'name': r[1], 'user': r[2], 'ts': str(r[3])} for r in ev_rows],
        'registry': [{'path': r[0], 'val': r[1], 'ts': str(r[2])} for r in reg_rows]
    }
    questions = [
        f"Які механізми persistence встановлено у {case_key}? Scheduled tasks чи services?",
        f"Чи встановлювались нові служби (EID 7045) у {case_key}? Назви ServiceName.",
        f"Є persistence через реєстр Run/Startup у {case_key}?"
    ]
    return {'category': 'persistence', 'findings': findings, 'questions': questions}


def _idle_analyze_lateral(case_key, conn):
    """Lateral Movement: EID 5140/5142/5145/4771/4776/4768/4769."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT event_id,
                   payload->>'ShareName' AS share,
                   payload->>'IpAddress' AS ip,
                   payload->>'TargetUserName' AS user,
                   payload->>'Status' AS status,
                   COUNT(*) AS cnt,
                   MAX(event_ts) AS last_ts
            FROM event_logs_v2
            WHERE case_key=%s AND event_id IN (5140,5142,5145,4771,4776,4768,4769,4648)
            GROUP BY event_id, share, ip, user, status
            ORDER BY last_ts DESC LIMIT 20
        """, (case_key,))
        rows = cur.fetchall()
    findings = [{'event_id': r[0], 'share': r[1], 'ip': r[2], 'user': r[3], 'status': r[4], 'cnt': r[5], 'last': str(r[6])} for r in rows]
    questions = [
        f"Чи є lateral movement у {case_key}? Мережеві шари (EID 5140/5145)?",
        f"Kerberos помилки (EID 4768/4769/4771) у {case_key} — хто і звідки?",
        f"Чи є pass-the-hash ознаки (EID 4776 NTLM) у {case_key}?"
    ]
    return {'category': 'lateral', 'findings': findings, 'questions': questions}


def _idle_analyze_tampering(case_key, conn):
    """Tampering/Evasion: EID 1100/1102/104/4719/4907/4616/1074."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT event_id,
                   payload->>'Channel' AS channel,
                   payload->>'SubjectUserName' AS user,
                   event_ts
            FROM event_logs_v2
            -- an event ID without its channel is just a number other providers reuse:
            -- 1102 has 559 hits in this database and 2 are the real Security event
            WHERE case_key=%s AND ((event_id IN (1100,1102,4719,4907,4616) AND coalesce(channel,'') ILIKE '%%Security%%') OR (event_id IN (104,1074) AND coalesce(channel,'') ILIKE '%%System%%'))
            ORDER BY event_ts ASC LIMIT 20
        """, (case_key,))
        rows = cur.fetchall()
    findings = [{'event_id': r[0], 'channel': r[1], 'user': r[2], 'ts': str(r[3])} for r in rows]
    questions = [
        f"Чи очищувались логи (EID 1102/104) у {case_key}? Хто і коли?",
        f"Чи змінювалась audit policy (EID 4719) у {case_key}?",
        f"Чи є ознаки часу зміни системного часу (EID 4616) у {case_key}?"
    ]
    return {'category': 'tampering', 'findings': findings, 'questions': questions}


def _idle_analyze_artifacts(case_key, conn):
    """Artifacts: downloads, LNK, Zone.Identifier, Amcache/Prefetch suspicious paths."""
    with conn.cursor() as cur:
        # Downloads
        try:
            cur.execute("""
                -- browser_downloads_v1 has never existed. The parsed downloads land in
                -- raw_fallback_v2 (5935 rows), and the except below hid that for good.
                SELECT payload->>'filename', payload->>'download_url',
                       payload->>'start_time', payload->>'target_path'
                FROM raw_fallback_v2
                WHERE case_key=%s AND parser_family='browser_downloads'
                ORDER BY row_id LIMIT 15
            """, (case_key,))
            dl_rows = cur.fetchall()
        except Exception:
            dl_rows = []
        # Zone.Identifier (files downloaded from internet)
        cur.execute("""
            -- HostUrl is not a payload key: the whole Zone.Identifier stream is stored as
            -- text under zone_id, so the URL has to be cut out of it.
            SELECT (coalesce(parent_path,'')||'\\'||coalesce(file_name,'')),
                   substring(coalesce(payload->>'zone_id','') from 'HostUrl=([^\r\n]+)') AS host_url,
                   event_ts
            FROM filesystem_v2
            WHERE case_key=%s AND extension='identifier'
              AND coalesce(payload->>'zone_id','') ILIKE '%%HostUrl%%'
            ORDER BY event_ts ASC LIMIT 10
        """, (case_key,))
        zone_rows = cur.fetchall()
        # LNK files
        cur.execute("""
            SELECT (coalesce(parent_path,'')||'\\'||coalesce(file_name,'')), payload->>'TargetPath' AS target, payload->>'LastWriteTime' AS lw
            FROM filesystem_v2
            WHERE case_key=%s AND extension='lnk'
            ORDER BY event_ts DESC LIMIT 10
        """, (case_key,))
        lnk_rows = cur.fetchall()
    findings = {
        'downloads': [{'file': r[0], 'url': r[1], 'ts': str(r[2]), 'path': r[3]} for r in dl_rows],
        'zone_ids': [{'path': r[0], 'url': r[1], 'ts': str(r[2])} for r in zone_rows],
        'lnks': [{'path': r[0], 'target': r[1], 'lw': r[2]} for r in lnk_rows]
    }
    questions = [
        f"Що завантажував користувач у {case_key}? Назви файли та URL-джерела.",
        f"Які LNK файли є у {case_key}? На що вони вказують?",
        f"Які файли мають Zone.Identifier (завантажені з інтернету) у {case_key}?"
    ]
    return {'category': 'artifacts', 'findings': findings, 'questions': questions}


def _idle_analyze_ad_users(case_key, conn):
    """AD/Users: EID 4720/4722/4723/4724/4725/4726/4738/4740/4728/4732/4756/5136/4794."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT event_id,
                   COALESCE(payload->>'TargetUserName', payload->>'SamAccountName') AS target_user,
                   payload->>'SubjectUserName' AS actor,
                   payload->>'MemberName' AS member,
                   event_ts
            FROM event_logs_v2
            WHERE case_key=%s AND event_id IN (4720,4722,4723,4724,4725,4726,4738,4740,4728,4732,4756,5136,4794,4741,4742)
            ORDER BY event_ts ASC LIMIT 25
        """, (case_key,))
        rows = cur.fetchall()
    findings = [{'event_id': r[0], 'target': r[1], 'actor': r[2], 'member': r[3], 'ts': str(r[4])} for r in rows]
    created = [f for f in findings if f['event_id'] == 4720]
    added_to_group = [f for f in findings if f['event_id'] in (4728, 4732, 4756)]
    questions = [
        f"Чи створювались нові облікові записи (EID 4720) у {case_key}? Назви і час.",
        f"Кого додавали до груп Administrators/RDP Users (EID 4728/4732) у {case_key}?",
        f"Чи змінювались паролі (EID 4723/4724) у {case_key}? Яких акаунтів?"
    ]
    return {'category': 'ad_users', 'findings': findings, 'created_accounts': created,
            'group_additions': added_to_group, 'questions': questions}


def _idle_ask_self_question(case_key, question):
    """Run ReAct analysis internally (no TG, no HTTP). Returns answer string."""
    try:
        model = LLM_FAST_MODEL
        lm_base = LLM_URL
        llm_url = lm_base.rstrip('/') + '/v1/chat/completions'

        case_sources = _react_get_case_sources(case_key)
        artifact_ctx = ''
        if case_sources:
            artifact_ctx = '\n\nДоступні артефакти:\n'
            for tbl, files in case_sources.items():
                artifact_ctx += f'  {tbl}: ' + ', '.join(files[:4]) + '\n'

        messages = [
            {'role': 'system', 'content': _REACT_SYSTEM.replace('{case_key}', case_key)},
            {'role': 'user', 'content': question + artifact_ctx},
        ]

        final_answer = None
        for step in range(1, 6):
            if _idle_worker_stop.is_set():
                break
            if _has_active_production_run():
                _log.error(f"[idle_ask] production run active, skipping LLM call")
                break
            try:
                raw = _react_call_llm(messages, model, llm_url)
            except Exception as _llm_e:
                _log.error(f"[idle_ask] LLM error step={step}: {_llm_e}")
                break

            if 'ANSWER:' in raw:
                final_answer = raw[raw.find('ANSWER:') + 7:].strip()
                break

            tool_name, param = _react_parse_action(raw)
            if not tool_name:
                messages.append({'role': 'assistant', 'content': raw})
                messages.append({'role': 'user', 'content': 'OBSERVATION: Не знайдено ACTION. Продовжуй або дай ANSWER:'})
                continue

            observation = _react_call_tool(tool_name, param, case_key)
            messages.append({'role': 'assistant', 'content': raw})
            messages.append({'role': 'user', 'content': f'OBSERVATION: {observation[:2500]}'})

        return final_answer or ''
    except Exception as _e:
        _log.error(f"[idle_ask] error: {_e}")
        return ''


def _idle_get_pdf_context(case_key):
    """Get PDF chunks from kb_reports Qdrant for this case."""
    try:
        _filter_body = json.dumps({
            'limit': 10, 'with_payload': True, 'with_vector': False,
            'filter': {'should': [
                {'key': 'case_key', 'match': {'value': case_key}},
                {'key': 'source_file', 'match': {'any': [case_key + '.pdf', case_key]}}
            ]}
        }).encode('utf-8')
        _req = urllib.request.Request(
            f'{QDRANT_URL}/collections/kb_reports/points/scroll',
            data=_filter_body, headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(_req, timeout=5) as _r:
            pts = json.loads(_r.read().decode('utf-8', errors='ignore')).get('result', {}).get('points', [])
        if not pts:
            _req2 = urllib.request.Request(
                f'{QDRANT_URL}/collections/kb_reports/points/scroll',
                data=json.dumps({'limit': 5, 'with_payload': True, 'with_vector': False}).encode('utf-8'),
                headers={'Content-Type': 'application/json'}
            )
            with urllib.request.urlopen(_req2, timeout=5) as _r2:
                pts = json.loads(_r2.read().decode('utf-8', errors='ignore')).get('result', {}).get('points', [])
        texts = [p.get('payload', {}).get('text', '') for p in pts if p.get('payload', {}).get('text')]
        return '\n'.join(texts[:5])[:3000]
    except Exception:
        return ''


def _idle_get_cases_with_reports():
    """Get cases that have logs in DB (PDF check done inside _idle_run_self_eval)."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT DISTINCT case_key FROM event_logs_v2 WHERE case_key IS NOT NULL LIMIT 20")
                db_cases = [r[0] for r in cur.fetchall()]
        return db_cases
    except Exception as _e:
        _log.error(f"[idle] _idle_get_cases_with_reports error: {_e}")
        return []


def _idle_compare_with_pdf(case_key, bot_findings, pdf_context, run_id, conn):
    """LLM compares bot findings vs PDF, saves gaps and lessons."""
    try:
        llm_url = LLM_URL
        model = LLM_FAST_MODEL

        prompt = (
            f"You are a DFIR quality evaluator.\n\n"
            f"Bot findings for case {case_key}:\n"
            f"{json.dumps(bot_findings, indent=2)[:2000]}\n\n"
            f"Human expert PDF report excerpt:\n"
            f"{pdf_context[:2000]}\n\n"
            f"Identify up to 5 gaps where bot missed important findings.\n"
            f'Return JSON array:\n'
            f'[{{"gap_type":"initial_access","expected_fact":"...","severity":"high","suggested_probe":"SELECT ..."}}]\n'
            # The model used to invent SIEM tables - process_events, registry_events,
            # windows_event_log - because it was never told what this database holds. 60 of
            # 177 stored probes could not run for that reason. Name the tables instead.
            f"suggested_probe must be plain SQL over THESE tables only, no other table exists:\n"
            f"  event_logs_v2(case_key,event_id,event_ts,computer,command_line,process_name,payload)\n"
            f"  program_exec_v2(case_key,executable_name,full_path,event_ts,source_file,payload)\n"
            f"  filesystem_v2(case_key,file_name,parent_path,extension,event_ts,payload)\n"
            f"  raw_fallback_v2(case_key,parser_family,payload)  srum_v2(case_key,payload)\n"
            f"Do not prefix it with 'SQL:'. Filter by case_key.\n"
            f"Only JSON, no explanation."
        )

        import os
        _body = json.dumps(build_chat_payload(
            model=model,
            messages=[{'role': 'user', 'content': prompt}],
            role='json',
            temperature=LLM_FAST_TEMPERATURE,
            max_tokens=int(os.environ.get('DFIR_IDLE_PDF_COMPARE_MAX_TOKENS', '1500')),
            stream=False,
            reasoning_effort=os.environ.get('DFIR_JSON_REASONING_EFFORT', 'low'),
        )).encode('utf-8')
        _req = urllib.request.Request(
            f'{llm_url.rstrip("/")}/v1/chat/completions',
            data=_body, headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(_req, timeout=600) as _r:
            _msg = json.loads(_r.read().decode('utf-8', errors='ignore'))['choices'][0]['message']
            content = (_msg.get('content') or _msg.get('reasoning') or '').strip()

        m = re.search(r'\[.*\]', content, re.DOTALL)
        if not m:
            return []
        gaps_data = json.loads(m.group())

        gaps_saved = []
        for g in gaps_data[:5]:
            g['suggested_probe'] = _validated_probe(g.get('suggested_probe', ''),
                                                    g.get('gap_type', ''), conn)
            with conn.cursor() as cur:
                cur.execute("""INSERT INTO dfir_self_eval_gaps_v1
                    (self_eval_run_id, case_key, gap_type, expected_fact, suggested_probe, severity)
                    VALUES (%s,%s,%s,%s,%s,%s) RETURNING id""",
                    (run_id, case_key, g.get('gap_type', ''), g.get('expected_fact', ''),
                     g.get('suggested_probe', ''), g.get('severity', 'medium')))
                cur.fetchone()  # consume RETURNING id
                conn.commit()

            lesson = (f"For intent '{g.get('gap_type','')}' in case {case_key}: "
                      f"{g.get('expected_fact','')}. Probe: {g.get('suggested_probe','')}")
            _save_lesson(case_key, g.get('gap_type', ''), 'gap_from_self_eval', lesson,
                         ['event_logs_v2'], [], {}, conn)
            gaps_saved.append(g)

        return gaps_saved
    except Exception as _e:
        _log.error(f"[idle] _idle_compare_with_pdf error: {_e}")
        return []


def _idle_compare_with_golden_facts(case_key, bot_findings, conn):
    """Compare bot SQL findings against dfir_golden_facts_v1 (structured ground truth).
    For each missing golden fact → save a gap lesson with a concrete SQL probe."""
    gaps = []
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT category, fact_key, fact_value, severity FROM dfir_golden_facts_v1 WHERE case_key=%s",
                (case_key,)
            )
            golden = cur.fetchall()
        if not golden:
            return []

        # Build a text summary of what bot found
        found_text = json.dumps(bot_findings, ensure_ascii=False)[:4000].lower()

        for category, fact_key, fact_value, severity in golden:
            # Quick heuristic: check if key tokens from the golden fact appear in bot findings
            tokens = [t for t in re.split(r'[\s,./\\]+', fact_value.lower()) if len(t) > 4]
            hit = any(t in found_text for t in tokens[:6])
            if hit:
                # Bot found this fact → save as confirmed knowledge
                try:
                    from analysis.learnings import _save_case_knowledge
                    _save_case_knowledge(
                        case_key, 'confirmed_fact',
                        f"[ПІДТВЕРДЖЕНО] {category}/{fact_key}: {fact_value}",
                        source='golden_facts', confirmed_by='idle_eval',
                    )
                except Exception:
                    pass
                continue

            # Bot missed this fact → create a gap lesson
            probe_hint = _golden_fact_to_probe(category, fact_key, fact_value, case_key)
            lesson = (
                f"[GOLDEN FACT MISS] case={case_key} category={category} key={fact_key}\n"
                f"Expected: {fact_value}\n"
                f"Probe: {probe_hint}"
            )
            _save_lesson(case_key, category, 'gap_from_self_eval', lesson,
                         ['event_logs_v2', 'program_exec_v2'], [], {}, conn)
            try:
                with conn.cursor() as cur:
                    cur.execute("""INSERT INTO dfir_self_eval_gaps_v1
                        (self_eval_run_id, case_key, gap_type, expected_fact, suggested_probe, severity)
                        VALUES (%s,%s,%s,%s,%s,%s)""",
                        (None, case_key, category, fact_value, probe_hint, severity or 'high'))
                conn.commit()
            except Exception:
                try: conn.rollback()
                except: pass
            gaps.append({'category': category, 'fact_key': fact_key, 'fact_value': fact_value})

        _log.info(f"[idle] golden_facts case={case_key}: {len(golden)} facts, {len(gaps)} misses")
    except Exception as _e:
        _log.error(f"[idle] _idle_compare_with_golden_facts error: {_e}")
    return gaps



def _validated_probe(probe, gap_type, conn):
    """Keep a suggested probe only if Postgres can plan it. Returns '' otherwise.

    EXPLAIN plans without running, so this is cheap and it is the only honest answer to
    "can this query execute at all". Measured before this existed: 60 of 177 stored probes
    referenced tables that have never been in this schema, and they were surfaced to the
    reader as the suggested next step.

    gap_type 'report_crosscheck' is exempt on purpose: it stores a QUESTION in this column,
    consumed by _detect_question_topic, and validating it as SQL would delete all of them.
    """
    probe = (probe or '').strip()
    if not probe:
        return ''
    if probe[:4].upper() == 'SQL:':          # the prompt's own example taught this prefix
        probe = probe[4:].strip()
    if gap_type == 'report_crosscheck':
        return probe
    if not probe.lstrip('(').upper().startswith('SELECT'):
        return ''
    try:
        with conn.cursor() as cur:
            cur.execute('EXPLAIN ' + probe)
            cur.fetchall()
        return probe
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        return ''

def _golden_fact_to_probe(category: str, fact_key: str, fact_value: str, case_key: str) -> str:
    """Generate a SQL probe hint based on golden fact category."""
    _probes = {
        'initial_access': "SELECT event_ts, payload->>'NewProcessName', payload->>'CommandLine' FROM event_logs_v2 WHERE case_key='{c}' AND event_id=4688 ORDER BY event_ts LIMIT 20",
        'malware':        "SELECT executable_name, event_ts, full_path FROM program_exec_v2 WHERE case_key='{c}' ORDER BY event_ts LIMIT 20",
        'persistence':    "SELECT event_id, payload->>'TaskName', event_ts FROM event_logs_v2 WHERE case_key='{c}' AND event_id IN (4698,4702,7045) ORDER BY event_ts",
        'keylogger':      "SELECT executable_name, full_path, event_ts FROM program_exec_v2 WHERE case_key='{c}' AND (full_path ILIKE '%log%' OR executable_name ILIKE '%log%') LIMIT 10",
        'remote_access':  "SELECT executable_name, full_path, event_ts FROM program_exec_v2 WHERE case_key='{c}' AND (executable_name ILIKE '%rms%' OR executable_name ILIKE '%rdp%' OR executable_name ILIKE '%lite%') LIMIT 10",
        'lateral_movement': "SELECT event_id, payload->>'IpAddress', event_ts FROM event_logs_v2 WHERE case_key='{c}' AND event_id IN (4648,4624) ORDER BY event_ts LIMIT 20",
        'log_tampering':  "SELECT event_id, event_ts FROM event_logs_v2 WHERE case_key='{c}' AND ((event_id=1102 AND coalesce(channel,'') ILIKE '%Security%') OR (event_id=104 AND coalesce(channel,'') ILIKE '%System%')) ORDER BY event_ts",
    }
    tpl = _probes.get(category, "SELECT * FROM event_logs_v2 WHERE case_key='{c}' LIMIT 10")
    return tpl.format(c=case_key)


def _idle_run_self_eval(case_key):
    """Full self-evaluation: 8 IR categories → auto self-questions → PDF comparison → save lessons."""
    conn = None
    run_id = None
    try:
        conn = psycopg2.connect(PG_DSN)
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO dfir_self_eval_runs_v1 (case_key, status) VALUES (%s, 'running') RETURNING id",
                (case_key,)
            )
            run_id = cur.fetchone()[0]
            conn.commit()

        def _mark_paused(reason='paused'):
            if conn and run_id:
                try:
                    with conn.cursor() as _c:
                        _c.execute("UPDATE dfir_self_eval_runs_v1 SET status=%s, finished_at=NOW() WHERE id=%s",
                                   (reason, run_id))
                        conn.commit()
                except Exception:
                    pass

        if _idle_worker_stop.is_set():
            _mark_paused('stopped')
            return

        # All 8 Windows IR analysis functions
        analyzers = [
            _idle_analyze_defender,
            _idle_analyze_logon_rdp,
            _idle_analyze_process_ps,
            _idle_analyze_persistence,
            _idle_analyze_lateral,
            _idle_analyze_tampering,
            _idle_analyze_artifacts,
            _idle_analyze_ad_users,
        ]

        bot_findings = {}
        all_questions = []

        for fn in analyzers:
            if _idle_worker_stop.is_set():
                _mark_paused('stopped')
                return
            if (time.time() - _state['last_user_request_ts']) < 900:
                _log.info(f"[idle] user active, pausing self_eval for {case_key}")
                _mark_paused('paused')
                return
            if not _is_gpu_idle():
                _log.info(f"[idle] GPU busy, pausing self_eval for {case_key}")
                _mark_paused('paused')
                return
            try:
                result = fn(case_key, conn)
                cat = result.get('category', fn.__name__)
                bot_findings[cat] = result.get('findings', {})
                all_questions.extend(result.get('questions', []))
                _log.info(f"[idle] analyzed {cat} for {case_key}: {len(str(result['findings']))} chars")
            except Exception as _fe:
                _log.error(f"[idle] analyzer {fn.__name__} error: {_fe}")
                try:
                    conn.rollback()
                except Exception:
                    pass

        # Golden facts comparison: structured ground truth → reliable gap detection
        golden_gaps = _idle_compare_with_golden_facts(case_key, bot_findings, conn)
        if golden_gaps:
            _log.info(f"[idle] golden_facts gaps saved: {len(golden_gaps)} for {case_key}")

        # Self-questioning: ask bot itself 1 question per category, save good answers
        answered = 0
        for q in all_questions[:8]:  # max 8 questions per run (1 per category)
            if _idle_worker_stop.is_set():
                _mark_paused('stopped')
                return
            if (time.time() - _state['last_user_request_ts']) < 900:
                _mark_paused('paused')
                return
            if not _is_gpu_idle():
                _mark_paused('paused')
                return
            try:
                if not _bg_llm_lock.acquire(timeout=600):
                    _log.info(f"[idle] self-qa lock timeout, skipping q={q[:60]!r}")
                    continue
                try:
                    answer = _idle_ask_self_question(case_key, q)
                finally:
                    _bg_llm_lock.release()
                if answer and len(answer) > 100:
                    lesson = f"Q: {q[:150]}\nA: {answer[:400]}"
                    _save_lesson(case_key, q[:50], 'self_qa', lesson, ['event_logs_v2'], [], {}, conn)
                    answered += 1
                    _log.info(f"[idle] self-qa saved case={case_key} q={q[:60]!r}")
            except Exception as _qe:
                _log.error(f"[idle] self-qa error: {_qe}")

        # PDF comparison (teacher/benchmark)
        pdf_context = _idle_get_pdf_context(case_key)
        gaps = []
        if pdf_context and bot_findings:
            gaps = _idle_compare_with_pdf(case_key, bot_findings, pdf_context, run_id, conn)

        score = max(0.0, 1.0 - len(gaps) * 0.1)
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE dfir_self_eval_runs_v1 SET status='done', finished_at=NOW(), coverage_score=%s WHERE id=%s",
                (score, run_id)
            )
            conn.commit()
        _log.info(f"[idle] self_eval done case={case_key} score={score:.2f} gaps={len(gaps)} qa={answered}")

    except Exception as _e:
        _log.error(f"[idle] _idle_run_self_eval error case={case_key}: {_e}")
        if conn and run_id:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE dfir_self_eval_runs_v1 SET status='error', notes=%s WHERE id=%s",
                        (str(_e)[:500], run_id)
                    )
                    conn.commit()
            except Exception:
                pass
    finally:
        if conn:
            try: conn.close()
            except: pass



def _idle_learning_worker():
    """Runs in background. Activates after 15 min idle. Pauses on user request."""
    _state['idle_worker_running'] = True
    _log.info("[idle] worker started")
    try:
        while not _idle_worker_stop.is_set():
            idle_secs = time.time() - _state['last_user_request_ts']
            if idle_secs < 900:  # 15 min
                _idle_worker_stop.wait(30)
                continue
            cases = _idle_get_cases_with_reports()
            _log.info(f"[idle] checking {len(cases)} cases")
            did_work = False
            for case_key in cases:
                if _idle_worker_stop.is_set():
                    break
                if (time.time() - _state['last_user_request_ts']) < 900:
                    break
                # Skip if completed or already running recently (last 6h)
                try:
                    with psycopg2.connect(PG_DSN) as _cc:
                        with _cc.cursor() as _cu:
                            _cu.execute("""SELECT COUNT(*) FROM dfir_self_eval_runs_v1
                                WHERE case_key=%s
                                AND status IN ('done', 'running')
                                AND started_at >= NOW() - INTERVAL '6 hours'""", (case_key,))
                            if _cu.fetchone()[0] > 0:
                                _log.info(f"[idle] skipping {case_key} (eval <6h ago)")
                                continue
                except Exception:
                    pass
                if not _wait_for_llm(_idle_worker_stop, 'idle'):
                    break
                if not _is_gpu_idle():
                    _log.info(f"[idle] GPU busy before self_eval for {case_key}, skipping")
                    break
                _log.info(f"[idle] starting self_eval for {case_key}")
                _idle_run_self_eval(case_key)
                did_work = True
            # If nothing to do — sleep 2h; if did work — check again in 60s
            _idle_worker_stop.wait(60 if did_work else 7200)
    finally:
        _state['idle_worker_running'] = False
        _log.error("[idle] worker stopped")


# ─── Report-driven QA regression worker ──────────────────────────────────────

_QA_CATEGORIES = [
    'initial_access', 'phishing_email', 'browser_downloads', 'files_payload',
    'powershell_process', 'defender_av', 'persistence', 'scheduled_tasks',
    'services', 'registry_run_keys', 'users_accounts', 'logon_rdp',
    'ngrok_c2_tunnels', 'lateral_movement', 'exfiltration', 'credential_access',
    'fiddler_proxy', 'log_tampering', 'ioc', 'timeline', 'final_conclusion',
]

_FAILURE_TYPES = [
    'sql_payload_gap', 'missing_table_probe', 'wrong_source_priority',
    'parser_normalization_gap', 'tool_gap', 'prompt_reasoning_gap',
    'timeline_gap', 'ioc_gap', 'report_quality_gap',
]


