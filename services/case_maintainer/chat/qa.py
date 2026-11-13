"""QA evaluation, QA cache worker, answer feedback — chat quality layer."""
import json, logging, os, re, time, urllib.request
import psycopg2
from core.config import PG_DSN, LLM_URL, LLM_MODEL, LLM_FAST_MODEL, LLM_MAX_TOKENS, TG_BOT_TOKEN, QDRANT_URL, LLM_JSON_TEMPERATURE
from core.http_utils import http_json as _http_json, llm_chat as _llm_chat
from core.model_router import build_chat_payload
from analysis.learnings import _save_lesson, _get_relevant_lessons
from analysis.qa_cache import _qa_cache_lookup, _qa_cache_save
from analysis.case_memory import get_verified_case_context
from telegram.notify import _tg_send_or_edit, _tg_send_admin
from analysis.chat import (
    _REACT_SYSTEM, _react_get_case_sources, _react_call_llm,
    _react_parse_action, _react_call_tool,
)
from workers.state import (
    _idle_worker_stop, _bg_llm_lock, _qa_case_queue, _qa_queue_lock, _state,
)
from workers.idle_learning import _idle_get_cases_with_reports
from analysis.learnings import _has_active_production_run
_log = logging.getLogger('app')


class _TSProxy:
    """Makes `time.time() - _last_user_request_ts` work by delegating to _state."""
    def __rsub__(self, other):
        return other - _state['last_user_request_ts']
    def __sub__(self, other):
        return _state['last_user_request_ts'] - other
    def __lt__(self, other):
        return _state['last_user_request_ts'] < other
    def __gt__(self, other):
        return _state['last_user_request_ts'] > other

_last_user_request_ts = _TSProxy()

def _eval_get_full_pdf(case_key):
    """Get ALL PDF chunks for a case from Qdrant kb_reports."""
    try:
        # First try case-specific filter
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
            # Fallback: get everything and filter by case name substring
            _req2 = urllib.request.Request(
                f'{QDRANT_URL}/collections/kb_reports/points/scroll',
                data=json.dumps({'limit': 100, 'with_payload': True, 'with_vector': False}).encode(),
                headers={'Content-Type': 'application/json'}
            )
            with urllib.request.urlopen(_req2, timeout=8) as _r2:
                all_pts = json.loads(_r2.read().decode('utf-8', errors='ignore')).get('result', {}).get('points', [])
            # match by case key fragment
            ck_short = case_key.split('_')[-1][:10].lower()
            pts = [p for p in all_pts if ck_short in (p.get('payload', {}).get('source_file', '') or '').lower()
                   or ck_short in (p.get('payload', {}).get('case_key', '') or '').lower()]
            if not pts:
                pts = all_pts[:20]  # last resort: first 20 chunks

        texts = [p.get('payload', {}).get('text', '') for p in pts if p.get('payload', {}).get('text')]
        source_file = pts[0].get('payload', {}).get('source_file', '') if pts else ''
        return '\n\n---\n\n'.join(texts[:30])[:12000], source_file
    except Exception as _e:
        _log.error(f"[qa] _eval_get_full_pdf error: {_e}")
        return '', ''


_EVAL_TEMPLATES = [
    # (question_template, category, expected_sources, pdf_keywords_for_answer)
    ('Який був первинний вектор атаки (initial access)? Що завантажив або відкрив користувач?',
     'initial_access', ['browser_downloads_v1', 'filesystem_v2'], ['initial access', 'завантаж', 'phishing', 'browser', 'download']),
    ('Які підозрілі exe/zip файли завантажувались через браузер?',
     'browser_downloads', ['browser_downloads_v1', 'filesystem_v2'], ['download', 'завантаж', '.zip', '.exe', 'browser']),
    ('Який перший підозрілий виконуваний файл з\'явився в системі (Amcache/Prefetch)?',
     'files_payload', ['program_exec_v2'], ['amcache', 'prefetch', 'exe', 'first', 'перший']),
    ('Чи є ознаки запуску PowerShell або cmd з підозрілими аргументами?',
     'powershell_process', ['event_logs_v2'], ['powershell', 'cmd', 'commandline', '4103', '4104', '4688']),
    ('Що знайшов Windows Defender? Назви троянів та файли (EID 1116/1117)?',
     'defender_av', ['event_logs_v2'], ['defender', 'trojan', 'malware', '1116', '1117', 'threat']),
    ('Які механізми persistence встановлено? Scheduled tasks, services, Run keys?',
     'persistence', ['event_logs_v2', 'raw_fallback_v2'], ['persistence', 'task', 'service', 'run key', 'автозапуск', 'заплановане']),
    ('Яке заплановане завдання (Scheduled Task) створено зловмисником? Назва та exe.',
     'scheduled_tasks', ['event_logs_v2', 'raw_fallback_v2'], ['svchost', 'task', 'schedule', 'not.exe', 'nott.exe', 'TaskCache']),
    ('Які нові служби Windows встановлено (EID 7045)? Назва та шлях.',
     'services', ['event_logs_v2'], ['7045', 'service', 'служба', 'rdpwrap', 'system32']),
    ('Є persistence через реєстр Run/ASEP? Які ключі та значення?',
     'registry_run_keys', ['raw_fallback_v2', 'filesystem_v2'], ['run key', 'HKLM', 'CurrentVersion\\Run', 'ASEP', 'реєстр']),
    ('Які нові облікові записи створено (EID 4720)? Ім\'я, SID, час створення.',
     'users_accounts', ['event_logs_v2'], ['4720', 'case_59', 'account', 'обліковий', 'SID', 'створен']),
    ('До яких груп додано новий обліковий запис (EID 4732/4728)? Administrators? RDP Users?',
     'users_accounts', ['event_logs_v2'], ['4732', '4728', 'Administrators', 'Remote Desktop', 'group', 'групу']),
    ('Звідки здійснювались RDP підключення (EID 4624 type 10 / EID 1149)? IP-адреси.',
     'logon_rdp', ['event_logs_v2'], ['4624', '1149', 'RDP', 'logon', 'ip', 'remote desktop', 'підключ']),
    ('Чи використовувався ngrok або інший тунель для C2? Коли і звідки?',
     'ngrok_c2_tunnels', ['program_exec_v2', 'event_logs_v2'], ['ngrok', 'tunnel', 'c2', 'command', 'тунель']),
    ('Чи встановлювався RDP Wrapper? Коли і звідки запущений rdpwinst.exe?',
     'logon_rdp', ['program_exec_v2'], ['rdpwrap', 'rdpwinst', 'RDP Wrapper', 'wrapper']),
    ('Чи є ознаки lateral movement? Мережеві шари (EID 5140/5145) або pass-the-hash (EID 4776)?',
     'lateral_movement', ['event_logs_v2'], ['5140', '5145', '4776', 'lateral', 'share', 'NTLM']),
    ('Які інструменти для ексфільтрації даних використовувались? 7za, архів, передача файлів?',
     'exfiltration', ['program_exec_v2', 'event_logs_v2'], ['7za', 'exfil', 'архів', 'передач', 'zip', 'rar']),
    ('Чи є Fiddler або інший MITM proxy? Чи встановлювались кореневі сертифікати?',
     'fiddler_proxy', ['program_exec_v2', 'raw_fallback_v2'], ['fiddler', 'proxy', 'trustcert', 'certificate', 'mitm', 'сертифікат']),
    ('Чи очищувались журнали подій (EID 1102/104)? Хто і коли?',
     'log_tampering', ['event_logs_v2'], ['1102', '104', 'log cleared', 'очищ', 'cleared', 'tamper']),
    ('Які IP-адреси, домени або хеші є IOC? Перелічи всі знайдені.',
     'ioc', ['case_trigger_hits_v2', 'event_logs_v2'], ['IOC', 'ip', 'hash', 'domain', 'indicator', 'хеш']),
    ('Побудуй повну хронологію атаки від initial access до останнього вторгнення.',
     'timeline', ['event_logs_v2', 'program_exec_v2'], ['timeline', 'хронолог', 'initial', 'attack', 'first', 'last']),
]


def _eval_pdf_search_answer(pdf_text, keywords):
    """Find relevant sentences in PDF text matching any keyword."""
    sentences = re.split(r'(?<=[.!?])\s+|\n', pdf_text)
    matched = []
    for s in sentences:
        s_lower = s.lower()
        if any(kw.lower() in s_lower for kw in keywords):
            matched.append(s.strip())
    return ' '.join(matched[:5])[:600] if matched else ''


def _eval_extract_questions(case_key, pdf_text, source_file, conn):
    """Build eval questions from hardcoded templates + PDF text search for expected answers."""
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM dfir_eval_questions_v1 WHERE case_key=%s", (case_key,))
        existing = cur.fetchone()[0]
    if existing >= 20:
        _log.info(f"[qa] {case_key} already has {existing} questions, skipping")
        return []

    saved = []
    for question_tmpl, category, exp_sources, pdf_keys in _EVAL_TEMPLATES:
        if _idle_worker_stop.is_set():
            break
        expected_answer = _eval_pdf_search_answer(pdf_text, pdf_keys)
        # Extract key facts: first 3 non-trivial words from expected_answer sentences
        facts = []
        for s in expected_answer.split('.'):
            s = s.strip()
            if len(s) > 20 and s not in facts:
                facts.append(s[:120])
            if len(facts) >= 3:
                break

        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO dfir_eval_questions_v1
                      (case_key, source_report, question, expected_answer, expected_facts, expected_sources, category)
                    VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id
                """, (case_key, source_file, question_tmpl, expected_answer,
                      json.dumps(facts), json.dumps(exp_sources), category))
                qid = cur.fetchone()[0]
                conn.commit()
            saved.append({'id': str(qid), 'question': question_tmpl,
                          'expected_answer': expected_answer, 'expected_facts': facts,
                          'category': category, 'expected_sources': exp_sources})
        except Exception as _ie:
            _log.error(f"[qa] insert question error: {_ie}")

    _log.info(f"[qa] extracted {len(saved)} questions for {case_key}")
    return saved


def _eval_answer_logs_first(case_key, question, force=False):
    """Run ReAct agent on question, tracking tools/SQL used. No PDF access."""
    tools_used = []
    sql_used = []
    sources_hit = []

    try:
        model = LLM_FAST_MODEL
        lm_base = LLM_URL
        llm_url = lm_base.rstrip('/') + '/v1/chat/completions'

        case_sources = _react_get_case_sources(case_key)
        artifact_ctx = ''
        if case_sources:
            artifact_ctx = '\n\nАртефакти:\n'
            for tbl, files in case_sources.items():
                artifact_ctx += f'  {tbl}: ' + ', '.join(files[:4]) + '\n'

        # Inject existing lessons and analyst-approved case facts
        lessons_str = ''
        try:
            verified_ctx = get_verified_case_context(case_key, limit=12)
            if verified_ctx:
                lessons_str += '\n\n' + verified_ctx
        except Exception:
            pass
        try:
            _ls = _get_relevant_lessons(case_key, question[:200])
            if _ls:
                lessons_str += '\n\n[LESSONS]\n' + '\n'.join(f'- {l[:250]}' for l in _ls[:3])
        except Exception:
            pass

        # Production parity: try the FAST PATH first (same as the live chat). ReAct
        # on the 20b emits harmony tokens and yields empty answers — that was the
        # eval's mass 'tool_gap'. The fast path (SQL + single synth) works on 20b.
        try:
            from analysis.chat import _detect_question_topic, _run_fast_path, _FAST_PATH_SQL
            _intent = _detect_question_topic(question)
            if _intent and _intent in _FAST_PATH_SQL:
                _fa = _run_fast_path(case_key, question, _intent, model, llm_url)
                if _fa and len(_fa) >= 30:
                    return {'answer': _fa, 'tools_used': [f'fast_path:{_intent}'],
                            'sql_used': [], 'sources_used': ['fast_path'], 'logs_first': True}
        except Exception as _fpe:
            _log.error(f"[qa] eval fast-path error: {_fpe}")

        messages = [
            {'role': 'system', 'content': _REACT_SYSTEM.replace('{case_key}', case_key)},
            {'role': 'user', 'content': question + artifact_ctx + lessons_str},
        ]

        final_answer = ''
        for step in range(1, 8):
            if _idle_worker_stop.is_set():
                break
            if not force and (time.time() - _last_user_request_ts) < 900:
                break
            if _has_active_production_run():
                _log.error(f"[qa_answer] production run active, skipping LLM call")
                break
            try:
                if not _bg_llm_lock.acquire(timeout=600):
                    _log.info(f"[qa_answer] lock timeout step={step}, skipping")
                    break
                try:
                    raw = _react_call_llm(messages, model, llm_url)
                finally:
                    _bg_llm_lock.release()
            except Exception as _le:
                _log.error(f"[qa_answer] LLM step={step} error: {_le}")
                break

            if 'ANSWER:' in raw:
                final_answer = raw[raw.find('ANSWER:') + 7:].strip()
                break

            tool_name, param = _react_parse_action(raw)
            if not tool_name:
                messages.append({'role': 'assistant', 'content': raw})
                messages.append({'role': 'user', 'content': 'OBSERVATION: Немає ACTION. Дай ANSWER:'})
                continue

            # Block PDF access in QA mode
            if tool_name == 'search_reports':
                tools_used.append('search_reports[BLOCKED]')
                messages.append({'role': 'assistant', 'content': raw})
                messages.append({'role': 'user', 'content': 'OBSERVATION: search_reports недоступний в QA режимі. Шукай тільки в логах.'})
                continue

            tools_used.append(tool_name)
            if tool_name == 'run_sql' and param:
                sql_used.append(param[:300])

            observation = _react_call_tool(tool_name, param, case_key)

            # Extract source tables from observation
            for tbl in ['event_logs_v2', 'program_exec_v2', 'filesystem_v2', 'raw_fallback_v2',
                        'srum_v2', 'case_trigger_hits_v2', 'browser_downloads_v1']:
                if tbl in observation and tbl not in sources_hit:
                    sources_hit.append(tbl)

            messages.append({'role': 'assistant', 'content': raw})
            messages.append({'role': 'user', 'content': f'OBSERVATION: {observation[:2500]}'})

        return {
            'answer': final_answer,
            'tools_used': tools_used,
            'sql_used': sql_used,
            'sources_used': sources_hit,
            'logs_first': 'search_reports[BLOCKED]' not in tools_used or bool(sources_hit),
        }
    except Exception as _e:
        _log.error(f"[qa] _eval_answer_logs_first error: {_e}")
        return {'answer': '', 'tools_used': tools_used, 'sql_used': sql_used, 'sources_used': [], 'logs_first': True}


def _failure_types():
    """The judge's vocabulary of failure kinds, owned by workers.self_improve."""
    try:
        from workers.self_improve import _FAILURE_TYPES
        return list(_FAILURE_TYPES)
    except Exception:
        return ['sql_payload_gap', 'missing_table_probe', 'wrong_source_priority',
                'parser_normalization_gap', 'tool_gap', 'prompt_reasoning_gap',
                'timeline_gap', 'ioc_gap', 'report_quality_gap']


def _eval_judge_answer(case_key, category, question, expected_answer, expected_facts, bot_answer, sql_used):
    """LLM judges PASS/FAIL and classifies failure type with root cause."""
    if _has_active_production_run():
        _log.error(f"[qa] judge skipping — production run active")
        return None
    if not bot_answer or len(bot_answer) < 30:
        return {
            'verdict': 'FAIL',
            'failure_type': 'tool_gap',
            'expected_fact': expected_facts[0] if expected_facts else expected_answer[:100],
            'actual_answer': bot_answer or '(empty)',
            'root_cause': 'Bot produced no answer — likely LLM timeout or no tool result',
            'suggested_fix': 'Check if relevant table has data; add fallback to raw_fallback_v2',
            'severity': 'high',
        }
    try:
        llm_url = LLM_URL
        model = LLM_FAST_MODEL

        sql_str = '\n'.join(sql_used[:5]) if sql_used else '(none)'
        prompt = (
            f"You are a DFIR QA judge evaluating a bot answer against an expert report.\n\n"
            f"Case: {case_key} | Category: {category}\n"
            f"Question: {question}\n\n"
            f"EXPECTED (from expert PDF report):\n{expected_answer[:800]}\n"
            f"KEY FACTS that must appear: {json.dumps(expected_facts)}\n\n"
            f"BOT ANSWER (from logs only):\n{bot_answer[:800]}\n\n"
            f"SQL used by bot:\n{sql_str[:500]}\n\n"
            f"Judge if the bot answer correctly covers the expected facts.\n"
            f"TIMEZONE RULE: KAPE logs are UTC, the expert report may use Kyiv time (UTC+2). "
            f"A CONSISTENT ±2-hour difference in timestamps is the SAME event — treat it as a "
            f"MATCH, never a failure. Only flag a timestamp if the DATE or the event itself differs.\n"
            # The list moved out with the workers split and nothing imported it back,
            # so this line raised NameError and the judge was skipped on every answer.
            f"Failure types: {', '.join(_failure_types())}\n\n"
            f"Return ONLY JSON (no explanation):\n"
            f'{{"verdict":"PASS|FAIL","failure_type":"...or null","missing_fact":"...","root_cause":"...","suggested_fix":"...","severity":"low|medium|high|critical"}}\n'
        )

        _body = json.dumps(build_chat_payload(
            model=model,
            messages=[{'role': 'user', 'content': prompt}],
            role='json',
            temperature=LLM_JSON_TEMPERATURE,
            max_tokens=int(os.environ.get('DFIR_QA_JUDGE_MAX_TOKENS', '800')),
            stream=False,
            reasoning_effort=os.environ.get('DFIR_JSON_REASONING_EFFORT', 'low'),
        )).encode('utf-8')
        _req = urllib.request.Request(
            f'{llm_url.rstrip("/")}/v1/chat/completions',
            data=_body, headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(_req, timeout=300) as _r:
            content = json.loads(_r.read().decode('utf-8', errors='ignore'))['choices'][0]['message']['content'].strip()

        m = re.search(r'\{.*?\}', content, re.DOTALL)
        if not m:
            return {'verdict': 'FAIL', 'failure_type': 'prompt_reasoning_gap',
                    'missing_fact': expected_answer[:100], 'root_cause': 'Judge returned no JSON',
                    'suggested_fix': '', 'severity': 'medium'}
        return json.loads(m.group())
    except Exception as _e:
        _log.error(f"[qa] _eval_judge_answer error (skipping): {_e}")
        return None  # None = timeout/error, caller skips without recording FAIL


def _eval_embed_lesson(text, case_key, intent, lesson_type, conn):
    """Embed a QA lesson/failure into Qdrant dfir_lessons_learned_v1."""
    try:
        _save_lesson(case_key, intent, lesson_type, text[:600], ['eval_qa'], [], {}, conn)
    except Exception:
        pass


def _eval_group_fix_candidates(case_key, conn):
    """Group recurring failures into fix_candidates (aggregate by failure_type)."""
    fix_area_map = {
        'sql_payload_gap': 'sql_queries',
        'missing_table_probe': 'tool_orchestration',
        'wrong_source_priority': 'react_system_prompt',
        'parser_normalization_gap': 'db_parser',
        'tool_gap': 'new_tool',
        'prompt_reasoning_gap': 'llm_prompt',
        'timeline_gap': 'timeline_builder',
        'ioc_gap': 'ioc_extractor',
        'report_quality_gap': 'benchmark',
    }
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT failure_type, COUNT(*) as cnt,
                       array_agg(DISTINCT category) as categories,
                       array_agg(root_cause ORDER BY created_at DESC) as root_causes,
                       array_agg(suggested_fix ORDER BY created_at DESC) as fixes,
                       array_agg(question_id::text ORDER BY created_at DESC) as qids
                FROM dfir_eval_failures_v1
                WHERE case_key=%s AND failure_type IS NOT NULL
                GROUP BY failure_type
                HAVING COUNT(*) >= 2
                ORDER BY cnt DESC
            """, (case_key,))
            groups = cur.fetchall()

        for g in groups:
            ft, cnt, cats, root_causes, fixes, qids = g
            with conn.cursor() as cur2:
                cur2.execute("""SELECT id FROM dfir_fix_candidates_v1
                    WHERE case_key=%s AND failure_type=%s AND status='proposed'""", (case_key, ft))
                existing = cur2.fetchone()
            if existing:
                with conn.cursor() as cur3:
                    cur3.execute("UPDATE dfir_fix_candidates_v1 SET priority=%s WHERE id=%s",
                                (min(cnt, 10), existing[0]))
                conn.commit()
                continue

            fix_area = fix_area_map.get(ft, 'general')
            rc_sample = '; '.join(list(dict.fromkeys(r for r in (root_causes or []) if r))[:3])
            fix_sample = (fixes or [''])[0]
            fix_prompt = (
                f"[{ft}] Recurring in {cnt} questions, categories: {', '.join(cats or [])}. "
                f"Root causes: {rc_sample[:300]}. "
                f"Suggested fix: {fix_sample[:200]}"
            )
            with conn.cursor() as cur4:
                cur4.execute("""
                    INSERT INTO dfir_fix_candidates_v1
                      (case_key, failure_type, fix_area, fix_prompt, affected_questions, priority)
                    VALUES (%s,%s,%s,%s,%s,%s)
                """, (case_key, ft, fix_area, fix_prompt,
                      json.dumps((qids or [])[:20]), min(cnt, 10)))
            conn.commit()
            _log.info(f"[qa] fix_candidate: case={case_key} type={ft} cnt={cnt}")
    except Exception as _e:
        _log.error(f"[qa] _eval_group_fix_candidates error: {_e}")


def _eval_run_case(case_key, force=False):
    """Full QA regression cycle for one case. force=True bypasses idle check."""
    conn = None
    try:
        conn = psycopg2.connect(PG_DSN)
        pdf_text, source_file = _eval_get_full_pdf(case_key)
        if not pdf_text:
            _log.error(f"[qa] no PDF found for {case_key}, skipping")
            return

        _log.info(f"[qa] starting eval for {case_key} pdf_chars={len(pdf_text)}")

        # Step 1: Extract questions (idempotent — skips if >=30 already exist)
        questions = _eval_extract_questions(case_key, pdf_text, source_file, conn)
        if not questions:
            # Load existing questions
            with conn.cursor() as cur:
                cur.execute("""SELECT id, question, expected_answer, expected_facts, category, expected_sources
                    FROM dfir_eval_questions_v1 WHERE case_key=%s ORDER BY created_at ASC""", (case_key,))
                rows = cur.fetchall()
            questions = [{'id': str(r[0]), 'question': r[1], 'expected_answer': r[2],
                          'expected_facts': r[3] or [], 'category': r[4], 'expected_sources': r[5] or []}
                         for r in rows]

        pass_count = 0
        fail_count = 0

        for q in questions:
            if _idle_worker_stop.is_set():
                break
            if not force and (time.time() - _last_user_request_ts) < 900:
                _log.info(f"[qa] user active — pausing eval for {case_key}")
                break

            qid = q['id']
            question = q['question']
            expected = q['expected_answer']
            expected_facts = q['expected_facts'] if isinstance(q['expected_facts'], list) else []
            category = q.get('category', '')

            # Skip if already answered recently (last 12h)
            with conn.cursor() as cur:
                cur.execute("""SELECT COUNT(*) FROM dfir_eval_answers_v1
                    WHERE question_id=%s AND created_at >= NOW() - INTERVAL '12 hours'""", (qid,))
                if cur.fetchone()[0] > 0:
                    continue

            _log.info(f"[qa] answering q={question[:60]!r} cat={category}")

            # Step 2: Bot answers logs-first (no PDF)
            result = _eval_answer_logs_first(case_key, question, force=force)
            bot_answer = result['answer']
            tools_used = result['tools_used']
            sql_used = result['sql_used']
            sources_used = result['sources_used']

            # Save answer
            with conn.cursor() as cur:
                cur.execute("""INSERT INTO dfir_eval_answers_v1
                    (question_id, case_key, bot_answer, tools_used, sql_used, sources_used, logs_first)
                    VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                    (qid, case_key, bot_answer, json.dumps(tools_used),
                     json.dumps(sql_used), json.dumps(sources_used), result['logs_first']))
                answer_id = cur.fetchone()[0]
                conn.commit()

            # Step 3: Judge
            if _idle_worker_stop.is_set():
                break
            if not force and (time.time() - _last_user_request_ts) < 900:
                break

            verdict = _eval_judge_answer(case_key, category, question, expected,
                                         expected_facts, bot_answer, sql_used)

            if verdict is None:
                _log.error(f"[qa] judge timeout/error for {case_key}, skipping")
                continue

            if verdict.get('verdict') == 'PASS':
                pass_count += 1
                # Save as positive lesson
                lesson = f"[PASS] Q: {question[:100]} → A correctly covered: {', '.join(expected_facts[:3])}"
                _eval_embed_lesson(lesson, case_key, category, 'qa_pass', conn)
            else:
                fail_count += 1
                # Save failure
                with conn.cursor() as cur:
                    cur.execute("""INSERT INTO dfir_eval_failures_v1
                        (question_id, answer_id, case_key, category, failure_type,
                         expected_fact, actual_answer, root_cause, suggested_fix, severity)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (qid, answer_id, case_key, category,
                         verdict.get('failure_type', 'prompt_reasoning_gap'),
                         verdict.get('missing_fact', '')[:500],
                         (bot_answer or '')[:500],
                         verdict.get('root_cause', '')[:500],
                         verdict.get('suggested_fix', '')[:500],
                         verdict.get('severity', 'medium')))
                    conn.commit()

                # Embed failure as lesson
                failure_lesson = (
                    f"[FAIL:{verdict.get('failure_type','')}] Q: {question[:100]}\n"
                    f"Missing: {verdict.get('missing_fact','')[:200]}\n"
                    f"Root cause: {verdict.get('root_cause','')[:200]}\n"
                    f"Fix: {verdict.get('suggested_fix','')[:150]}"
                )
                _eval_embed_lesson(failure_lesson, case_key, category, 'qa_failure', conn)

        # Step 4: Group recurring failures into fix_candidates
        _eval_group_fix_candidates(case_key, conn)

        _log.info(f"[qa] eval done case={case_key} pass={pass_count} fail={fail_count}")

    except Exception as _e:
        _log.error(f"[qa] _eval_run_case error case={case_key}: {_e}")
    finally:
        if conn:
            try: conn.close()
            except: pass


def dfir_report_qa_worker():
    """Background report-driven QA regression. Processes cases sequentially."""
    _log.info("[qa] worker started")
    try:
        while not _idle_worker_stop.is_set():
            # Priority: drain manual queue first
            with _qa_queue_lock:
                next_item = _qa_case_queue.pop(0) if _qa_case_queue else None

            if next_item:
                case_key, force = next_item
                _log.info(f"[qa] processing queued case={case_key} force={force}")
                _eval_run_case(case_key, force=force)
                continue  # immediately check for more queued items

            # No queued items: check idle timer for background eval
            idle_secs = time.time() - _last_user_request_ts
            if idle_secs < 900:
                _idle_worker_stop.wait(30)
                continue

            if _has_active_production_run():
                _idle_worker_stop.wait(300)
                continue

            cases = _idle_get_cases_with_reports()
            _log.info(f"[qa] idle: checking {len(cases)} cases")

            for case_key in cases:
                if _idle_worker_stop.is_set():
                    break
                with _qa_queue_lock:
                    if _qa_case_queue:
                        break  # prioritize manual queue
                if _has_active_production_run():
                    break
                if (time.time() - _last_user_request_ts) < 900:
                    _log.info("[qa] user request — pausing background eval")
                    break
                try:
                    with psycopg2.connect(PG_DSN) as _cc:
                        with _cc.cursor() as _cu:
                            _cu.execute("""SELECT COUNT(*) FROM dfir_eval_answers_v1
                                WHERE case_key=%s AND created_at >= NOW() - INTERVAL '12 hours'""", (case_key,))
                            if _cu.fetchone()[0] >= 5:
                                continue
                except Exception:
                    pass
                _eval_run_case(case_key, force=False)

            _idle_worker_stop.wait(60)
    except Exception as _e:
        _log.error(f"[qa] worker error: {_e}")
    finally:
        _log.error("[qa] worker stopped")


def _send_answer_with_feedback(chat_id, answer_text, case_key, question_short, tg_token, answer_id=None):
    """Send feedback buttons (✅/❌/🤷) after a QA answer."""
    if not tg_token or not chat_id:
        return
    aid = answer_id or 'noid'
    keyboard = {
        'inline_keyboard': [
            [
                {'text': '✅ Вірно', 'callback_data': f'qa_fb:correct:{aid}'},
                {'text': '❌ Невірно', 'callback_data': f'qa_fb:wrong:{aid}'},
                {'text': '🤷 Не знаю', 'callback_data': f'qa_fb:unknown:{aid}'},
            ],
            [
                {'text': '📁 До кейсу', 'callback_data': 'case_menu'},
                {'text': '🏠 Меню', 'callback_data': 'menu_back'},
            ],
        ]
    }
    try:
        _body = json.dumps({
            'chat_id': chat_id, 'text': answer_text[:4000],
            'reply_markup': keyboard,
        }, ensure_ascii=False).encode('utf-8')
        _req = urllib.request.Request(
            f'https://api.telegram.org/bot{tg_token}/sendMessage',
            data=_body, headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(_req, timeout=15) as _r:
            _r.read()
    except Exception as _e:
        _log.error(f"[qa] _send_answer_with_feedback error: {_e}")




