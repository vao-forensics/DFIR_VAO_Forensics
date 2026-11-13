"""Case Q&A autofill — Phase 1 MVP.

Runs the deterministic fast-path SQL engine over a fixed question set per case and
stores each answer with a TRUST STATUS. This is the answer to "how do we know it's
correct": every answer is either grounded in the case's own logs (with sources cited
in the text by _run_fast_path's synth prompt) or honestly marked as having no data —
never an ungrounded guess. See docs/PLAN_CASE_QA_AUTOFILL.md.

Phase 1 uses fast-path ONLY (no ReAct): on a single 20B model ReAct leaks raw
`json{sql}` and is unreliable. Statuses here are therefore just:
  grounded — fast-path returned data + a synthesized, source-cited answer
  no_data  — no rows for that intent in this case's logs (honest)
"""
import hashlib
import json
import logging
import os
import re
import urllib.request
import uuid

import psycopg2

from analysis.chat import _run_fast_path, _FAST_PATH_SQL, PG_DSN, _TOPIC_QUESTIONS
from core.config import QDRANT_URL
from core.model_router import build_chat_payload

_log = logging.getLogger(__name__)

# One canonical question per fast-path intent (reuse _TOPIC_QUESTIONS where defined).
# Order = how it reads in the review/report (overview → specifics → timeline).
CASE_QA_QUESTIONS = [
    ('os_info',          'Коли була встановлена ОС, яка версія та збірка?'),
    ('user_info',        'Які локальні облікові записи є в системі?'),
    ('shutdown',         'Коли система вимикалась/перезавантажувалась?'),
    ('initial_access',   _TOPIC_QUESTIONS.get('initial_access', 'Як відбувся початковий доступ?')),
    ('process_exec',     'Які процеси/програми запускались? Чи були підозрілі exe?'),
    ('persistence',      _TOPIC_QUESTIONS.get('persistence', 'Як закріпився зловмисник?')),
    ('c2',               _TOPIC_QUESTIONS.get('c2', 'Які C2/IP та інструменти remote access використовувались?')),
    ('credential',       'Чи були ознаки крадіжки облікових даних? (lsass, mimikatz, procdump)'),
    ('lateral_movement', _TOPIC_QUESTIONS.get('lateral_movement', 'Чи був lateral movement / нові облікові записи?')),
    ('defender',         _TOPIC_QUESTIONS.get('defender', 'Чи виявив Defender загрозу? Яка назва?')),
    ('exfiltration',     _TOPIC_QUESTIONS.get('exfiltration', 'Чи були ознаки ексфільтрації даних? (7za, архіви)')),
    ('tampering',        'Чи очищались або змінювались журнали подій? (anti-forensics)'),
    ('browser',          'Що завантажувалось через браузер і які сайти відвідувались?'),
    ('file_ops',         'Які файли відкривались або видалялись? (lnk, кошик, recent)'),
    ('usb',              'Чи підключались USB-носії?'),
    ('shellbags',        _TOPIC_QUESTIONS.get('shellbags', 'До яких папок мав доступ зловмисник? (shellbags)')),
    ('timeline',         _TOPIC_QUESTIONS.get('timeline', 'Яка повна хронологія атаки від початку до кінця?')),
]


def _ensure_case_qa_table():
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS dfir_case_qa_v1 (
                  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                  case_key TEXT NOT NULL,
                  intent TEXT,
                  question TEXT NOT NULL,
                  answer TEXT,
                  status TEXT NOT NULL,
                  confidence FLOAT DEFAULT 0,
                  reviewed BOOLEAN DEFAULT FALSE,
                  review_verdict TEXT,
                  run_id UUID,
                  created_at TIMESTAMPTZ DEFAULT NOW(),
                  updated_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_case_qa ON dfir_case_qa_v1(case_key, question)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_case_qa_case ON dfir_case_qa_v1(case_key)")
            cur.execute("ALTER TABLE dfir_case_qa_v1 ADD COLUMN IF NOT EXISTS fastpath_ver TEXT")


_FASTPATH_VER_CACHE = None


def _fastpath_version():
    """Short stable hash of _FAST_PATH_SQL. Changes whenever the fast-path queries change,
    so stored fast-path answers carrying an older hash are treated as stale by
    case_qa_lookup and lazily recomputed from logs. Cached per process."""
    global _FASTPATH_VER_CACHE
    if _FASTPATH_VER_CACHE is None:
        try:
            blob = json.dumps(_FAST_PATH_SQL, sort_keys=True, default=str)
        except Exception:
            blob = repr(_FAST_PATH_SQL)
        blob += '|cellfmt:2026-10-02'  # _det_cell: whole lines + CP866 mojibake repair
        _FASTPATH_VER_CACHE = hashlib.sha1(blob.encode('utf-8')).hexdigest()[:12]
    return _FASTPATH_VER_CACHE


def _collapse_loop(a, min_rep=8, max_period=6):
    """Cut a run where the same 1..6 words repeat >= min_rep times in a row. Linear in the
    number of words - a backtracking regex for this took minutes on long answers."""
    words = a.split(' ')
    n = len(words)
    norm = [w.strip(',;') for w in words]
    for i in range(n):
        for p in range(1, max_period + 1):
            if i + p * min_rep > n or not any(ch.isalnum() for ch in ''.join(norm[i:i + p])):
                continue
            k = 1
            while i + (k + 1) * p <= n and norm[i + k * p:i + (k + 1) * p] == norm[i:i + p]:
                k += 1
            if k >= min_rep:
                return ' '.join(words[:i + p]) + ' … ' + ' '.join(words[i + k * p:]), True
    return a, False


def _degenerate(answer):
    """(clean_answer, reason|None). A model that runs out of tokens stops mid-sentence
    («Висновок: У наданих»); one stuck in a loop prints «5010, 5012, 5010, 5012…» until the
    limit (case_50, 2026-10-02). Both were stored as grounded and printed in the report."""
    a = str(answer or '')
    reason = None
    a, looped = _collapse_loop(a)
    if looped:
        reason = 'зациклення генерації'
    t = a.rstrip()
    # only free-text LLM answers (they close with a «Висновок» block) can be cut off; the
    # deterministic fast-path answers also open with «##» but legitimately end with a raw
    # log field («...local group»), so the heading is no sign of free text
    # ...and only when the answer ENDS inside that block: after the conclusion the seeds append
    # deterministic IOC lists («... rdpwinst.exe, rdpwrap») that rightly have no full stop
    _concl = t.rsplit('**Висновок', 1)[1] if '**Висновок' in t else ''
    llm_like = bool(_concl) and '\n\n' not in _concl.strip() and '•' not in _concl
    if llm_like and re.search(r'[A-Za-zА-Яа-яІіЇїЄєҐґ0-9]$', t) and not re.search(r'[.!?»)`|*:]\s*$', t):
        tail = t.rsplit('\n', 1)[-1]
        if len(tail) < 400:
            reason = reason or 'обрив генерації'
    return a, reason


def _upsert(case_key, intent, question, answer, status, conf, run_id):
    answer, _bad = _degenerate(answer)
    if _bad and status == 'grounded':
        status = 'no_data'
        answer = (answer or '').rstrip() + '\n\n⟨Відповідь не завершена (%s); не використовувати як висновок.⟩' % _bad
        conf = min(float(conf or 0), 0.2)
    fpv = _fastpath_version()
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO dfir_case_qa_v1 (case_key, intent, question, answer, status, confidence, run_id, fastpath_ver)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (case_key, question) DO UPDATE SET
                  intent=EXCLUDED.intent, answer=EXCLUDED.answer, status=EXCLUDED.status,
                  confidence=EXCLUDED.confidence, run_id=EXCLUDED.run_id,
                  fastpath_ver=EXCLUDED.fastpath_ver, updated_at=NOW()
            """, (case_key, intent, question, answer, status, conf, run_id, fpv))


def _is_no_data_answer(ans):
    """True if the answer is essentially 'no evidence found' (so it must NOT be stored as a
    confirmed/grounded finding). A real finding cites a timestamp or an evidence table row."""
    if not ans or not str(ans).strip():
        return True
    a = str(ans).lower()
    _NEG = ('немає жодного', 'не знайдено', 'не зустріч', 'не виявлено',
            'відсутн', 'немає запис', 'немає даних', 'жодного запису',
            'не містить', 'не вдалося знайти', 'no record', 'not found',
            'не задокументован', 'немає доказ', 'не зафіксовано', 'неможливо підтвердити',
            'не можна визначити', 'неможливо визначити', 'немає жодних', 'не підтверджується')
    # An answer that OPENS with a denial is a no-data answer even when a date follows:
    # «У зібраних логах є лише запис 2026-08-29 ... немає жодного артефакту про Mega.nz»
    # used to count as grounded because of the date, and 30 such threads filled a report.
    head = re.split(r'(?<=[.!?])\s+', a.strip(), maxsplit=1)[0][:220]
    if any(p in head for p in _NEG) and not re.search(r'(evtx|\.csv|\.pf|\$mft|\$j|event_logs_v2|filesystem_v2|program_exec_v2|eid\s*\d{3,4})', head):
        return True
    neg = any(p in a for p in _NEG)
    has_evidence = bool(re.search(r'\d{4}-\d{2}-\d{2}', a)) or a.count('|') > 6
    return neg and not has_evidence


def _norm_q(q):
    return re.sub(r'\s+', ' ', (q or '').strip().lower())


# слова без змісту для порівняння питань (укр. службові + типові DFIR-филери)
_Q_STOPWORDS = {'які', 'який', 'яка', 'яке', 'саме', 'було', 'були', 'була', 'чи', 'для',
                'під', 'час', 'або', 'та', 'і', 'що', 'як', 'перед', 'після', 'їх',
                'допомогою', 'наприклад', 'конкретні', 'конкретно', 'будь-яких', 'цього',
                'атаки', 'під час', 'зафіксовано', 'наявні', 'вказує', 'можна'}


def _q_tokens(q):
    return {w for w in re.findall(r"[a-zа-яіїєґ0-9_.\\'-]{3,}", (q or '').lower())
            if w not in _Q_STOPWORDS}


def _is_dup_q(q, asked):
    """Near-duplicate check проти вже поставлених питань: LLM у deep-раундах любить
    перефразовувати те саме («Які файли архівовані 7za перед експортом?» ×6 у case_58).
    Токени матчаться по 8-символьному префіксу (грубий укр. стеммінг: використовувався/
    використовувалися -> використ) або включенню (порт ⊂ порти). Дублікат = containment
    >=0.75 або Jaccard >=0.55."""
    qt = _q_tokens(q)
    if len(qt) < 2:
        return False

    def _tok_match(t1, t2):
        return t1[:8] == t2[:8] or (len(t1) >= 4 and len(t2) >= 4 and (t1 in t2 or t2 in t1))

    for a in asked:
        at = _q_tokens(a)
        if len(at) < 2:
            continue
        inter = sum(1 for t in qt if any(_tok_match(t, u) for u in at))
        containment = inter / min(len(qt), len(at))
        jaccard = inter / max(1, len(qt | at))
        if containment >= 0.75 or jaccard >= 0.55:
            return True
    return False


# Questions that investigate US, not the case. Six cases carried at least one: the
# collector's own staging folder, the examiner's working drive, the parser output whose
# CSV name was read as a LNK file, the moment of collection itself, and cloud services the
# data never mentions but the model likes to name. (FIX_QUEUE №3.)
_QA_STOPLIST_RX = re.compile(
    r'kape|dfirtriage|dfir_triage|dfircollector|dfir_collector|vao_collector|vao_triage|'
    r'magnetram|magnet ram|dumpit|winpmem|accessdata|ftk imager|eztools|'
    r'_lecmd_output|_pecmd_output|_jlecmd_output|_evtxecmd_output|_amcacheparser|'
    r'_mftecmd|_recmd_output|_srumecmd|_rbcmd|_sbecmd|hayabusa|deepbluecli|'
    r'e:\\work|kape\\input|\\kape\\|тек[аиі] експерт|шлях[уи]? експерт|'
    r'момент(?:у|і)? (?:збор|знімання|вилученн)|під час збор(?:у|ання)|'
    r'дат[аиі] збор|запуск(?:у|і)? збирача', re.I)

# A question about network traffic, exfiltration volumes or browsing is only worth asking
# when the case actually has a table that could answer it. Six of case_49's questions —
# and four other cases — asked about outbound traffic on archives with no SRUM and no
# browser history at all, and every answer was «даних немає».
_NET_Q_RX = re.compile(
    r'мереж|трафік|вивед(?:ено|ення)|ексфільтрац|вивант|передан(?:о|ня) назовні|'
    r'srum|браузер|browser|історі[яї] відвідув|завантаж(?:ення|ував)[^?]{0,20}з інтернет|'
    r'c2|командн(?:ий|ого) сервер|domain|домен(?:у|и)? підключ', re.I)

_NET_TABLE_CACHE = {}


def _case_has_network_tables(case_key):
    """True when srum_v2 or a browser table holds at least one row for this case."""
    if case_key in _NET_TABLE_CACHE:
        return _NET_TABLE_CACHE[case_key]
    ok = False
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            with c.cursor() as cur:
                cur.execute("SET statement_timeout='8000'")
                for t in ('srum_v2', 'browser_provenance_v1', 'browser_history_v2'):
                    try:
                        cur.execute("SELECT 1 FROM " + t + " WHERE case_key=%s LIMIT 1", (case_key,))
                        if cur.fetchone():
                            ok = True
                            break
                    except Exception:
                        try: c.rollback()
                        except Exception: pass
    except Exception:
        ok = False
    _NET_TABLE_CACHE[case_key] = ok
    return ok


def _qa_question_allowed(case_key, q):
    """(ok, reason) — the two rules a self-generated question must pass before it is asked."""
    s = str(q or '')
    if _QA_STOPLIST_RX.search(s):
        return False, 'стоп-лист (наш інструментарій / шлях експерта / момент збору)'
    if _NET_Q_RX.search(s) and not _case_has_network_tables(case_key):
        return False, 'мережеве питання без жодної мережевої таблиці в кейсі'
    return True, ''


_ENTITY_TOKEN_RX = re.compile(r"[A-Za-z][A-Za-z0-9_.\\:\-]{2,}|[0-9]{3,}[A-Za-z0-9_.\-]*")
_ENTITY_STOP = {'eid', 'usb', 'rdp', 'smb', 'dns', 'http', 'https', 'post', 'get', 'exe', 'dll', 'ps1', 'evtx',
                'csv', 'log', 'logs', 'ip', 'url', 'llm', 'sam', 'system', 'security', 'windows', 'microsoft',
                'defender', 'powershell', 'cmd', 'lsass', 'mimikatz', 'procdump', 'psexec', 'wmic', 'net',
                'prefetch', 'amcache', 'shimcache', 'mft', 'lnk', 'shellbags', 'srum', 'recent', 'type', 'logon',
                # folders every Windows machine has: naming them proves nothing about the case
                'config', 'system32', 'syswow64', 'temp', 'users', 'public', 'programdata', 'appdata', 'local',
                'roaming', 'desktop', 'downloads', 'documents', 'tasks', 'program', 'files', 'startup', 'run',
                'runonce', 'currentversion', 'software', 'services', 'hklm', 'hkcu', 'schtasks', 'powershell.exe',
                'cmd.exe', 'explorer.exe', 'svchost.exe', 'rundll32.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe'}


def _verdict_entities(case_key):
    """Names the deterministic layer proved for this case (task names, files, GPO GUIDs,
    paths, services, hosts) — the only things a self-generated question may be built on."""
    ents = set()
    try:
        from analysis.threat_detect import detect_threats
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            for f in (detect_threats(case_key, conn) or []):
                if f.get('severity') not in ('critical', 'high', 'medium'):
                    continue
                for i in (f.get('iocs') or []):
                    if isinstance(i, dict) and i.get('value'):
                        v = str(i['value']).lower()
                        ents.add(v)
                        ents.add(v.rsplit(chr(92), 1)[-1])
                for e in (f.get('events') or []):
                    if isinstance(e, dict):
                        # a 'presence' event is a file stamp: it says the binary was on the
                        # disk, not that anything happened. Anchoring a question on one is
                        # how «початковий доступ» got answered with a 2017 PE stamp and a
                        # 2020 Defender definition day in four cases (FIX_QUEUE №3/№7).
                        if str(e.get('kind') or '').lower() == 'presence':
                            continue
                        for t in _ENTITY_TOKEN_RX.findall(str(e.get('label', ''))):
                            ents.add(t.lower())
                for s in (f.get('samples') or []):
                    for t in _ENTITY_TOKEN_RX.findall(str(s)):
                        ents.add(t.lower())
    except Exception as e:
        _log.error(f"[case_qa] verdict entities: {repr(e)[:120]}")
    return {x for x in ents if len(x) >= 3}


def _question_is_anchored(q, anchor_text, verdict_ents):
    """A follow-up may only name things the case has already shown: every entity-like
    token in the question (a file, tool, host, domain, GUID — Latin/digit tokens) must
    appear in the grounded answers so far or in the verdict entities. Questions without
    entity tokens (phase questions like «чи очищались журнали?») pass. This is what
    stops the Mega.nz / HackTool / wmiprvse threads that had nothing behind them."""
    toks = []
    for t in _ENTITY_TOKEN_RX.findall(q or ''):
        tl = t.lower().strip('.:-').rstrip(chr(92)).strip('.:-')
        if len(tl) < 3 or tl in _ENTITY_STOP or tl.isdigit() and len(tl) < 4:
            continue
        if chr(92) in tl and tl.rsplit(chr(92), 1)[-1] in _ENTITY_STOP:
            continue  # C:\Windows\System32\config\ - a system folder, not an entity
        if re.fullmatch(r'\d{1,2}[:.]\d{2}([:.]\d{2})?', tl) or re.fullmatch(r'\d{2,4}[-.]\d{2}[-.]\d{2,4}', tl):
            continue  # times/dates are fine
        toks.append(tl)
    if not toks:
        return True
    hay = (anchor_text or '').lower()
    # a question about our own collector / staging folder / probes investigates ourselves
    try:
        from analysis.own_footprint import is_own as _own
        if any(_own(t) for t in toks):
            return False
    except Exception:
        pass
    for tl in toks:
        base = tl.rsplit(chr(92), 1)[-1]
        if tl in hay or base in hay or tl in verdict_ents or base in verdict_ents:
            continue
        # a token that is a prefix of a known entity («vao_collector» vs full name) also counts
        if any(base[:12] and (base[:12] in v) for v in verdict_ents if len(base) >= 8):
            continue
        return False
    return True


def _generate_followups(case_key, answered, intents, asked, model, llm_url, remaining, synth_model=None):
    """Ask the LLM for the next most valuable follow-up ('наводящі') questions to complete
    the incident picture. Each is tagged with a known fast-path intent so the answer stays
    grounded in real log SQL. Returns list[(intent, question)]; [] when the picture is complete."""
    if remaining <= 0:
        return []
    digest = '\n'.join(f"[{i}] {q}\n  -> {(a or '')[:280]}" for (i, q, a) in answered)[:6000]
    intents_str = ', '.join(intents)
    _vents = _verdict_entities(case_key)
    _vents_line = ''
    if _vents:
        _vlist = sorted(v for v in _vents if 4 <= len(v) <= 60)[:40]
        _vents_line = ("СУТНОСТІ, ДОВЕДЕНІ ДЕТЕРМІНОВАНО (питання стосуються ТІЛЬКИ їх або незакритих фаз; "
                       "не вигадуй нових файлів/сервісів/доменів, яких тут і у відповідях немає): "
                       + ', '.join(_vlist) + ". ")
    sysmsg = ("Ти провідний DFIR-аналітик. Нижче - Q&A, які бот уже зібрав З ЛОГІВ кейсу. "
              "Постав НАСТУПНІ найцінніші НАВОДЯЩІ питання, щоб ДОБУДУВАТИ ПОВНУ картину інциденту "
              "(як проник, що робив, чим закріпився, що вкрав/вивів, повна хронологія, наслідки). Спершу подумай, ЯКІ ЛАНКИ ланцюга атаки ще НЕ закриті наявними відповідями, і став питання САМЕ на ці прогалини. "
              "Питання мають бути КОНКРЕТНІ й такі, що відповідаються з логів - не загальні. "
              + _vents_line +
              "УСІ ПИТАННЯ ПИШИ ВИКЛЮЧНО УКРАЇНСЬКОЮ МОВОЮ. "
              "НЕ повторюй уже поставлені. Кожне питання познач міткою intent РІВНО з цього списку "
              f"(інакше воно буде відкинуте): {intents_str}. "
              "Якщо картина вже повна і нових ЦІННИХ питань немає - поверни порожній список і complete=true. "
              f"Поверни не більше {remaining} питань. "
              'Відповідай ТІЛЬКИ JSON: {"questions":[{"intent":"...","question":"..."}],"complete":true/false}')
    # НЕ обрізати список поставлених до 2000 (~20 питань): LLM не бачив хвіст і
    # генерував ті самі питання знову — корінь 6× дублікатів 7za у case_58
    user = "[ЗІБРАНО ДОСІ]\n" + digest + "\n\n[УЖЕ ПОСТАВЛЕНІ]\n" + ('\n'.join(sorted(asked))[:8000])
    raw = _llm_json_raw(synth_model or model, llm_url, sysmsg, user, max_tokens=6000, temperature=0.3)
    if not raw:
        return []
    data = _parse_json_obj(raw)
    out = []
    _anchor_txt = digest + ' ' + ' '.join(sorted(_vents))
    _rejected = 0
    for item in (data.get('questions') or []):
        if not isinstance(item, dict):
            continue
        it = str(item.get('intent', '')).strip()
        q = str(item.get('question', '')).strip()
        if q and it in intents and _norm_q(q) not in asked and not _is_dup_q(q, asked):
            _ok, _why = _qa_question_allowed(case_key, q)
            if not _ok:
                _rejected += 1
                _log.error(f"[case_qa deep] {case_key}: dropped question — {_why}")
                continue
            if not _question_is_anchored(q, _anchor_txt, _vents):
                _rejected += 1
                continue
            out.append((it, q))
            asked = set(asked) | {_norm_q(q)}  # локальна копія: дедуп і в межах одного батчу
    if _rejected:
        _log.error(f"[case_qa deep] {case_key}: rejected {_rejected} follow-ups naming things the case never showed")
    return out[:remaining]


def _gap_probes(case_key):
    """Report-crosscheck gaps (facts in the expert report the QA missed) -> targeted probes,
    each routed to a fast-path intent so the deep pass can dig them out of the logs."""
    from analysis.chat import _detect_question_topic
    out = []
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""SELECT suggested_probe FROM dfir_self_eval_gaps_v1
                               WHERE case_key=%s AND gap_type='report_crosscheck'
                                 AND suggested_probe IS NOT NULL AND length(suggested_probe) > 10
                               ORDER BY severity DESC""", (case_key,))
                rows = cur.fetchall()
        for (probe,) in rows:
            it = _detect_question_topic(probe) or ''
            if it in _FAST_PATH_SQL:
                out.append((it, probe.strip()))
    except Exception as e:
        _log.error(f"[case_qa] gap_probes error: {repr(e)[:140]}")
    return out


# sentinel run_id marking rows seeded from the deterministic DFIR report (not an LLM run)
REPORT_SEED_RUN_ID = '00000000-0000-4000-8000-0000000feed1'


def seed_qa_from_report(case_key):
    """DFIR-аналіз «сідить» Q&A: write the report's DETERMINISTIC findings into
    dfir_case_qa_v1 under the canonical questions, so run_case_qa reuses them
    instead of re-deriving the same facts. No LLM — pure SQL/reshape sources:
      initial_access <- scored infection-point chain (reports.reshape),
      c2             <- case_iocs roll-up (domains/IPs/RAT tools),
      defender       <- malware names from Defender detections (case_iocs),
      tampering      <- red-combo / anti-forensics detections (threat_detect).
    Returns the number of seeded answers."""
    _ensure_case_qa_table()
    # FRESH_SEEDS_CLEAR: wipe this case's previous report-seeds so a re-run rebuilds
    # ONLY from CURRENT deterministic findings. Without this, a fixed detector (e.g.
    # the anti-forensics 4907 FP) left a stale '18780 anti-forensics [high]' seed that
    # kept leaking into the LLM narrative on every re-run. Human-verified findings live
    # in dfir_case_verified_findings and are NOT touched.
    try:
        with psycopg2.connect(PG_DSN) as _sc_c:
            _sc_c.autocommit = True
            with _sc_c.cursor() as _sc_cu:
                _sc_cu.execute('DELETE FROM dfir_case_qa_v1 WHERE case_key=%s AND run_id=%s',
                               (case_key, REPORT_SEED_RUN_ID))
    except Exception:
        pass
    seeded = 0
    q_by_intent = {i: q for (i, q) in CASE_QA_QUESTIONS}

    def _seed(intent, answer, conf=0.9):
        nonlocal seeded
        q = q_by_intent.get(intent)
        if not q or not answer or len(str(answer).strip()) < 30:
            return
        _upsert(case_key, intent, q, str(answer).strip()[:4000], 'grounded', conf, REPORT_SEED_RUN_ID)
        seeded += 1

    # initial access: the same deterministic chain the report's 🎯 section renders
    try:
        from reports.reshape import _initial_access, _incident_window
        _lines = _initial_access(case_key, _incident_window(case_key)[0]) or []
        _txt = '\n'.join(_lines)
        if 'не вдалося однозначно встановити' not in _txt:
            _seed('initial_access', _txt, 0.9)
    except Exception as e:
        _log.error(f"[qa seed] initial_access: {repr(e)[:120]}")

    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # c2 / remote access: curated IOCs (deterministic extractor output)
                cur.execute("""SELECT ioc_type, ioc_value FROM case_iocs WHERE case_key=%s
                               AND ioc_type IN ('public_ip','domain','url','tool_name','anydesk_id')
                               AND coalesce(source_table,'') NOT IN ('report_llm','qa_analysis','timeline_analysis','ps_c2','browser_provenance/infra')
                               AND NOT (ioc_type='tool_name' AND lower(ioc_value) ~ '^(7za|7z|7zr|kape|gkape|dumpit|ftkimager|magnet|autoruns|procexp|cports|winpmem|belkasoft|vao_|dfir_collector|mftecmd|pecmd|evtxecmd|recmd|hayabusa|thor|loki)')
                               ORDER BY ioc_type LIMIT 40""", (case_key,))
                rows = cur.fetchall()
                if rows:
                    _lbl = {'public_ip': 'IP', 'domain': 'Домен', 'url': 'URL',
                            'tool_name': 'Інструмент', 'anydesk_id': 'AnyDesk ID'}
                    _seed('c2', 'Куровані індикатори кейсу (детермінований екстрактор):\n' +
                          '\n'.join('• %s: %s' % (_lbl.get(t, t), v) for t, v in rows), 0.85)
                # defender: malware names straight from Defender detections
                cur.execute("""SELECT DISTINCT ioc_value FROM case_iocs WHERE case_key=%s
                               AND ioc_type='malware_name' LIMIT 12""", (case_key,))
                mals = [r[0] for r in cur.fetchall() if r[0]]
                if mals:
                    _seed('defender', 'Так, Windows Defender зафіксував загрози (EID 1116/1117): ' +
                          ', '.join(mals) + '.', 0.9)
            # tampering / red combos: deterministic threat signatures
            from analysis.threat_detect import detect_threats
            _fs = detect_threats(case_key, conn)
            # «Чи очищались журнали?» is a question about 1102 (Security cleared), 104
            # (a System-channel log cleared), wevtutil and fsutil — and about nothing else.
            # It used to be answered with a Defender red-combo or a DeepBlueCLI count of
            # 104 records from operational channels (StateRepository, SmartCard…), which is
            # a false «так, журнали чистили» on four cases. (FIX_QUEUE №16.)
            _AF_RX = re.compile(r'1102|(?<!\d)104(?!\d)|wevtutil|fsutil|clear-?eventlog|'
                                r'очищено журнал|очищення журнал|audit log (was )?cleared', re.I)
            _tmp = [f for f in _fs
                    if f.get('category') == 'Анти-форензика'
                    or _AF_RX.search('%s %s' % (f.get('title') or '', f.get('detail') or ''))]
            if _tmp:
                _seed('tampering', 'Детермінований аналіз виявив анти-форензику:\n' +
                      '\n'.join('• [%s] %s — %s' % (f['severity'], f['title'], f['detail'])
                                for f in _tmp[:6]), 0.9)
            else:
                _seed('tampering', 'Очищення журналів не зафіксовано: подій 1102 (Security), '
                      '104 (System) чи запусків wevtutil/fsutil у доказах немає.', 0.9)
            # VERDICT SEEDS (2026-09-04): the high/critical findings carry events and IOCs
            # (threat_detect.add schema). They answer the attack-framed questions directly,
            # so the LLM fast path never gets to invent «фішинг з EUSignWebInstall» while
            # the SQL layer holds a GPO-delivered wiper. Confidence 0.9 = reuse path.
            try:
                _hi = [f for f in (_fs or []) if f.get('severity') in ('critical', 'high')]
                _hi.sort(key=lambda f: 0 if f.get('severity') == 'critical' else 1)
                # the entry anchor comes from cause-type findings only (page-1 rule): detections,
                # evasion and ransomware are consequences of the intrusion, not its start
                import re as _re_ia
                _CONSEQ_IA = _re_ia.compile(r'очищення журнал|зміна аудиту|antivirus задетектив|детекці|вимкнення windows defender|захист вимик|захисне пз|шифруван|записка з вимогою|wiper', _re_ia.I)
                _CONSEQ_CATS_IA = {'Захист обходили', 'Захист вимикали', 'Анти-форензика', 'Захист (інформаційно)', 'Захист', 'Ransomware', 'Знищення'}
                _hi_cause = [f for f in _hi if str(f.get('category') or '') not in _CONSEQ_CATS_IA
                             and not _CONSEQ_IA.search(str(f.get('title') or ''))] or _hi
                _ev_all = []
                for f in _hi_cause:
                    for e in (f.get('events') or []):
                        if isinstance(e, dict) and e.get('ts') and e.get('kind') != 'presence':
                            _ev_all.append((str(e.get('ts')), str(e.get('label', ''))[:140],
                                            str(e.get('source') or e.get('artifact') or '')[:60], f.get('title', '')))
                _ev_all.sort()
                # incident floor: nothing older than 240 days before the latest anchor
                if _ev_all:
                    try:
                        import datetime as _dt_ia
                        _last = _dt_ia.datetime.fromisoformat(_ev_all[-1][0][:19])
                        _floor = (_last - _dt_ia.timedelta(days=240)).isoformat(sep=' ')
                        _ev_all = [e for e in _ev_all if e[0][:19] >= _floor[:19]] or _ev_all
                    except Exception:
                        pass
                _ioc_all = []
                for f in _hi:
                    for i in (f.get('iocs') or []):
                        if isinstance(i, dict) and i.get('value'):
                            _ioc_all.append((str(i.get('type', '?')), str(i.get('value'))[:160], str(i.get('role', ''))[:80]))
                if _hi and _ev_all:
                    _t0 = _ev_all[0]
                    _seed('initial_access',
                          'Детермінований якір початкового доступу (перша подія головної знахідки «%s»): %s — %s [%s]. '
                          'Вектор доставки встановлено сигнатурою без ШІ; інші версії — лише гіпотези.'
                          % (_t0[3], _t0[0][:16], _t0[1], _t0[2]), 0.9)
                    _seed('timeline',
                          'Хронологія за підтвердженими знахідками (SQL-сигнатури):\n' +
                          '\n'.join('• %s — %s [%s] (%s)' % (t[:16], l, s, ttl) for t, l, s, ttl in _ev_all[:25]), 0.9)
                _pers = [f for f in _hi if str(f.get('category', '')) in ('Закріплення',)
                         or any(str(i.get('type', '')) in ('task', 'service', 'gpo') for i in (f.get('iocs') or []) if isinstance(i, dict))]
                if _pers:
                    _seed('persistence', 'Закріплення / механізм запуску за підтвердженими знахідками:\n' +
                          '\n'.join('• [%s] %s — %s' % (f['severity'], f['title'], str(f.get('detail', ''))[:300]) for f in _pers[:4])
                          + ('\nIOC: ' + '; '.join('%s: %s' % (t, v) for t, v, _r in _ioc_all if t in ('task', 'service', 'gpo', 'path', 'file'))[:800]
                             if _ioc_all else ''), 0.9)
                _av = [f for f in (_fs or []) if str(f.get('category', '')) == 'Захист' or 'Захисне ПЗ' in str(f.get('title', ''))]
                if _av:
                    _seed('defender', ('Стан захисного ПЗ за детермінованими даними:\n' +
                          '\n'.join('• [%s] %s — %s' % (f['severity'], f['title'], str(f.get('detail', ''))[:300]) for f in _av[:3])
                          + ('\nDefender-детекції: ' + ', '.join(mals) if mals else '')), 0.9)
                # what the SQL layer did NOT find must not become an LLM story either
                _cats = {str(f.get('category', '')) for f in _hi}
                if not any('Латеральн' in c or 'Кред' in c or 'Доступ до кред' in c for c in _cats):
                    _seed('lateral_movement',
                          'Підтверджених ознак латерального руху немає: сигнатури 5140/5145/4769/явні облікові дані '
                          'спрацювали лише на рівні medium або не спрацювали. Події 4648/4624 від машинного акаунта '
                          '(ім\'я з «$») — фонова робота служб і завдань, НЕ латеральний рух.', 0.88)
                    _seed('credential',
                          'Підтверджених ознак крадіжки облікових даних (lsass/mimikatz/procdump) немає. '
                          'Хеші локальних акаунтів у звіті відновив сам бот офлайн із SAM/SYSTEM (impacket-secretsdump '
                          'в алертах) — це не дія зловмисника.', 0.88)
                if not any('Ексфільтр' in c or 'Збір' in c for c in _cats):
                    try:
                        from analysis.own_footprint import own_started_at as _osa
                        _st = _osa(case_key)
                    except Exception:
                        _st = None
                    # an archiver OUTSIDE the collector's folders (case_50: Users\\Public\\Documents\\7za.exe
                    # next to ngrok) is the attacker's staging, and the seed must not wave it off
                    _arch = []
                    try:
                        from analysis.own_footprint import sql_not_own as _sno
                        with psycopg2.connect(PG_DSN) as _ac:
                            with _ac.cursor() as _acur:
                                _acur.execute("""SELECT DISTINCT coalesce(full_path, executable_name), min(event_ts)
                                                 FROM program_exec_v2 WHERE case_key=%s
                                                  AND lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) ~ '(^|[\\\\/ ])(7za?|7zg|rar|winrar|7zfm)\\.exe'
                                                  AND lower(coalesce(full_path,'')) !~ 'program files|dfirtriage|kape'
                                                  AND """ + _sno("coalesce(full_path,'')||' '||coalesce(executable_name,'')") + """
                                                  AND (%s IS NULL OR event_ts < %s)
                                                 GROUP BY 1 ORDER BY 2 LIMIT 5""", (case_key, _st, _st))
                                _arch = [r for r in _acur.fetchall() if r and r[0]]
                    except Exception:
                        _arch = []
                    if _arch:
                        _seed('exfiltration',
                              'Архіватор поза теками засобу збору: ' +
                              '; '.join('%s (%s)' % (a[0], str(a[1])[:16]) for a in _arch) +
                              ' — можлива підготовка даних до вивантаження; підтвердженої ексфільтрації сигнатури не встановили, '
                              'перевірити обсяги відправлених даних (SRUM) і що архівувалось.', 0.88)
                    else:
                        _seed('exfiltration',
                              'Підтверджених ознак ексфільтрації/архівації зловмисником немає.' +
                              (' 7za.exe/KAPE.EXE/dfp_*.ps1 у Temp\\DFIRTriage_* після %s — це наш збирач vao_collector, '
                               'а не збір даних атакувальником.' % str(_st)[:16] if _st else ''), 0.88)
            except Exception as _vse:
                _log.error(f"[qa seed] verdict seeds: {repr(_vse)[:140]}")
            # CLEAN_CASE_CALM_SEEDS: when NO high/critical deterministic finding
            # exists, pre-answer the attack-framed questions with a grounded
            # 'no attacker evidence' line so run_case_qa reuses it instead of letting
            # the LLM invent an attacker from benign medium events (new services /
            # EID 4648) — the case_49 23_07 leak. Confidence >=0.85 so the reuse
            # path (_fresh_report_seed) actually picks it up.
            try:
                _has_hi_qa = any(f.get('severity') in ('critical', 'high') for f in (_fs or []))
                if not _has_hi_qa:
                    _calm = ('Прямих ознак дій зловмисника за цим напрямом автоматичний '
                             'аналіз НЕ виявив — підтверджених high/critical загроз немає. '
                             'Наявні події (нові служби, логони, EID 4648 тощо) — типово '
                             'звичайна системна/адміністративна активність, а не доведена '
                             'атака. Рекомендована ручна перевірка, але автоматика атаку не підтвердила.')
                    for _ci in ('initial_access', 'persistence', 'c2', 'credential',
                                'lateral_movement', 'exfiltration', 'tampering'):
                        _seed(_ci, _calm, 0.85)
            except Exception:
                pass
    except Exception as e:
        _log.error(f"[qa seed] sql: {repr(e)[:140]}")
    _log.error(f"[qa seed] {case_key}: seeded {seeded} report-grounded answers")
    return seeded


def _fresh_report_seed(case_key, question):
    """Answer text if this question already has a FRESH report-seeded grounded answer
    (<=14 days old) — run_case_qa reuses it instead of recomputing."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""SELECT answer FROM dfir_case_qa_v1
                               WHERE case_key=%s AND question=%s AND status='grounded'
                                 AND run_id=%s AND confidence >= 0.85
                                 AND updated_at > NOW() - interval '14 days'
                                 AND length(coalesce(answer,'')) > 30""",
                            (case_key, question, REPORT_SEED_RUN_ID))
                r = cur.fetchone()
                return r[0] if r else None
    except Exception:
        return None


def run_case_qa(case_key, model, llm_url, progress_cb=None, deep=True, max_total=40, synth_model=None):
    """Collect the case's Q&A and store with a trust status. DEEP mode (default): after the
    canonical question set, the LLM dynamically generates follow-up ('наводящі') questions in
    rounds until the incident picture is complete or `max_total` questions are reached, so the
    bot builds the FULL story, not just the fixed checklist. Every grounded answer is also
    seeded into the semantic chat cache (dfir_qa_cache_v1) so future similar user questions
    reuse it instead of recomputing. Idempotent (upsert per question).
    `progress_cb(done, total, intent)` optional. Returns a summary dict."""
    _ensure_case_qa_table()
    run_id = str(uuid.uuid4())
    base = [(i, q) for (i, q) in CASE_QA_QUESTIONS if i in _FAST_PATH_SQL]
    base_set = set(base)
    # self-generated follow-ups are capped (default 10): 30 of them once filled a report
    # with Mega.nz / USB / HackTool threads the case never contained
    try:
        _fu_cap = max(0, int(os.environ.get('DFIR_QA_MAX_FOLLOWUPS', '10') or 10))
    except Exception:
        _fu_cap = 10
    max_total = min(int(max_total or 40), len(base) + _fu_cap)
    fp_intents = list(_FAST_PATH_SQL.keys())
    try:
        from analysis.qa_cache import _qa_cache_save as _seed_cache
    except Exception:
        _seed_cache = None

    asked = set()
    answered = []
    grounded = no_data = 0
    done = 0
    rounds = 0
    gaps_injected = False
    queue = list(base)

    # PARALLEL answering (was strictly sequential = ~25 min/case): the heavy SQL of
    # different questions overlaps; LLM synth calls still serialize on the global
    # cross-process LLM queue, so wall-clock ≈ sum(LLM) + max(SQL) instead of
    # sum(LLM + SQL). Deep rounds stay sequential (follow-ups need prior answers).
    import concurrent.futures as _cf
    _par = max(1, int(os.environ.get('DFIR_QA_PARALLEL', '3') or 3))

    def _answer_one(intent, question):
        # report already answered this deterministically -> reuse, don't recompute
        _seeded = _fresh_report_seed(case_key, question)
        if _seeded:
            return intent, question, _seeded, True
        try:
            return intent, question, _run_fast_path(case_key, question, intent, model, llm_url), False
        except Exception as e:
            _log.error(f"[case_qa] {intent} error: {repr(e)[:140]}")
            return intent, question, None, False

    while queue and len(asked) < max_total:
        batch = []
        while queue and len(asked) < max_total:
            intent, question = queue.pop(0)
            qn = _norm_q(question)
            if qn in asked:
                continue
            asked.add(qn)
            batch.append((intent, question))
        if not batch:
            break
        with _cf.ThreadPoolExecutor(max_workers=_par) as _ex:
            _futs = [_ex.submit(_answer_one, i, q) for i, q in batch]
            for _fut in _cf.as_completed(_futs):
                intent, question, answer, from_seed = _fut.result()
                is_followup = (intent, question) not in base_set
                if from_seed:
                    grounded += 1
                    answered.append((intent, question, answer))
                    done += 1
                    if progress_cb:
                        try:
                            progress_cb(done, max(len(asked) + len(queue), done), intent + ' ♻')
                        except Exception:
                            pass
                    continue
                if answer and not _is_no_data_answer(answer):
                    status, conf = 'grounded', 0.6
                    grounded += 1
                    answered.append((intent, question, answer))
                    if _seed_cache:
                        try:
                            _seed_cache(case_key, question, answer, source='deep_qa', confidence=0.85)
                        except Exception:
                            pass
                else:
                    status, conf = 'no_data', 0.0
                    no_data += 1
                _upsert(case_key, intent, question, answer, status, conf, run_id)
                done += 1
                if progress_cb:
                    lbl = ('\U0001F9E0 ' + intent) if is_followup else intent
                    try:
                        progress_cb(done, max(len(asked) + len(queue), done), lbl)
                    except Exception:
                        pass
        # deepening: first dig out the report-crosscheck GAPS (priority), then let the LLM
        # generate further follow-ups until the picture is complete or max_total is hit.
        if deep and len(asked) < max_total:
            added = 0
            if not gaps_injected:
                gaps_injected = True
                for (gi, gq) in _gap_probes(case_key):
                    if _norm_q(gq) not in asked:
                        queue.append((gi, gq)); added += 1
                if added:
                    _log.error(f"[case_qa deep] injected {added} report-gap probes")
            if added == 0 and rounds < 6:
                rounds += 1
                try:
                    follow = _generate_followups(case_key, answered, fp_intents, asked,
                                                 model, llm_url, remaining=max_total - len(asked),
                                                 synth_model=synth_model)
                except Exception as e:
                    _log.error(f"[case_qa deep] gen error: {repr(e)[:140]}")
                    follow = []
                for (fi, fq) in follow:
                    if _norm_q(fq) in asked or _is_dup_q(fq, asked):
                        continue
                    # не палимо бюджет питань на переораний intent (у case_58
                    # exfiltration зʼїв 6 follow-up про той самий 7za-архів)
                    if sum(1 for (ai, _aq, _aa) in answered if ai == fi) >= 6:
                        continue
                    queue.append((fi, fq))
            if not queue:
                break  # gaps dug + LLM signalled complete
        elif not deep:
            break
    _log.error(f"[case_qa] {case_key} done: grounded={grounded} no_data={no_data} "
               f"total={len(asked)} rounds={rounds} parallel={_par}")
    # EVERY-ANALYSIS IOC growth: harvest indicators from ALL grounded answers (batch,
    # ONE overlap recompute) — grounded answers cite real log evidence, so this is safe.
    try:
        _txt = '\n'.join((a or '') for (_i, _q, a) in answered if a)
        if _txt.strip():
            from app import enrich_case_iocs_from_analysis as _enrich
            _enrich(case_key, _txt, 'qa_analysis', confidence=0.6, recompute=True)
    except Exception as _e_en:
        _log.warning(f"[case_qa] ioc enrich skip: {repr(_e_en)[:120]}")
    return {'case_key': case_key, 'run_id': run_id, 'total': len(asked),
            'grounded': grounded, 'no_data': no_data, 'deep_rounds': rounds}


def _fetch_report_text(case_key, max_chars=8000):
    """Concatenate the expert report chunks for the case from kb_reports (ordered)."""
    body = json.dumps({'limit': 300, 'with_payload': True, 'with_vector': False,
                       'filter': {'must': [{'key': 'case_key', 'match': {'value': case_key}}]}}).encode()
    try:
        req = urllib.request.Request(QDRANT_URL.rstrip('/') + '/collections/kb_reports/points/scroll',
                                     data=body, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=15) as r:
            pts = json.loads(r.read()).get('result', {}).get('points', [])
    except Exception as e:
        _log.error(f"[case_qa xcheck] kb_reports fetch error: {repr(e)[:120]}")
        return ''
    pts.sort(key=lambda p: (p.get('payload', {}).get('page_num') or 0,
                            p.get('payload', {}).get('chunk_index') or 0))
    txt = '\n'.join(str(p.get('payload', {}).get('text') or '') for p in pts)
    return txt[:max_chars]


def _strip_think(x):
    """Remove reasoning-model chain-of-thought (<think>...</think>), harmony channel
    tokens, and any leading unclosed think block, so reasoner-31b output never leaks CoT."""
    if not x:
        return x
    x = re.sub(r'(?is)<think>.*?</think>', '', x)
    x = re.sub(r'(?is)<\|[^>]*\|>', '', x)
    x = re.sub(r'(?is)^\s*<think>.*', '', x)
    return x.strip()


def _llm_json_raw(model, llm_url, sysmsg, user, max_tokens=6000, temperature=0.2, tries=3):
    """POST a chat completion (fast role) and return message content, RETRYING while it comes
    back empty. gpt-oss reasoning models can burn the whole token budget on the (separate)
    reasoning channel and emit empty content (finish_reason='length'); a retry usually lands a
    shorter reasoning pass. Generous max_tokens + retries make structured-JSON calls reliable.
    Returns '' only after all attempts fail."""
    for _attempt in range(max(1, tries)):
        try:
            body = json.dumps(build_chat_payload(
                model=model, messages=[{'role': 'system', 'content': sysmsg},
                                        {'role': 'user', 'content': user}],
                role='fast', temperature=temperature, max_tokens=max_tokens, stream=False,
                reasoning_effort='low',
            )).encode('utf-8')
            req = urllib.request.Request((llm_url if '/chat/completions' in llm_url else llm_url.rstrip('/')+'/v1/chat/completions'), data=body, headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=400) as resp:
                rd = json.loads(resp.read().decode('utf-8', errors='ignore'))
            raw = ((rd.get('choices') or [{}])[0].get('message', {}).get('content') or '').strip()
            raw = _strip_think(raw)
            if raw:
                return raw
            _log.error(f"[case_qa] empty LLM content (attempt {_attempt + 1}/{tries}) - retrying")
        except Exception as e:
            _log.error(f"[case_qa] llm call error (attempt {_attempt + 1}/{tries}): {repr(e)[:140]}")
    return ''


def _parse_json_obj(raw):
    """Defensively extract a JSON object from an LLM reply (strip fences/preamble)."""
    if not raw:
        return {}
    s = re.sub(r'^```[a-zA-Z]*|```$', '', raw.strip(), flags=re.MULTILINE).strip()
    i, j = s.find('{'), s.rfind('}')
    if i == -1 or j == -1 or j < i:
        return {}
    try:
        return json.loads(s[i:j + 1])
    except Exception:
        return {}


def crosscheck_case_qa(case_key, model, llm_url):
    """Cross-check the case's collected Q&A against the uploaded expert report
    (kb_reports). Corroborated answers get a confidence boost; facts present in the
    report but MISSING from the Q&A become gaps + follow-up ("наводящі") questions
    stored in dfir_self_eval_gaps_v1. See docs/PLAN_CASE_QA_AUTOFILL.md §5."""
    report = _fetch_report_text(case_key)
    if not report:
        return {'case_key': case_key, 'error': 'no_report', 'gaps': [], 'corroborated': []}
    qa = [r for r in get_case_qa(case_key) if r['status'] == 'grounded']
    qa_summary = '\n'.join(f"[{r['intent']}] {r['question']}\n  → {(r['answer'] or '')[:400]}" for r in qa)

    sys = ("Ти DFIR-аналітик. Дано (А) фрагмент ЕКСПЕРТНОГО ЗВІТУ по кейсу і (Б) Q&A, які бот "
           "зібрав з логів. Знайди ВАЖЛИВІ факти/події/IOC/файли з (А), яких НЕМАЄ у відповідях "
           "бота (Б). Для кожного gap дай коротке наводяще питання українською, яким бот міг би "
           "дотягнути цей факт з логів. Також у 'corroborated' перелічи ТОЧНІ мітки intent у "
           "квадратних дужках з (Б) (напр. \"c2\",\"os_info\",\"persistence\"), які звіт ПІДТВЕРДЖУЄ — "
           "вживай рівно ці мітки, не вигадуй свої. "
           "Відповідай ТІЛЬКИ JSON без пояснень: "
           '{"corroborated":["intent",...],"gaps":[{"missing_fact":"...","follow_up_question":"...","category":"..."}]}')
    user = f"[А) ЕКСПЕРТНИЙ ЗВІТ]\n{report}\n\n[Б) Q&A БОТА]\n{qa_summary[:6000]}"

    raw = _llm_json_raw(model, llm_url, sys, user, max_tokens=6000, temperature=0.1)
    if not raw:
        return {'case_key': case_key, 'error': 'llm', 'gaps': [], 'corroborated': []}

    data = _parse_json_obj(raw)
    corroborated = [str(x) for x in (data.get('corroborated') or [])]
    gaps = [g for g in (data.get('gaps') or []) if isinstance(g, dict) and g.get('missing_fact')]

    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            # ACCUMULATIVE corroboration: union THIS run's corroborated intents with any
            # intent ALREADY confirmed (prior crosscheck OR user review) so the ✓ status is
            # STICKY and only grows — a noisy run that corroborates fewer intents never erases
            # prior ones. (Crosscheck noise is in recall, not precision.)
            cur.execute("""SELECT DISTINCT intent FROM dfir_case_qa_v1
                           WHERE case_key=%s AND status='grounded' AND confidence>=0.9
                             AND intent IS NOT NULL""", (case_key,))
            _prev = [r[0] for r in cur.fetchall()]
            _union = sorted(set(_prev) | set(c for c in corroborated if c))
            if _union:
                cur.execute("""UPDATE dfir_case_qa_v1 SET confidence=0.6, updated_at=NOW()
                               WHERE case_key=%s AND status='grounded' AND NOT (intent = ANY(%s))
                                 AND (review_verdict='wrong') IS NOT TRUE""",
                            (case_key, _union))
                cur.execute("""UPDATE dfir_case_qa_v1 SET confidence=0.9, updated_at=NOW()
                               WHERE case_key=%s AND status='grounded' AND intent = ANY(%s)
                                 AND (review_verdict='wrong') IS NOT TRUE""",
                            (case_key, _union))
            else:
                cur.execute("""UPDATE dfir_case_qa_v1 SET confidence=0.6, updated_at=NOW()
                               WHERE case_key=%s AND status='grounded'
                                 AND (review_verdict='wrong') IS NOT TRUE""", (case_key,))
            # refresh report-crosscheck gaps (idempotent)
            cur.execute("DELETE FROM dfir_self_eval_gaps_v1 WHERE case_key=%s AND gap_type='report_crosscheck'", (case_key,))
            for g in gaps:
                cur.execute("""INSERT INTO dfir_self_eval_gaps_v1
                               (case_key, gap_type, expected_fact, bot_found, suggested_probe, severity)
                               VALUES (%s,'report_crosscheck',%s,FALSE,%s,%s)""",
                            (case_key, str(g.get('missing_fact'))[:1000],
                             str(g.get('follow_up_question') or '')[:1000],
                             str(g.get('category') or 'medium')[:40]))
    _log.error(f"[case_qa xcheck] {case_key}: corroborated={len(corroborated)} gaps={len(gaps)}")
    return {'case_key': case_key, 'corroborated': corroborated, 'gaps': gaps, 'gap_count': len(gaps)}


def get_case_qa(case_key):
    """Return stored Q&A for a case, grounded first."""
    _ensure_case_qa_table()
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
                SELECT intent, question, answer, status, confidence, reviewed, review_verdict, updated_at
                FROM dfir_case_qa_v1 WHERE case_key=%s
                ORDER BY CASE status WHEN 'grounded' THEN 0 WHEN 'inferred' THEN 1 ELSE 2 END, intent
            """, (case_key,))
            rows = cur.fetchall()
    return [{'intent': r[0], 'question': r[1], 'answer': r[2], 'status': r[3],
             'confidence': r[4], 'reviewed': r[5], 'review_verdict': r[6],
             'updated_at': r[7].isoformat() if r[7] else None} for r in rows]


def get_trusted_answer(case_key, intent, min_conf=0.9, max_age_days=30):
    """KERNEL (self-learning): return a VERIFIED cached answer for (case_key, intent) so
    the bot serves known answers instantly instead of recomputing. Trusted =
    grounded AND (confidence>=min_conf i.e. corroborated by the report, OR user-confirmed
    ✅). Returns None if nothing trusted/fresh. See docs/PLAN_CASE_QA_AUTOFILL.md."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                _cq = {i: qq for (i, qq) in CASE_QA_QUESTIONS}.get(intent)
                cur.execute("""SELECT answer, confidence, reviewed, review_verdict, updated_at
                               FROM dfir_case_qa_v1
                               WHERE case_key=%s AND intent=%s AND status='grounded'
                                 AND answer IS NOT NULL AND length(answer) > 30
                                 AND (review_verdict='wrong') IS NOT TRUE
                                 AND (confidence >= %s OR (reviewed=TRUE AND review_verdict='ok'))
                                 AND updated_at > NOW() - (%s || ' days')::interval
                                 AND (%s IS NULL OR question = %s)
                               ORDER BY confidence DESC, updated_at DESC LIMIT 6""",
                            (case_key, intent, min_conf, max_age_days, _cq, _cq))
                rows = cur.fetchall()
        # Prefer a SUBSTANTIVE trusted answer: skip 'no evidence found' rows so a narrow
        # no-data follow-up (e.g. «no ngrok connections») can't shadow the real IOC roll-up.
        r = None
        for _row in rows:
            if not _is_no_data_answer(_row[0]):
                r = _row
                break
        if not r:
            return None
        return {'answer': r[0], 'confidence': r[1], 'reviewed': r[2], 'verdict': r[3]}
    except Exception:
        return None


def mark_answer_reviewed(case_key, intent, verdict):
    """KERNEL: human feedback on a case answer. verdict 'ok' → confidence 1.0 (trusted,
    100% — confirmed by user on top of logs/report); 'wrong' → confidence 0 (won't be
    served from cache, flagged for re-derivation)."""
    if not case_key or not intent:
        return False
    conf = 1.0 if verdict == 'ok' else 0.0
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""UPDATE dfir_case_qa_v1
                               SET reviewed=TRUE, review_verdict=%s, confidence=%s, updated_at=NOW()
                               WHERE case_key=%s AND intent=%s""",
                            (verdict, conf, case_key, intent))
                return cur.rowcount > 0
    except Exception:
        return False


_INTENT_LABEL = {
    'initial_access': 'Точка зараження', 'os_info': 'Система та ОС', 'user_info': 'Облікові записи',
    'shutdown': 'Вмикання/вимикання', 'process_exec': 'Запуск процесів', 'persistence': 'Закріплення',
    'c2': 'C2 / віддалений доступ', 'credential': 'Крадіжка облікових даних',
    'lateral_movement': 'Lateral movement', 'defender': 'Defender / AV', 'exfiltration': 'Ексфільтрація',
    'tampering': 'Зачистка слідів', 'browser': 'Браузер', 'file_ops': 'Файлові операції',
    'usb': 'USB-носії', 'shellbags': 'Доступ до папок', 'timeline': 'Хронологія',
}


def _answer_gist(a):
    """Condense a stored Q&A answer into a readable one-liner: drop md headers, the
    'Хронологія подій' title, the table column-header and separator rows; keep real content."""
    a = a or ''
    good = []
    for ln in a.split(chr(10)):
        t = ln.strip()
        if not t:
            continue
        low = t.lower()
        if t.startswith('#') or 'хронологія подій' in low:
            continue
        if set(t) <= set('|-: '):
            continue
        if ('час (utc' in low) and ('артефакт' in low or 'деталі' in low):
            continue
        good.append(t)
    txt = ' '.join(good).replace('|', ' · ')
    txt = re.sub(r'\s+', ' ', txt).strip()
    return txt


def build_case_qa_report(case_key, model, llm_url, synth_model=None):
    """#1 SHOWCASE-звіт (КОРОТКИЙ): людська розповідь + ключові факти + прогалини, зібрані
    з УЖЕ наявного Q&A (dfir_case_qa_v1). 1 LLM-виклик, бо аналіз уже зроблено. Працює без
    еталонного звіту. Повертає текст для Telegram (emoji-заголовки, без сирого дампу).
    Повні відповіді — через «📋 Q&A кейсу». docs/PLAN_CASE_QA_AUTOFILL.md."""
    qa = [r for r in get_case_qa(case_key) if r['status'] == 'grounded' and r.get('answer')]
    if not qa:
        return None
    gaps = get_case_gaps(case_key)
    disp = case_key.replace('_', ' ')
    n_conf = sum(1 for r in qa if (r.get('confidence') or 0) >= 0.9)
    _ia_lines, _ia_txt = [], ''
    try:
        from reports.reshape import _initial_access, _incident_window
        _iw = _incident_window(case_key)
        _iw_start = _iw[0] if isinstance(_iw, (tuple, list)) and _iw else (_iw if isinstance(_iw, str) else None)
        _ia_lines = _initial_access(case_key, _iw_start) or []
        _ia_txt = ' '.join(x.replace('*', '').replace('`', '') for x in _ia_lines)
    except Exception:
        _ia_lines, _ia_txt = [], ''

    qa_brief = '\n'.join(f"[{_INTENT_LABEL.get(r['intent'], r['intent'])}] {(r['answer'] or '')[:400]}" for r in qa)
    if _ia_txt:
        qa_brief = ('АВТОРИТЕТНА ТОЧКА ЗАРАЖЕННЯ (обчислена детерміновано з кореляції завантаження->запуск — ВИКОРИСТАЙ САМЕ ЦЕ як початок атаки; НЕ бери типнуті URL, go.microsoft.com, оновлення чи артефакти до вікна інциденту): '
                    + _ia_txt + chr(10) + chr(10) + qa_brief)
        sys = ("Ти досвідчений DFIR-аналітик. На основі зібраних відповідей (грунтованих на логах) напиши "
           "ДЕТАЛЬНИЙ (але зрозумілий) звіт українською, РІВНО дві частини, без markdown-таблиць:\n"
           "РОЗПОВІДЬ: 8-14 живих простих речень БЕЗ жаргону/EID/кодів — що сталося, з чого почалось "
           "(точка зараження і як саме), як виконав/запустив шкідливе, як закріпився, як отримав віддалений доступ і куди тунелював, що збирав чи виводив, які наслідки, і що зробити першими кроками. Пиши природно й послідовно, як досвідчений аналітик пояснює замовнику.\n"
           "ФАКТИ: 8-12 стислих пунктів через '- ' з конкретикою (точка зараження: файл+джерело; C2/IP; "
           "persistence: служба/задача; Defender; ексфільтрація; акаунти; ключові дати). Кожен пункт — рядок, факт + коротке джерело словами.\n"
           "Формат відповіді РІВНО:\n[РОЗПОВІДЬ]\n<текст>\n[ФАКТИ]\n- <пункт>\nТільки на основі наданих фактів, не вигадуй.")
    raw = _llm_json_raw(synth_model or model, llm_url, sys, qa_brief[:9000], max_tokens=8000, temperature=0.3)
    if not raw:
        return None

    # split into narrative + facts
    narrative, facts = raw, ''
    m = re.search(r'(?is)\[?\s*ФАКТИ\s*\]?', raw)
    if m:
        narrative = re.sub(r'(?is)^\s*\[?\s*РОЗПОВІДЬ\s*\]?\s*', '', raw[:m.start()]).strip()
        facts = raw[m.end():].strip()
    else:
        narrative = re.sub(r'(?is)^\s*\[?\s*РОЗПОВІДЬ\s*\]?\s*', '', raw).strip()

    out = [f"📄 DFIR-звіт: {disp}", "", "📌 КОРОТКО", narrative]
    if _ia_lines and not (len(_ia_lines) == 1 and 'не вдалося' in _ia_lines[0].lower()):
        out += ['', '🎯 ТОЧКА ЗАРАЖЕННЯ (кореляція завантаження -> запуск)'] + _ia_lines
    if facts:
        out += ["", "🔑 КЛЮЧОВІ ФАКТИ", facts]
    out += ["", "🧾 ПИТАННЯ → ВІДПОВІДЬ (з логів):", ""]
    out += build_qa_table_md(case_key)   # 📋 базові + 🧠 те, що LLM запитала сама (підсвічено)
    if gaps:
        out += ["", "⚠️ ПОТРЕБУЄ ПЕРЕВІРКИ"]
        for g in gaps:
            out.append(f"• {g['missing_fact']}")
    out += ["", f"✓ Грунтовано на логах ({len(qa)} напрямів), підтверджено звітом: {n_conf}. Деталі — «📋 Q&A кейсу»."]
    return '\n'.join(out)


def get_case_gaps(case_key):
    """Report-crosscheck gaps (facts in the expert report missing from the Q&A) with
    their follow-up ('наводящі') questions."""
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""SELECT expected_fact, suggested_probe, severity
                           FROM dfir_self_eval_gaps_v1
                           WHERE case_key=%s AND gap_type='report_crosscheck'
                           ORDER BY created_at""", (case_key,))
            rows = cur.fetchall()
    return [{'missing_fact': r[0], 'follow_up_question': r[1], 'category': r[2]} for r in rows]


# sentinel run_id for answers grown from a user's CHAT question (answered off the logs)
CHAT_QA_RUN_ID = '00000000-0000-4000-8000-0000000feed2'


def case_qa_lookup(case_key, question, intent=None, min_conf=0.5, min_sim=0.55):
    """CHAT «БД-перше»: serve a stored GROUNDED answer when the case DB already holds a RELEVANT
    question. Two SAFE matches, in order:
      1) a stored question SIMILAR to the user's (pg trigram >= min_sim) — exact/close rephrasings,
         incl. a specific follow-up the user asks closely;
      2) else, if `intent` given, the CANONICAL base-question answer for that topic (broad answer,
         same intent-level behaviour as get_trusted_answer but usable at 0.6).
    A NARROW follow-up is NEVER served for a loosely-related question (that was the risk of pure
    intent-matching). Excludes user-rejected. None if nothing relevant (→ chat computes from logs
    and records the new Q&A). Falls back to None if pg_trgm/similarity is unavailable."""
    if not case_key or not question or len(str(question).strip()) < 5:
        return None
    q = re.sub(r'\s+', ' ', str(question).strip())
    _fpv = _fastpath_version()
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # 1) closest stored question by trigram similarity
                cur.execute("""SELECT answer, confidence, question, similarity(question, %s) AS sim
                               FROM dfir_case_qa_v1
                               WHERE case_key=%s AND status='grounded'
                                 AND (fastpath_ver IS NULL OR fastpath_ver=%s OR reviewed OR confidence >= 0.85)
                                 AND answer IS NOT NULL AND length(answer) > 30
                                 AND (review_verdict='wrong') IS NOT TRUE
                                 AND confidence >= %s
                                 AND updated_at > NOW() - interval '45 days'
                                 AND similarity(question, %s) >= %s
                               ORDER BY sim DESC, confidence DESC, updated_at DESC LIMIT 1""",
                            (q, case_key, _fpv, min_conf, q, min_sim))
                r = cur.fetchone()
                if r:
                    return {'answer': r[0], 'confidence': r[1], 'question': r[2],
                            'sim': float(r[3]), 'via': 'question'}
                # 2) canonical base-question answer for the detected topic (broad; never a follow-up)
                cq = {i: qq for (i, qq) in CASE_QA_QUESTIONS}.get(intent) if intent else None
                if cq:
                    cur.execute("""SELECT answer, confidence, question FROM dfir_case_qa_v1
                                   WHERE case_key=%s AND question=%s AND status='grounded'
                                     AND (fastpath_ver IS NULL OR fastpath_ver=%s OR reviewed OR confidence >= 0.85)
                                     AND answer IS NOT NULL AND length(answer) > 30
                                     AND (review_verdict='wrong') IS NOT TRUE
                                     AND confidence >= %s
                                     AND updated_at > NOW() - interval '45 days'
                                   ORDER BY confidence DESC, updated_at DESC LIMIT 1""",
                                (case_key, cq, _fpv, min_conf))
                    r2 = cur.fetchone()
                    if r2:
                        return {'answer': r2[0], 'confidence': r2[1], 'question': r2[2],
                                'sim': None, 'via': 'intent'}
        return None
    except Exception:
        return None


def record_chat_qa(case_key, question, answer, intent=None):
    """GROW dfir_case_qa_v1 from a user's chat question answered off the logs, so the case
    Q&A table + report include it and it is reused next time. Skips no-data answers and never
    downgrades a stronger existing answer (>=0.85) for the same question."""
    if not case_key or not question or not answer or _is_no_data_answer(answer):
        return False
    q = re.sub(r'\s+', ' ', str(question).strip())[:2000]
    if len(q) < 6:
        return False
    # Reject pasted chat logs / analyses masquerading as a "question": a real question is
    # short and has no chat-log timestamp. Storing them pollutes the case Q&A and leaks chat
    # timestamps + operator names into the client report (mirrors the build_qa_table_md guard).
    if len(q) > 240 or re.search(r'\[\d{1,2}\.\d{1,2}\.\d{4}\s+\d{1,2}:\d{2}\]', q):
        return False
    try:
        _ensure_case_qa_table()
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("SELECT confidence FROM dfir_case_qa_v1 WHERE case_key=%s AND question=%s",
                            (case_key, q))
                _ex = cur.fetchone()
        if _ex and (_ex[0] or 0) >= 0.85:
            return False
        _upsert(case_key, intent, q, str(answer).strip()[:4000], 'grounded', 0.6, CHAT_QA_RUN_ID)
        return True
    except Exception:
        return False


def human_answer_line(a):
    """Human one-liner for a stored Q&A answer: prefer the plain 'Висновок:' sentence, else
    strip the leading evidence chain (date·table·file·EID·) off the gist. Drops md, caps ~220.
    Same logic the «📋 Q&A кейсу» table view uses, so the report table matches it."""
    a = (a or '').strip()
    if not a:
        return ''
    m = re.search(r'(?is)висновок\s*[:\-]\s*(.+)', a)
    if m:
        txt = m.group(1)
    else:
        # no plain conclusion: condense to a one-liner and strip only the LEADING raw-evidence
        # tokens (a date/table/file/EID prefix), keeping the substance (names, indicators, facts).
        txt = _answer_gist(a)
        txt = re.sub(r'(?i)^(?:[·|]\s*)?(?:\d{4}[-‑.].{0,30}?|program_exec_v2|filesystem_v2|'
                     r'event_logs_v2|[\w.\-]+\.(?:csv|evtx)|EID\s*\d+|Запуск[^·|]*)\s*[·|]\s*', '', txt).strip()
        # tidy the noisiest inline dump tokens without dropping the readable facts
        txt = re.sub(r'(?i)\b(?:event_ts|event_id|sha1|sha256|md5)\s*[:=]\s*', '', txt)
        txt = re.sub(r'%%\d+', '', txt)
    txt = re.sub(r'[*`#]', '', txt)
    # readability pass (both branches): compress noisy timestamps to a plain date and drop the
    # raw dump field-labels so a Q&A line reads like a sentence, not a log row.
    txt = re.sub(r'(\d{4})-(\d{2})-(\d{2})[ T][\d:.,+\-]{4,}',
                 lambda m: '%s.%s.%s' % (m.group(3), m.group(2), m.group(1)), txt)
    txt = re.sub(r'(?i)\b(?:event_ts|event_id|by_who|Target|DisplayName|UserPrincipalName|'
                 r'HomeDirectory|HomePath|SamAccountName|MapDescription|PayloadData\d|'
                 r'source_file|Hostname)\s*[:=]\s*', '', txt)
    txt = re.sub(r'\s*[·|]\s*', '; ', txt)
    txt = re.sub(r'\s*;\s*;+', '; ', txt)
    txt = re.sub(r'\s+', ' ', txt).strip(' :·—-;')
    return txt[:200]


def build_qa_table_md(case_key, limit=10):
    """Report Q&A section as list[str], split into two clearly-labelled groups:
      «📋 Базові питання»  — the fixed canonical set (static, in order);
      «🧠 Питання, які система поставила САМА» — the LLM's OWN adaptive follow-ups, HIGHLIGHTED
        (🧠) so the analyst sees what the model asked beyond the fixed 17, best-confidence first.
    Short human answers. `limit` caps the LLM group only (canonical always fully shown). [] if empty."""
    try:
        # re-judge at render time: rows stored as «grounded» under the older, looser
        # no-data rule («немає жодного артефакту … 2026-08-29») must not print as facts
        rows = [r for r in get_case_qa(case_key)
                if r.get('status') == 'grounded' and r.get('answer') and not _is_no_data_answer(r.get('answer'))]
    except Exception:
        return []
    if not rows:
        return []
    _base = {q: i for i, (_i, q) in enumerate(CASE_QA_QUESTIONS)}

    def _fmt(r, prefix):
        q = re.sub(r'\s+', ' ', (r.get('question') or '')).strip()
        a = human_answer_line(r.get('answer'))
        if not q or not a or len(q) > 240:
            return None
        # skip pasted chat-log "questions" (chat-timestamp marker) — privacy + garbage guard
        if re.search(r'\[\d{1,2}\.\d{1,2}\.\d{4}\s+\d{1,2}:\d{2}\]', q):
            return None
        mark = ' ✅' if (r.get('confidence') or 0) >= 0.9 else ''
        return ['**%s %s%s**' % (prefix, q, mark), '  → ' + a, '']

    canon = sorted((r for r in rows if r.get('question') in _base), key=lambda r: _base[r['question']])
    llm = sorted((r for r in rows if r.get('question') not in _base),
                 key=lambda r: -(r.get('confidence') or 0))
    # self-generated questions that name things the case never showed (Mega.nz, wmiprvse,
    # HackTool on a USB stick...) are dropped at render time too, so old rows cannot leak
    try:
        _vents = _verdict_entities(case_key)
        _anchor = ' '.join((r.get('answer') or '') for r in canon)
        llm = [r for r in llm if _question_is_anchored(r.get('question') or '', _anchor, _vents)]
    except Exception:
        pass
    # The rows in the table are what PAST runs asked, so the stop-list and the near-duplicate
    # rule have to hold at render time as well — otherwise a report keeps printing the six
    # rephrasings of one 7za question, and the questions about our own parser output, that
    # three cases still carry in the database. (FIX_QUEUE №3.)
    _kept, _asked = [], []
    for r in llm:
        q = (r.get('question') or '').strip()
        if not q:
            continue
        _ok, _why = _qa_question_allowed(case_key, q)
        if not _ok:
            continue
        if _norm_q(q) in _asked or _is_dup_q(q, _asked):
            continue
        _asked.append(_norm_q(q))
        _kept.append(r)
    llm = _kept
    out = ['**📋 Базові питання:**', '']
    for r in canon:
        blk = _fmt(r, '•')
        if blk:
            out += blk
    llm_blocks = [b for r in llm for b in [_fmt(r, '🧠')] if b][:limit]
    if llm_blocks:
        out += ['', '**🧠 Питання, які система поставила САМА (LLM, %d):**' % len(llm_blocks),
                '_Модель згенерувала їх, аналізуючи відповіді на базові, щоб добити картину атаки._', '']
        for blk in llm_blocks:
            out += blk
    return out if len(out) > 3 else []
