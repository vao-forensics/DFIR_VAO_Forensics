"""Synthesis — ReAct agent loop, planner, KB context fetcher."""
import json, re, time, os, logging
import urllib.request, urllib.error
import psycopg2
from datetime import datetime, timedelta, timezone
from core.config import (
    PG_DSN, LLM_URL, LLM_MODEL, LLM_FAST_MODEL,
    LLM_MAX_TOKENS, LLM_SYNTH_MAX_TOKENS, LLM_FAST_TIMEOUT, LLM_FAST_MAX_TOKENS, LLM_TIMEOUT,
    QDRANT_URL, EMBED_URL, EMBED_MODEL, TEXT_COLL_PRIMARY,
    CTX_BUDGET_CHARS, BACKTRACE_SLOT, CASE_LIB,
    LLM_JSON_TEMPERATURE,
)
from core.http_utils import http_json as _http_json, llm_chat as _llm_chat
from core.model_router import build_chat_payload
from core.db import table_exists
from reports.claims import _safe_case_folder
from analysis.assemblers import _ensure_browser_provenance_view
from analysis.learnings import _get_relevant_lessons, _save_lesson
from analysis.structured_input import _trim_structured_input_for_llm
from analysis import investigation_journal as _journal
from analysis.agent_tools import (
    _load_agent_learnings, _save_agent_learnings, _execute_agent_tool,
    _agent_tool_get_tampering_events, _sync_iocs_to_pg,
)
_log = logging.getLogger('app')


# A tool «found nothing» answer is one short line: «Результат порожній.», «Детекцій не знайдено.»,
# «SRUM: даних немає…». The old check (len<10 / 'no results') let all of them through as evidence -
# 29% of agent steps were stored as ok=true with nothing in them (audit 15.10.2026).
_EMPTY_RX = re.compile(r'(порожн|не знайдено|нічого не знайдено|даних немає|записів немає|ще немає|no results|not found)', re.I)


def _is_empty_result(res):
    t = str(res or '').strip()
    if len(t) < 10 or t in ('[]', '{}', 'None'):
        return True
    return '\n' not in t and len(t) < 200 and bool(_EMPTY_RX.search(t))


def _build_threat_summary_block(case_key, structured_input):
    """High-signal block FORCE-FED into the LLM context as the attack-chain skeleton.

    Combines (a) the deterministic detections already computed in
    structured_input['threat_detections'] and (b) a Hayabusa/Sigma rule-aggregated
    summary (high+med). The fixed TOOL_PLAN only pulled Hayabusa at min_level='high'
    (mostly one noisy 'unsigned DLL' rule) so the juicy med-level rules
    ('Potentially Malicious PwSh', 'Uncommon PowerShell Hosts', web-request cmdlets,
    obfuscation) never reached the model. This guarantees them up front, deduped by
    rule with counts + time window — so the 20b synthesiser builds a real chain
    instead of generic hedging.
    """
    parts = []
    try:
        dets = (structured_input or {}).get('threat_detections') or []
        if dets:
            lines = []
            for f in dets[:18]:
                sev = str(f.get('severity', '')).upper()
                title = f.get('title', '')
                detail = str(f.get('detail', ''))[:200]
                mitre = f.get('mitre', '')
                cnt = f.get('count', 0)
                samp = '; '.join(str(s)[:60] for s in (f.get('samples') or [])[:3])
                line = f"- [{sev}] {title} (MITRE {mitre}, x{cnt}) — {detail}"
                if samp:
                    line += f" | приклади: {samp}"
                lines.append(line)
            parts.append("ДЕТЕРМІНОВАНІ ДЕТЕКЦІЇ (SQL-сигнатури без ШІ — це підтверджені факти, спирайся на них):\n" + '\n'.join(lines))
    except Exception as e:
        _log.warning(f"[threat_block] dets: {repr(e)[:120]}")
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT severity, rule, count(*) c, min(event_ts), max(event_ts) "
                    "FROM tool_alerts_v2 WHERE case_key=%s "
                    "AND lower(coalesce(severity,'')) IN ('crit','critical','high','med','medium') "
                    "AND (lower(coalesce(source_file,'')) ~ 'hayabusa|sigma' "
                    "     OR lower(coalesce(tool,'')) ~ 'hayabusa|sigma') "
                    "GROUP BY severity, rule "
                    "ORDER BY CASE lower(severity) WHEN 'crit' THEN 0 WHEN 'critical' THEN 0 "
                    "         WHEN 'high' THEN 1 ELSE 2 END, c DESC LIMIT 45",
                    (case_key,))
                rows = cur.fetchall()
                if rows:
                    hl = []
                    for sev, rule, c, t0, t1 in rows:
                        if t0 and t1 and str(t0)[:16] != str(t1)[:16]:
                            win = f" [{str(t0)[:16]}..{str(t1)[:16]}]"
                        elif t0:
                            win = f" [{str(t0)[:16]}]"
                        else:
                            win = ''
                        hl.append(f"- [{str(sev).upper()}] {rule} x{c}{win}")
                    parts.append("HAYABUSA/SIGMA ДЕТЕКЦІЇ (агреговано по правилах, high+med — кістяк attack-chain):\n" + '\n'.join(hl))
    except Exception as e:
        _log.warning(f"[threat_block] hayabusa: {repr(e)[:120]}")
    return '\n\n'.join(parts)


_SEV_RANK = {'critical': 4, 'crit': 4, 'high': 3, 'medium': 2, 'med': 2, 'low': 1, 'info': 0}
# how a delivery / entry event is labelled by the detectors (Ukrainian + the artefact names)
_DELIVERY_RX = re.compile(r'msi|gpo|sysvol|доставк|delivery|завантаж|download|вкладен|attach|фішинг|phish|'
                          r'zone\.identifier|motw|\.zip|\.rar|\.7z|\.iso|\.lnk|hosturl|referrer|rdp|4624|1149|'
                          r'зареєстровано завдання|task|schtasks|\.exe|\.ps1|\.js|\.vbs|\.hta|\.scr', re.I)


def _fmt_ts(ts):
    return str(ts)[:16] if ts else '?'


def _verdict_constraints(case_key, structured_input):
    """The deterministic layer as HARD CONSTRAINTS for the language model, plus the
    machine-readable facts behind them (for the self-review pass and the guard).

    Born 2026-09-04 on 3-4-19-1N: the SQL layer had the wiper (GPO-delivered MSI → task
    → WinPE boot image → 6008) as a critical finding on line 324 of the report, while the
    model's narrative above it said the entry point "could not be established", called the
    collector's own KAPE/7za "collection before destruction" and invented a path for
    boot.wim. The block below goes FIRST in every prompt; the narrative may not exceed the
    verdict, must use the verdict's anchor as the entry point, may only name paths that
    are in the findings' IOCs or the evidence, and may never call our own footprint an
    attacker tool. Returns (text, meta); meta = {'verdict','max_sev','anchor','own',
    'iocs','events','findings'}. Never raises."""
    meta = {'verdict': '', 'max_sev': 'none', 'anchor': None, 'own': {}, 'iocs': [],
            'events': [], 'findings': []}
    try:
        dets = [f for f in ((structured_input or {}).get('threat_detections') or []) if isinstance(f, dict)]
        try:
            from analysis.threat_detect import verdict_line as _vl
            meta['verdict'] = _vl(dets)
        except Exception:
            meta['verdict'] = ''
        hi = [f for f in dets if _SEV_RANK.get(str(f.get('severity', '')).lower(), 0) >= 3]
        hi.sort(key=lambda f: -_SEV_RANK.get(str(f.get('severity', '')).lower(), 0))
        if dets:
            meta['max_sev'] = max(dets, key=lambda f: _SEV_RANK.get(str(f.get('severity', '')).lower(), 0)).get('severity', 'none')
        lines = []
        for f in hi[:8]:
            ev = [e for e in (f.get('events') or []) if isinstance(e, dict)]
            io = [i for i in (f.get('iocs') or []) if isinstance(i, dict)]
            ev.sort(key=lambda e: str(e.get('ts') or ''))
            lines.append("- [%s] %s (MITRE %s, x%s) — %s" % (
                str(f.get('severity', '')).upper(), f.get('title', ''), f.get('mitre', ''),
                f.get('count', 0), str(f.get('detail', ''))[:300]))
            for e in ev[:10]:
                lines.append("    подія: %s — %s [%s]" % (_fmt_ts(e.get('ts')), str(e.get('label', ''))[:120],
                                                        str(e.get('source') or e.get('artifact') or '')[:60]))
                meta['events'].append({'ts': str(e.get('ts') or ''), 'label': str(e.get('label', ''))[:160],
                                       'source': str(e.get('source') or e.get('artifact') or '')[:80],
                                       'finding': f.get('title', '')})
            for i in io[:12]:
                lines.append("    IOC: %s: %s — %s" % (i.get('type', '?'), str(i.get('value', ''))[:160],
                                                     str(i.get('role', ''))[:80]))
                meta['iocs'].append({'type': str(i.get('type', '')), 'value': str(i.get('value', ''))[:200],
                                     'role': str(i.get('role', ''))[:80]})
            if not ev and not io:
                samp = '; '.join(str(s)[:80] for s in (f.get('samples') or [])[:4])
                if samp:
                    lines.append("    приклади: " + samp)
            meta['findings'].append({'severity': f.get('severity'), 'title': f.get('title'),
                                     'category': f.get('category'), 'n_events': len(ev), 'n_iocs': len(io)})
        # entry-point anchor = the earliest DELIVERY-shaped event of the top finding (an MSI
        # from GPO, a download, an attachment, a task registration...); events before it
        # that are not delivery (an AV crash at 07:36 before the MSI at 08:53) are named as
        # precursors, not as the entry point. Falls back to the earliest event.
        if hi:
            ev0 = sorted([e for e in (hi[0].get('events') or []) if isinstance(e, dict) and e.get('ts')],
                         key=lambda e: str(e.get('ts')))
            if ev0:
                _deliv = [e for e in ev0 if _DELIVERY_RX.search(str(e.get('label', '')) + ' ' + str(e.get('source', '')))]
                a = _deliv[0] if _deliv else ev0[0]
                meta['anchor'] = {'ts': str(a.get('ts')), 'label': str(a.get('label', ''))[:160],
                                  'source': str(a.get('source') or a.get('artifact') or '')[:80],
                                  'finding': hi[0].get('title', '')}
                meta['precursors'] = [{'ts': str(e.get('ts')), 'label': str(e.get('label', ''))[:120]}
                                      for e in ev0 if str(e.get('ts')) < str(a.get('ts'))][:4]
        # our own footprint on this machine
        own = {}
        try:
            from analysis.own_footprint import own_started_at as _osa, OWN_TOOLS as _ot
            st = _osa(case_key)
            own['started'] = _fmt_ts(st) if st else None
            own['tools'] = list(_ot)
        except Exception:
            own['started'] = None
            own['tools'] = ['kape.exe', '7za.exe', 'mftecmd.exe', 'evtxecmd.exe', 'recmd.exe', 'hayabusa.exe']
        try:
            from analysis.collector_self import declared_self_paths as _dsp
            own['declared'] = sorted(_dsp(case_key))[:8]
        except Exception:
            own['declared'] = []
        meta['own'] = own

        out = ["═══ ВЕРДИКТ ДЕТЕРМІНОВАНОГО ШАРУ (SQL-сигнатури, без ШІ) — ЖОРСТКІ ОБМЕЖЕННЯ ДЛЯ ЗВІТУ ═══",
               "ВЕРДИКТ: " + (meta['verdict'] or 'детермінований шар не дав вердикту'),
               "МАКСИМАЛЬНА ТЯЖКІСТЬ, ДОВЕДЕНА ДЕТЕРМІНОВАНО: " + str(meta['max_sev']).upper()]
        if lines:
            out.append("ПІДТВЕРДЖЕНІ ЗНАХІДКИ (high/critical) з подіями та IOC:")
            out.extend(lines)
        else:
            out.append("ПІДТВЕРДЖЕНИХ ЗНАХІДОК high/critical НЕМАЄ.")
        if meta['anchor']:
            a = meta['anchor']
            out.append("ЯКІР ПОЧАТКОВОГО ДОСТУПУ (перша подія доставки головної знахідки): %s — %s [%s]"
                       % (_fmt_ts(a['ts']), a['label'], a['source']))
            if meta.get('precursors'):
                out.append("ПЕРЕДУМОВИ ДО ЯКОРЯ (раніші події тієї ж знахідки — підготовка, не точка входу): "
                           + '; '.join('%s — %s' % (_fmt_ts(p['ts']), p['label']) for p in meta['precursors']))
        else:
            out.append("ЯКІР ПОЧАТКОВОГО ДОСТУПУ: детермінованого якоря НЕМАЄ — точку входу можна подавати лише як гіпотезу з поміткою «не підтверджено».")
        own_l = ("ВЛАСНИЙ СЛІД КОНВЕЄРА (це НАШ збирач і НАШ бот, НЕ інструменти зловмисника, НЕ collection/exfiltration/persistence): "
                 "збирач vao_collector*.exe" + (" запущено о %s" % own['started'] if own.get('started') else " (час запуску невідомий)")
                 + "; його інструменти після цього часу: KAPE.EXE, 7za.exe, MFTECmd/EvtxECmd/RECmd/AmcacheParser/PECmd/LECmd/hayabusa та інші парсери; "
                 "проби dfp_<hex>.ps1; теки Temp\\DFIRTriage_<hex> і C:\\DFIR_Triage; винятки Defender, які додав збирач"
                 + (": " + "; ".join(own['declared']) if own.get('declared') else "")
                 + "; відновлення NTLM-хешів із SAM/SYSTEM (impacket-secretsdump у алертах) — робота бота офлайн.")
        out.append(own_l)
        out.append("ПРАВИЛА (порушення будь-якого = брак звіту):\n"
                   "1. Тяжкість наративу НЕ може перевищувати ВЕРДИКТ. Атака доведена лише в обсязі знахідок вище; без знахідки high/critical не пиши «цілеспрямована атака», «зловмисник отримав контроль», «бекдор», «ексфільтрація».\n"
                   "2. Перша точка зараження / initial access = ЯКІР вище, якщо він є. Будь-яка інша версія — лише «гіпотеза (не підтверджено)» після якоря, ніколи замість нього.\n"
                   "3. Шляхи, імена файлів, завдань, служб, GPO — ТІЛЬКИ дослівно з IOC вище або з FORENSIC ДАНИХ. Не домислюй розташування файлу (напр. System32), якщо доказ каже інше.\n"
                   "4. Нічого з ВЛАСНОГО СЛІДУ не називай інструментом атаки, збором даних, ексфільтрацією чи закріпленням. Якщо сумніваєшся — не згадуй.\n"
                   "5. Кожну знахідку high/critical відобрази у висновку, хронології та IOC з її часом і джерелом.\n"
                   "6. Події EID 4648/4624 від машинного акаунта (ім'я закінчується на $) — фонова робота служб, НЕ латеральний рух.")
        return '\n'.join(out), meta
    except Exception as e:
        _log.warning(f"[verdict_block] {repr(e)[:160]}")
        return '', meta


def _verdict_constraints_block(case_key, structured_input):
    """Text only (see _verdict_constraints)."""
    return _verdict_constraints(case_key, structured_input)[0]


def _get_expert_style_sample(case_key):
    """Fetch expert report chunks from kb_reports for this case (style + depth reference)."""
    try:
        import urllib.request as _ur
        qdrant = QDRANT_URL
        # Try exact case match first
        body = json.dumps({'limit': 6, 'with_payload': True, 'with_vector': False,
            'filter': {'should': [
                {'key': 'case_key', 'match': {'value': case_key}},
                {'key': 'source_file', 'match': {'any': [case_key + '.pdf', case_key]}}
            ]}}).encode('utf-8')
        req = _ur.Request(f'{qdrant}/collections/kb_reports/points/scroll',
                          data=body, headers={'Content-Type': 'application/json'})
        with _ur.urlopen(req, timeout=8) as r:
            pts = json.loads(r.read().decode('utf-8', errors='ignore')).get('result', {}).get('points', [])
        if not pts:
            # Fallback: any report as style guide
            body2 = json.dumps({'limit': 4, 'with_payload': True, 'with_vector': False}).encode('utf-8')
            req2 = _ur.Request(f'{qdrant}/collections/kb_reports/points/scroll',
                               data=body2, headers={'Content-Type': 'application/json'})
            with _ur.urlopen(req2, timeout=8) as r2:
                pts = json.loads(r2.read().decode('utf-8', errors='ignore')).get('result', {}).get('points', [])
        texts = [p.get('payload', {}).get('text', '') for p in pts if p.get('payload', {}).get('text')]
        return '\n---\n'.join(texts[:4])[:2500]
    except Exception:
        return ''


def _get_benchmark_context(case_key):
    """Fetch known gaps and playbooks for this case from benchmark runs."""
    gaps_txt = ''
    playbooks_txt = ''
    try:
        with psycopg2.connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute("""SELECT gap_type, expected, severity FROM dfir_benchmark_gaps_v1
                    WHERE case_key=%s AND severity IN ('critical','high')
                    ORDER BY severity DESC, created_at DESC LIMIT 8""", (case_key,))
                gaps = cur.fetchall()
                if gaps:
                    gaps_txt = '\n'.join(f"  [{r[2].upper()}] {r[0]}: {r[1][:150]}" for r in gaps)
                cur.execute("""SELECT title, checklist FROM dfir_playbooks_v1
                    WHERE case_key=%s ORDER BY created_at DESC LIMIT 5""", (case_key,))
                pbs = cur.fetchall()
                if pbs:
                    lines = []
                    for title, checklist in pbs:
                        steps = (checklist or [])[:4]
                        lines.append(f"  {title}: " + '; '.join(str(s) for s in steps))
                    playbooks_txt = '\n'.join(lines)
    except Exception:
        pass
    return gaps_txt, playbooks_txt


def _get_qa_failure_hints(case_key, limit=6):
    """Fetch top QA failures with suggested fixes — inject into synthesis so LLM avoids repeating mistakes."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT category, expected_fact, suggested_fix
                    FROM dfir_eval_failures_v1
                    WHERE case_key=%s AND suggested_fix IS NOT NULL AND suggested_fix != ''
                    AND severity IN ('critical','high')
                    ORDER BY severity DESC, created_at DESC LIMIT %s
                """, (case_key, limit))
                rows = cur.fetchall()
        if not rows:
            return ''
        lines = [f"- [{cat}] {(exp or '')[:130]} → {(fix or '')[:100]}"
                 for cat, exp, fix in rows]
        return '\n'.join(lines)
    except Exception:
        return ''


def _get_qa_pass_answers(case_key, limit=4):
    """Fetch Q&A pairs where bot answered correctly — show synthesis what good answers look like."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT q.category, q.question, a.bot_answer
                    FROM dfir_eval_answers_v1 a
                    JOIN dfir_eval_questions_v1 q ON q.id = a.question_id
                    WHERE a.case_key = %s
                    AND a.id NOT IN (
                        SELECT answer_id FROM dfir_eval_failures_v1
                        WHERE case_key = %s AND answer_id IS NOT NULL
                    )
                    ORDER BY a.created_at DESC LIMIT %s
                """, (case_key, case_key, limit))
                rows = cur.fetchall()
        if not rows:
            return ''
        lines = [f"- [{cat}] {(q or '')[:100]} → {(ans or '')[:160]}"
                 for cat, q, ans in rows]
        return '\n'.join(lines)
    except Exception:
        return ''


def _source_counts_line(case_key):
    """Deterministic row counts per evidence table — injected so the LLM never claims
    a populated source is 'absent' (the audits found false 'MFT/SRUM/THOR відсутні')."""
    labels = [
        ('event_logs_v2', 'EVTX-події'), ('filesystem_v2', 'файлова система (MFT/USN/MOTW)'),
        ('program_exec_v2', 'виконання (Prefetch/Amcache)'), ('srum_v2', 'SRUM (мережа/застосунки)'),
        ('tool_alerts_v2', 'алерти інструментів (Hayabusa/THOR/DeepBlue/Sigma)'),
        ('raw_fallback_v2', 'інші артефакти (реєстр/браузер/jumplists)'),
    ]
    parts = []
    try:
        with psycopg2.connect(PG_DSN) as _c:
            _c.autocommit = True
            with _c.cursor() as _cu:
                for tbl, lbl in labels:
                    try:
                        _cu.execute("SELECT count(*) FROM %s WHERE case_key=%%s" % tbl, (case_key,))
                        n = int((_cu.fetchone() or [0])[0] or 0)
                    except Exception:
                        n = 0
                    if n > 0:
                        parts.append('%s=%d' % (lbl, n))
    except Exception:
        return ''
    if not parts:
        return ''
    return ('ДОСТУПНІ ДЖЕРЕЛА ДОКАЗІВ (кількість рядків у БД — ЦІ джерела НАПОВНЕНІ, '
            'ЗАБОРОНЕНО писати що вони відсутні/порожні): ' + '; '.join(parts) + '.\n')



_EVID_DATE_RX = re.compile(r'(\d{4}-\d{2}-\d{2})')
_RANK_BY_WINDOW = os.getenv('DFIR_RANK_BY_WINDOW', '0') == '1'


def _rank_evidence_lines(text, win, margin_days=30):
    """Stable-sort a tool's lines so evidence inside the incident window meets the cap first.

    Nothing is dropped and nothing is rewritten - only the order changes, so the per-tool
    character cap falls on background noise instead of on evidence. Rows arrive in whatever
    order the table returned them; measured on this system the cap discarded up to 88% of a
    tool's output, and on 11 of 11 live cases the discarded part held the remote-access tool
    and the keylogger while Windows servicing noise survived.

    Lines carrying no date (headers, counts, labels) keep rank 0 so the block stays readable;
    1 is inside the window, 2 within margin_days of it, 3 the rest. The sort is stable, so
    chronology within a rank is preserved and the multiset of lines is unchanged - a
    before/after diff must show the same lines in a different order, never a different set.
    """
    if not win or not text:
        return text
    if text.find(chr(10)) < 0:
        return text
    from datetime import date as _date, timedelta as _td
    try:
        _s = _date.fromisoformat(str(win.get('start'))[:10])
        _e = _date.fromisoformat(str(win.get('end'))[:10])
    except Exception:
        return text
    _lo, _hi = _s - _td(days=margin_days), _e + _td(days=margin_days)
    ranked = []
    for _i, _ln in enumerate(text.split(chr(10))):
        _m = _EVID_DATE_RX.search(_ln)
        _r = 0
        if _m:
            try:
                _d = _date.fromisoformat(_m.group(1))
                _r = 1 if _s <= _d <= _e else (2 if _lo <= _d <= _hi else 3)
            except Exception:
                _r = 0
        ranked.append((_r, _i, _ln))
    ranked.sort(key=lambda t: (t[0], t[1]))
    return chr(10).join(t[2] for t in ranked)


def _compute_incident_window(case_key):
    """Deterministically locate the incident window by the DENSITY of high-signal
    security events per day (remote/failed logons, priv-group adds, RDP connects,
    real Defender tamper, Security-log clears). This anchors the analysis to the
    real attack period instead of a stale trigger timestamp (a KAPE image is full
    of old baseline events — event VOLUME alone reflects log recency, not the
    incident, so we score by high-signal EIDs only). Returns dict or None.
    """
    from datetime import timedelta as _td
    try:
        day_counts = {}  # date -> weighted signal
        def _add(d, v):
            if d:
                day_counts[d] = day_counts.get(d, 0) + v
        with psycopg2.connect(PG_DSN) as _c:
            with _c.cursor() as cur:
                # (1) HIGH-CONFIDENCE incident markers (intrusion + defense-evasion):
                # remote/failed logons, account/priv changes, RDP auth, Defender
                # tamper/detect, Security-log clear, backup-catalog delete. Weight ×3 —
                # these rarely fire outside a real incident.
                cur.execute("""
                    SELECT date_trunc('day', event_ts)::date AS d, count(*) c
                    FROM event_logs_v2
                    WHERE case_key=%s AND event_ts IS NOT NULL
                      AND (
                        -- Security-log IDs are only meaningful in the Security channel:
                        -- 1102 has 559 hits here and 2 are real (the rest are
                        -- TerminalServices-RDPClient / ShellCommon-StartLayoutPopulation),
                        -- and 4625 has 310 Application-channel hits that are not logons.
                        (coalesce(channel,'')='Security' AND (
                            (event_id=4624 AND (logon_type ILIKE '%%remote interactive%%' OR logon_type ILIKE '%%RDP%%' OR logon_type='10'))
                            OR event_id=4625
                            OR event_id IN (4720,4728,4732,4756,4724,4738)))
                        OR (event_id=1149 AND channel ILIKE '%%TerminalServices%%')
                        OR (event_id IN (5001,5010,5012) AND coalesce(provider,'') ILIKE '%%Windows Defender%%')
                        OR (event_id IN (1116,1117) AND coalesce(provider,'') ILIKE '%%Windows Defender%%')
                        OR (event_id=1102 AND coalesce(channel,'')='Security')
                        OR (event_id=524 AND coalesce(provider,'') ILIKE '%%Backup%%')
                      )
                    GROUP BY 1
                """, (case_key,))
                for d, c in cur.fetchall():
                    _add(d, int(c) * 3)
                # (2) ransomware detonation: ransom-note creation times. Weight ×5 — a
                # note-drop day is almost always THE incident day.
                cur.execute("""
                    SELECT date_trunc('day', event_ts)::date AS d, count(*) c
                    FROM filesystem_v2
                    WHERE case_key=%s AND event_ts IS NOT NULL
                      AND (lower(file_name) ~ 'restore|decrypt|recover|how.{0,4}to|unlock|_readme|!!!'
                           AND lower(file_name) ~ '\\.(txt|hta|html|htm)$'
                           -- A ransom note lands in user data. Vendor documentation named
                           -- "How to manually restore Android.htm" under Program Files does
                           -- not: on the case_40 case 107 such help files won the window
                           -- at weight x5 and anchored the whole investigation on August
                           -- 2025, a period with zero event-log activity, while the real
                           -- incident was March 2026. Genuine note drops are unaffected -
                           -- case_66 still peaks at 1303 notes on its encryption day.
                           AND lower(coalesce(parent_path,'')) !~ 'program files|programdata|winsxs|driverstore|recycle|system volume information|appdata.local.packages')
                    GROUP BY 1
                """, (case_key,))
                for d, c in cur.fetchall():
                    _add(d, int(c) * 5)
                # (3) SUPPORTING execution/persistence bursts (service install, process
                # creation, PowerShell). NOISY (benign software installs spike these), so
                # weight ×1 AND cap each day at 40 — enough to break ties / anchor APT
                # cases (Gamaredon = tasks+PS heavy) without a benign install day winning.
                cur.execute("""
                    SELECT date_trunc('day', event_ts)::date AS d, count(*) c
                    FROM event_logs_v2
                    WHERE case_key=%s AND event_ts IS NOT NULL
                      AND ((event_id=7045 AND coalesce(channel,'')='System')
                           OR (event_id IN (4697,4688) AND coalesce(channel,'')='Security')
                           OR (event_id=4104 AND channel ILIKE '%%PowerShell%%'))
                    GROUP BY 1
                """, (case_key,))
                for d, c in cur.fetchall():
                    _add(d, min(int(c), 40))
                # (4) DESTRUCTION / staged-deployment markers. A wiper day is a handful of events of
                # several KINDS, not a burst of one kind: the 3-4-19-1N wiper (2026-09-02) scored 0 in
                # tiers 1-3 and the window peaked on a benign August workday, while an OS-install day
                # registers dozens of non-Microsoft tasks on its own. So: each kind counts at most 3
                # (x10), and a day scores only when two or more kinds are present.
                try:
                    from analysis.threat_detect import AV_SERVICE_RX as _avrx
                except Exception:
                    _avrx = 'ekrn|eset|windefend|msmpsvc|msmpeng|sophos|kaspersky|bitdefender|crowdstrike|sentinel'
                cur.execute("""
                    SELECT d, kind, sum(c) FROM (
                      SELECT date_trunc('day', event_ts)::date AS d,
                             CASE WHEN event_id IN (7031,7034) THEN 'av_down'
                                  WHEN event_id=6008 THEN 'shutdown'
                                  WHEN event_id=106 THEN 'task'
                                  ELSE 'destruct_cmd' END AS kind, count(*) c
                      FROM event_logs_v2
                      WHERE case_key=%s AND event_ts IS NOT NULL AND (
                           (event_id IN (7031,7034) AND channel ILIKE '%%System%%' AND payload::text ~* %s)
                        OR (event_id=6008 AND channel ILIKE '%%System%%')
                        OR (event_id=106 AND channel ILIKE '%%TaskScheduler%%' AND coalesce(payload->>'PayloadData1','') NOT ILIKE '%%Microsoft%%')
                        OR (event_id=4688 AND lower(coalesce(command_line,'') || ' ' || coalesce(process_name,''))
                            ~ 'bcdedit|vssadmin|wbadmin|diskpart|cipher.{0,8}/w|format[.]com|wmic.{0,30}shadowcopy')
                      ) GROUP BY 1, 2
                      UNION ALL
                      SELECT date_trunc('day', event_ts)::date,
                             CASE WHEN lower(file_name) LIKE '%%.msi' THEN 'gpo_msi' ELSE 'boot_image' END, count(*)
                      FROM filesystem_v2
                      WHERE case_key=%s AND event_ts IS NOT NULL AND (
                           (lower(file_name) LIKE '%%.msi' AND parent_path ILIKE '%%GroupPolicy%%DataStore%%')
                        OR (lower(file_name) IN ('boot.wim','winpe.wim') AND coalesce(parent_path,'') NOT ILIKE '%%Windows%%Boot%%'
                            AND coalesce(parent_path,'') NOT ILIKE '%%Windows Kits%%' AND coalesce(parent_path,'') NOT ILIKE '%%WindowsRE%%')
                      ) GROUP BY 1, 2
                    ) t GROUP BY 1, 2
                """, (case_key, _avrx, case_key))
                _kinds = {}
                for d, kind, c in cur.fetchall():
                    _kinds.setdefault(d, {})[kind] = min(int(c), 3)
                for d, km in _kinds.items():
                    if len(km) >= 2:
                        _add(d, sum(km.values()) * 10)
        if not day_counts:
            return None
        rows = sorted(day_counts.items(), key=lambda x: x[1], reverse=True)
        peak_day, peak_c = rows[0]
        # cluster = days with >=30%% of peak signal, but bounded to peak ± 21 days so a
        # long-dwell campaign does not stretch the "incident window" across many months.
        thr = max(3, int(peak_c * 0.30))
        lo, hi = peak_day - _td(days=45), peak_day + _td(days=45)  # multi-week campaigns (P0-B stops out-of-window suppression)
        sig_days = sorted(d for d, c in rows if c >= thr and lo <= d <= hi)
        if not sig_days:
            sig_days = [peak_day]
        return {
            'start': str(sig_days[0]),
            'end': str(sig_days[-1]),
            'peak_day': str(peak_day),
            'peak_count': int(peak_c),
            'total_signal': int(sum(c for _, c in rows)),
        }
    except Exception as _e:
        _log.error(f"[agent] incident-window compute error: {_e}")
        return None


# Tools the investigator may call in the follow-up loop, with a terse arg hint.
# Kept to high-signal, read-only pivots (+ KB/cross-case + run_sql for advanced digs).
_INV_LINE_CAP = int(os.environ.get('DFIR_INVESTIGATE_LINE_CAP', '600'))
_INV_RESULT_CAP = int(os.environ.get('DFIR_INVESTIGATE_RESULT_CAP', '6000'))


def _cap_investigate_result(text, line_cap=None, total_cap=None):
    """Keep many rows instead of a few giant ones.

    Measured on job e445d30f: a 20-row search_events answer weighed 125 KB because six
    Sigma rows carried ~9 KB of ScriptBlockText each. Cutting the blob at a flat 6000
    chars threw away most of the rows the model had actually asked for. Capping each row
    first means the same budget carries roughly ten rows rather than one script dump -
    and a truncated row still shows its timestamp, event id and command, which is what
    the model reasons over.
    """
    line_cap = line_cap or _INV_LINE_CAP
    total_cap = total_cap or _INV_RESULT_CAP
    lines = (text or '').splitlines()
    out, used = [], 0
    for i, ln in enumerate(lines):
        if len(ln) > line_cap:
            ln = ln[:line_cap] + ' …[рядок обрізано]'
        if used + len(ln) + 1 > total_cap:
            out.append('…[ще %d рядків не показано]' % (len(lines) - i))
            break
        out.append(ln)
        used += len(ln) + 1
    return '\n'.join(out)


_INVESTIGATE_TOOLS = {
    'search_events': '{"keyword": "<str>", "limit": 20}  # full-text over event log cmdlines/messages',
    'get_powershell_events': '{"limit": 30}  # PowerShell 4104 script blocks',
    'get_suspicious_executables': '{"limit": 40}  # program exec of interest',
    'get_logon_activity': '{"limit": 40}  # logons 4624/4625 incl. remote',
    'get_lateral_movement': '{"limit": 30}  # RDP/SMB/WinRM pivoting',
    'get_persistence_events': '{"limit": 30}  # services/tasks/run keys',
    'get_download_artifacts': '{"since": "YYYY-MM-DD", "limit": 30}  # MOTW/downloads',
    'get_context_window': '{"timestamp": "YYYY-MM-DDTHH:MM:SS", "hours_before": 2, "hours_after": 6}  # what happened around a time',
    'get_user_timeline': '{"username": "<user>"}  # everything one account did',
    'backtrace': '{"anchor_ts": "YYYY-MM-DDTHH:MM:SS", "days_back": 14, "days_forward": 3}  # find delivery before a late-phase anchor',
    'search_knowledge_base': '{"query": "<technique/family>"}  # analyst playbooks + past reports (Qdrant)',
    'run_sql': '{"query": "SELECT ... FROM event_logs_v2 WHERE ..."}  # read-only pivot. Фільтр case_key додається АВТОМАТИЧНО — НЕ пиши його сам',
    'unwind_file': '{"name": "<імʼя файлу>"}  # Course: розкрутка файлу — виконання(Prefetch/Amcache/ShimCache)+4688+Defender+MFT+YARA одним викликом',
}


# ── DFIR-ORDER methodology phases (owner's cheat sheet). Each row: name, label, a WHERE that
# says whether the case HAS data for the phase, and a probe that samples it. Used to steer the
# agentic loop and to guarantee per-phase coverage.
_DFIR_PHASES = [
    ('initial_access', u'Initial Access', "event_id=4688",
     "SELECT event_ts, payload->>'NewProcessName' AS proc, payload->>'ParentProcessName' AS parent, left(payload->>'CommandLine',140) AS cmd FROM event_logs_v2 WHERE case_key=%s AND event_id=4688 ORDER BY event_ts LIMIT 20"),
    ('defender', u'Defender/AV', "event_id IN (1116,1117,1118,1119,5001,5007,5010)",
     "SELECT event_ts, event_id, left(payload::text,180) AS d FROM event_logs_v2 WHERE case_key=%s AND event_id IN (1116,1117,5001,5007) ORDER BY event_ts LIMIT 20"),
    ('logon_rdp', u'Logon/RDP', "event_id IN (4624,4625,1149,4648,4672,4778)",
     "SELECT event_ts, event_id, target_user, logon_type, payload->>'IpAddress' AS ip FROM event_logs_v2 WHERE case_key=%s AND event_id IN (4624,4625,1149,4648) ORDER BY event_ts LIMIT 25"),
    ('process_ps', u'Process/PowerShell', "event_id IN (4688,4103,4104)",
     "SELECT event_ts, event_id, left(coalesce(payload->>'ScriptBlockText',payload->>'CommandLine'),180) AS x FROM event_logs_v2 WHERE case_key=%s AND event_id IN (4104,4688) ORDER BY event_ts LIMIT 20"),
    ('persistence', u'Persistence', "event_id IN (4698,4699,4702,7045,7040)",
     "SELECT event_ts, event_id, coalesce(payload->>'TaskName',payload->>'ServiceName') AS name, left(payload->>'ImagePath',140) AS path FROM event_logs_v2 WHERE case_key=%s AND event_id IN (4698,4702,7045) ORDER BY event_ts LIMIT 20"),
    ('lateral', u'Lateral Movement', "event_id IN (5140,5145,4648,4768,4769,4776)",
     "SELECT event_ts, event_id, target_user, left(payload::text,160) AS d FROM event_logs_v2 WHERE case_key=%s AND event_id IN (5140,5145,4769,4776) ORDER BY event_ts LIMIT 20"),
    ('tampering', u'Tampering/Evasion', "((event_id=1102 AND channel='Security') OR event_id IN (104,1100,4719,4616))",
     "SELECT event_ts, event_id, channel, left(payload::text,140) AS d FROM event_logs_v2 WHERE case_key=%s AND ((event_id=1102 AND channel='Security') OR event_id IN (104,1100,4719,4616)) ORDER BY event_ts LIMIT 20"),
    ('ad_dc', u'AD/DC', "event_id IN (4720,4722,4723,4724,4725,4726,4728,4732,4756,4738,4662,5136,4794)",
     "SELECT event_ts, event_id, target_user, left(payload::text,140) AS d FROM event_logs_v2 WHERE case_key=%s AND event_id IN (4720,4728,4732,4756,4662,5136) ORDER BY event_ts LIMIT 20"),
]


def _phase_coverage(case_key):
    """Methodology phases this case actually HAS data for (skip empty ones). Returns list of
    (name, label, probe_sql, count)."""
    have = []
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            with c.cursor() as cur:
                for name, label, where, probe in _DFIR_PHASES:
                    try:
                        cur.execute("SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND ("
                                    + where + ")", (case_key,))
                        n = int((cur.fetchone() or [0])[0] or 0)
                    except Exception:
                        try:
                            c.rollback()
                        except Exception:
                            pass
                        n = 0
                    if n:
                        have.append((name, label, probe, n))
    except Exception:
        pass
    return have


def _agentic_investigate(case_key, incident_window, seed_summary, collected,
                         progress_cb=None, max_rounds=4, max_tools_per_round=4,
                         job_id=''):
    """LLM-driven follow-the-lead loop. Given the baseline evidence + incident window,
    the model repeatedly decides which tools to pull next (hypothesis → verify → dig →
    backtrack) until it is satisfied. Merges new evidence into `collected` in place and
    returns a human-readable investigation trace to inject into the synthesis prompt.
    Fully exception-safe: any failure returns whatever trace was gathered so far, so the
    report path never breaks. Gated by the caller via DFIR_AGENTIC_LOOP."""
    import urllib.request as _ur
    trace = []
    seen_calls = set()
    # The machine's biography goes in FIRST, ahead of the computed window. The window is a
    # heuristic and has been wrong (it once pointed at a date before the OS was installed);
    # the install date and the data coverage are facts, and seeing them first lets the model
    # notice when the window contradicts them instead of dutifully investigating a period
    # that cannot contain evidence.
    try:
        from analysis.machine_biography import machine_biography as _mbio
        _bio_txt = _mbio(case_key)
    except Exception:
        _bio_txt = ''
    _bio_block = (_bio_txt + '\n\n') if _bio_txt else ''
    win_txt = (f"{incident_window['start']}..{incident_window['end']} (peak {incident_window['peak_day']})"
               if incident_window else "unknown")
    catalog = '\n'.join(f'- {k} {v}' for k, v in _INVESTIGATE_TOOLS.items())
    try:
        from analysis.agent_tools import sql_schema_hint as _ssh
        _schema_txt = _ssh()
    except Exception:
        _schema_txt = ''
    # The catalog names the table but not its columns, so the model used to guess them
    # and waste calls on SQL errors. Real schema, straight from the database.
    _schema_block = (('\n\nСХЕМА ДЛЯ run_sql — ІСНУЮТЬ ЛИШЕ ЦІ таблиці й колонки '
                      '(час — event_ts, НЕ event_time; завжди фільтруй case_key):\n' + _schema_txt)
                     if _schema_txt else '')
    _phases = _phase_coverage(case_key)
    _cover_line = ((u'ФАЗИ МЕТОДИКИ, ДЛЯ ЯКИХ Є ДАНІ (перевір КОЖНУ перш ніж писати done): '
                    + ', '.join(u'%s(%d)' % (lbl, n) for _n, lbl, _p, n in _phases) + '\n\n')
                   if _phases else u'')
    for rnd in range(max_rounds):
        # compact digest of everything gathered so far (names + first line of each)
        digest = []
        for k, v in list(collected.items())[:60]:
            head = (v or '').strip().split('\n')[0][:120]
            digest.append(f"{k.split('|')[0]}: {head}")
        digest_txt = '\n'.join(digest)[:6000]
        trace_txt = '\n'.join(trace)[-3000:]
        planner_prompt = (
            "Ти — старший DFIR-слідчий. Веди розслідування як людина: висувай гіпотезу, "
            "перевіряй її інструментом, копай глибше по знахідках, за потреби роби backtrace. "
            "НЕ пиши звіт зараз — лише вирішуй, які дані ще ВАРТО витягнути.\n"
            f"{_bio_block}ВІКНО ІНЦИДЕНТУ: {win_txt}. Фокус на цьому періоді; старе — baseline.\n"
            f"КОРОТКО ПРО КЕЙС:\n{seed_summary[:2500]}\n\n"
            f"ВЖЕ ЗІБРАНО (інструмент: перший рядок):\n{digest_txt}\n\n"
            + (f"ТВІЙ ХІД ДОСІ:\n{trace_txt}\n\n" if trace_txt else "")
            + _cover_line + "ДОСТУПНІ ІНСТРУМЕНТИ:\n" + catalog + _schema_block + "\n\n"
            "Поверни ЛИШЕ JSON (без markdown):\n"
            '{"reasoning": "<1-2 речення: що підозрюєш і чому саме ці запити>", '
            '"next_tools": [{"tool": "<назва>", "args": {...}}], "done": false}\n'
            f"Максимум {max_tools_per_round} інструменти за раунд. Обери ЛИШЕ те, що звузить картину "
            "(нові зачіпки, підтвердження ланцюга, перетин з іншими кейсами, плейбук по техніці). "
            'Якщо картина вже повна — {"next_tools": [], "done": true}.'
        )
        plan, raw = {}, ''
        # gpt-oss reasoning models spend budget on the reasoning channel first and
        # return EMPTY content if max_tokens is too small → give generous headroom and
        # retry once before giving up on the round.
        _attempts = max(2, int(os.environ.get('DFIR_INVESTIGATE_ATTEMPTS', '3')))
        for _attempt in range(_attempts):
            # A failed attempt is usually the backend being mid-restart or mid-swap, not a
            # bad prompt. Retrying instantly just fails again, so wait - and give llama-swap
            # time to finish loading - before spending the next attempt.
            if _attempt:
                _backoff = 10 * _attempt
                _log.error('[investigate] round %d: waiting %ds before attempt %d'
                           % (rnd, _backoff, _attempt + 1))
                time.sleep(_backoff)
                try:
                    _ur.urlopen(LLM_URL.rstrip('/') + '/v1/models', timeout=20).read(1)
                except Exception as _he:
                    _log.error('[investigate] backend still not answering: %s' % _he)
            try:
                body = json.dumps(build_chat_payload(
                    model=(os.getenv('DFIR_AGENT_JSON_MODEL') or LLM_FAST_MODEL),
                    messages=[{'role': 'user', 'content': planner_prompt}],
                    role='json', temperature=LLM_JSON_TEMPERATURE,
                    max_tokens=int(os.environ.get('DFIR_INVESTIGATE_MAX_TOKENS', '4000')),
                    stream=False, reasoning_effort=os.environ.get('DFIR_JSON_REASONING_EFFORT', 'low'),
                )).encode('utf-8')
                req = _ur.Request(LLM_URL.rstrip('/') + '/v1/chat/completions',
                                  data=body, headers={'Content-Type': 'application/json'})
                with _ur.urlopen(req, timeout=int(os.environ.get('DFIR_INVESTIGATE_TIMEOUT', '240'))) as resp:
                    data = json.loads(resp.read().decode('utf-8', errors='ignore'))
                raw = (data.get('choices') or [{}])[0].get('message', {}).get('content', '') or ''
                st, en = raw.find('{'), raw.rfind('}')
                if st != -1 and en > st:
                    plan = json.loads(raw[st:en+1])
                    break
                _log.error(f"[investigate] round {rnd} attempt {_attempt}: no JSON in content (len={len(raw)}): {raw[:200]!r}")
            except Exception as _pe:
                _log.error(f"[investigate] round {rnd} attempt {_attempt} planner error: {_pe} raw={raw[:150]!r}")
        if not plan:
            # Planner unusable this round. Falling through to the deterministic coverage
            # sweep is the right behaviour - but it used to happen in total silence, so a
            # run where the agent contributed nothing looked identical to a healthy one.
            _log.error('[investigate] PLANNER FAILED at round %d after %d attempts - '
                       'agent contributed nothing beyond the baseline sweep' % (rnd, _attempts))
            _journal.log(case_key, job_id, 'planner_failed', round_no=rnd, ok=False,
                         detail='no usable JSON after %d attempts; last raw=%r' % (_attempts, raw[:300]))
            break
        _journal.log(case_key, job_id, 'planner', round_no=rnd, ok=True,
                     reasoning=str(plan.get('reasoning', ''))[:1500],
                     args={'next_tools': [str(t.get('tool', ''))[:60]
                                          for t in (plan.get('next_tools') or [])[:8]],
                           'done': bool(plan.get('done'))})
        reasoning = str(plan.get('reasoning', ''))[:400]
        next_tools = plan.get('next_tools') or []
        if reasoning:
            trace.append(f"[Раунд {rnd+1}] {reasoning}")
        if plan.get('done') or not next_tools:
            break
        if progress_cb:
            progress_cb(f'investigate_r{rnd+1}', min(78, 60 + rnd * 4))
        for call in next_tools[:max_tools_per_round]:
            tname = str(call.get('tool', '')).strip()
            targs = call.get('args') if isinstance(call.get('args'), dict) else {}
            if tname not in _INVESTIGATE_TOOLS:
                continue
            sig = f"{tname}|{json.dumps(targs, sort_keys=True)}"
            if sig in seen_calls:
                continue
            seen_calls.add(sig)
            try:
                res = str(_execute_agent_tool(tname, targs, case_key))
                low = res.lower()[:80]
                if _is_empty_result(res):
                    trace.append(f"   → {tname}({targs}) = порожньо")
                    _journal.log(case_key, job_id, 'tool', round_no=rnd, tool=tname,
                                 args=targs, result=res, ok=False, detail='empty result')
                    continue
                collected[f"investigate:{sig}"] = _cap_investigate_result(res)
                _journal.log(case_key, job_id, 'tool', round_no=rnd, tool=tname,
                             args=targs, result=res, ok=True)
                trace.append(f"   → {tname}({targs}) = {res.strip().splitlines()[0][:140]}")
            except Exception as _te:
                _log.error(f"[investigate] tool {tname} error: {_te}")
    _log.error(f"[investigate] done: {len(trace)} trace lines, {sum(1 for k in collected if str(k).startswith('investigate:'))} new evidence blocks")
    # ── COVERAGE SWEEP (P2): guarantee every data-bearing methodology phase is represented,
    # even if the planner skipped it. Uses the safe run_sql tool (SELECT-only, read-only txn).
    for _name, _lbl, _probe, _n in _phases:
        sig = 'coverage:' + _name
        if any(str(k).startswith(sig) for k in collected):
            continue
        try:
            _q = _probe.replace('%s', "'" + str(case_key).replace("'", "''") + "'")
            res = str(_execute_agent_tool('run_sql', {'query': _q}, case_key))
        except Exception as _se:
            _log.error(f"[investigate] coverage {_name} error: {_se}")
            continue
        low = res.lower()[:80]
        if len(res) < 12 or 'порожн' in low or 'error' in low or 'no results' in low:
            trace.append(u'   → [покриття] %s — даних для фази немає' % _lbl)
            continue
        collected[sig] = res[:5000]
        trace.append(u'   → [покриття] %s: %s' % (_lbl, res.strip().splitlines()[-1][:120]))
    _log.error(f"[investigate] coverage sweep done: {sum(1 for k in collected if str(k).startswith('coverage:'))} phases")
    try:
        _have_names = {p[0] for p in _phases}
        _gaps = [lbl for (nm, lbl, _w, _pr) in _DFIR_PHASES if nm not in _have_names]
        if _gaps:
            trace.append(u'   → [прогалини збору] фази методики БЕЗ даних: ' + ', '.join(_gaps))
    except Exception:
        pass

    # ── AUTO-UNWIND (P7): run the Course file dossier on the case's suspicious executables,
    # so appearance→execution→hash→Defender is always in the evidence, not only when the model
    # thought to ask. Bounded + exception-safe.
    try:
        _files = []
        with psycopg2.connect(PG_DSN) as _uc:
            _uc.autocommit = True
            with _uc.cursor() as _ucur:
                _ucur.execute(
                    "SELECT executable_name, count(*) FROM program_exec_v2 "
                    "WHERE case_key=%s AND executable_name IS NOT NULL "
                    "AND lower(coalesce(full_path,'')) !~ 'dfirtriage_|dfir_triage|vao_collector|kape_triage' AND ("
                    "  lower(coalesce(full_path,'')) ~ 'temp|appdata|programdata|public|downloads' "
                    "  OR lower(coalesce(executable_name,'')) ~ "
                    "     'mimikatz|ngrok|psexec|procdump|nanodump|chromepass|lazagne|rclone|anydesk|rutserv|netscan|advanced_port|cobalt|meterpreter') "
                    "GROUP BY 1 ORDER BY 2 DESC LIMIT 5", (case_key,))
                _files = [r[0] for r in _ucur.fetchall() if r[0]]
        _done = 0
        for _fn in _files:
            sig = 'unwind:' + str(_fn).lower()
            if any(str(k).startswith(sig) for k in collected):
                continue
            try:
                res = str(_execute_agent_tool('unwind_file', {'name': _fn}, case_key))
            except Exception:
                continue
            if len(res) > 60 and u'не знайдено' not in res:
                collected[sig] = res[:4000]
                trace.append(u'   → [авто-розкрутка] %s' % _fn)
                _done += 1
        if _done:
            _log.error(f"[investigate] auto-unwound {_done} suspicious file(s)")
    except Exception as _ue:
        _log.error(f"[investigate] auto-unwind error: {_ue}")

    return '\n'.join(trace)[:4000]


def _evidence_sufficiency_banner(case_key, structured_input):
    """Anti-confabulation LOW-CONFIDENCE gate. When threat scanners did NOT run
    (tool_alerts_v2 empty) AND the deterministic signature layer found nothing
    high/critical, forbid the LLM from asserting a targeted compromise out of a
    bare narrative. Root cause of the case_56_Gleb false positive (2026-07-22)."""
    try:
        _dets = (structured_input or {}).get("threat_detections") or []
        _hi = sum(1 for f in _dets if isinstance(f, dict) and f.get("severity") in ("critical", "high"))
        _scan_rows = -1
        try:
            with psycopg2.connect(PG_DSN) as _c:
                _c.autocommit = True
                with _c.cursor() as _cu:
                    _cu.execute("SELECT count(*) FROM tool_alerts_v2 WHERE case_key=%s", (case_key,))
                    _scan_rows = int(_cu.fetchone()[0] or 0)
        except Exception:
            _scan_rows = -1
        if _scan_rows == 0 and _hi == 0:
            return (
                u"⚠️ РЕЖИМ НИЗЬКОЇ ДОВІРИ — доказів атаки не знайдено детерміновано.\n"
                u"Сканери загроз НЕ відпрацювали (tool_alerts порожня: Hayabusa/THOR/Sigma без алертів), і детермінований шар не знайшов критичної/високої загрози.\n"
                u"ЗАБОРОНЕНО: стверджувати цілеспрямовану компрометацію, наявність атакувальника, backdoor, exfiltration чи lateral movement лише на основі наративу. Без КОНКРЕТНОГО артефакта-доказу — НЕ вигадуй атакувальника.\n"
                u"ПРАВИЛО КЛАСИФІКАЦІЇ: самозаражені PUA/піратські активатори (KMSAuto, кряки), майнери, HackTool від Defender, легітимні RAT без вхідних сесій (TeamViewer/AnyDesk без inbound logon), OUTBOUND RDP користувача — це НЕ цілеспрямована атака, а self-inflicted PUA або звичайна активність.\n"
                u"ПРО НОВІ СЛУЖБИ/ЗАДАЧІ/ОБЛІК.ДАНІ (GATE_SERVICES_CLAUSE): поява нових служб (EID 7045) чи запланованих завдань (EID 4698) — САМА ПО СОБІ звичайна (драйвери, оновлювачі, легітимний софт). НЕ пиши «зловмисник закріпився» без доказу шкідливості (підозрілий шлях Temp/AppData/ProgramData, random-name, або кореляція з підтвердженою атакою). EID 4648 (explicit credentials) сам по собі — звичайний runas/адмін-дія, а НЕ «підвищення привілеїв зловмисником».\n"
                u"ВЕРДИКТ за замовчуванням: 'Ймовірно чисто / недостатньо даних для висновку про атаку', Confidence=low. Якщо всупереч цьому ти стверджуєш атаку — наведи конкретний timestamp+джерело+артефакт.\n\n"
            )
    except Exception:
        pass
    return u""


def _run_dfir_agent_loop(case_key, structured_input, progress_cb=None, max_iterations=25):
    """
    DFIR analysis: sequential tool collection + single LLM report generation.
    Returns final report text (Ukrainian).
    """
    import urllib.request, urllib.error
    # Report synthesis defaults to the FAST model (user prioritises low latency —
    # the 31b synth was ~50min/report, impractical). Set DFIR_SYNTH_MODEL=reasoner-31b
    # to trade speed for a stronger dense model when quality matters more than time.
    model = os.getenv('DFIR_SYNTH_MODEL', LLM_FAST_MODEL)
    lm_base = LLM_URL
    url = lm_base.rstrip('/') + '/v1/chat/completions'

    meta = structured_input.get('meta', {})
    iocs_brief = ', '.join(
        str(x.get('value', ''))[:40] for x in (structured_input.get('ioc_artifacts') or [])[:6]
    )
    learnings_context = _load_agent_learnings(case_key)

    # --- Incident window (auto-anchor): find the real attack period by security-event
    # density so the LLM anchors the timeline there, not on a stale baseline timestamp.
    _incident_window = _compute_incident_window(case_key)
    if _incident_window:
        _log.error(f"[agent] incident window: {_incident_window['start']}..{_incident_window['end']} "
                   f"peak={_incident_window['peak_day']}({_incident_window['peak_count']})")

    # --- Phase 1: Sequential tool execution ---
    # Step 1: Get triggers to determine FIRST_TS for download artifact search
    _triggers_raw = ''
    _first_ts = None
    try:
        _triggers_raw = str(_execute_agent_tool('get_case_triggers', {'limit': 40}, case_key))
        # Parse FIRST_TS from triggers result
        import re as _re
        _ts_match = _re.search(r'first_ts["\s:]+([0-9T:\.\+\-Z]+)', _triggers_raw)
        if not _ts_match:
            _ts_match = _re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2})', _triggers_raw)
        if _ts_match:
            _first_ts = _ts_match.group(1)[:10]  # YYYY-MM-DD
            # Sanity check: ignore first_ts older than 3 years (noise triggers)
            try:
                from datetime import datetime as _dt_cls
                _ts_year = int(_first_ts[:4])
                _cur_year = _dt_cls.now().year
                if _ts_year <= _cur_year - 3:
                    _log.error(f"[agent] FIRST_TS={_first_ts} too old, ignoring (noise trigger)")
                    _first_ts = None
                else:
                    _log.error(f"[agent] parsed FIRST_TS={_first_ts}")
            except Exception:
                try: conn.rollback()
                except: pass
                pass
    except Exception as _te:
        _log.error(f"[agent] triggers error: {_te}")

    # Compute since date (FIRST_TS minus 14 days)
    _since = None
    if _first_ts:
        try:
            from datetime import datetime, timedelta
            _dt = datetime.fromisoformat(_first_ts)
            _since = (_dt - timedelta(days=14)).strftime('%Y-%m-%d')
        except Exception: pass

    TOOL_PLAN = [
        # --- CONTEXT ---
        ('get_saved_findings', {}),
        ('get_system_profile', {}),
        ('get_sensitive_secrets', {}),
        ('get_case_triggers', {'limit': 40}),
        ('get_log_gaps', {'min_gap_hours': 2}),
        ('get_attack_phases', {}),
        # --- A: DEFENDER / AV ---
        ('get_defender_events', {'limit': 40}),
        ('get_hayabusa_detections', {'min_level': 'high', 'limit': 30}),
        ('get_top_alerts', {'limit': 30}),
        # --- B: LOGON / RDP ---
        ('get_logon_activity', {'limit': 50}),
        ('get_lateral_movement', {'limit': 40}),
        # --- C: PROCESS / POWERSHELL ---
        ('get_powershell_events', {'limit': 40}),
        ('get_suspicious_executables', {'limit': 50}),
        ('search_events', {'keyword': 'powershell', 'limit': 20}),
        ('search_events', {'keyword': 'cmd /c', 'limit': 15}),
        # --- D: PERSISTENCE / SERVICES / TASKS ---
        ('get_persistence_events', {'limit': 40}),
        ('get_registry_persistence', {'limit': 25}),
        ('get_regripper_data', {'limit': 25}),
        # --- E: LATERAL / NETWORK ---
        ('get_srum_network_traffic', {'limit': 40}),
        ('search_events', {'keyword': 'ngrok', 'limit': 15}),
        ('search_events', {'keyword': 'anydesk', 'limit': 10}),
        # --- F: TAMPERING / DEFENSE EVASION ---
        ('get_tampering_events', {'limit': 40}),
        # --- G: ARTIFACTS CONFIRMATION ---
        ('get_artifacts_confirmation', {'limit': 50}),
        ('get_download_artifacts', {'limit': 35, **({'since': _since} if _since else {})}),
        ('get_browser_downloads', {'limit': 30}),
        ('get_browser_activity', {'limit': 60}),
        ('get_filesystem_artifacts', {'pattern': '%Zone.Identifier%', 'limit': 20}),
        ('get_thor_file_hashes', {'limit': 40}),
        # --- H: AD/DC ---
        ('get_ad_events', {'limit': 40}),
        # --- TIMELINE / INTEL ---
        ('get_forensic_timeline', {'limit': 40}),
        # compare_cases REMOVED from per-case synthesis: it injected OTHER cases'
        # IOCs into context and the weak LLM echoed them as this-case facts
        # (e.g. swisstransfer leaking into 06_02). Cross-case stays in /ioc-cross.
        # GENERIC, case-agnostic technique searches. The old plan hard-coded IOCs
        # from OTHER cases (swisstransfer/case_59/try.exe/ngrok/rdpwinst/LAPTOP-…)
        # which leaked those terms into the context; the cross-case guard then saw
        # "foreign" IOCs in the narrative and DISCARDED the whole LLM report. These
        # generic PowerShell/defense-evasion/cred-access keywords apply to ANY case.
        ('search_events', {'keyword': 'Add-MpPreference', 'limit': 12}),
        ('search_events', {'keyword': 'ExclusionPath', 'limit': 10}),
        ('search_events', {'keyword': 'DownloadString', 'limit': 12}),
        ('search_events', {'keyword': 'Invoke-WebRequest', 'limit': 12}),
        ('search_events', {'keyword': 'FromBase64String', 'limit': 10}),
        ('search_events', {'keyword': 'EncodedCommand', 'limit': 10}),
        ('search_events', {'keyword': 'password.txt', 'limit': 10}),
        ('search_events', {'keyword': 'Credential Manager', 'limit': 10}),
        ('search_events', {'keyword': 'lsass', 'limit': 10}),
    ]

    # --- BACKTRACE: if first anchor events are late-phase, search back 14 days ---
    _LATE_PHASE_TRIGGERS = {'log clearing', 'log cleared', '1102', '104', 'defender tamper',
                             'rdp activity', 'quarantine remov', 'remote tool uninstall',
                             'keylogger', 'litemanager', 'rutserv', 'persistence'}
    _backtrace_needed = False
    _backtrace_anchor = None
    try:
        _bt_check = _agent_tool_get_tampering_events(case_key, limit=3)
        _log.error(f"[agent] backtrace-check: tamper_len={len(_bt_check) if _bt_check else 0} found={'не знайдено' not in (_bt_check or '')}")
        if _bt_check and len(_bt_check) > 30 and 'не знайдено' not in _bt_check:
            import re as _re_bt
            _ts_m = _re_bt.search(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})', _bt_check)
            if _ts_m:
                _backtrace_anchor = _ts_m.group(1).replace(' ', 'T')
                _backtrace_needed = True
        _log.error(f"[agent] backtrace-check: needed={_backtrace_needed} anchor={_backtrace_anchor}")
        if _backtrace_needed and _backtrace_anchor:
            TOOL_PLAN.insert(5, ('backtrace', {'anchor_ts': _backtrace_anchor, 'days_back': 14, 'days_forward': 3}))
    except Exception as _bt_exc:
        _log.error(f"[agent] backtrace-check ERROR: {_bt_exc}")

    _COLLECT_HIGH_TOOLS = {
        'backtrace', 'get_suspicious_executables', 'get_download_artifacts',
        'get_artifacts_confirmation', 'get_tampering_events', 'get_defender_events',
        'get_persistence_events', 'get_logon_activity', 'get_forensic_timeline',
        'get_hayabusa_detections', 'get_top_alerts', 'get_attack_phases',
        'get_browser_downloads', 'get_browser_activity', 'get_srum_network_traffic',
    }
    collected = {}
    # ── RESUME: reuse a recent phase-1 sweep instead of redoing ~40 tool calls ───────
    # Phase 1 is deterministic given the case database, and it is most of the run's cost.
    # A run that died after it (container recreate, llama-swap restart, power loss) should
    # not pay for it a second time. Only reused when nothing was ingested since the
    # snapshot was taken, so re-analysing a freshly topped-up case always re-collects.
    # OFF by default: turn on with DFIR_RESUME_PHASE1=1 once validated on a real retry.
    _resume_job_id = str((structured_input or {}).get('job_id', '') or '')
    if os.environ.get('DFIR_RESUME_PHASE1', '0').strip().lower() in ('1', 'on', 'true', 'yes'):
        try:
            _max_age = int(os.environ.get('DFIR_RESUME_MAX_AGE_MIN', '120'))
            _snap, _snap_trace, _age = _journal.load_recent_case_snapshot(case_key, 'phase1', _max_age)
            if _snap and not _journal.ingest_changed_since(case_key, int(_age) + 5):
                collected.update(_snap)
                TOOL_PLAN = []
                _log.error('[agent] phase1 REUSED from a snapshot %.0f min old: %d tools'
                           % (_age, len(_snap)))
                _journal.log(case_key, _resume_job_id, 'phase1_reused', ok=True,
                             detail='%d tools from a snapshot %.0f min old' % (len(_snap), _age))
            elif _snap:
                _log.error('[agent] phase1 snapshot found but the case was re-ingested - collecting fresh')
        except Exception as _re_err:
            _log.error('[agent] phase1 reuse failed, collecting fresh: %s' % _re_err)
    for i, (tool_name, args) in enumerate(TOOL_PLAN):
        if progress_cb:
            progress_cb(f'collect_{tool_name}', min(70, 20 + i * 3))
        try:
            result = _execute_agent_tool(tool_name, args, case_key)
            result_str = str(result)
            low = result_str.lower()[:80]
            if _is_empty_result(result_str):
                continue
            key = f"{tool_name}|{json.dumps(args, sort_keys=True)}"
            store_limit = 8000 if tool_name in _COLLECT_HIGH_TOOLS else 2500
            collected[key] = result_str[:store_limit]
            _log.error(f"[agent] collected {tool_name}: {len(result_str)} chars (stored {min(len(result_str), store_limit)})")
        except Exception as e:
            _log.error(f"[agent] tool {tool_name} error: {e}")

    # Strip EXAMINER-environment noise from everything fed to the LLM so the 20b
    # model does not mistake the analyst's own VM/forensic tools for attacker
    # artifacts / initial access (it wrongly called VMware.Workstation "delivery"
    # and the Cisco cscnvmpt/ancrcl services "persistence").
    try:
        import re as _re_ex
        _EX_RE = _re_ex.compile(
            r'(?i)vmware[. _]?workstation|accessdata|forensic tools|\bftk\b|dell_forensic|'
            r'networkminer|passware|\bfiddler\b|\bwireshark\b|\bcscnvmpt\b|\bancrcl\b|\bacsock\b|'
            r'for_dump_event|\beztools\b|x-ways|autopsy|magnet\s*axiom')
        for _k in list(collected.keys()):
            _kept = [ln for ln in collected[_k].split('\n') if not _EX_RE.search(ln)]
            collected[_k] = '\n'.join(_kept)
    except Exception:
        pass
    _log.error(f"[agent] phase1 done, {len(collected)} tools with data, first_ts={_first_ts}")
    _agent_job_id = str((structured_input or {}).get('job_id', '') or '')
    _journal.log(case_key, _agent_job_id, 'phase1', ok=True,
                 detail='%d tools with data, first_ts=%s' % (len(collected), _first_ts))
    _journal.snapshot(case_key, _agent_job_id, 'phase1', collected)

    # --- Phase 1.5: AGENTIC investigate loop (follow-the-lead) ---
    # Baseline static collection above stays as-is (deterministic coverage = fallback).
    # On top of it, let the model reason about what ELSE to pull. Flag off → pure legacy.
    _investigation_trace = ''
    if os.environ.get('DFIR_AGENTIC_LOOP', '1').strip().lower() not in ('0', 'off', 'false', 'no'):
        try:
            _seed_parts = []
            for _sk in ('get_case_triggers|{}', 'get_system_profile|{}',
                        'get_attack_phases|{}', 'get_hayabusa_detections',
                        'get_defender_events'):
                for _ck2, _cv2 in collected.items():
                    if _ck2.startswith(_sk):
                        _seed_parts.append(f"[{_ck2.split('|')[0]}]\n{_cv2[:800]}")
                        break
            _seed_summary = '\n\n'.join(_seed_parts)[:3000]
            # the investigator starts from the deterministic verdict, so its leads follow
            # the confirmed chain (GPO MSI → task → boot image) instead of the loudest noise
            try:
                _vtxt, _vmeta = _verdict_constraints(case_key, structured_input)
                if _vtxt:
                    _vshort = _vtxt.split("ПРАВИЛА (порушення")[0][:2200]
                    _seed_summary = (_vshort + "\n\n" + _seed_summary)[:5200]
            except Exception:
                pass
            _investigation_trace = _agentic_investigate(
                case_key, _incident_window, _seed_summary, collected,
                progress_cb=progress_cb,
                max_rounds=int(os.environ.get('DFIR_INVESTIGATE_ROUNDS', '3')),
                job_id=_agent_job_id,
            )
            _journal.snapshot(case_key, _agent_job_id, 'investigate', collected,
                              trace=_investigation_trace)
        except Exception as _ie:
            _log.error(f"[agent] agentic investigate failed (using baseline): {_ie}")
            _investigation_trace = ''

    if progress_cb:
        progress_cb('llm_report', 80)

    # --- Phase 2: Single LLM call ---
    # How much a technique search is worth when the context budget starts cutting.
    # Keyed by the keyword TEXT, not by a case: the plan above issues these, and this
    # table only says which of them a forensic reader wants to see first.
    _SEARCH_TIERS = {
        'Add-MpPreference': 0, 'ExclusionPath': 0,          # evasion: a hand-added exclusion is rarely benign
        'lsass': 1, 'Credential Manager': 1, 'password.txt': 1,   # credential access
        'DownloadString': 2, 'Invoke-WebRequest': 2,        # delivery / obfuscated execution
        'FromBase64String': 2, 'EncodedCommand': 2,
        'ngrok': 3, 'anydesk': 3,                           # remote-access tooling
        'powershell': 4, 'cmd /c': 4,                       # broad shell noise: thousands of benign lines
    }
    _plan_search_kws = [a.get('keyword', '') for (t, a) in TOOL_PLAN
                        if t == 'search_events' and isinstance(a, dict) and a.get('keyword')]
    _search_priority = sorted(
        _plan_search_kws,
        key=lambda k: (_SEARCH_TIERS.get(k, 3), _plan_search_kws.index(k)))

    # Priority order: investigation-critical tools first (A-H DFIR order)
    PRIORITY_KEYS = [
        'investigate:',                                                       # agentic follow-ups — the model's own leads
        'backtrace',                                                          # highest: delivery artifacts -14d
        'get_suspicious_executables',                                         # G: масковані EXE, known malware
        'get_tampering_events',                                               # F: tampering — critical for timeline
        'get_defender_events',                                                # A: Defender
        'get_download_artifacts', 'get_browser_downloads',                   # G: artifacts
        'get_artifacts_confirmation',
        'get_attack_phases',
        'get_top_alerts', 'get_hayabusa_detections',
        'get_persistence_events',                                             # D: persistence
        'get_logon_activity', 'get_lateral_movement',                        # B: logon/lateral
        'get_forensic_timeline',
        'get_log_gaps',
        'get_srum_network_traffic',                                           # E: network
        'get_registry_persistence', 'get_regripper_data',
        'get_powershell_events',
        'get_ad_events',                                                      # H: AD/DC
        'get_filesystem_artifacts',
        'get_sensitive_secrets',
        # Technique searches, ranked by _SEARCH_TIERS and taken FROM THE PLAN.
        # Until 2026-08-20 this was a hand-written list naming the artefacts of one
        # old case; the plan had already stopped searching for them, so not one of
        # those entries could match a collected key. Names are in git, not here -
        # writing them down again is how they come back.
        *['search_events|{"keyword": "%s"' % _k for _k in _search_priority],
        'get_case_triggers', 'get_system_profile', 'get_saved_findings',
    ]
    def _sort_key(k):
        for i, p in enumerate(PRIORITY_KEYS):
            if k.startswith(p): return i
        return 99

    sorted_collected = sorted(collected.items(), key=lambda x: _sort_key(x[0]))
    ctx_parts = []
    total = 0
    # Budget: leave room for prompt header + KB ctx + response
    # Budget in chars: Gemma tokenizes Ukrainian at ~2 chars/token.
    # n_ctx=25000 tokens. Reserve 4000 for response, 1500 for prompts → 19500 tokens ≈ 39000 chars for context.
    _ctx_budget = CTX_BUDGET_CHARS
    # Slots below were sized for a 25k-token window. When the budget is raised for a
    # model with a bigger window, scale them with it - otherwise the extra budget lets
    # more tools through but each is still cut where evidence was being lost.
    _slot_scale = max(1.0, float(_ctx_budget) / 40000.0)
    # backtrace gets a large dedicated slot; other high-prio tools 4000; low-prio 1200
    _BACKTRACE_SLOT = BACKTRACE_SLOT
    HIGH_PRIORITY_TOOLS = {
        'get_download_artifacts', 'get_browser_downloads', 'get_browser_activity',
        'get_thor_file_hashes', 'get_filesystem_artifacts', 'get_suspicious_executables',
        'get_srum_network_traffic', 'get_attack_phases', 'get_log_gaps',
        'get_hayabusa_detections', 'get_top_alerts', 'get_sensitive_secrets', 'get_regripper_data',
        'get_defender_events', 'get_powershell_events', 'get_persistence_events',
        'get_tampering_events', 'get_lateral_movement', 'get_artifacts_confirmation',
        'get_forensic_timeline', 'get_logon_activity',
    }
    # A bigger slot for the searches that carry technique signal (tiers 0-2).
    # Same source as the ordering, so the two can never disagree.
    _MALWARE_SEARCH_KEYWORDS = {_k for _k in _plan_search_kws
                               if _SEARCH_TIERS.get(_k, 3) <= 2}
    for key, result in sorted_collected:
        tool_label = key.split('|')[0]
        if tool_label.startswith('investigate:'):
            limit = int(3500 * _slot_scale)
        elif tool_label == 'backtrace':
            limit = int(_BACKTRACE_SLOT * _slot_scale)
        elif tool_label in HIGH_PRIORITY_TOOLS:
            limit = int(4000 * _slot_scale)
        elif tool_label == 'search_events' and any(kw in key for kw in _MALWARE_SEARCH_KEYWORDS):
            limit = int(2000 * _slot_scale)
        else:
            limit = int(1200 * _slot_scale)
        if _RANK_BY_WINDOW and _incident_window:
            result = _rank_evidence_lines(result, _incident_window)
        snippet = f"[{tool_label}]:\n{result[:limit]}"
        if total + len(snippet) > _ctx_budget:
            break
        ctx_parts.append(snippet)
        total += len(snippet)
    context_block = '\n\n'.join(ctx_parts)
    try:
        _log.error('[synth] evidence to model: %d chars from %d/%d tools (budget %d, slots x%.1f)'
                   % (len(context_block), len(ctx_parts), len(sorted_collected), _ctx_budget, _slot_scale))
    except Exception:
        pass
    # Force-feed the deterministic + Hayabusa/Sigma high-signal detections (guaranteed
    # in context, ahead of the budget-trimmed tool dump) — the attack-chain skeleton.
    _threat_block = _build_threat_summary_block(case_key, structured_input)
    _ctx_tool_names = [p.split('\n')[0].strip('[]') for p in ctx_parts]
    _log.error(f"[agent] context_block: {len(ctx_parts)} tools, {total} chars: {_ctx_tool_names}")

    # Fetch KB context based on collected trigger families
    _agent_families = []
    try:
        trig_raw = collected.get('get_case_triggers|{}', '')
        for fam_key in _KB_FAMILY_QUERIES:
            if fam_key.replace('_', ' ').split()[0] in trig_raw.lower() or fam_key in trig_raw.lower():
                _agent_families.append(fam_key)
    except Exception:
        try: conn.rollback()
        except: pass
        pass
    _agent_kb_ctx = _fetch_kb_context_for_incident(_agent_families, hits_per_query=1, max_total=3)

    # Force search_reports: mandatory expert context fetch before synthesis
    _forced_expert_ctx = ''
    try:
        _key_terms = ' '.join([
            collected.get('get_case_triggers|{}', '')[:200],
            iocs_brief[:100],
        ]).strip()
        if _key_terms:
            _forced_expert_ctx = _execute_agent_tool(
                'search_reports',
                {'query': _key_terms[:300]},
                case_key
            )
            if _forced_expert_ctx and 'нічого не знайдено' not in _forced_expert_ctx:
                _forced_expert_ctx = f'[EXPERT REPORTS CONTEXT]:\n{_forced_expert_ctx[:2000]}'
                _log.error(f"[agent] forced search_reports: {len(_forced_expert_ctx)} chars")
            else:
                _forced_expert_ctx = ''
    except Exception as _fse:
        _log.error(f"[agent] forced search_reports error: {_fse}")
        _forced_expert_ctx = ''

    # Expert report sample + benchmark feedback + idle/qa lessons + qa failures
    _expert_sample = _get_expert_style_sample(case_key)
    _known_gaps, _playbooks = _get_benchmark_context(case_key)
    _idle_lessons_list = _get_relevant_lessons(case_key, iocs_brief or case_key, limit=8, for_synthesis=True)
    _idle_lessons_str = ('\n'.join(f'- {l[:400]}' for l in _idle_lessons_list[:6])) if _idle_lessons_list else ''
    _qa_failures_str = _get_qa_failure_hints(case_key, limit=6)
    _qa_pass_str = _get_qa_pass_answers(case_key, limit=4)

    learnings_short = (learnings_context or '')[:300]
    _build_val = meta.get('build') or ''
    _os_str = f"{meta.get('os_name','?')} (build {_build_val})" if _build_val else meta.get('os_name','?')
    _users_str = ', '.join(str(u.get('username','')) for u in (meta.get('users') or []))
    _shutdown_str = meta.get('last_shutdown_utc') or 'невідомо'
    _install_str = meta.get('install_date_utc') or 'невідомо'
    # Caps for GPT-OSS-120B ctx=15063 tokens
    # Expert sample increased: style learning is the most valuable signal
    _expert_sample_cap = (_expert_sample or '')[:2500]
    _agent_kb_ctx_cap = (_agent_kb_ctx or '')[:300]
    _forced_expert_ctx_cap = (_forced_expert_ctx or '')[:300]
    _known_gaps_cap = (_known_gaps or '')[:1200]
    _playbooks_cap = (_playbooks or '')[:300]
    _idle_lessons_cap = _idle_lessons_str[:2000]
    _qa_failures_cap = _qa_failures_str[:400]
    _qa_pass_cap = _qa_pass_str[:300]
    _window_block = ''
    if _incident_window:
        _window_block = (
            f"⚠️ ВІКНО ІНЦИДЕНТУ (обчислено детерміновано за щільністю подій безпеки): "
            f"{_incident_window['start']} — {_incident_window['end']} "
            f"(пік активності {_incident_window['peak_day']}).\n"
            f"Це ОРІЄНТИР, де КОНЦЕНТРУЄТЬСЯ активність (фокус для хронології). "
            f"АЛЕ вікно НЕ ВИКЛЮЧАЄ докази: будь-яка ПІДТВЕРДЖЕНА детектором подія (RDP, RAT/тунель, нові служби, "
            f"AV-детект, очищення логів, створення/зміна акаунтів) — частина справи, навіть якщо її timestamp поза вікном; "
            f"опиши її. КАТЕГОРИЧНО ЗАБОРОНЕНО писати 'у вікні нічого не сталося' чи ставити (gap), якщо детектор дав count>0 "
            f"будь-де в даних. Baseline-шум (старі оновлення, легітимні драйвери) відсіюй — але не плутай його з детекціями.\n"
            f"⛔ ДАТУВАННЯ: дата встановлення ОС ({_install_str}) — це НЕ початок інциденту і НЕ дата атаки. "
            f"ЗАБОРОНЕНО датувати інцидент, initial access чи будь-яку подію найранішим timestamp (він зазвичай = встановлення ОС / first-boot артефакти). "
            f"Період інциденту = ВІКНО вище ({_incident_window['start']} — {_incident_window['end']}). "
            f"Кожну подію датуй ЇЇ ВЛАСНИМ timestamp У МЕЖАХ вікна, а не глобальним мінімумом. "
            f"Якщо подія має дату за роки до вікна — це майже завжди baseline (встановлення ОС, старий софт), НЕ атака.\n"
        )
    _sources_line = ''
    try:
        _sources_line = _source_counts_line(case_key)
    except Exception:
        _sources_line = ''
    # The deterministic verdict goes FIRST, as constraints — not as a footnote in the middle
    # of the evidence dump (that is how a critical wiper finding ended up below "entry
    # point could not be established" on 2026-09-04).
    _verdict_block, _verdict_meta = _verdict_constraints(case_key, structured_input)
    prompt = (
        (_verdict_block + "\n\n" if _verdict_block else "")
        + f"КЕЙС: {case_key}\n"
        + _window_block
        + _sources_line
        + f"ХОСТ: {meta.get('computer_name','?')} | ОС: {_os_str} | Timezone: {meta.get('utc_offset','?')}\n"
        f"Встановлення ОС: {_install_str} | Останнє вимкнення: {_shutdown_str}\n"
        f"Локальні акаунти (SAM): {_users_str or 'невідомо'}\n"
        f"Відомі IOC: {iocs_brief or 'невідомо'}\n"
        + (f"Досвід: {learnings_short}\n" if learnings_short else "")
        + (_agent_kb_ctx_cap + "\n\n" if _agent_kb_ctx_cap else "")
        + (f"[ЕТАЛОННИЙ ЗВІТ АНАЛІТИКА — ПИШИ ТОЧНО В ТАКОМУ СТИЛІ, З ТАКОЮ Ж ГЛИБИНОЮ І ДЕТАЛІЗАЦІЄЮ]:\n{_expert_sample_cap}\n[КІНЕЦЬ ЕТАЛОНУ]\n\n" if _expert_sample_cap else "")
        + (f"[ПРОГАЛИНИ З ПОПЕРЕДНІХ АНАЛІЗІВ]:\n{_known_gaps_cap}\n\n" if _known_gaps_cap else "")
        + (f"[ПЛЕЙБУК]:\n{_playbooks_cap}\n\n" if _playbooks_cap else "")
        + (f"[УРОКИ З САМОНАВЧАННЯ]:\n{_idle_lessons_cap}\n\n" if _idle_lessons_cap else "")
        + (f"[ПРАВИЛЬНІ ВІДПОВІДІ З ПОПЕРЕДНІХ ПЕРЕВІРОК]:\n{_qa_pass_cap}\n\n" if _qa_pass_cap else "")
        + (f"[ДЕ БОТ ПОМИЛЯВСЯ РАНІШЕ — ПЕРЕВІР ОБОВ'ЯЗКОВО]:\n{_qa_failures_cap}\n\n" if _qa_failures_cap else "")
        + (f"{_forced_expert_ctx_cap}\n\n" if _forced_expert_ctx_cap else "")
        + (f"[ПРІОРИТЕТНІ ДЕТЕКЦІЇ — ОБОВ'ЯЗКОВО ВИКОРИСТАЙ ЯК ОСНОВУ ВИСНОВКУ І ХРОНОЛОГІЇ; це підтверджені сигнатури + Hayabusa/Sigma]:\n{_threat_block}\n\n" if _threat_block else "")
        + (("⛔ ЗАЛІЗНЕ ПРАВИЛО КОНСИСТЕНТНОСТІ (найважливіше): усі пункти блоку ПРІОРИТЕТНІ ДЕТЕКЦІЇ вище — це ПІДТВЕРДЖЕНІ детермінованими сигнатурами факти. Кожен пункт з count>0 ТИ ЗОБОВ'ЯЗАНИЙ відобразити у наративі, хронології, списку IOC і вердикті. КАТЕГОРИЧНО ЗАБОРОНЕНО писати 'немає persistence', 'немає віддаленого доступу', 'немає exfiltration', 'атака зупинилась на доставці', 'ознак не виявлено' — для будь-якої категорії, де детектор дав count>0. Якщо детектор знайшов RAT/тунель (AnyDesk/ngrok/RustDesk), нові служби (EID 7045), створення акаунтів (4720/4728/4732), хакерські інструменти (psexec/nltest/mimikatz) чи вимкнення Defender — ти МУСИШ це описати як факт, а не заперечувати. Твій наратив НЕ МОЖЕ суперечити блоку детекцій.\n\n"))
        + (f"[ХІД РОЗСЛІДУВАННЯ — так ти (слідчий) розкручував справу крок за кроком; спирайся на ці зачіпки й підтвердження при побудові наративу та хронології]:\n{_investigation_trace}\n\n" if _investigation_trace else "")
        + "УВАГА — ШУМ СЕРЕДОВИЩА ЕКСПЕРТА (НЕ вважати IOC / initial access / collection): Dell_Forensic, VMware Workstation, AccessData/FTK, NetworkMiner, Passware, Fiddler, Wireshark, 7za у форензик-шляхах, Cisco-сервіси cscnvmpt/ancrcl/acsock. Це інструменти та ВМ аналітика, НЕ артефакти атаки. Будуй висновок і attack-chain на блоці ПРІОРИТЕТНІ ДЕТЕКЦІЇ (Hayabusa/Sigma/детерміновані сигнатури), а не на цьому шумі.\n"
        + '⛔ ЧАС ПОДІЙ: кожна подія МУСИТЬ мати СВІЙ реальний timestamp з доказів; НЕ приписуй кільком різним подіям (ngrok/7za/try/акаунт) один час; невідомий — познач діапазон. Час — у поясі кейсу, познач пояс ПРАВИЛЬНО (не UTC якщо локальний).'
        + '⛔ ШУМ ЗНОВУ: Fiddler, Wireshark, 7za, NetworkMiner, FTK, msedgex у форензик-контексті — НЕ інструменти атаки, НЕ exfiltration/monitoring/collection без ПРЯМого доказу.'
        + "FORENSIC ДАНІ — це єдине джерело фактів для звіту:\n"
        + f"{context_block}\n\n"
        + "ЗАВДАННЯ:\n"
        + "Напиши красивий, структурований, клієнтський DFIR-звіт українською. "
        + "Не роби сухий dump. Пояснюй простими словами, але кожен технічний висновок підкріплюй timestamp + source. "
        + "Якщо факт не підтверджений — пиши 'ймовірно' або 'потребує ручної перевірки', але не вигадуй.\n\n"
        + "ФОРМАТ ВІДПОВІДІ ОБОВʼЯЗКОВО — чистий Markdown без службових заголовків типу Run/status/job_id і без згадки LM Studio/tool-функцій:\n"
        + "# FORENSIC ЗВІТ\n\n"
        + "## 1. ВХІДНІ ДАНІ\n"
        + "Кейс, хост, ОС, timezone, дата встановлення ОС, останнє вимкнення, локальні акаунти, AV/Defender, основні джерела доказів.\n\n"
        + "## 2. ПИТАННЯ – ВІДПОВІДЬ\n"
        + "У стилі звітів аналітика: кожне питання окремим підзаголовком або жирним рядком, відповідь простими словами. Покрий: який ПК/ОС; активна фаза; перша точка зараження/якщо не доведена — найсильніше підтверджене вікно; як зайшли; що запустилось; AV/Defender; акаунти; persistence; remote access; архівація/exfiltration; першочергові дії. Якщо у FORENSIC ДАНИХ є initial_access_highlights — ОБОВʼЯЗКОВО використай їх і познач confirmed/likely залежно від confidence.\n\n"
        + "## 3. ЗАГАЛЬНИЙ ВИСНОВОК\n"
        + "Це головний модуль. Напиши 3-5 людських абзаців, як у звітах експерта: що сталося, з якої дати, як користувач/ПК міг бути скомпрометований, що отримав атакувальник, які ризики для бізнесу. Потім блоки:\n"
        + "### Встановлено точно\n- ...\n### Ймовірно\n- ...\n### Потребує ручної перевірки\n- ...\n\n"
        + "## 4. ЗАГАЛЬНА ІНФОРМАЦІЯ ПРО СИСТЕМУ\n"
        + "OS/host/timezone/install/shutdown/accounts/SAM/remote tools/services/AV.\n\n"
        + "## 5. ХРОНОЛОГІЯ ПОДІЙ З ДОКАЗАМИ\n"
        + "20–30 ключових attack-chain подій, якщо даних достатньо. Не обрізай цей розділ. Перша подія — найкращий initial_access_highlight, якщо він є; якщо прямого initial access немає — чесно познач gap. Кожна подія як картка:\n"
        + "### Подія N — коротка назва\n- Час: ...\n- Фаза: delivery/execution/persistence/remote_access/tampering/impact/collection\n- Що сталося: ...\n- Чому це важливо: ...\n- Джерело доказу: реальний EVTX/CSV/Prefetch/AppCompatCache/MFT/Zone.Identifier/browser source\n- Confidence: confirmed/likely/suspicious\n\n"
        + "## 6. ІНДИКАТОРИ КОМПРОМЕТАЦІЇ (IOC)\n"
        + "Файли, шляхи, хеші якщо є, акаунти, IP/URL/домени, tools. Кожен IOC окремою markdown-карткою: Тип / Значення / Роль в атаці / Джерело / Confidence.\n\n"
        + "## 7. РЕКОМЕНДАЦІЇ\n"
        + "### Негайно (P0)\n### Короткостроково (P1)\n### Довгостроково (P2)\nДля кожної дії — очікуваний результат.\n\n"
        + "## 8. ЯКІСТЬ ДОКАЗІВ І ПРОГАЛИНИ\n"
        + "Що доведено точно, що ймовірно, які джерела бракують, які timestamp caveats.\n\n"
        + "ВАЖЛИВО: якщо evidence містить дані — заборонено писати 'дані відсутні'. Заборонено посилатись на назви tool-функцій як джерела; НІКОЛИ не пиши [get_attack_phases], [get_case_triggers], [pivot], [run_sql]. Перетворюй їх у реальні джерела: EVTX, Prefetch, Amcache/AppCompatCache, MFT, Zone.Identifier, SRUM, THOR, browser history, конкретний CSV/EVTX filename. "
        + "Не використовуй markdown-таблиці з символом | — Telegram їх погано показує. Замість таблиць роби акуратні списки/картки з полями."
    )
    _log.error(f"[agent] prompt sizes: prompt={len(prompt)} ctx={len(context_block)} lessons={len(_idle_lessons_cap)} gaps={len(_known_gaps_cap)} qa_fails={len(_qa_failures_cap)} qa_pass={len(_qa_pass_cap)}")
    _ev_gate = _evidence_sufficiency_banner(case_key, structured_input)
    if _ev_gate:
        prompt = _ev_gate + prompt
        _log.error("[agent] evidence-sufficiency LOW-CONFIDENCE gate ENGAGED for %s" % case_key)

    _expert_hint = (
        "Якщо в промпті є [ЕТАЛОННИЙ ЗВІТ АНАЛІТИКА] — відповідай ТОЧНО ТАКОЮ Ж глибиною, деталізацією та структурою. "
        "Це еталонний звіт людини-аналітика, твій звіт має бути не гіршим за деталізацією і стилем.\n"
    ) if _expert_sample else ""
    _verdict_hint = (
        "НАЙВИЩИЙ ПРІОРИТЕТ: блок «ВЕРДИКТ ДЕТЕРМІНОВАНОГО ШАРУ» на початку запиту — це межі твого звіту. "
        "Тяжкість не вище вердикту; точка входу = його якір; шляхи лише з IOC/доказів; власний слід конвеєра "
        "(vao_collector, KAPE, 7za у DFIRTriage, dfp_*.ps1) — не атака. Порушення = брак.\n"
    ) if _verdict_block else ""
    sys_msg = (
        "Ти — досвідчений forensic-аналітик (DFIR, GCFE/Exam). Звіт ТІЛЬКИ на основі даних у запиті. "
        "Мова: українська. Стиль Study Course. Для кожного факту: timestamp + джерело.\n"
        + _verdict_hint
        + _expert_hint
        + "\nINITIAL ACCESS RULES (строго):\n"
        "НЕ є initial access: EID 1102/104 (log clear), 5001/5007 (Defender tamper), 1149/4624 (RDP), 4697/7045 (service). Це пізня фаза.\n"
        "Scoring: download_only=candidate; download+Prefetch/Amcache(0-60хв)=strong; download+AppCompatCache+Prefetch=confirmed.\n"
        "ЯКЩО перший якір=tamper/RDP → шукай [backtrace] для delivery за -14 днів.\n"
        "ЯКЩО [backtrace] містить LNK/EXE/Prefetch → це і є delivery timestamp (НЕ раніші download-only entries).\n"
        "Часові рамки: початок = timestamp першого delivery artifact з [backtrace] або [get_download_artifacts] з LNK/EXE доказом.\n\n"
        "ZONE.ID FILTERING (критично):\n"
        "⚠️ Zone.ID від ЛЕГІТИМНИХ ДЖЕРЕЛ — НЕ initial access: zakon.rada.gov.ua, minjust.gov.ua, justice-km.gov.ua, iit.com.ua, google.com, drive.google.com, doc.justice, minjust. Це звичайна нотаріальна робота.\n"
        "✅ Zone.ID = PHISHING тільки якщо: домен підозрілий (swisstransfer, pixeldrain, mega, ukr.net/mail attach, tinyurl→redirect, coopterra.it, незнайомий хостинг) І файл = ZIP/EXE/DLL/VBS.\n"
        "✅ Підтвердження phishing: ZIP/EXE Download + execution малварного файлу за <2 годин = CONFIRMED initial access.\n\n"
        "СТРУКТУРА (8 розділів, всі обов'язкові):\n"
        "1. ВИСНОВОК / EXECUTIVE SUMMARY:\n"
        "   a) КОРОТКА ЛЮДСЬКА РОЗПОВІДЬ (showcase ШІ): 5-7 живих простих речень для керівника — як зрозуміла детективна хронологія: що сталося, з чого почалось, чим небезпечно, що зробити першим. БЕЗ жаргону й EID у самому тексті, читається природно, ніби пояснює людина-експерт. Кожен факт спирається на докази нижче.\n"
        "   b) Ключові поля окремими рядками: Verdict, Confidence, Infection point, Attack window, Causal chain, Business impact.\n"
        "   c) Causal chain одним рядком: delivery → execution → persistence/remote access → defense evasion → impact. Якщо ланка не доведена, познач 'gap', але не прибирай підтверджені ланки.\n"
        "2. СИСТЕМА: ОС/hostname/timezone/install/shutdown/акаунти(SAM з датами та Login Count)/remote tools/EID 7045/AV.\n"
        "3. DFIR A-H (ВСІ обов'язкові):\n"
        "A)DEFENDER: EID 1116/5001/5007, threat/path/exclusions/tamper.\n"
        "B)LOGON/RDP: EID 4624/4625/1149, account/type/IP/sessions. Вказати звідки (hostname/IP зловмисника).\n"
        "C)PROCESS/PS: EID 4688/4104, LOLBins/base64/IEX/Add-MpPreference. Вказати конкретні підозрілі EXE з program_exec.\n"
        "D)PERSISTENCE: EID 4698/7045, task/service/Run keys. Обов'язково перерахувати конкретні завдання/сервіси з назвами та шляхами.\n"
        "E)LATERAL/NET: EID 5140/4771, SRUM MB/day per RAT process. ngrok authtoken якщо знайдено.\n"
        "F)TAMPERING: EID 1102/104/5007, channel/user/before-after.\n"
        "G)ARTIFACTS: AppCompatCache/Amcache[program_exec_v2], Prefetch(.pf), Zone.Identifier(HostUrl від ПІДОЗРІЛИХ доменів), LNK, browser downloads.\n"
        "  ⚠️ MFT timestamps часто системні (1980/1985/2013) — не використовувати для Initial Access без підтвердження з EVTX/Prefetch/Amcache.\n"
        "  Ключові малварні EXE: ngrok.exe, try.exe, not.exe, nott.exe, webbrowserpassview, rdpwinst — вказати timestamp+SHA1 якщо є. 7za.exe — лише якщо він НЕ у власному сліді конвеєра (DFIRTriage_*, після запуску vao_collector); fiddler — лише поза форензик-контекстом.\n"
        "H)AD/DC: EID 4720/4726/4732, або явно 'AD даних немає'.\n"
        "BROWSER/DOWNLOAD (пріоритет): ZIP/EXE від підозрілих доменів → HostUrl/ReferrerUrl + timestamp. Phishing = конкретна назва файлу та URL.\n"
        "ЧЕРВОНІ КОМБІНАЦІЇ (якщо бачиш у даних — познач ЯВНО як сильний сигнал, не шум): "
        "5001+5007 поряд з 4688 (Defender вимкнули→виконання); 4624 type10 + 4672 + 4688 (RDP+привілеї+виконання); "
        "4698/7045 з шляху Temp/AppData/ProgramData (persistence з підозрілого місця); 4720 + 4728/4732/4756 (створили акаунт і одразу дали права); "
        "1102/104 ПІСЛЯ 4688/7045 (зачистка слідів після виконання/persistence).\n\n"
        "4. ХРОНОЛОГІЯ (20–30 пунктів, тільки важливі attack-chain події, без шуму):\n"
        "Кожен пункт оформлюй НЕ таблицею, а карткою:\n"
        "- Час: ...\n"
        "  Фаза: delivery/execution/persistence/remote_access/tampering/impact/collection\n"
        "  Подія: ...\n"
        "  Чому важливо: ...\n"
        "  Джерело: реальний файл/таблиця evidence\n"
        "  Confidence: confirmed/likely/suspicious\n"
        "Обов'язково включити initial_access_highlights, перші EXE/script executions, persistence, backdoor users, RDP/remote sessions, Defender tampering, log clearing, collection/exfil/impact якщо є у даних. Не вимагай phishing email/link, якщо його немає; пиши як gap.\n\n"
        "5. IOC (кожен IOC окремою карткою, без markdown-таблиць):\n"
        "Для кожного IOC: Тип, Значення, Роль в атаці, Джерело, Confidence.\n"
        "Типи: FILE (path + SHA1/MD5 якщо є), IP, DOMAIN/URL, ACCOUNT, TASK, SERVICE, HASH, TOOL, COMMAND.\n"
        "Якщо IOC невідомий — все одно вписати з поміткою 'не підтверджено'.\n"
        "6. GAPS: GAP/SOURCES CHECKED/FOUND/NOT FOUND/MANUAL CHECK для кожної прогалини.\n"
        "7. РЕКОМЕНДАЦІЇ:\n"
        "   НЕГАЙНО (сьогодні): ізоляція машини, блокування зовнішніх IP/акаунтів, скидання паролів.\n"
        "   КОРОТКОСТРОКОВО (тиждень): видалення persistence, перевірка інших машин на ті ж IOC.\n"
        "   ДОВГОСТРОКОВО: що змінити щоб це не повторилось.\n\n"
        "Джерела: [AppCompatCache]/[Amcache]/[Prefetch]/[MFT]/[EVTX]/[Zone.ID]/[SRUM]/[THOR]/[browser_downloads].\n\n"
        "НАЗВИ ДЖЕРЕЛ У ЗВІТІ (ОБОВ'ЯЗКОВО використовувати реальні назви файлів KAPE, НЕ назви функцій):\n"
        "get_defender_events → Microsoft-Windows-Windows Defender%4Operational.evtx\n"
        "get_logon_events → Security.evtx (EID 4624/4625/4648/4634/4647)\n"
        "get_process_events → Security.evtx (EID 4688) або Sysmon.evtx (EID 1)\n"
        "get_scheduled_tasks → Microsoft-Windows-TaskScheduler%4Operational.evtx (EID 4698/4702)\n"
        "get_service_events → System.evtx (EID 7045/7036)\n"
        "get_tampering_events → Security.evtx (EID 1102) або System.evtx (EID 104)\n"
        "get_rdp_events → Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx (EID 1149)\n"
        "get_download_artifacts → Zone.Identifier (NTFS ADS у папках Downloads/Desktop/Temp)\n"
        "program_exec_v2 → Prefetch (C:\\Windows\\Prefetch\\*.pf), AppCompatCache (SYSTEM hive), Amcache.hve\n"
        "filesystem_v2 → $MFT, $UsnJrnl:$J\n"
        "event_logs_v2 → відповідний EVTX файл за EID (Security/System/Application)\n"
        "tool_alerts_v2 → THOR/LOKI scan результати\n"
        "browser_downloads_v2 → Chrome: C:\\Users\\...\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History (SQLite)\n"
        "НЕ ПИСАТИ '[get_defender_events]' або '[get_logon_events]' — лише реальні назви файлів!"
    )
    _log.error(f"[agent] total LLM input: sys={len(sys_msg)} prompt={len(prompt)} total={len(sys_msg)+len(prompt)} (~{(len(sys_msg)+len(prompt))//3} tokens)")
    import time as _time
    _job_id_hb = structured_input.get('job_id', '')

    def _hb_update():
        if _job_id_hb:
            try:
                with psycopg2.connect(PG_DSN) as _hb_conn:
                    with _hb_conn.cursor() as _hb_cur:
                        _hb_cur.execute("UPDATE dfir_run_jobs_v2 SET last_heartbeat_at=now() WHERE job_id=%s AND status='running'", (_job_id_hb,))
            except Exception:
                pass

    def _llm_stream_call(url, body_bytes, timeout_total=3600):
        """Stream LLM response and wait long enough for a full analyst Markdown report."""
        req = urllib.request.Request(url, data=body_bytes, headers={'Content-Type': 'application/json'})
        chunks = []
        t_start = _time.time()
        completed = False
        with urllib.request.urlopen(req, timeout=600) as resp:
            while True:
                line = resp.readline()
                if not line:
                    break
                line = line.decode('utf-8', errors='ignore').strip()
                if not line or line == 'data: [DONE]':
                    if line == 'data: [DONE]':
                        completed = True
                        break
                    continue
                if line.startswith('data: '):
                    try:
                        chunk = json.loads(line[6:])
                        delta = (chunk.get('choices') or [{}])[0].get('delta', {}).get('content', '')
                        if delta:
                            chunks.append(delta)
                    except Exception:
                        pass
                if _time.time() - t_start > timeout_total:
                    _log.error(f"[agent] stream timeout after {timeout_total}s, captured {len(''.join(chunks))} chars; response incomplete")
                    return ''.join(chunks), False
                if len(chunks) % 50 == 0 and chunks:
                    _hb_update()
        return ''.join(chunks), completed

    # TOKEN BUDGET (2026-09-06). Three of eight runs produced no narrative at all: case_45's
    # prompt was 33,993 tokens against reasoner-31b's 32,768 context (HTTP 400), and on two
    # phishing cases the prompt ate almost the whole window, so max_tokens=24000 left the
    # server nothing to generate and it returned an empty completion three times. Fit the
    # request to the model: shrink the evidence block until the prompt leaves room for the
    # answer, and never ask for more output tokens than the window can hold.
    _ctx_tokens = int(os.environ.get('DFIR_SYNTH_CTX', '32768'))
    _want_out = int(os.environ.get('DFIR_AGENT_MAX_TOKENS', '24000'))
    _min_out = int(os.environ.get('DFIR_AGENT_MIN_OUT', '6000'))
    _cpt = float(os.environ.get('DFIR_CHARS_PER_TOKEN', '2.6'))   # Ukrainian + paths, conservative
    def _tok(s):
        return int(len(s or '') / _cpt) + 1
    _reserve = 512
    _room = _ctx_tokens - _tok(sys_msg) - _tok(prompt) - _reserve
    if _room < _min_out and context_block and context_block in prompt:
        _need_chars = int((_min_out - _room) * _cpt) + 200
        _keep = max(4000, len(context_block) - _need_chars)
        _short = context_block[:_keep] + "\n\n[... evidence обрізано під контекст моделі: показано %d з %d символів ...]" % (_keep, len(context_block))
        prompt = prompt.replace(context_block, _short, 1)
        _log.error("[agent] prompt trimmed to fit ctx=%d: context %d -> %d chars" % (_ctx_tokens, len(context_block), _keep))
        context_block = _short
        _room = _ctx_tokens - _tok(sys_msg) - _tok(prompt) - _reserve
    _max_out = max(1024, min(_want_out, _room))
    _log.error("[agent] token budget: ctx=%d prompt~%d sys~%d -> max_tokens=%d" % (_ctx_tokens, _tok(prompt), _tok(sys_msg), _max_out))

    for _attempt in range(1, 4):
        try:
            body = json.dumps(build_chat_payload(
                model=model,
                messages=[
                    {"role": "system", "content": sys_msg},
                    {"role": "user", "content": prompt}
                ],
                role='strong',
                temperature=float(os.environ.get('DFIR_AGENT_TEMPERATURE', '0.18')),
                max_tokens=_max_out,
                stream=True,
                reasoning_effort=os.environ.get('DFIR_AGENT_REASONING_EFFORT', 'low'),
            )).encode('utf-8')
            report, stream_completed = _llm_stream_call(url, body, timeout_total=3600)
            _log.error(f"[agent] report generated attempt={_attempt}, len={len(report)}, completed={stream_completed}")
            if not stream_completed:
                _log.error(f"[agent] streamed narrative incomplete attempt={_attempt}; waited up to 3600s")
                if _attempt < 3:
                    continue
            # Validate: Gemma degenerates to <unused24> tokens when context overflows
            if report and len(report) > 200:
                _unused_count = report.count('<unused')
                _unused_ratio = _unused_count * 8 / len(report)  # each tag ~8+ chars
                if _unused_ratio > 0.1:
                    _log.error(f"[agent] garbage output: {_unused_count} <unused> tokens ({_unused_ratio:.2f}), skipping")
                    report = ''
            # EMPTY/SHORT narrative WITHOUT an exception = the backend returned nothing
            # (llama-swap mid-swap, or a gpt-oss reasoning-only turn). This is TRANSIENT —
            # but retrying instantly hammers the swapping backend and all attempts fail in
            # seconds → silent deterministic fallback. Wait ~15s (like the error path) so
            # the model finishes loading, THEN retry. This is what saves the AI narrative.
            if not (report and len(report) > 200) and _attempt < 3:
                _log.error(f"[agent] empty/short narrative attempt={_attempt} (len={len(report) if report else 0}); backend likely swapping — wait 15s then retry")
                for _hb_i in range(3):
                    _time.sleep(5)
                    _hb_update()
                continue
            if report and len(report) > 200:
                try:
                    _save_agent_learnings(case_key, structured_input.get('job_id', ''), {}, report)
                    _sync_iocs_to_pg(case_key)
                except Exception as le:
                    _log.error(f"[agent] post-report tasks error: {le}")
                return report
        except Exception as e:
            body_err = ''
            if hasattr(e, 'read'):
                try: body_err = e.read().decode('utf-8', errors='ignore')[:500]
                except Exception: pass
            is_unloaded = ('unload' in body_err.lower() or 'unload' in str(e).lower()
                           or 'canceled' in body_err.lower() or 'canceled' in str(e).lower()
                           or 'timed out' in str(e).lower() or 'timeout' in str(e).lower())
            # Connection-level drops: llama-swap closes the socket mid-request when it
            # swaps the model in/out ("Remote end closed connection without response",
            # ConnectionReset, BadStatusLine, IncompleteRead). These are TRANSIENT —
            # the very next request hits the now-loaded model and succeeds. The old code
            # only retried on 'unloaded', so a swap-time disconnect killed the whole
            # narrative → the report silently fell back to the deterministic template.
            _es = str(e).lower()
            is_conn = (isinstance(e, (ConnectionError, urllib.error.URLError))
                       or 'remote end closed' in _es or 'connection reset' in _es
                       or 'connection aborted' in _es or 'broken pipe' in _es
                       or 'badstatusline' in _es or 'incompleteread' in _es
                       or 'remotedisconnected' in _es or 'connection refused' in _es)
            is_retryable = is_unloaded or is_conn
            _log.error(f"[agent] LLM report error attempt={_attempt}: {e} | body={body_err!r} retryable={is_retryable} (unloaded={is_unloaded} conn={is_conn})")
            if is_retryable and _attempt < 3:
                _log.error(f"[agent] transient LLM error, waiting ~15s then retry (attempt {_attempt+1}/3)")
                for _hb_i in range(3):
                    _time.sleep(5)
                    _hb_update()
                continue
            break

    # Fallback: plain summary of collected data
    fallback = '\n\n'.join(f"**{k.split('|')[0]}**\n{v}" for k, v in collected.items())
    return fallback or 'Дані не зібрані.'



def _call_ollama_structurer(structured_input):
    import urllib.request, urllib.error
    model = LLM_FAST_MODEL
    lm_base = LLM_URL
    url = lm_base.rstrip('/') + '/v1/chat/completions'

    trimmed_input = _trim_structured_input_for_llm(structured_input)

    prompt = (
        "Ти — судово-технічний аналітик (DFIR). Напиши повний людиночитаний звіт УКРАЇНСЬКОЮ МОВОЮ "
        "виключно на основі фактів з INPUT_JSON. Нічого не вигадуй.\n\n"
        "Структура звіту (суворо дотримуйся):\n\n"
        "## Загальний висновок\n"
        "Одним абзацом: вердикт (компрометація / підозра / чисто), хост, часове вікно, рівень впевненості, "
        "головні вектори атаки.\n\n"
        "## Хронологія атаки\n"
        "Кожна подія з нового рядка у форматі:\n"
        "• [timestamp] — [що сталося простими словами] — джерело: [таблиця | файл]\n"
        "Впорядкуй за часом. Виводь лише події з часовими мітками.\n\n"
        "## Підтверджені знахідки\n"
        "Маркований список: що знайдено, де знайдено, чому підозріло.\n\n"
        "## IOC та артефакти\n"
        "Маркований список: підозрілі файли, IP-адреси, інструменти, облікові записи.\n\n"
        "## Що перевірити вручну\n"
        "Пронумерований список конкретних дій для аналітика.\n\n"
        "INPUT_JSON:\n" + json.dumps(trimmed_input, ensure_ascii=False)
    )

    body = json.dumps({
        'model': model,
        'messages': [{'role': 'user', 'content': prompt}],
        'temperature': 0.15,
        'max_tokens': 8192,
        'stream': False
    }).encode('utf-8')
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=180) as resp:
        data = json.loads(resp.read().decode('utf-8', errors='ignore'))
    if 'error' in data and 'choices' not in data:
        raise RuntimeError(f"LLM API error: {data['error']}")
    text = (data.get('choices') or [{}])[0].get('message', {}).get('content', '') or ''
    return text


def _validate_ollama_output(text, structured_input):
    # hard rule: reject if output contains Source lines not present in evidence table|file pairs (rule #5)
    allowed = set()
    for ev in structured_input.get('attack_chronology_events', []):
        for e in ev.get('evidence', []):
            t = e.get('source_table') or ''
            f = e.get('source_file') or ''
            if t and f:
                allowed.add(f"{t} | {f}")

    source_lines = [ln.strip() for ln in text.splitlines() if ln.strip().lower().startswith('source:')]
    for ln in source_lines:
        val = ln.split(':', 1)[1].strip()
        if val and val not in allowed:
            return False, f'invalid_source_attribution:{val[:120]}'
    return True, None




def _planner_loop_v1_build_bundle(case_key, run_id=None):
    # read-only analytical summary over normalized PostgreSQL data
    bundle = {
        'case_key': case_key,
        'run_id': run_id,
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'source_of_truth': 'postgres_normalized_tables_only',
        'tables_used': [],
        'system_profile': {},
        'users_summary': [],
        'execution_summary': [],
        'logon_summary': {},
        'browser_delivery_summary': {},
        'defender_security_summary': {},
        'network_summary': {},
        'thor_alerts': [],
        'key_events': [],
        'timeline_top_events': [],
        'evidence_gaps': [],
    }

    tables_used = set()
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            # system profile — prefer system_profile_v1, fallback to event_logs_v2
            sp_row = None
            try:
                cur.execute("""
                    SELECT computer_name, hostname, os_name, build, install_date_utc, timezone, utc_offset, last_shutdown_utc, users_json
                    FROM system_profile_v1 WHERE case_key=%s LIMIT 1
                """, (case_key,))
                sp_row = cur.fetchone()
                if sp_row:
                    tables_used.add('system_profile_v1')
            except Exception:
                sp_row = None
            cur.execute("""
                SELECT min(event_ts), max(event_ts),
                       (array_agg(computer ORDER BY cnt DESC))[1]
                FROM (
                  SELECT event_ts, computer, count(*) OVER (PARTITION BY computer) cnt
                  FROM event_logs_v2 WHERE case_key=%s
                ) q
            """, (case_key,))
            r = cur.fetchone() or (None, None, None)
            tables_used.add('event_logs_v2')
            if sp_row:
                sp_users = sp_row[8] or {}
                local_accts = sp_users.get('local_accounts') or []
                bundle['system_profile'] = {
                    'host': sp_row[0] or sp_row[1] or r[2],
                    'computer_name': sp_row[0] or r[2],
                    'os_name': sp_row[2],
                    'version': sp_row[3],
                    'install_time': sp_row[4],
                    'timezone': sp_row[5],
                    'utc_offset': sp_row[6],
                    'last_shutdown': sp_row[7],
                    'local_accounts': local_accts,
                    'local_ips': [],
                    'notable_ips': [],
                    'incident_window_start': r[0].isoformat() if r[0] else None,
                    'incident_window_end': r[1].isoformat() if r[1] else None,
                }
            else:
                bundle['system_profile'] = {
                    'host': r[2],
                    'computer_name': r[2],
                    'os_name': None,
                    'version': None,
                    'install_time': None,
                    'timezone': 'Europe/Kiev',
                    'utc_offset': '+02:00',
                    'last_shutdown': None,
                    'local_accounts': [],
                    'local_ips': [],
                    'notable_ips': [],
                    'incident_window_start': r[0].isoformat() if r[0] else None,
                    'incident_window_end': r[1].isoformat() if r[1] else None,
                }

            cur.execute("""
                SELECT ip, count(*) c FROM (
                  SELECT (regexp_match(coalesce(remote_host,''), '((?:\\d{1,3}\\.){3}\\d{1,3})'))[1] ip
                  FROM event_logs_v2 WHERE case_key=%s
                  UNION ALL
                  SELECT (regexp_match(coalesce(payload::text,''), '(?i)(?:IpAddress|Source Network Address|Client Address)[^0-9]{0,20}((?:\\d{1,3}\\.){3}\\d{1,3})'))[1] ip
                  FROM event_logs_v2 WHERE case_key=%s
                ) x
                WHERE ip IS NOT NULL
                GROUP BY ip ORDER BY c DESC LIMIT 20
            """, (case_key, case_key))
            ips=[x[0] for x in cur.fetchall() if x and x[0] and x[0] != '0.0.0.0']
            bundle['system_profile']['notable_ips']=ips[:8]
            bundle['system_profile']['local_ips']=[ip for ip in ips if ip.startswith(('10.','172.','192.168.'))][:8]

            # users summary
            cur.execute("""
                SELECT u, min(ts), max(ts),
                       max(CASE WHEN is_remote THEN 1 ELSE 0 END),
                       max(CASE WHEN is_service THEN 1 ELSE 0 END)
                FROM (
                  SELECT
                    COALESCE(NULLIF(target_user,''), (regexp_match(payload::text,'(?i)TargetUserName[^A-Za-z0-9]{0,40}([A-Za-z0-9_\\\\.-]+)'))[1]) AS u,
                    event_ts AS ts,
                    (coalesce(logon_type::text,'') IN ('3','10') OR coalesce(remote_host,'')<>'') AS is_remote,
                    (lower(coalesce(target_user,'')) LIKE '%%$' OR lower(coalesce(target_user,'')) LIKE 'nt authority%%') AS is_service
                  FROM event_logs_v2 WHERE case_key=%s
                ) z
                WHERE u IS NOT NULL AND btrim(u)<>''
                GROUP BY u ORDER BY max(ts) DESC NULLS LAST LIMIT 30
            """, (case_key,))
            for u,fs,ls,is_remote,is_service in cur.fetchall():
                lu=str(u).lower()
                if lu.endswith('$') or lu in ('local service','network service','system','анонимный вход') or lu.startswith('nt authority'):
                    continue
                bundle['users_summary'].append({
                    'user': u,
                    'first_seen': fs.isoformat() if fs else None,
                    'last_seen': ls.isoformat() if ls else None,
                    'interactive_or_remote': 'remote' if is_remote else 'interactive_or_unknown',
                    'service_like': bool(is_service),
                })

            # execution summary (suspicious tools/scripts — broad pattern for any case)
            if table_exists('program_exec_v2'):
                tables_used.add('program_exec_v2')
                cur.execute("""
                    SELECT event_ts, source_file, coalesce(executable_name,''), coalesce(full_path,'')
                    FROM program_exec_v2
                    WHERE case_key=%s
                      AND lower(coalesce(executable_name,'') || ' ' || coalesce(full_path,'')) ~
                          '(wscript|cscript|powershell|cmd\\.exe|7za|ngrok|mimikatz|try\\.exe|msedgex\\.exe|rdpwinst|rdpwrap|system32\\.exe|anydesk|teamviewer|upd2\\.exe|websigner|mshta|regsvr32|rundll32|certutil|bitsadmin)'
                    ORDER BY event_ts DESC NULLS LAST LIMIT 60
                """, (case_key,))
                for ts,sf,exe,path in cur.fetchall()[:25]:
                    bundle['execution_summary'].append({
                        'event_ts': ts.isoformat() if ts else None,
                        'tool_or_exec': exe or path,
                        'path': path,
                        'source_file': sf,
                    })

            # logon summary
            cur.execute("""
                SELECT
                  count(*) FILTER (WHERE event_id IN (4624,4625)),
                  count(*) FILTER (WHERE event_id=1149),
                  count(*) FILTER (WHERE event_id=4720),
                  count(*) FILTER (WHERE event_id IN (4732,4672))
                FROM event_logs_v2 WHERE case_key=%s
            """, (case_key,))
            a,b,c,d = cur.fetchone() or (0,0,0,0)
            bundle['logon_summary'] = {
                'interactive_logons': int(a or 0),
                'rdp_or_remote_logons': int(b or 0),
                'new_local_accounts': int(c or 0),
                'privilege_relevant_rows': int(d or 0),
            }

            # browser delivery summary
            try:
                _ensure_browser_provenance_view()
                cur.execute("""
                    SELECT count(*),
                           count(*) FILTER (WHERE evidence_kind='native'),
                           count(*) FILTER (WHERE coalesce(url,'')<>''),
                           count(*) FILTER (WHERE coalesce(zone_identifier_host_url,'')<>'' OR coalesce(zone_identifier_referrer_url,'')<>'')
                    FROM browser_provenance_v1 WHERE case_key=%s
                """, (case_key,))
                total,native,urlc,zonec = cur.fetchone() or (0,0,0,0)
                tables_used.add('browser_provenance_v1')
                cur.execute("""
                    SELECT event_ts, coalesce(url,''), coalesce(local_path,''), coalesce(source_file,''), coalesce(evidence_kind,'')
                    FROM browser_provenance_v1 WHERE case_key=%s
                    ORDER BY event_ts DESC NULLS LAST LIMIT 20
                """, (case_key,))
                rows=[{'event_ts':r[0].isoformat() if r[0] else None,'url':r[1],'local_path':r[2],'source_file':r[3],'evidence_kind':r[4]} for r in cur.fetchall()]
                bundle['browser_delivery_summary'] = {
                    'total_rows': int(total or 0),
                    'native_rows': int(native or 0),
                    'url_rows': int(urlc or 0),
                    'zone_identifier_rows': int(zonec or 0),
                    'rows': rows,
                }
            except Exception:
                bundle['browser_delivery_summary'] = {'total_rows':0,'native_rows':0,'url_rows':0,'zone_identifier_rows':0,'rows':[]}

            # defender/security
            cur.execute("""
                SELECT count(*) FILTER (WHERE lower(coalesce(command_line,'')) LIKE '%%add-mppreference%%' OR lower(coalesce(command_line,'')) LIKE '%%exclusionpath%%'),
                       count(*) FILTER (WHERE payload::text ILIKE '%%Windows Defender%%' OR payload::text ILIKE '%%MpPreference%%')
                FROM event_logs_v2 WHERE case_key=%s
            """, (case_key,))
            t1,t2 = cur.fetchone() or (0,0)
            bundle['defender_security_summary'] = {
                'tampering_rows': int(t1 or 0),
                'defender_related_rows': int(t2 or 0),
            }

            # network summary
            ng = 0
            if table_exists('program_exec_v2'):
                cur.execute("""SELECT count(*) FROM program_exec_v2 WHERE case_key=%s AND lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) LIKE '%%ngrok%%'""", (case_key,))
                ng = (cur.fetchone() or [0])[0] or 0
            cur.execute("""
                SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND coalesce(remote_host,'') NOT IN ('', '-', '::1', '127.0.0.1', '0.0.0.0')
            """, (case_key,))
            rm = (cur.fetchone() or [0])[0] or 0
            bundle['network_summary'] = {
                'ngrok_rows': int(ng),
                'remote_activity_rows': int(rm),
            }

            # THOR / tool alerts — high and critical alerts for key IOCs
            thor_alerts = []
            try:
                if table_exists('tool_alerts_v2'):
                    tables_used.add('tool_alerts_v2')
                    cur.execute("""
                        SELECT tool, severity, rule, event_ts, ioc_value, substring(details,1,120)
                        FROM tool_alerts_v2
                        WHERE case_key=%s AND severity IN ('high','critical')
                          AND coalesce(tool,'') NOT IN ('impacket-secretsdump','bmc-tools','collector_self','confirmed_fact','dfir_report')
                        ORDER BY
                          CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,
                          event_ts DESC NULLS LAST
                        LIMIT 30
                    """, (case_key,))
                    for tool,sev,rule,ts,ioc,det in cur.fetchall():
                        thor_alerts.append({
                            'tool': tool,
                            'severity': sev,
                            'rule': rule,
                            'event_ts': ts.isoformat() if ts else None,
                            'ioc_value': ioc,
                            'details': det,
                        })
            except Exception:
                try: conn.rollback()
                except: pass
                pass
            bundle['thor_alerts'] = thor_alerts

            # key event log entries (tampering, account creation/deletion, service installs)
            key_events = []
            try:
                cur.execute("""
                    SELECT event_id, event_ts, computer, target_user, source_file,
                           substring(payload::text, 1, 200)
                    FROM event_logs_v2
                    WHERE case_key=%s
                      AND ((event_id IN (1102,4720,4726,4732,4697,4698,4688,4625,4771) AND channel ILIKE '%%Security%%') OR (event_id IN (104,7045) AND (channel ILIKE '%%System%%' OR channel ILIKE '%%Eventlog%%')) OR (event_id IN (5007,1116) AND channel ILIKE '%%Windows Defender%%'))
                    ORDER BY event_ts DESC NULLS LAST LIMIT 40
                """, (case_key,))
                for eid,ts,comp,tuser,sf,pay in cur.fetchall():
                    key_events.append({
                        'event_id': eid,
                        'event_ts': ts.isoformat() if ts else None,
                        'computer': comp,
                        'target_user': tuser,
                        'source_file': sf,
                        'payload_snippet': pay,
                    })
            except Exception:
                try: conn.rollback()
                except: pass
                pass
            bundle['key_events'] = key_events

            # timeline top events from stored incident timeline when available
            t_ev=[]
            if run_id:
                cur.execute("""SELECT meta_json FROM dfir_run_steps_v2 WHERE job_id=%s AND step_code='incident_timeline'""", (run_id,))
                rr=cur.fetchone()
                if rr and isinstance(rr[0], dict):
                    t_ev=(rr[0].get('incident_timeline') or [])
                    tables_used.add('dfir_run_steps_v2')
            if not t_ev:
                # fallback from latest usable
                cur.execute("""
                    SELECT s.meta_json
                    FROM dfir_run_jobs_v2 j
                    JOIN dfir_run_steps_v2 s ON s.job_id=j.job_id AND s.step_code='incident_timeline'
                    WHERE j.case_key=%s AND j.status IN ('completed','partial')
                    ORDER BY j.created_at DESC LIMIT 1
                """, (case_key,))
                rr=cur.fetchone()
                if rr and isinstance(rr[0], dict):
                    t_ev=(rr[0].get('incident_timeline') or [])
                    tables_used.add('dfir_run_jobs_v2'); tables_used.add('dfir_run_steps_v2')

            # causal ordering and ids
            order=['delivery','file_drop','execution','defender','rdp_user','ngrok','remote','supporting']
            def bkt(e):
                t=(str(e.get('summary') or '')+' '+str(e.get('source_file') or '')).lower()
                if any(k in t for k in ['delivery','hosturl','download']): return 'delivery'
                if any(k in t for k in ['edit.dll','gcapi.dll','start.vbs','ng.bat','msedgex.exe','file-drop']): return 'file_drop'
                if any(k in t for k in ['script_or_batch_execution_event','staged_execution_context_event','wscript','powershell','try.exe']): return 'execution'
                if any(k in t for k in ['defender','add-mppreference','exclusionpath']): return 'defender'
                if any(k in t for k in ['user_creation_event','privilege_assignment_event','remote_logon_event','rdp_context_event']): return 'rdp_user'
                if any(k in t for k in ['ngrok','7za']): return 'ngrok'
                if any(k in t for k in ['remote']): return 'remote'
                return 'supporting'
            grp={k:[] for k in order}
            for e in (t_ev or []): grp[bkt(e)].append(e)
            out=[]
            for k in order:
                out.extend(grp[k][:4])
            out=out[:25]
            for i,e in enumerate(out,1):
                bundle['timeline_top_events'].append({
                    'evidence_id': f'E{i:03d}',
                    'event_ts': e.get('event_ts'),
                    'summary': e.get('summary'),
                    'source_table': e.get('source_table'),
                    'source_file': e.get('source_file'),
                    'bucket': bkt(e),
                    'time_source': e.get('time_source') or 'unknown',
                })

    # evidence gaps
    if bundle['browser_delivery_summary'].get('native_rows',0) == 0:
        bundle['evidence_gaps'].append('No native browser/MotW provenance rows for strict delivery proof')
    if bundle['logon_summary'].get('new_local_accounts',0) == 0:
        bundle['evidence_gaps'].append('No explicit 4720 new-account rows in normalized logs for this run window')
    if not bundle['timeline_top_events']:
        bundle['evidence_gaps'].append('No stored incident timeline available for causal ordering')
    if not bundle['thor_alerts']:
        bundle['evidence_gaps'].append('No THOR high/critical alerts — may lack THOR scan data')
    if not bundle['execution_summary']:
        bundle['evidence_gaps'].append('No suspicious execution artifacts found in program_exec_v2')

    bundle['tables_used'] = sorted(tables_used)
    return bundle


def _planner_loop_v1_prompt(bundle):
    schema = {
      "incident_assessment": "",
      "confidence": 0.0,
      "hypotheses": [
        {"name": "", "status": "confirmed|corroborated|hypothesis|rejected", "reason": "", "supporting_evidence_ids": []}
      ],
      "key_entities": {"users": [], "hosts": [], "ips": [], "files": [], "tools": []},
      "missing_information": [],
      "next_actions": [
        {"action": "", "reason": "", "priority": 1, "target_scope": ""}
      ],
      "report_readiness": {"executive_summary_ready": False, "chronology_ready": False, "ioc_ready": False, "gaps_remaining": []}
    }
    bundle_json = json.dumps(bundle, ensure_ascii=False)
    prompt = (
        "You are DFIR planning assistant. Return ONLY valid JSON matching exact schema. "
        "Do not output markdown. Do not invent facts. Use ONLY EVIDENCE_BUNDLE_JSON. "
        "Do not use PDF/TXT/report artifacts as evidence. "
        "The bundle contains: system_profile (OS/hostname/shutdown), users_summary, execution_summary, "
        "logon_summary, browser_delivery_summary, defender_security_summary, network_summary, "
        "thor_alerts (THOR/tool HIGH+CRITICAL IOC hits), key_events (event log EIDs: 1102=log_clear, "
        "4720=account_create, 4726=account_delete, 4697=service_install, 5007=defender_tamper, 1116=defender_detect, "
        "7045=service_new, 4688=process_create), timeline_top_events (causal chain), evidence_gaps. "
        "thor_alerts severity=critical means confirmed malware/IOC hit. "
        "Every strong claim must reference supporting_evidence_ids from timeline_top_events evidence_id. "
        "If proof is weak, status must be corroborated or hypothesis. "
        "Provide 3-7 next_actions, concrete and tied to missing data.\n\n"
        "SCHEMA:\n" + json.dumps(schema, ensure_ascii=False) + "\n\n"
        "EVIDENCE_BUNDLE_JSON:\n" + bundle_json[:18000]
    )
    return prompt


def _planner_loop_v1_run(case_key, run_id=None):
    bundle = _planner_loop_v1_build_bundle(case_key, run_id=run_id)
    prompt = _planner_loop_v1_prompt(bundle)

    # call local Ollama in strict JSON mode intent
    lm_base = LLM_URL
    model = os.getenv('DFIR_AGENT_JSON_MODEL') or LLM_FAST_MODEL
    url = lm_base.rstrip('/') + '/v1/chat/completions'
    body = json.dumps(build_chat_payload(
        model=model,
        messages=[{'role': 'user', 'content': prompt}],
        role='json',
        temperature=LLM_JSON_TEMPERATURE,
        max_tokens=int(os.environ.get('DFIR_PLANNER_MAX_TOKENS', '4000')),
        stream=False,
        reasoning_effort=os.environ.get('DFIR_JSON_REASONING_EFFORT', 'low'),
    )).encode('utf-8')
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
    raw = ''
    planner = None
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode('utf-8', errors='ignore'))
            raw = (data.get('choices') or [{}])[0].get('message', {}).get('content', '') or ''
        # extract JSON object
        st = raw.find('{'); en = raw.rfind('}')
        if st != -1 and en != -1 and en > st:
            planner = json.loads(raw[st:en+1])
    except Exception as e:
        users = [u.get('user') for u in (bundle.get('users_summary') or [])[:5] if u.get('user')]
        ips = bundle.get('system_profile', {}).get('notable_ips', [])[:6]
        tools = [x.get('tool_or_exec') for x in (bundle.get('execution_summary') or [])[:8] if x.get('tool_or_exec')]
        planner = {
            'incident_assessment': 'planner_unavailable',
            'confidence': 0.25,
            'hypotheses': [
                {'name':'script_host_execution_chain','status':'corroborated','reason':'execution_summary contains script-host related tools','supporting_evidence_ids':['E002','E003']},
                {'name':'rdp_user_activity_chain','status':'corroborated','reason':'logon_summary and timeline include rdp/user milestones','supporting_evidence_ids':['E007','E008']},
                {'name':'delivery_origin_strict_proof','status':'hypothesis','reason':'delivery native strict linkage incomplete','supporting_evidence_ids':['E001']},
            ],
            'key_entities': {'users': users, 'hosts': [bundle.get('system_profile', {}).get('host')], 'ips': ips, 'files': ['start.vbs','ng.bat','try.exe','msedgex.exe'], 'tools': tools[:8]},
            'missing_information': [f'planner_error:{str(e)[:140]}'],
            'next_actions': [
                {'action':'validate_ollama_connectivity','reason':'planner call failed','priority':1,'target_scope':'planner_loop_v1'},
                {'action':'extract_strict_delivery_triplet','reason':'need suspicious origin + native provenance + payload linkage','priority':1,'target_scope':'delivery_browser_provenance'},
                {'action':'verify_rdp_identity_temporal_chain','reason':'ensure creation/privilege/logon coherence','priority':2,'target_scope':'rdp_user_creation_linkage'},
                {'action':'stabilize_json_only_planner_prompt','reason':'enforce strict JSON parser compatibility','priority':2,'target_scope':'planner_loop_v1'}
            ],
            'report_readiness': {'executive_summary_ready': True, 'chronology_ready': True, 'ioc_ready': True, 'gaps_remaining': ['planner_error']}
        }

    if planner is None:
        users = [u.get('user') for u in (bundle.get('users_summary') or [])[:5] if u.get('user')]
        ips = bundle.get('system_profile', {}).get('notable_ips', [])[:6]
        tools = [x.get('tool_or_exec') for x in (bundle.get('execution_summary') or [])[:8] if x.get('tool_or_exec')]
        planner = {
            'incident_assessment': 'planner_parse_failed',
            'confidence': 0.3,
            'hypotheses': [
                {'name':'script_host_execution_chain','status':'corroborated','reason':'timeline and execution summary indicate likely script-host chain','supporting_evidence_ids':['E002','E003']},
                {'name':'rdp_user_activity_chain','status':'corroborated','reason':'rdp/logon/user creation events present','supporting_evidence_ids':['E007','E008']},
                {'name':'delivery_origin_strict_proof','status':'hypothesis','reason':'strict native delivery linkage not established','supporting_evidence_ids':['E001']},
            ],
            'key_entities': {'users': users, 'hosts': [bundle.get('system_profile', {}).get('host')], 'ips': ips, 'files': ['start.vbs','ng.bat','try.exe','msedgex.exe'], 'tools': tools[:8]},
            'missing_information': ['planner_output_not_json'],
            'next_actions': [
                {'action':'re-run_planner_with_json_only_constraint','reason':'non-json planner output','priority':1,'target_scope':'planner_loop_v1'},
                {'action':'extract_strict_delivery_triplet','reason':'need suspicious origin + native provenance + payload linkage','priority':1,'target_scope':'delivery_browser_provenance'},
                {'action':'validate_script_host_direct_refs','reason':'ensure direct execution proof for key scripts','priority':2,'target_scope':'script_host_execution_linkage'},
                {'action':'confirm_rdp_user_sid_mapping','reason':'strengthen deterministic identity joins','priority':2,'target_scope':'rdp_user_creation_linkage'}
            ],
            'report_readiness': {'executive_summary_ready': True, 'chronology_ready': True, 'ioc_ready': True, 'gaps_remaining': ['planner_output_not_json']}
        }

    # persist outputs as artifacts
    safe_case = _safe_case_folder(case_key)
    rep_dir = os.path.join(CASE_LIB, safe_case, 'reports')
    os.makedirs(rep_dir, exist_ok=True)
    stamp = int(time.time())
    eb_path = os.path.join(rep_dir, f'evidence_bundle_{run_id or "latest"}_{stamp}.json')
    po_path = os.path.join(rep_dir, f'planner_output_{run_id or "latest"}_{stamp}.json')
    with open(eb_path, 'w', encoding='utf-8') as f:
        json.dump(bundle, f, ensure_ascii=False, indent=2)
    with open(po_path, 'w', encoding='utf-8') as f:
        json.dump(planner, f, ensure_ascii=False, indent=2)

    return {
        'ok': True,
        'case_key': case_key,
        'run_id': run_id,
        'tables_used': bundle.get('tables_used', []),
        'evidence_bundle_path': eb_path,
        'planner_output_path': po_path,
        'evidence_bundle': bundle,
        'planner_output': planner,
    }


_SCOPE_TO_TOOL = {
    'delivery_browser_provenance':   '_agent_tool_get_download_artifacts',
    'browser_downloads':             '_agent_tool_get_browser_downloads',
    'browser_activity':              '_agent_tool_get_browser_activity',
    'script_host_execution_linkage': '_agent_tool_get_suspicious_executables',
    'process_exec':                  '_agent_tool_get_suspicious_executables',
    'process_file_evidence':         '_agent_tool_get_process_file_evidence',
    'rdp_user_creation_linkage':     '_agent_tool_get_logon_rdp_evidence',
    'rdp_identity':                  '_agent_tool_get_user_identity_evidence',
    'logon_activity':                '_agent_tool_get_logon_activity',
    'ioc_evidence':                  '_agent_tool_get_ioc_evidence',
    'persistence':                   '_agent_tool_get_registry_persistence',
    'persistence_evidence':          '_agent_tool_get_persistence_evidence',
    'defender':                      '_agent_tool_get_defender_evidence',
    'defender_events':               '_agent_tool_get_defender_events',
    'initial_access':                '_agent_tool_get_initial_access_evidence',
    'tampering':                     '_agent_tool_get_tampering_evidence',
    'lateral_movement':              '_agent_tool_get_lateral_movement',
    'network':                       '_agent_tool_get_logon_rdp_evidence',
    'timeline':                      '_agent_tool_get_forensic_timeline',
    'log_gaps':                      '_agent_tool_get_log_gaps',
    'attack_phases':                 '_agent_tool_get_attack_phases',
    'srum_network':                  '_agent_tool_get_srum_network_traffic',
    'backtrace':                     '_agent_tool_backtrace',
}

_TOOL_FN_MAP = None

def _get_tool_fn_map():
    global _TOOL_FN_MAP
    if _TOOL_FN_MAP is None:
        from analysis.agent_tools import (
            _agent_tool_get_download_artifacts, _agent_tool_get_browser_downloads,
            _agent_tool_get_browser_activity, _agent_tool_get_suspicious_executables,
            _agent_tool_get_process_file_evidence, _agent_tool_get_logon_rdp_evidence,
            _agent_tool_get_user_identity_evidence, _agent_tool_get_logon_activity,
            _agent_tool_get_ioc_evidence, _agent_tool_get_registry_persistence,
            _agent_tool_get_persistence_evidence, _agent_tool_get_defender_evidence,
            _agent_tool_get_defender_events, _agent_tool_get_initial_access_evidence,
            _agent_tool_get_tampering_evidence, _agent_tool_get_lateral_movement,
            _agent_tool_get_forensic_timeline, _agent_tool_get_log_gaps,
            _agent_tool_get_attack_phases, _agent_tool_get_srum_network_traffic,
            _agent_tool_backtrace,
        )
        _TOOL_FN_MAP = {
            '_agent_tool_get_download_artifacts':      _agent_tool_get_download_artifacts,
            '_agent_tool_get_browser_downloads':       _agent_tool_get_browser_downloads,
            '_agent_tool_get_browser_activity':        _agent_tool_get_browser_activity,
            '_agent_tool_get_suspicious_executables':  _agent_tool_get_suspicious_executables,
            '_agent_tool_get_process_file_evidence':   _agent_tool_get_process_file_evidence,
            '_agent_tool_get_logon_rdp_evidence':      _agent_tool_get_logon_rdp_evidence,
            '_agent_tool_get_user_identity_evidence':  _agent_tool_get_user_identity_evidence,
            '_agent_tool_get_logon_activity':          _agent_tool_get_logon_activity,
            '_agent_tool_get_ioc_evidence':            _agent_tool_get_ioc_evidence,
            '_agent_tool_get_registry_persistence':    _agent_tool_get_registry_persistence,
            '_agent_tool_get_persistence_evidence':    _agent_tool_get_persistence_evidence,
            '_agent_tool_get_defender_evidence':       _agent_tool_get_defender_evidence,
            '_agent_tool_get_defender_events':         _agent_tool_get_defender_events,
            '_agent_tool_get_initial_access_evidence': _agent_tool_get_initial_access_evidence,
            '_agent_tool_get_tampering_evidence':      _agent_tool_get_tampering_evidence,
            '_agent_tool_get_lateral_movement':        _agent_tool_get_lateral_movement,
            '_agent_tool_get_forensic_timeline':       _agent_tool_get_forensic_timeline,
            '_agent_tool_get_log_gaps':                _agent_tool_get_log_gaps,
            '_agent_tool_get_attack_phases':           _agent_tool_get_attack_phases,
            '_agent_tool_get_srum_network_traffic':    _agent_tool_get_srum_network_traffic,
            '_agent_tool_backtrace':                   _agent_tool_backtrace,
        }
    return _TOOL_FN_MAP


def _planner_fill_gaps(case_key, planner_result, max_actions=4):
    """Run targeted evidence queries for gaps identified by the planner.

    Called when executive_summary_ready=False. Returns dict with gap_fills text
    and list of actions taken. Skips planner-internal scopes (planner_loop_v1, etc.).
    """
    planner_out = planner_result.get('planner_output') or {}
    readiness = planner_out.get('report_readiness') or {}
    if readiness.get('executive_summary_ready', True):
        return {'filled': False, 'reason': 'already_ready', 'sections': []}

    next_actions = planner_out.get('next_actions') or []
    gaps_remaining = readiness.get('gaps_remaining') or []
    tool_map = _get_tool_fn_map()

    skip_scopes = {'planner_loop_v1', 'planner_internal', 'json_parser', ''}
    sections = []
    seen_tools = set()

    # Priority-sorted actions (priority=1 first)
    sorted_actions = sorted(next_actions, key=lambda a: int(a.get('priority', 9)))

    for action in sorted_actions[:max_actions * 2]:
        scope = (action.get('target_scope') or '').lower().replace('-', '_')
        if scope in skip_scopes:
            continue
        tool_name = _SCOPE_TO_TOOL.get(scope)
        if not tool_name or tool_name in seen_tools:
            continue
        fn = tool_map.get(tool_name)
        if not fn:
            continue
        seen_tools.add(tool_name)
        try:
            result = fn(case_key)
            if result and len(result) > 50 and 'ERROR' not in result[:20]:
                label = action.get('action', scope).replace('_', ' ').title()
                sections.append(f'### {label}\n{result[:3000]}')
                if len(sections) >= max_actions:
                    break
        except Exception as _e:
            _log.warning(f'[planner_fill_gaps] {tool_name} error: {_e}')

    if not sections and gaps_remaining:
        # Fallback: try matching gaps_remaining strings to scopes
        for gap in gaps_remaining[:3]:
            scope = gap.lower().replace('-', '_').replace(' ', '_')
            tool_name = _SCOPE_TO_TOOL.get(scope)
            if not tool_name or tool_name in seen_tools:
                continue
            fn = tool_map.get(tool_name)
            if not fn:
                continue
            seen_tools.add(tool_name)
            try:
                result = fn(case_key)
                if result and len(result) > 50 and 'ERROR' not in result[:20]:
                    sections.append(f'### {gap.replace("_"," ").title()}\n{result[:3000]}')
            except Exception:
                pass

    return {
        'filled': bool(sections),
        # sorted(): this list is written into the case result JSON and into the
        # step_success meta_json, so an unordered set left a different record of the
        # same work in every process.
        'actions_taken': sorted(seen_tools),
        'gaps_targeted': gaps_remaining,
        'sections': sections,
        'text': '\n\n'.join(sections) if sections else '',
    }


def _ensure_llm_self_improvement_table():
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.llm_self_improvement_v1 (
                    id bigserial PRIMARY KEY,
                    case_key text NOT NULL,
                    job_id uuid NOT NULL,
                    verdict text,
                    confidence text,
                    initial_access_method text,
                    what_worked jsonb,
                    what_was_missing jsonb,
                    how_gaps_were_filled jsonb,
                    key_techniques jsonb,
                    llm_reflection text,
                    step_contributions jsonb,
                    planner_confidence numeric,
                    chains_found jsonb,
                    created_at timestamptz NOT NULL DEFAULT now()
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_llm_selfimprove_case ON public.llm_self_improvement_v1(case_key, created_at DESC)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_llm_selfimprove_verdict ON public.llm_self_improvement_v1(verdict, confidence)")
            conn.commit()


def _get_reasoning_by_job(job_id):
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COALESCE(meta_json,'{}'::jsonb)
                    FROM public.dfir_run_steps_v2
                    WHERE job_id=%s AND step_code='case_reasoning_v1'
                    ORDER BY updated_at DESC LIMIT 1
                """, (job_id,))
                r = cur.fetchone()
                meta = (r[0] if r and isinstance(r[0], dict) else {})
                return (meta.get('case_reasoning_v1') if isinstance(meta, dict) else {}) or {}
    except Exception:
        return {}

def _save_llm_self_improvement(job_id, case_key, planner_result):
    """Extract what worked, what was missing, and ask LLM to reflect. Save to self-improvement table."""
    try:
        _ensure_llm_self_improvement_table()
    except Exception:
        return

    # Gather data from completed steps
    reasoning = _get_reasoning_by_job(job_id)
    verdict = reasoning.get('summary_verdict') or reasoning.get('verdict') or reasoning.get('incident_assessment') or 'unknown'
    confidence = reasoning.get('confidence_overall') or reasoning.get('confidence') or 'unknown'
    chains = reasoning.get('chains') or {}

    # Identify what steps contributed
    step_contributions = {}
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT step_code, step_status, COALESCE(meta_json,'{}')
                    FROM public.dfir_run_steps_v2
                    WHERE job_id=%s AND step_status='success'
                    ORDER BY step_no
                """, (job_id,))
                for row in cur.fetchall():
                    sc, ss, mj = row
                    meta = mj if isinstance(mj, dict) else {}
                    step_contributions[sc] = {
                        'status': ss,
                        'findings_count': len(meta.get('confirmed', meta.get('timeline_events', meta.get('evidence', [])))),
                    }
    except Exception:
        try: conn.rollback()
        except: pass
        pass

    planner = planner_result.get('planner_output') or {}
    missing_info = planner.get('missing_information') or []
    next_actions = planner.get('next_actions') or []
    hypotheses = planner.get('hypotheses') or []
    planner_confidence = float(planner.get('confidence') or 0)

    # Initial access candidate
    initial_access_method = None
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COALESCE(meta_json,'{}') FROM public.dfir_run_steps_v2
                    WHERE job_id=%s AND step_code='case_reasoning_v1'
                    ORDER BY updated_at DESC LIMIT 1
                """, (job_id,))
                r = cur.fetchone()
                if r:
                    rmeta = r[0] if isinstance(r[0], dict) else {}
                    cr = rmeta.get('case_reasoning_v1') or rmeta
                    ia_cands = cr.get('initial_access_candidates') or []
                    if ia_cands:
                        top = ia_cands[0]
                        initial_access_method = f"{top.get('browser_artifact_type','unknown')}:{top.get('candidate_strength','?')}:{top.get('confidence','?')}"
                    else:
                        # Fallback: use chains.initial_access status
                        ia_chain = (cr.get('chains') or {}).get('initial_access') or {}
                        ia_status = ia_chain.get('status') or 'unknown'
                        initial_access_method = f"chain:{ia_status}"
    except Exception:
        try: conn.rollback()
        except: pass
        pass

    # What worked: corroborated/confirmed hypotheses
    what_worked = [h for h in hypotheses if h.get('status') in ('confirmed', 'corroborated')]
    what_was_missing = [{'item': m} for m in missing_info if m]
    how_gaps_were_filled = [{'action': a.get('action'), 'reason': a.get('reason'), 'scope': a.get('target_scope')} for a in next_actions]

    # Key techniques derived from what worked
    key_techniques = []
    for h in what_worked:
        if h.get('reason'):
            key_techniques.append({'technique': h.get('name'), 'reason': h.get('reason')})

    # Ask LLM to generate reflection (best-effort, non-blocking)
    llm_reflection = ''
    try:
        lm_base = LLM_URL
        model = LLM_FAST_MODEL
        reflection_prompt = (
            f"You are a DFIR analyst. This case ({case_key}) concluded: verdict={verdict}, confidence={confidence}.\n"
            f"Confirmed chains: {json.dumps(list(chains.keys()))}\n"
            f"What worked: {json.dumps([h.get('name') for h in what_worked])}\n"
            f"Gaps remaining: {json.dumps(missing_info[:5])}\n"
            f"In 3-5 sentences, reflect: what analytical technique led to the verdict, what was hardest to prove, "
            f"and what you would do differently next time to find the initial access faster. "
            f"Be specific and evidence-based. No markdown."
        )
        body = json.dumps({'model': model, 'messages': [{'role': 'user', 'content': reflection_prompt}],
                           'temperature': 0.3, 'stream': False, 'max_tokens': 300}).encode('utf-8')
        req = urllib.request.Request(lm_base.rstrip('/') + '/v1/chat/completions', data=body,
                                     headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=30) as resp:
            rdata = json.loads(resp.read().decode('utf-8', errors='ignore'))
            llm_reflection = (rdata.get('choices') or [{}])[0].get('message', {}).get('content', '') or ''
            llm_reflection = llm_reflection.strip()[:1000]
    except Exception:
        try: conn.rollback()
        except: pass
        pass

    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO public.llm_self_improvement_v1
                        (case_key, job_id, verdict, confidence, initial_access_method,
                         what_worked, what_was_missing, how_gaps_were_filled,
                         key_techniques, llm_reflection, step_contributions,
                         planner_confidence, chains_found)
                    VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s::jsonb,%s::jsonb,%s,%s::jsonb,%s,%s::jsonb)
                """, (
                    case_key, job_id, verdict, str(confidence), initial_access_method,
                    json.dumps(what_worked), json.dumps(what_was_missing),
                    json.dumps(how_gaps_were_filled), json.dumps(key_techniques),
                    llm_reflection, json.dumps(step_contributions),
                    planner_confidence, json.dumps({k: (v.get('status') if isinstance(v, dict) else str(v)) for k, v in chains.items()})
                ))
                conn.commit()
    except Exception:
        try: conn.rollback()
        except: pass
        pass


# Mapping: trigger family → KB queries
_KB_FAMILY_QUERIES = {
    'ransom_extension_mass':        ['ransomware file encryption forensics', 'mass file rename extension indicators'],
    'ransom_note_pattern':          ['ransomware note readme artifacts analysis', 'ransomware incident response initial access'],
    'rdp_external_burst':           ['RDP brute force forensics windows event logs', 'remote desktop intrusion lateral movement'],
    'log_tampering':                ['windows event log clearing forensics 1102 104', 'anti-forensics log tampering detection'],
    'remote_tooling_context':       ['ngrok reverse tunnel forensics', 'remote access tool RAT evidence artifacts'],
    'script_host_execution_linkage':['VBScript WScript PowerShell execution artifacts forensics', 'script host malicious execution chain'],
    'delivery_browser_provenance':  ['browser download forensics zone identifier MOTW', 'chrome download history forensic analysis'],
    'defender_tampering':           ['windows defender exclusion path forensics', 'Add-MpPreference exclusion defense evasion'],
}

_KB_GENERIC_QUERIES = [
    'DFIR initial access point determination methodology',
    'windows forensics incident timeline reconstruction',
]


def _fetch_kb_context_for_incident(families, extra_queries=None, hits_per_query=3, max_total=12):
    """Query Qdrant knowledge base for relevant DFIR methodology based on detected families.
    Returns a compact string to inject into LLM prompts."""
    try:
        qdrant = QDRANT_URL.rstrip('/')
        embed_url = EMBED_URL.rstrip('/')
        embed_model = EMBED_MODEL
        collection = TEXT_COLL_PRIMARY

        # Check collection exists
        try:
            _http_json('GET', f"{qdrant}/collections/{collection}", timeout=10)
        except Exception:
            return ''

        # Build query list from families + generic
        queries = []
        for fam in (families or []):
            queries.extend(_KB_FAMILY_QUERIES.get(fam, []))
        queries.extend(extra_queries or [])
        if not families:
            queries.extend(_KB_GENERIC_QUERIES)

        seen_ids = set()
        chunks = []

        for q in queries[:10]:  # cap queries to avoid timeout
            try:
                emb_resp = _http_json('POST', f"{embed_url}/v1/embeddings",
                                      body={'model': embed_model, 'input': q}, timeout=45)
                vec = ((emb_resp or {}).get('data') or [{}])[0].get('embedding')
                if not vec:
                    continue
                result = _http_json('POST', f"{qdrant}/collections/{collection}/points/search",
                                    body={'vector': vec, 'limit': hits_per_query, 'with_payload': True}, timeout=20)
                for hit in ((result or {}).get('result') or []):
                    pid = hit.get('id')
                    if pid in seen_ids:
                        continue
                    seen_ids.add(pid)
                    payload = hit.get('payload', {})
                    text = str(payload.get('text', payload.get('chunk', '')))[:400].strip()
                    src = str(payload.get('source_file', '')).split('/')[-1][:40]
                    score = round(hit.get('score', 0), 2)
                    if score >= 0.35 and text:
                        chunks.append(f"[{src} s={score}] {text}")
                    if len(chunks) >= max_total:
                        break
            except Exception:
                continue
            if len(chunks) >= max_total:
                break

        if not chunks:
            return ''
        return "FORENSIC KNOWLEDGE BASE CONTEXT:\n" + '\n\n'.join(chunks)
    except Exception:
        return ''

