"""Grounded DFIR self-critique (self-review).

After the analyst LLM writes its narrative, a senior-reviewer LLM pass re-reads it AGAINST
hard evidence (incident window, initial-access evidence, threat detections) and REVISES if
the entry-point / claims are wrong, unsupported, or fabricated. ONE pass, grounded, never
raises — returns the original narrative on any failure. Appends a short '🔎 Самоперевірка:'
block so the reviewer's checks are visible.
"""
import logging

_log = logging.getLogger('dfir')


def _ground_truth(case_key, structured_input):
    """Compact bundle of HARD facts the narrative must agree with (best-effort, never raises)."""
    parts = []
    si = structured_input or {}
    # the deterministic verdict with its events/IOCs and our own footprint — the same
    # constraints the writer got, so the reviewer judges against the same facts
    try:
        from analysis.synthesis import _verdict_constraints_block as _vcb
        vb = _vcb(case_key, si)
        if vb:
            parts.append(vb[:3200])
    except Exception:
        pass
    # incident window (deterministic, by event density)
    try:
        from analysis.synthesis import _compute_incident_window as _ciw
        w = _ciw(case_key)
        if w and w.get('start'):
            parts.append(
                "ВІКНО ІНЦИДЕНТУ (обчислено за щільністю подій безпеки): %s — %s (пік %s). "
                "ТОЧКА ВХОДУ / початковий доступ МАЄ бути В ЦЬОМУ ВІКНІ або трохи до нього — "
                "НЕ за тижні до нього. Системні/OneDrive/телеметрія-файли та найраніші артефакти "
                "до вікна — це НЕ початок інциденту." % (w.get('start'), w.get('end'), w.get('peak_day')))
    except Exception:
        pass
    # threat detections that fired
    try:
        td = si.get('threat_detections') or []
        cats = []
        for t in td[:15]:
            if isinstance(t, dict):
                c = t.get('category') or t.get('name') or t.get('title') or ''
            else:
                c = str(t)
            if c:
                cats.append(str(c)[:50])
        if cats:
            parts.append("ДЕТЕКТОРИ ЗАГРОЗ, ЩО СПРАЦЮВАЛИ: " + "; ".join(cats))
    except Exception:
        pass
    # deterministic initial-access evidence (downloads / zone / lnk / first exec / rdp / email)
    try:
        from analysis.agent_tools import _agent_tool_get_initial_access_evidence as _ia
        ev = _ia(case_key)
        if ev:
            parts.append("ДОКАЗИ ПОЧАТКОВОГО ДОСТУПУ (з логів):\n" + str(ev)[:2800])
    except Exception:
        pass
    return "\n\n".join(parts)[:8500]


_SYS = (
    "Ти — старший DFIR-рецензент. Тобі дають ЧОРНОВИЙ звіт молодшого аналітика і ТВЕРДІ ДОКАЗИ "
    "з логів. Прискіпливо перевір звіт ПРОТИ доказів і виправ помилки. Особлива увага:\n"
    "1) ТОЧКА ВХОДУ / початковий доступ — чи збігається з ВІКНОМ ІНЦИДЕНТУ і реальними шкідливими "
    "файлами? Якщо точкою входу вказано системний/OneDrive/телеметрія-файл або файл за тижні до "
    "інциденту — це ПОМИЛКА: знайди в доказах справжній вхід (фішинг-вкладення з архіву/temp, "
    "завантаження з файлообмінника, RDP) і виправ.\n"
    "2) Кожне твердження має бути підкріплене доказами — непідкріплені прибери або чесно познач.\n"
    "3) НЕ вигадуй хеші/IP/домени/імена — лиши лише ті, що ДОСЛІВНО є в доказах.\n"
    "Якщо звіт коректний — лиши його без змін. Відповідай УКРАЇНСЬКОЮ. Виведи ПОВНИЙ звіт "
    "(виправлений або без змін), а В САМОМУ КІНЦІ додай блок:\n"
    "'🔎 Самоперевірка:' і 1-4 короткі пункти що перевірив/виправив (або один пункт "
    "'без правок — звіт узгоджений з доказами')."
)


def self_review_narrative(case_key, narrative, structured_input, llm_fn):
    """Return a grounded-revised narrative, or the original on any failure. Never raises."""
    try:
        if not narrative or len(narrative) < 100 or not callable(llm_fn):
            return narrative
        gt = _ground_truth(case_key, structured_input)
        if not gt:
            return narrative  # no hard evidence to check against — do not touch
        usr = ("=== ТВЕРДІ ДОКАЗИ (ground truth) ===\n%s\n\n"
               "=== ЧОРНОВИЙ ЗВІТ (перевір і, за потреби, виправ) ===\n%s" % (gt, narrative))
        msgs = [{"role": "system", "content": _SYS}, {"role": "user", "content": usr}]
        out = str(llm_fn(msgs) or "").strip()
        # sanity: accept only a substantial reply (guards truncation / empty / backend swap)
        if len(out) >= max(200, int(len(narrative) * 0.5)):
            return out
        _log.warning("[self_review] revision too short (%d vs %d) — keeping original"
                     % (len(out), len(narrative)))
    except Exception as e:
        _log.warning("[self_review] %s" % repr(e)[:160])
    return narrative


import json as _json
import re as _re

# ─────────────────────────────────────────────────────────────────────────────
# FACT-CHECK PASS (2026-08-15). Replaces the old rewrite-shaped review at the
# call site. Measured on 6 real cases with 5 injected fabrications each:
#   • rewrite shape (agent-30b, max_tokens=4000): caught 37% AND truncated the
#     narrative to the token cap — 26 of 31 stored narratives sat exactly in the
#     4000-token band, 80% ended mid-sentence. Net harmful.
#   • deterministic entity grounding: 23/24 entity-class fabrications, 0/6
#     interpretive ones, no GPU at all.
#   • flag-only pass on the RESIDENT fast model: 6/6 valid replies, 24/30 overall
#     and 6/6 on the interpretive class (examiner tool described as attacker
#     persistence), and it needs NO card swap (card 0 stays loaded).
# So: deterministic first (certain, cheap), LLM second (semantic), narrative is
# ANNOTATED, never rewritten. Details in docs/NIGHT_WORKLOG.md.
# ─────────────────────────────────────────────────────────────────────────────

_HASH_RE = _re.compile(r'\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{32}\b')
_IP_RE = _re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_SVC_RE = _re.compile(u'(?:служб[ауи]|сервіс)\\s+([A-Za-z][A-Za-z0-9_\\-]{5,40})')
# the bot's own infra / documentation ranges must never be treated as case IOCs
_IP_SKIP_RE = _re.compile(r'^(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.|255\.|169\.254\.)')

_EV_QUERIES = (
    "select 1 from case_iocs where case_key=%s and ioc_norm ilike %s limit 1",
    "select 1 from program_exec_v2 where case_key=%s and (executable_name ilike %s "
    "or full_path ilike %s or coalesce(hash_sha1,'') ilike %s or payload::text ilike %s) limit 1",
    "select 1 from filesystem_v2 where case_key=%s and (file_name ilike %s "
    "or parent_path ilike %s or source_file ilike %s) limit 1",
    "select 1 from event_logs_v2 where case_key=%s and (coalesce(command_line,'') ilike %s "
    "or coalesce(process_name,'') ilike %s or coalesce(remote_host,'') ilike %s "
    "or source_file ilike %s) limit 1",
)


def _token_in_evidence(cur, case_key, token):
    """True if the literal token appears anywhere in this case's parsed evidence."""
    pat = '%' + str(token) + '%'
    for q in _EV_QUERIES:
        n = q.count('%s') - 1
        try:
            cur.execute(q, tuple([case_key] + [pat] * n))
            if cur.fetchone():
                return True
        except Exception:
            continue
    return False


def ungrounded_entities(case_key, text, max_items=6):
    """Hashes / public IPs / service names cited in the text that are ABSENT from the
    case evidence, as (token, description) pairs. Deterministic, no LLM. Never raises."""
    found = []
    try:
        import psycopg2
        from core.config import PG_DSN
        cands = []
        for m in sorted(set(_HASH_RE.findall(text or ''))):
            cands.append(('хеш', m))
        for m in sorted(set(_IP_RE.findall(text or ''))):
            if not _IP_SKIP_RE.match(m):
                cands.append(('IP-адреса', m))
        for m in sorted(set(_SVC_RE.findall(text or ''))):
            cands.append(('служба', m))
        if not cands:
            return []
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            with c.cursor() as cur:
                try:
                    cur.execute("set statement_timeout='20s'")
                except Exception:
                    pass
                for kind, tok in cands:
                    if len(found) >= max_items:
                        break
                    if not _token_in_evidence(cur, case_key, tok):
                        found.append((tok, "%s `%s` не зустрічається в зібраних даних справи"
                                      % (kind, tok)))
    except Exception as e:
        _log.warning("[self_review] ungrounded_entities: %s" % repr(e)[:160])
    return found


_FLAG_SYS = (
    u"Ти — старший DFIR-рецензент. Тобі дають ТВЕРДІ ДОКАЗИ з логів справи і ЧОРНОВИЙ ЗВІТ. "
    u"Знайди у звіті твердження, які НЕ підтверджені доказами: вигадані хеші, IP, домени, "
    u"імена служб; дати початкового доступу поза вікном інциденту; а також ПОМИЛКОВІ "
    u"ТРАКТУВАННЯ — коли інструмент самого експерта-криміналіста (KAPE, MFTECmd, LECmd, PECmd, "
    u"EvtxECmd, AmcacheParser, RECmd, hayabusa та подібні парсери артефактів, а також наш збирач "
    u"vao_collector, його теки DFIRTriage_*/DFIR_Triage і проби dfp_*.ps1 — див. «ВЛАСНИЙ СЛІД "
    u"КОНВЕЄРА» у доказах) описано як інструмент зловмисника, збір даних, ексфільтрацію або "
    u"закріплення в системі; і СУПЕРЕЧНОСТІ З ВЕРДИКТОМ — коли звіт каже «не виявлено / не вдалося "
    u"встановити / немає» про те, що в блоці «ВЕРДИКТ ДЕТЕРМІНОВАНОГО ШАРУ» є як підтверджена "
    u"знахідка або якір початкового доступу, або навпаки — заявляє атаку тяжчу за вердикт без знахідки.\n"
    u"НЕ переписуй звіт. Поверни ЛИШЕ JSON без пояснень:\n"
    u'{"unsupported":[{"claim":"<коротка цитата зі звіту>","why":"<чому не підтверджено>"}]}\n'
    u'Якщо все підтверджено — {"unsupported":[]}'
)


def _parse_flag_json(text):
    """Extract the largest {...} object containing an `unsupported` list. Chatter around
    the JSON is tolerated; free-form prose without JSON yields nothing (fail closed)."""
    t = str(text or '')
    best = None
    for m in _re.finditer(r'\{', t):
        depth = 0
        for i in range(m.start(), len(t)):
            if t[i] == '{':
                depth += 1
            elif t[i] == '}':
                depth -= 1
                if depth == 0:
                    frag = t[m.start():i + 1]
                    if 'unsupported' in frag:
                        try:
                            d = _json.loads(frag)
                            if isinstance(d, dict) and isinstance(d.get('unsupported'), list):
                                if best is None or len(frag) > len(best):
                                    best = frag
                        except Exception:
                            pass
                    break
    if not best:
        return []
    out = []
    try:
        for it in (_json.loads(best).get('unsupported') or []):
            if isinstance(it, dict):
                claim = str(it.get('claim') or '').strip()
                why = str(it.get('why') or '').strip()
                if claim:
                    out.append((claim[:180] + (" — " + why[:160] if why else "")))
            elif str(it).strip():
                out.append(str(it).strip()[:280])
    except Exception:
        return []
    return out


def _flag_llm(msgs, max_tokens=8000):
    """Direct call to the resident fast model. Keeps BOTH channels: gpt-oss often leaves
    `content` empty and puts the answer in `reasoning_content`, which the shared ReAct
    helper drops — that silently disabled this whole pass. Never raises."""
    import urllib.request
    from core.config import LLM_URL, LLM_FAST_MODEL, LLM_MODEL
    import os as _os
    url = LLM_URL.rstrip('/') + '/v1/chat/completions'
    body = _json.dumps({
        'model': _os.environ.get('DFIR_FACTCHECK_MODEL') or LLM_FAST_MODEL or LLM_MODEL,
        'messages': msgs, 'temperature': 0.1, 'stream': False,
        'max_tokens': int(_os.environ.get('DFIR_FACTCHECK_MAX_TOKENS', str(max_tokens))),
        'reasoning_effort': _os.environ.get('DFIR_FACTCHECK_EFFORT', 'low'),
    }).encode('utf-8')
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
    timeout = int(_os.environ.get('DFIR_FACTCHECK_TIMEOUT', '420'))
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        d = _json.loads(resp.read().decode('utf-8', errors='ignore'))
    m = ((d.get('choices') or [{}])[0].get('message') or {})
    return (m.get('content') or '').strip() or (m.get('reasoning_content') or '').strip()


_NEG_ENTRY_RX = _re.compile(u'(не вдалося (однозначно )?встановити|не (вдалося|можна) (визначити|підтвердити)|'
                            u'точн[аеу]? (вектор|точк)[^.\n]{0,60}(не доведен|не встановлен)|'
                            u'(не|немає) (виявлено|доказ|ознак)[^.\n]{0,40}(атак|компромет|загроз))', _re.I)
_ESCALATE_RX = _re.compile(u'(цілеспрямован(а|ої) атак|повн(ий|ого|у) контрол|бекдор|ексфільтрац|викраден(ня|о) (даних|облікових)|'
                           u'lateral movement|латеральн(ий|ого) рух)', _re.I)
# On a CALM deterministic verdict the narrative may say «підозріле», «варто перевірити» —
# and nothing stronger. These are the words that make a reader believe somebody broke in,
# and two clean machines (kyiv, case_67) got them over vendor components and a game.
_ATTACK_WORD_RX = _re.compile(
    u'(зловмисник|атакувальник|зламано|зламали|скомпрометован|компромета[цч]|'
    u'(?<!не )проникненн|хакер|кібератак|шкідлив(е|ого|ий|а) ПЗ встановлен|'
    u'встановив бекдор|(?<!не )була атака|стал(а|ася) атака|атака (почалась|почалася|розпочалась))',
    _re.I)
_DENIAL_RX = _re.compile(
    u'\\bне\\s+(виявлен|зафіксован|встановлен|підтверджен|знайден|бул[аои]|є)|'
    u'\\bнемає\\b|\\bвідсутн|\\bжодн(их|ого|ої)\\b|\\bбез ознак', _re.I)


def _sentence_at(text, pos):
    """The sentence a match sits in — the smallest unit in which a negation still applies."""
    a = max(text.rfind('.', 0, pos), text.rfind('\n', 0, pos), text.rfind('!', 0, pos),
            text.rfind('?', 0, pos))
    b = min([x for x in (text.find('.', pos), text.find('\n', pos), len(text)) if x >= 0] or [len(text)])
    return text[a + 1:b]


# a date the narrative asserts as a fact about this machine
_DATE_RX = _re.compile(r'\b(20[12][0-9])-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])\b')
_WIN_PATH_RX = _re.compile(r'[A-Za-z]:\\(?:[^\\\s"`\'<>|*?\n]+\\)*[^\\\s"`\'<>|*?\n]+')
_EXE_TOKEN_RX = _re.compile(r'\b[A-Za-z0-9_.\-]{2,60}\.(?:exe|ps1|cmd|bat|dll|msi|wim)\b', _re.I)


def _norm_path(p):
    return (p or '').replace('/', chr(92)).strip().strip('`"\'').lower()


def contradiction_claims(case_key, narrative, structured_input, max_items=8):
    """Deterministic pass, no LLM: claims in the narrative that (a) name our own footprint
    as attacker activity, (b) contradict the deterministic verdict (deny an entry point or
    a category the SQL layer proved, or escalate above a calm verdict), (c) cite a Windows
    path whose directory the evidence does not have for that file name. Each item is a
    tagged string «[тег] …». Never raises."""
    out = []
    try:
        from analysis.synthesis import _verdict_constraints as _vc
        _txt, meta = _vc(case_key, structured_input)
    except Exception:
        return out
    text = narrative or ''
    low = text.lower()
    if not text:
        return out

    def _ctx(pos, span=70):
        a = max(0, pos - span)
        b = min(len(text), pos + span)
        return ' '.join(text[a:b].split())[:150]

    # (a) our own footprint described as the attack
    try:
        from analysis.own_footprint import is_own, OWN_TOOLS, own_started_at
        started = own_started_at(case_key)
        # the narrative itself talking about our staging folder / probes / collector is as
        # good a signal as the DB start time: the tools it names next to them are ours
        narr_marker = any(kw in low for kw in ('dfirtriage', 'dfir_triage', 'vao_collector', 'dfp_'))
        seen_tok = set()
        tool_stems = [t.split('.')[0] for t in OWN_TOOLS]
        for m in _EXE_TOKEN_RX.finditer(text):
            tok = m.group(0)
            tl = tok.lower()
            if tl in seen_tok:
                continue
            base = tl.rsplit(chr(92), 1)[-1]
            own = is_own(tok)
            if not own and (started is not None or narr_marker) and (base in OWN_TOOLS or base.split('.')[0] in tool_stems):
                own = True
            if own:
                seen_tok.add(tl)
                out.append(u"[власний слід] «%s» — це інструмент/файл нашого збирача (vao_collector запущено %s), "
                           u"а не дія зловмисника: %s" % (tok, str(started)[:16] if started else '?', _ctx(m.start())))
        for kw in ('dfirtriage', 'dfir_triage', 'vao_collector', 'dfp_'):
            i = low.find(kw)
            if i >= 0 and kw not in seen_tok:
                seen_tok.add(kw)
                out.append(u"[власний слід] згадка «%s» — тека/проба нашого збирача, не артефакт атаки: %s"
                           % (kw, _ctx(i)))
    except Exception as e:
        _log.warning("[self_review] own-footprint pass: %s" % repr(e)[:120])

    # (b) verdict contradictions
    try:
        max_sev = str(meta.get('max_sev') or 'none').lower()
        anchor = meta.get('anchor')
        if anchor:
            m = _NEG_ENTRY_RX.search(text)
            if m:
                out.append(u"[суперечить вердикту] звіт каже «%s», але детермінований якір входу є: %s — %s [%s]"
                           % (m.group(0)[:60], str(anchor.get('ts'))[:16], anchor.get('label'), anchor.get('source')))
            # the anchor's IOC names must appear somewhere in the narrative
            names = [str(i.get('value') or '') for i in (meta.get('iocs') or [])]
            names = [n.rsplit(chr(92), 1)[-1].lower() for n in names if n]
            names = [n for n in names if 4 <= len(n) <= 80]
            if names and not any(n in low for n in names[:12]):
                out.append(u"[суперечить вердикту] у наративі немає жодного IOC головної знахідки «%s» (напр. %s)"
                           % (anchor.get('finding'), ', '.join(names[:3])))
        if max_sev in ('none', 'info', 'low', 'medium', 'med'):
            m = _ESCALATE_RX.search(text)
            if m:
                out.append(u"[перевищує вердикт] «%s» — детермінований шар не має знахідок high/critical (макс. %s); "
                           u"без конкретної знахідки це гіпотеза, не факт: %s" % (m.group(0), max_sev, _ctx(m.start())))
            # the whole vocabulary of an intrusion, not only its strongest words: the model
            # may describe what it sees as «підозріле» or «варто перевірити», never as a
            # person who broke in. Severity in the LLM half may not exceed the SQL layer's.
            _seen_w = set()
            for mw in _ATTACK_WORD_RX.finditer(text):
                w = mw.group(0).lower()
                if w in _seen_w:
                    continue
                # «ознак проникнення НЕ виявлено» is the honest sentence a calm case
                # should contain — flagging it would be exactly backwards
                if _DENIAL_RX.search(_sentence_at(text, mw.start())):
                    continue
                _seen_w.add(w)
                out.append(u"[перевищує вердикт] «%s» — на цій справі вердикт спокійний (макс. %s): "
                           u"допустимо лише «підозріле / треба перевірити», не «атака/зловмисник»: %s"
                           % (mw.group(0)[:40], max_sev, _ctx(mw.start())))
                if len(_seen_w) >= 3:
                    break
    except Exception as e:
        _log.warning("[self_review] verdict pass: %s" % repr(e)[:120])

    # (b2) invented DATES: a date the narrative states as a fact about this machine, on a
    # day the case has no event of any kind. case_56's narrative dated the incident to a day
    # that produced nothing in three tables (FIX_QUEUE №4).
    try:
        import psycopg2
        from core.config import PG_DSN
        # a date we HANDED the model (the incident window, the install date, an event in
        # the evidence bundle) is not an invention even when no row falls on that day
        _given = ''
        try:
            import json as _json
            _given = _json.dumps(structured_input, ensure_ascii=False, default=str)
        except Exception:
            _given = str(structured_input)
        _dates, _pos = [], {}
        for m in _DATE_RX.finditer(text):
            d = m.group(0)
            if d in _given:
                continue
            if d not in _pos:
                _pos[d] = m.start()
                _dates.append(d)
        if _dates:
            with psycopg2.connect(PG_DSN) as c:
                c.autocommit = True
                with c.cursor() as cur:
                    try:
                        cur.execute("set statement_timeout='20s'")
                    except Exception:
                        pass
                    for d in _dates[:8]:
                        _hit = False
                        for _t in ('event_logs_v2', 'program_exec_v2', 'filesystem_v2'):
                            try:
                                cur.execute("SELECT 1 FROM " + _t + " WHERE case_key=%s "
                                            "AND event_ts >= %s::date AND event_ts < (%s::date + 1) LIMIT 1",
                                            (case_key, d, d))
                                if cur.fetchone():
                                    _hit = True
                                    break
                            except Exception:
                                try: c.rollback()
                                except Exception: pass
                        if not _hit:
                            out.append(u"[вигадана дата] `%s` — у доказах цієї справи немає жодної події "
                                       u"за цю добу: %s" % (d, _ctx(_pos[d])))
    except Exception as e:
        _log.warning("[self_review] date pass: %s" % repr(e)[:120])

    # (c) invented paths: the file is in the evidence, its directory is not
    try:
        import psycopg2
        from core.config import PG_DSN
        paths = []
        for m in _WIN_PATH_RX.finditer(text):
            p = _norm_path(m.group(0))
            if '...' in p or '…' in p or '{' in p:
                continue  # an abbreviated path is not a claim about a folder
            if p and p not in paths and chr(92) in p:
                paths.append(p)
        ioc_paths = {_norm_path(str(i.get('value') or '')) for i in (meta.get('iocs') or [])}
        if paths:
            with psycopg2.connect(PG_DSN) as c:
                c.autocommit = True
                with c.cursor() as cur:
                    try:
                        cur.execute("set statement_timeout='20s'")
                    except Exception:
                        pass
                    try:
                        from analysis.own_footprint import is_own as _is_own_p
                    except Exception:
                        _is_own_p = lambda *_a, **_k: False
                    for p in paths[:12]:
                        if p in ioc_paths or any(p in ip or ip in p for ip in ioc_paths if ip):
                            continue
                        if _is_own_p(p):
                            continue  # already reported by the own-footprint pass
                        d, _, base = p.rpartition(chr(92))
                        if len(base) < 4 or not d or d.count(chr(92)) < 1:
                            continue
                        tail = d.rsplit(chr(92), 1)[-1]
                        if len(tail) < 3:
                            continue
                        cur.execute("""SELECT 1 FROM filesystem_v2 WHERE case_key=%s AND lower(file_name)=%s LIMIT 1""",
                                    (case_key, base))
                        if not cur.fetchone():
                            cur.execute("""SELECT 1 FROM program_exec_v2 WHERE case_key=%s
                                           AND lower(coalesce(executable_name,'')) LIKE %s LIMIT 1""",
                                        (case_key, '%' + base))
                            if not cur.fetchone():
                                continue  # unknown file: the entity pass handles that class
                        cur.execute("""SELECT 1 FROM filesystem_v2 WHERE case_key=%s AND lower(file_name)=%s
                                       AND lower(coalesce(parent_path,'')) LIKE %s LIMIT 1""",
                                    (case_key, base, '%' + tail + '%'))
                        if cur.fetchone():
                            continue
                        cur.execute("""SELECT 1 FROM program_exec_v2 WHERE case_key=%s
                                       AND lower(coalesce(full_path,'')) LIKE %s LIMIT 1""",
                                    (case_key, '%' + tail + chr(92) + base + '%'))
                        if cur.fetchone():
                            continue
                        out.append(u"[вигаданий шлях] `%s` — файл %s у доказах є, але не в цій теці; візьми шлях з IOC/доказів"
                                   % (p[:120], base))
    except Exception as e:
        _log.warning("[self_review] path pass: %s" % repr(e)[:120])
    return out[:max_items]


def flag_unsupported_claims(case_key, narrative, structured_input, llm_fn=None,
                            max_items=8, status=None):
    """Second-model fact-check: return short descriptions of claims the evidence does not
    support. Deterministic entity grounding first, then one LLM pass. Never raises.

    `status` (optional dict) is filled with {'llm_ok': bool} so the caller can tell
    "nothing found" apart from "the reviewer never answered"."""
    if isinstance(status, dict):
        status['llm_ok'] = False
    items = []
    seen = set()
    entity_tokens = set()

    def _add(s, entity=None):
        s = str(s or '').strip()
        if not s:
            return
        k = ' '.join(s.split()).lower()[:90]
        if k in seen:
            return
        # an LLM claim that merely restates an entity the deterministic pass already
        # flagged adds no information and must not consume a display slot
        low = s.lower()
        if entity is None and any(t in low for t in entity_tokens):
            return
        seen.add(k)
        if entity:
            entity_tokens.add(str(entity).lower())
        items.append(s)

    # structured, deterministic passes first: own footprint, verdict contradictions,
    # invented paths (2026-09-04) - then entity grounding, then the language pass
    for s in contradiction_claims(case_key, narrative, structured_input, max_items=max_items):
        _add(s)
    for ent, s in ungrounded_entities(case_key, narrative):
        _add(u"[не в доказах] " + s, entity=ent)
    try:
        _fn = llm_fn if callable(llm_fn) else _flag_llm
        if callable(_fn):
            gt = _ground_truth(case_key, structured_input)
            if gt:
                usr = (u"=== ТВЕРДІ ДОКАЗИ ===\n%s\n\n=== ЧОРНОВИЙ ЗВІТ ===\n%s" % (gt, narrative))
                msgs = [{"role": "system", "content": _FLAG_SYS},
                        {"role": "user", "content": usr}]
                found = _parse_flag_json(_fn(msgs))
                if not found:
                    # no JSON in the reply — the fast model sometimes spends the whole
                    # budget on free-form reasoning. Ask once more, tersely.
                    retry = list(msgs)
                    retry.append({"role": "user", "content":
                                  u"Відповідай ОДНИМ рядком валідного JSON у вказаному "
                                  u"форматі. Без міркувань, без пояснень, без Markdown. "
                                  u"Максимум 6 пунктів."})
                    try:
                        found = _parse_flag_json(_fn(retry))
                    except Exception:
                        found = []
                    if not found:
                        _log.warning("[self_review] flag pass produced no parsable JSON for %s"
                                     % case_key)
                if found and isinstance(status, dict):
                    status['llm_ok'] = True
                for s in found:
                    _add(u"[друга модель] " + s)
    except Exception as e:
        _log.warning("[self_review] flag pass: %s" % repr(e)[:160])
    return items[:max_items]


_CHECK_HEADING = u"🔎 Самоперевірка (другою моделлю)"


def annotate_narrative(case_key, narrative, structured_input, llm_fn=None, max_items=10):
    """ANNOTATE the analyst narrative with a bounded list of unsupported claims.

    Deliberately never replaces the narrative: the previous rewrite shape truncated
    ~84% of stored reports at the reviewer's token cap. Returns the original text on
    any failure, so the pipeline can only gain a block, never lose the report."""
    try:
        if not narrative or len(narrative) < 100:
            return narrative
        if _CHECK_HEADING in narrative:
            return narrative
        st = {}
        flags = flag_unsupported_claims(case_key, narrative, structured_input, llm_fn,
                                        max_items=max_items, status=st)
        if not flags and st.get('llm_ok'):
            block = (u"\n\n---\n\n%s\n\nПеревірку виконано: твердження звіту звірено з "
                     u"зібраними даними справи, розбіжностей не виявлено.\n" % _CHECK_HEADING)
        elif not flags:
            # entity grounding ran, the language pass did not answer — say exactly that
            block = (u"\n\n---\n\n%s\n\nЗвірку сутностей (хеші, IP, служби) із зібраними "
                     u"даними справи виконано, розбіжностей не виявлено. Змістову перевірку "
                     u"тверджень другою моделлю виконати не вдалося — звіт потребує звичайної "
                     u"перевірки експертом.\n" % _CHECK_HEADING)
        else:
            lines = "\n".join(u"- %s" % f for f in flags)
            block = (u"\n\n---\n\n%s\n\nНаведені нижче твердження НЕ підтверджені зібраними "
                     u"даними і потребують перевірки експертом перед передачею звіту:\n\n%s\n"
                     % (_CHECK_HEADING, lines))
        # A calm verdict with an "attack" story under it is the reviewer's "two halves":
        # case_49 (clean) got "серйозні інциденти, фішинг через LNK", kyiv (WinUtil run)
        # got "цілеспрямовані дії, фішинг через LNK". The list at the bottom is not enough -
        # the reader meets the story first. Say it at the top, before the first sentence.
        _esc = [f for f in (flags or []) if f.startswith(u"[перевищує вердикт]")]
        _inv = [f for f in (flags or []) if f.startswith(u"[вигаданий шлях]") or f.startswith(u"[власний слід]")]
        head = u""
        if _esc:
            head = (u"> ⚠️ **Детермінований шар не виявив критичних/високих загроз.** Твердження нижче про "
                    u"атаку, фішинг, компрометацію чи зловмисника — гіпотези моделі без підтвердженої знахідки "
                    u"(%d познач. у самоперевірці внизу); не передавати їх як факти.\n\n" % len(_esc))
        elif _inv:
            head = (u"> ⚠️ Самоперевірка знайшла %d твердження з непідтвердженими шляхами або нашим власним "
                    u"інструментарієм — див. список унизу перед використанням.\n\n" % len(_inv))
        return head + narrative.rstrip() + block
    except Exception as e:
        _log.warning("[self_review] annotate: %s" % repr(e)[:160])
        return narrative
