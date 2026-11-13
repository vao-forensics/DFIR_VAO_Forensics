"""Attacker attribution across cases — the cross-case IOC intersection engine +
an LLM 'attacker portrait'. Answers the owner's need: dozens of cases show 'the same
hand' but each surfaced different pieces; this stitches shared indicators into one
actor profile with ALL indicators over time. No egress — local LLM only."""
import json
import logging
import urllib.request

import psycopg2
from core.config import PG_DSN

_log = logging.getLogger('app')

# types that are meaningful for attribution (drop ubiquitous file paths etc.)
_ATTR_TYPES = ('public_ip', 'domain', 'url', 'hash_sha1', 'hash_sha256', 'hash_md5',
               'malware_name', 'tool_name', 'anydesk_id', 'email', 'user_account',
               'attacker_host', 'attacker_token', 'windows_sid', 'technique', 'file_name')
# norms too generic to link actors (shared toolset != same actor)
_ATTR_GENERIC = {'powershell', 'anydesk', 'rdp wrapper', 'rdpwrapper', 'ngrok', '7za',
                 'rdp', 'cmd', 'rundll32', 'mshta', 'wscript', 'cscript', 'regsvr32'}
# SOFT sources = LLM/prose-derived → can be poisoned by the LLM→IOC→LLM loop. An IOC
# from a soft source alone MUST NOT drive cross-case attribution; it only counts if it
# is ALSO backed by a deterministic/human source OR corroborated by ≥2 sources.
_SOFT_SOURCES = ('report_llm', 'qa_analysis', 'timeline_analysis', 'ps_b64_decoded')


def _pretty(ck):
    import re
    m = re.match(r'^(\d{2})_(\d{2})_(\d{4})_*(.*)$', str(ck or ''))
    if m:
        dd, mm, yy, rest = m.groups()
        base = re.sub(r'\s+', ' ', rest.replace('_', ' ')).strip()
        return f"{dd}.{mm}.{yy}" + (f" - {base}" if base else '')
    return str(ck or '').replace('_', ' ')


def gather_intersections(allowed_cases=None):
    """Return (shared, per_case). shared = [{ioc_type, ioc_norm, sample_value, cases[],
    first, last}] present in >=2 cases; per_case = {case_key: {type: [values]}}."""
    shared, per_case = [], {}
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("SET statement_timeout = '20s'")
                _ph, args = '', []
                if allowed_cases:
                    _ph = " AND case_key IN (" + ','.join(['%s'] * len(allowed_cases)) + ")"
                    args = list(allowed_cases)
                # shared indicators across cases (group by normalized value).
                # ANTI-POISONING: only ELIGIBLE rows count — a per-(case,type,norm) IOC is
                # eligible if it has ≥1 HARD (non-soft) source OR ≥2 distinct sources.
                cur.execute(
                    "WITH elig AS ("
                    "  SELECT case_key, ioc_type, coalesce(nullif(ioc_norm,''),lower(ioc_value)) AS v, "
                    "         min(coalesce(ioc_value,'')) AS sample, min(event_ts) AS f, max(event_ts) AS l "
                    "  FROM case_iocs WHERE ioc_type IN %s AND coalesce(ioc_value,'')<>'' AND case_key<>'file'" + _ph +
                    "  GROUP BY 1,2,coalesce(nullif(ioc_norm,''),lower(ioc_value)) "
                    "  HAVING bool_or(coalesce(source_table,'') NOT IN %s) OR count(DISTINCT source_table) >= 2) "
                    "SELECT ioc_type, v, count(DISTINCT case_key) AS nc, array_agg(DISTINCT case_key) AS cks, "
                    "  min(sample) AS sample, min(f) AS f, max(l) AS l "
                    "FROM elig GROUP BY 1,2 HAVING count(DISTINCT case_key) >= 2 ORDER BY nc DESC, ioc_type",
                    tuple([_ATTR_TYPES] + args + [_SOFT_SOURCES]))
                for it, v, nc, cks, sample, f, l in cur.fetchall():
                    if v in _ATTR_GENERIC:
                        continue
                    shared.append({'ioc_type': it, 'ioc_norm': v, 'sample_value': sample or v,
                                   'cases': sorted(cks), 'n_cases': nc,
                                   'first': str(f)[:10] if f else None,
                                   'last': str(l)[:10] if l else None})
                # per-case indicator roll-up
                cur.execute(
                    "SELECT case_key, ioc_type, coalesce(nullif(ioc_value,''),ioc_norm) "
                    "FROM case_iocs WHERE ioc_type IN %s AND coalesce(ioc_value,'')<>'' "
                    "  AND case_key<>'file'" + _ph +
                    " ORDER BY case_key, ioc_type",
                    tuple([_ATTR_TYPES] + args))
                for ck, it, val in cur.fetchall():
                    per_case.setdefault(ck, {}).setdefault(it, [])
                    if val not in per_case[ck][it]:
                        per_case[ck][it].append(val)
    except Exception as e:
        _log.error('[attribution] gather: %s', repr(e)[:150])
    _mark_background_hashes(shared)
    return shared, per_case


_TYPE_UA = {'public_ip': 'IP', 'domain': 'домен', 'url': 'URL', 'hash_sha1': 'SHA1',
            'hash_sha256': 'SHA256', 'hash_md5': 'MD5', 'malware_name': 'малваре',
            'tool_name': 'інструмент', 'anydesk_id': 'AnyDesk ID', 'email': 'email',
            'user_account': 'акаунт', 'attacker_host': 'машина атакувальника',
            'attacker_token': 'токен/акаунт (ngrok)', 'windows_sid': 'SID'}


def build_intersection_facts(shared, per_case):
    """Deterministic facts block (ground truth) for the LLM."""
    L = []
    _bg_n = sum(1 for s in shared if s.get('bg_hash'))
    shared = [s for s in shared if not s.get('bg_hash')]
    if shared:
        L.append('СПІЛЬНІ ІНДИКАТОРИ (той самий IOC у 2+ кейсах — головні звʼязки):')
        for s in shared[:60]:
            cs = ', '.join(_pretty(c) for c in s['cases'])
            span = ''
            if s['first'] and s['last'] and s['first'] != s['last']:
                span = ' [%s→%s]' % (s['first'], s['last'])
            L.append('• %s: %s — %d кейси: %s%s'
                     % (_TYPE_UA.get(s['ioc_type'], s['ioc_type']), s['sample_value'],
                        s['n_cases'], cs, span))
    else:
        L.append('СПІЛЬНИХ ІНДИКАТОРІВ між кейсами не знайдено (кожен кейс має власний набір).')
    if _bg_n:
        L.append('(Відкинуто %d спільних хешів як фон: штатне ПЗ у теках встановлених програм '
                 '— однаковий білд вендора має однаковий хеш на будь-якому ПК.)' % _bg_n)
    L.append('')
    L.append('ІНДИКАТОРИ ПО КЕЙСАХ:')
    for ck in sorted(per_case):
        parts = []
        for it in _ATTR_TYPES:
            vals = per_case[ck].get(it) or []
            if vals:
                parts.append('%s: %s' % (_TYPE_UA.get(it, it), ', '.join(vals[:12])))
        if parts:
            L.append('▸ %s — %s' % (_pretty(ck), '; '.join(parts)))
    return '\n'.join(L)


def _union_rows(case_keys):
    """UNION composite (owner intent #1): every attribution IOC across ALL the actor's cases,
    grouped by (type, norm), with nc = #cases it appears in, whether a HARD source backs it, max
    confidence and a sample. INCLUDES one-off (nc==1) rows — case-unique leaks (an IP/token that
    slipped in only one case) are part of the actor's portrait too."""
    import re as _re
    if not case_keys:
        return []
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("SET statement_timeout='20s'")
                ph = ','.join(['%s'] * len(case_keys))
                cur.execute(
                    "SELECT ioc_type, coalesce(nullif(ioc_norm,''),lower(ioc_value)) AS v, "
                    "  min(coalesce(ioc_value,'')) AS sample, count(DISTINCT case_key) AS nc, "
                    "  array_agg(DISTINCT case_key) AS cks, max(confidence) AS conf, "
                    "  bool_or(coalesce(source_table,'') NOT IN %s) AS hard "
                    "FROM case_iocs WHERE ioc_type IN %s AND coalesce(ioc_value,'')<>'' "
                    "  AND case_key IN (" + ph + ") "
                    "GROUP BY 1,2 ORDER BY nc DESC, hard DESC, ioc_type",
                    tuple([_SOFT_SOURCES, _ATTR_TYPES] + list(case_keys)))
                out = []
                for it, v, sample, nc, cks, conf, hard in cur.fetchall():
                    if v in _ATTR_GENERIC:
                        continue
                    out.append({'type': it, 'norm': v, 'sample': sample or v, 'nc': nc,
                                'cases': sorted(cks), 'conf': float(conf or 0), 'hard': bool(hard),
                                'weight': _link_weight(it, v)})
                return out
    except Exception as e:
        _log.error('[attribution] union rows: %s', repr(e)[:150])
        return []


def build_union_facts(rows):
    """Two grounded sections for the LLM facts: the STABLE signature (recurs in >=2 cases) and the
    ONE-OFF traces (in a single case — still part of the composite)."""
    stable = [r for r in rows if r['nc'] >= 2]
    oneoff = [r for r in rows if r['nc'] == 1]
    L = ['', 'ЗВЕДЕНИЙ АРСЕНАЛ АКТОРА (обʼєднання ВСІХ його кейсів — кожен кейс докидає свій пазл):']
    L.append('# СТАБІЛЬНИЙ ПІДПИС (повторюється у 2+ кейсах — головні звʼязки, стійкі до ротації):')
    if stable:
        for r in sorted(stable, key=lambda r: (-r['weight'], -r['nc'])):
            L.append('• %s: %s [повтор ×%d; %s]' % (_TYPE_UA.get(r['type'], r['type']), r['sample'],
                     r['nc'], 'тверде' if r['hard'] else 'зі звіту, потребує підтвердження'))
    else:
        L.append('• (спільних поки немає — актор поки з одного кейса)')
    L.append('# РАЗОВІ СЛІДИ (лише в одному кейсі — теж у портреті; майбутній кейс може їх підтвердити):')
    for r in sorted(oneoff, key=lambda r: (-r['weight'], r['type']))[:40]:
        L.append('• %s: %s [1 кейс; %s]' % (_TYPE_UA.get(r['type'], r['type']), r['sample'],
                 'тверде' if r['hard'] else 'зі звіту, потребує підтвердження'))
    return '\n'.join(L)


def _defang(v, t):
    v = str(v or '')
    if t in ('domain', 'url'):
        v = v.replace('https://', 'hxxps://').replace('http://', 'hxxp://').replace('.', '[.]')
    elif t == 'public_ip':
        v = v.replace('.', '[.]')
    elif t == 'email':
        v = v.replace('@', '[@]').replace('.', '[.]')
    return v


def build_defanged_block(rows):
    """Authoritative defanged IOC block straight from the DB (NOT LLM narration) — ready to paste
    into a firewall/SIEM. Recurring indicators first, tagged (повтор ×N)."""
    order = ['attacker_host', 'attacker_token', 'public_ip', 'domain', 'url', 'email', 'anydesk_id',
             'hash_sha256', 'hash_sha1', 'hash_md5', 'user_account', 'windows_sid', 'tool_name', 'malware_name']
    by = {}
    for r in rows:
        by.setdefault(r['type'], []).append(r)
    L = ['', '📌 ЗВЕДЕНІ ІНДИКАТОРИ (готовий блок для блокування/пошуку — звірено з БД):']
    n = 0
    for t in order:
        rs = by.get(t)
        if not rs:
            continue
        vals = []
        for r in sorted(rs, key=lambda r: -r['nc'])[:20]:
            if t in ('domain', 'email', 'url') and r.get('weight', 1) <= 0:
                continue  # benign free-mail/vendor/gov — not a block target
            tag = ' (×%d)' % r['nc'] if r['nc'] >= 2 else ''
            vals.append(_defang(r['sample'], t) + tag)
        if not vals:
            continue
        L.append('%s: %s' % (_TYPE_UA.get(t, t), ', '.join(vals)))
        n += 1
    return '\n'.join(L) if n else ''


def build_subpoena_block(rows):
    """Actionable legal-request targets keyed off the actor's identifiers (ngrok/file-host/mail/IP)."""
    import re as _re
    L = []
    for r in rows:
        t, v = r['type'], r['sample']
        if t == 'attacker_token':
            L.append('• ngrok/Equinox — запит на власника акаунта за токеном: %s' % v[:60])
        elif t == 'url' and len(v) > 20 and _re.search(r'(?i)swisstransfer|wetransfer|dropbox|mega|gofile|files\.fm|dropmefiles|filemail', v):
            L.append('• Файлообмінник — запит на IP/пошту завантажувача за посиланням: %s' % v[:90])
        elif t == 'email':
            L.append('• Поштовий провайдер — логи входів/реєстрації для: %s' % v)
        elif t == 'anydesk_id':
            L.append('• AnyDesk — власник ID: %s' % v)
        elif t == 'public_ip' and r['conf'] >= 0.6:
            L.append('• ISP/abuse — запит за IP: %s' % v)
    if not L:
        return ''
    return '\n\n⚖️ ЦІЛІ ДЛЯ ЗАПИТІВ (subpoena/interpol):\n' + '\n'.join(dict.fromkeys(L))


def _ensure_actor_table():
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""CREATE TABLE IF NOT EXISTS dfir_actor_profiles_v1 (
                    scope_key text PRIMARY KEY, facts_hash text, n_cases int,
                    portrait_text text, updated_at timestamptz DEFAULT now())""")
    except Exception as e:
        _log.warning('[attribution] ensure table: %s', repr(e)[:120])


def _facts_hash(facts):
    import hashlib
    return hashlib.sha1((facts or '').encode('utf-8')).hexdigest()


def build_attacker_portrait(model, llm_url, allowed_cases=None, refresh=False):
    """Cross-case attacker portrait. Returns formatted UA text, or a 'not enough data'
    line. Deterministic intersection facts + one LLM synthesis pass. Cached by facts-hash
    so re-opening it is instant (no repeated ~1-2 min GPU synthesis) until IOCs change."""
    shared, per_case = gather_intersections(allowed_cases)
    n_cases = len(per_case)
    if n_cases < 2:
        return ('🕵 Портрет зловмисника недоступний: потрібно ≥2 кейси з індикаторами '
                '(зараз %d). Заливай більше кейсів — і бот почне зшивати «одну руку».' % n_cases)
    facts = build_intersection_facts(shared, per_case)
    _urows = _union_rows(sorted(per_case.keys()))
    facts = facts + '\n' + build_union_facts(_urows)
    # ── cache: same case-set + same facts + not forced → serve stored portrait ──
    _scope = 'all' if not allowed_cases else '|'.join(sorted(allowed_cases))
    _fh = _facts_hash(facts)
    _ensure_actor_table()
    if not refresh:
        try:
            with psycopg2.connect(PG_DSN) as conn:
                conn.autocommit = True
                with conn.cursor() as cur:
                    cur.execute("SELECT portrait_text FROM dfir_actor_profiles_v1 WHERE scope_key=%s AND facts_hash=%s",
                                (_scope, _fh))
                    r = cur.fetchone()
                    if r and r[0]:
                        return r[0].rstrip() + '\n\n_(з кешу — натисни «оновити» якщо додав кейси/IOC)_'
        except Exception:
            pass

    system = (
        "Ти — провідний CTI-аналітик (threat intelligence). На основі ДЕТЕРМІНОВАНИХ фактів "
        "(спільні індикатори між кейсами + індикатори по кейсах) склади ПОРТРЕТ ЗЛОВМИСНИКА/ГРУПИ "
        "українською. Спирайся ТІЛЬКИ на надані факти, не вигадуй. Пиши стисло і по суті, "
        "БЕЗ markdown-таблиць (тільки списки через '- '). НЕ повторюй текст інструкцій у заголовках — "
        "пиши рівно такі заголовки:\n"
        "🧬 ЗВʼЯЗОК КЕЙСІВ\n🏗 ІНФРАСТРУКТУРА\n🛠 ІНСТРУМЕНТАРІЙ (TTP)\n🕰 АКТИВНІСТЬ У ЧАСІ\n"
        "🎯 ПОЧЕРК\n✅ РЕКОМЕНДАЦІЇ\n\n"
        "Під кожним:\n"
        "• ЗВʼЯЗОК КЕЙСІВ — які кейси повʼязані і ЧИМ (спільні індикатори як докази) + оцінка "
        "впевненості (низька/середня/висока), що це один актор, і чому.\n"
        "• ІНФРАСТРУКТУРА — спільні домени/IP/URL/файлообмінники/сервіси віддаленого доступу.\n"
        "• ІНСТРУМЕНТАРІЙ — які інструменти/малваре повторюються; що це каже про рівень і звички.\n"
        "• АКТИВНІСТЬ — діапазон дат за кейсами; ескалація/повторення.\n"
        "• ПОЧЕРК — характерні прийоми (фішинг під держустанову, конкретний RAT, тунель тощо).\n"
        "• РЕКОМЕНДАЦІЇ — що заблокувати, де шукати актора далі, які кейси перевірити разом.\n"
        "ВАЖЛИВО (грунтованість): НЕ вигадуй звʼязків, DNS-резолвів, геолокації чи власників; НЕ "
        "називай РАЗОВИЙ слід «спільним»; літучі сліди (IP/токен/хеш) — доказ ЛИШЕ коли збіглися "
        "у 2+ кейсах (розділ СТАБІЛЬНИЙ ПІДПИС), інакше це разовий слід. Готовий блок зведених IOC "
        "і цілі для запитів додаються ПРОГРАМНО після твого тексту — НЕ дублюй сирі значення.\n"
        "Якщо спільних індикаторів мало — чесно скажи, що звʼязок слабкий, і які IOC добрати."
    )
    payload = {
        'model': model, 'temperature': 0.2, 'max_tokens': 3500, 'stream': False,
        'messages': [{'role': 'system', 'content': system},
                     {'role': 'user', 'content': facts[:12000]}],
        'chat_template_kwargs': {'enable_thinking': False},
    }
    try:
        req = urllib.request.Request(llm_url.rstrip('/') + '/v1/chat/completions',
                                     data=json.dumps(payload).encode('utf-8'),
                                     headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=240) as r:
            rj = json.loads(r.read().decode('utf-8', errors='ignore'))
        m = (rj.get('choices') or [{}])[0].get('message', {}) or {}
        txt = (m.get('content') or '').strip() or (m.get('reasoning_content') or '').strip()
    except Exception as e:
        _log.error('[attribution] llm: %s', repr(e)[:150])
        txt = ''
    import re as _re
    txt = _re.sub(r'</?[a-zA-Z!][^>]*>', '', txt)
    txt = txt.replace(r'$\rightarrow$', '→')
    # flatten any markdown tables the model still emits into '- ' lines
    _flat = []
    for ln in txt.split('\n'):
        s = ln.strip()
        if set(s) <= set('|-: ') and '|' in s:
            continue  # table separator row
        if s.startswith('|') and s.count('|') >= 2:
            cells = [c.strip() for c in s.strip('|').split('|') if c.strip()]
            if cells:
                _flat.append('- ' + ' — '.join(cells))
            continue
        _flat.append(ln)
    txt = '\n'.join(_flat)
    txt = _re.sub(r'\n{3,}', '\n\n', txt).strip()
    header = '🕵 ПОРТРЕТ ЗЛОВМИСНИКА (крос-кейс аналіз %d кейсів, %d спільних індикаторів)\n' % (
        n_cases, len(shared))
    _defb = build_defanged_block(_urows)
    _subp = build_subpoena_block(_urows)
    _tail = ('\n' + _defb if _defb else '') + (_subp if _subp else '')
    if not txt:
        # graceful deterministic fallback if the LLM flaked — still ships the IOC/subpoena blocks
        return header + '\n' + facts[:3500] + _tail
    result = header + '\n' + txt + _tail
    # store in cache for instant re-open until IOCs change
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""INSERT INTO dfir_actor_profiles_v1(scope_key,facts_hash,n_cases,portrait_text,updated_at)
                    VALUES(%s,%s,%s,%s,now()) ON CONFLICT(scope_key) DO UPDATE
                    SET facts_hash=EXCLUDED.facts_hash, n_cases=EXCLUDED.n_cases,
                        portrait_text=EXCLUDED.portrait_text, updated_at=now()""",
                    (_scope, _fh, n_cases, result))
    except Exception:
        pass
    return result


# ═════════════════════════ ACTOR SEPARATION (many cases → many attackers) ═════════════════════════
# Problem at scale: MANY cases = MANY distinct attackers; one all-cases portrait would blend
# unrelated actors. Fix: cluster cases into DISTINCT actors by WEIGHTED shared-IOC links, so a
# lone commodity overlap (ngrok / AsyncRAT / a public file host — used by unrelated actors) does
# NOT merge them. Actor identity is persisted so labels stay stable as cases are added.
import re as _re2

_STRONG_TYPES = {'public_ip', 'hash_sha1', 'hash_sha256', 'hash_md5', 'anydesk_id',
                 'email', 'attacker_host', 'attacker_token', 'windows_sid', 'url'}
_WEAK_VALUE_RE = _re2.compile(r'(?i)(swisstransfer|wetransfer|dropbox|mega\.nz|mediafire|gofile|'
    r'dropmefiles|files\.fm|anonfiles|pixeldrain|ngrok|equinox\.io|trycloudflare|cloudflar|'
    r'localtonet|serveo|pastebin|discord|t\.me|telegram|github|google|onedrive|bit\.ly|tinyurl)')
_COMMODITY_MAL_RE = _re2.compile(r'(?i)(asyncrat|quasar|njrat|nanocore|remcos|agenttesla|formbook|'
    r'redline|dcrat|venomrat|xworm|yomal|lokibot|warzone|netwire|orcus|darkcomet|blackshades|'
    r'cybergate|snakekeylogger|guloader|smokeloader)')
_COMMODITY_TOOL_RE = _re2.compile(r'(?i)(rdpwrap|mimikatz|7za|7zip|anydesk|teamviewer|rustdesk|'
    r'psexec|procdump|lazagne|winrar|advanced ip scanner|angry ip|nircmd|nirsoft)')
_GENERIC_ACCT_RE = _re2.compile(r'(?i)^(admin|administrator|user|guest|case_59|test|support|operator|root)\d*$')
# free-mail / vendor / CDN / gov domains: EVERYONE uses them → a shared one links NOTHING → weight 0.
# (closes the biggest false-merge hole: 2 shared free-mail domains used to sum past the threshold.)
_BENIGN_DOMAIN_RE = _re2.compile(r'(?i)(?:^|\.)(?:gmail|googlemail|google|gstatic|outlook|hotmail|live|msn|'
    r'microsoft|windows|office365|office|apple|icloud|yahoo|protonmail|proton|gmx|zoho|aol|yandex|mail\.ru|'
    r'ukr\.net|i\.ua|meta\.ua|amazonaws|cloudfront|akamai|azureedge|fastly|digicert|sectigo|letsencrypt)\.|'
    r'\.(?:gov|mil|edu)(?:\.[a-z]{2})?$')
# techniques EVERY intruder uses → weak (w1); a distinctive TTP (e.g. the specific tunnel behaviour) → w2
_COMMODITY_TECH_RE = _re2.compile(r'(?i)(phishing|spearphish|t1566|powershell|t1059|t1021|valid.?account|'
    r'uac.?bypass|t1548|scheduled.?task|t1053|living.?off|lolbin|defender|mppreference|t1562|exclusionpath)')
_HARD_MIN = 3  # min summed HARD-channel (weight>=2) shared weight to MERGE two cases into one actor


# ── ФОН ІЗ ІНВЕНТАРЯ ПЗ ──────────────────────────────────────────────────────────────────────
# Виміряно 2026-08-17: усі ребра, якими кейс case_49 зшився з шістьма іншими, — це hash_sha1
# із source_table='sql_program_exec', тобто інвентар програм самої машини (Amcache/program-exec).
# Той самий білд вендора має ТОЙ САМИЙ SHA1 на кожному ПК у світі, тож 62 із 67 спільних хешів
# прийшли лише з ПʼЯТИ тек: Windows Defender platform, Zoom/bin і UBExtension/UBHostDSTU
# (хост банківського підпису). Самі ці хеші зварили 8 із 11 кейсів в одного «актора».
# Хеш з інвентаря щось каже про ВИКОНАВЦЯ лише тоді, коли файл лежав у місці закидання
# (Public, корінь Roaming/Local/ProgramData, будь-який Temp, тека розпаковки Rar$, Downloads,
# Desktop), а не в теці встановленої програми. Шлях нормалізується до '/' і нижнього регістру.
_STAGING_PATH_RE = _re2.compile(
    r'/users/public/'
    r'|/appdata/roaming/[^/]+$'
    r'|/appdata/local/[^/]+$'
    r'|/temp/'
    r'|rar[$]'
    r'|/programdata/[^/]+$'
    r'|/downloads/'
    r'|/desktop/')
_HASH_TYPES = ('hash_sha1', 'hash_sha256', 'hash_md5')


def _mark_background_hashes(shared):
    """Позначити спільні хеші, які є чистим фоном інвентаря ПЗ: s['bg_hash']=True.
    НІКОЛИ не позначає хеш, який має ще й неінвентарне джерело, і НІКОЛИ — той, чий шлях
    не вдалося встановити: «невідомо» не має ставати «фоном». Збій запиту = нічого не міняємо."""
    norms = sorted({s['ioc_norm'] for s in shared if s['ioc_type'] in _HASH_TYPES})
    if not norms:
        return shared
    paths, srcs = {}, {}
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("SET statement_timeout='20s'")
                cur.execute("SELECT lower(hash_sha1), array_agg(DISTINCT coalesce(full_path,'')) "
                            "FROM program_exec_v2 WHERE lower(coalesce(hash_sha1,''))=ANY(%s) "
                            "GROUP BY 1", (norms,))
                paths = {r[0]: (r[1] or []) for r in cur.fetchall()}
                cur.execute("SELECT lower(coalesce(nullif(ioc_norm,''),lower(ioc_value))), "
                            "array_agg(DISTINCT coalesce(source_table,'')) FROM case_iocs "
                            "WHERE ioc_type=ANY(%s) "
                            "  AND lower(coalesce(nullif(ioc_norm,''),lower(ioc_value)))=ANY(%s) "
                            "GROUP BY 1", (list(_HASH_TYPES), norms))
                srcs = {r[0]: set(r[1] or []) for r in cur.fetchall()}
    except Exception as e:
        _log.error('[attribution] bg-hash gate: %s', repr(e)[:150])
        return shared
    _bs = chr(92)
    for s in shared:
        if s['ioc_type'] not in _HASH_TYPES:
            continue
        if srcs.get(s['ioc_norm'], set()) - {'sql_program_exec'}:
            continue                     # хеш бачило ще щось, крім інвентаря
        ps = paths.get(s['ioc_norm']) or []
        if not ps:
            continue                     # шлях невідомий -> не фон
        if not any(_STAGING_PATH_RE.search(str(p or '').replace(_bs, '/').lower()) for p in ps):
            s['bg_hash'] = True


def _hash_label(norm):
    """Ім'я файлу для голого хеша — «SHA1 a1b2...» нічого не каже слідчому."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("SET statement_timeout='10s'")
                cur.execute("SELECT coalesce(full_path,''), coalesce(executable_name,'') "
                            "FROM program_exec_v2 WHERE lower(coalesce(hash_sha1,''))=%s "
                            "ORDER BY row_id LIMIT 1", (str(norm or '').lower(),))
                r = cur.fetchone()
                if r:
                    p = (r[0] or r[1] or '')
                    nm = p.replace(chr(92), '/').rsplit('/', 1)[-1]
                    if nm:
                        return nm
    except Exception:
        pass
    return None


def _link_weight(ioc_type, ioc_norm):
    """How strongly a SHARED indicator ties two cases to the same actor.
    3 = strong/specific (C2 IP, hash, AnyDesk ID, email, attacker host/SID, unique URL);
    2 = attacker-registered domain / non-commodity malware or tool / non-generic account;
    1 = weak/commodity (public file host, ngrok CDN, commodity RAT/tool, generic account)."""
    v = (ioc_norm or '').strip().lower()
    if not v:
        return 0
    if ioc_type in ('domain', 'url', 'email') and _BENIGN_DOMAIN_RE.search(v):
        return 0  # free-mail/vendor/gov — shared use is not attribution
    if _WEAK_VALUE_RE.search(v):
        return 1
    if ioc_type == 'malware_name':
        return 1 if _COMMODITY_MAL_RE.search(v) else 2
    if ioc_type == 'tool_name':
        return 1 if _COMMODITY_TOOL_RE.search(v) else 2
    if ioc_type == 'user_account':
        return 1 if _GENERIC_ACCT_RE.match(v) else 2
    if ioc_type == 'technique':
        return 1 if _COMMODITY_TECH_RE.search(v) else 2   # distinctive TTP links; universal TTP is weak
    if ioc_type in _STRONG_TYPES:
        return 3
    if ioc_type == 'domain':
        return 2
    return 1


def cluster_actors(allowed_cases=None):
    """Group cases into DISTINCT actor clusters via WEIGHTED shared-IOC links (connected
    components); two cases link only when summed shared-indicator weight >= _LINK_MIN.
    Returns clusters most-active first: [{cases[], links[{type,norm,weight}], weight,
    confidence(висока/середня/низька), n_cases}]. Singleton clusters = unattributed cases."""
    shared, per_case = gather_intersections(allowed_cases)
    cases = sorted(per_case.keys())
    from itertools import combinations
    from collections import defaultdict
    edge_hard = defaultdict(int)   # HARD channel: only weight>=2 shared IOCs — drives the MERGE
    edge_iocs = defaultdict(list)  # ALL shared IOCs (incl. commodity) — for display only
    for s in shared:
        w = _link_weight(s['ioc_type'], s['ioc_norm'])
        if s.get('bg_hash'):
            w = min(w, 1)   # фон інвентаря: показуємо як слабкий збіг, але не зшиваємо кейси
        if w <= 0:
            continue
        for a, b in combinations(sorted(s['cases']), 2):
            if w >= 2:                 # commodity (w=1: ngrok/AsyncRAT/file-hosts) NEVER merges actors
                edge_hard[(a, b)] += w
            edge_iocs[(a, b)].append({'type': s['ioc_type'], 'norm': s['ioc_norm'], 'weight': w})
    parent = {c: c for c in cases}
    def _find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x
    for (a, b), hw in edge_hard.items():
        if hw >= _HARD_MIN:
            ra, rb = _find(a), _find(b)
            if ra != rb:
                parent[rb] = ra
    comp = defaultdict(list)
    for c in cases:
        comp[_find(c)].append(c)
    clusters = []
    for _root, cks in comp.items():
        cks = sorted(cks)
        links, tot, strong = [], 0, False
        seen_l = set()
        for (a, b), iocs in edge_iocs.items():
            if a in cks and b in cks and edge_hard.get((a, b), 0) >= _HARD_MIN:
                for it in iocs:
                    key = (it['type'], it['norm'])
                    if key not in seen_l:
                        seen_l.add(key); links.append(it); tot += it['weight']
                    if it['weight'] >= 3:
                        strong = True
        conf = ('висока' if strong else ('середня' if tot >= 5 else 'низька')) if len(cks) >= 2 else 'н/д'
        clusters.append({'cases': cks, 'links': links, 'weight': tot,
                         'confidence': conf, 'n_cases': len(cks)})
    clusters.sort(key=lambda c: (-c['n_cases'], -c['weight']))
    return clusters


def _ensure_actors_table():
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""CREATE TABLE IF NOT EXISTS dfir_actors_v1 (
                    actor_uid text PRIMARY KEY, label text, case_keys text[], confidence text,
                    weight int, n_cases int, first_seen timestamptz DEFAULT now(),
                    updated_at timestamptz DEFAULT now())""")
    except Exception as e:
        _log.warning('[attribution] ensure actors: %s', repr(e)[:120])


def sync_actors():
    """Recompute actor clusters and reconcile with the persistent registry so actor_uid/label
    stay STABLE as cases are added: match each new multi-case cluster to the existing actor with
    the most overlapping cases (keep its uid+label); mint a new uid only for a genuinely new
    cluster; drop actors whose cases regrouped. Returns current actors, most-active first."""
    _ensure_actors_table()
    clusters = [c for c in cluster_actors() if c['n_cases'] >= 2]
    out = []
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("SELECT actor_uid, label, case_keys FROM dfir_actors_v1")
                existing = [{'uid': r[0], 'label': r[1], 'cases': set(r[2] or [])} for r in cur.fetchall()]
                used = set()

                def _next_label():
                    labs = {e['label'] for e in existing} | {o['label'] for o in out}
                    n = 1
                    while ('Актор #%d' % n) in labs:
                        n += 1
                    return 'Актор #%d' % n

                for cl in clusters:
                    cset = set(cl['cases'])
                    best, best_ov = None, 0
                    for e in existing:
                        if e['uid'] in used:
                            continue
                        ov = len(cset & e['cases'])
                        if ov > best_ov:
                            best, best_ov = e, ov
                    if best and best_ov >= 1:
                        uid, label = best['uid'], best['label']
                        used.add(best['uid'])
                    else:
                        uid, label = 'act_' + _facts_hash('|'.join(cl['cases']))[:10], _next_label()
                    cur.execute("""INSERT INTO dfir_actors_v1(actor_uid,label,case_keys,confidence,weight,n_cases,updated_at)
                        VALUES(%s,%s,%s,%s,%s,%s,now()) ON CONFLICT(actor_uid) DO UPDATE
                        SET label=EXCLUDED.label, case_keys=EXCLUDED.case_keys, confidence=EXCLUDED.confidence,
                            weight=EXCLUDED.weight, n_cases=EXCLUDED.n_cases, updated_at=now()""",
                        (uid, label, cl['cases'], cl['confidence'], cl['weight'], cl['n_cases']))
                    out.append({'uid': uid, 'label': label, 'cases': cl['cases'],
                                'confidence': cl['confidence'], 'weight': cl['weight'], 'n_cases': cl['n_cases']})
                keep = {o['uid'] for o in out}
                for e in existing:
                    if e['uid'] not in keep:
                        cur.execute("DELETE FROM dfir_actors_v1 WHERE actor_uid=%s", (e['uid'],))
    except Exception as e:
        _log.error('[attribution] sync_actors: %s', repr(e)[:150])
    out.sort(key=lambda o: (-o['n_cases'], -o['weight']))
    return out


_CONF_ICON = {'висока': '🔴', 'середня': '🟠', 'низька': '🟡', 'н/д': '⚪'}


def build_actor_menu():
    """Return (text, actors, solo_cases) for the «Портрети зловмисників» menu: one entry per
    DISTINCT actor (a group of cases linked by strong-enough shared indicators) + an
    'unattributed' bucket for cases with no reliable cross-case link. app.py adds a button per
    actor (callback tool:actorportrait:<uid>)."""
    actors = sync_actors()
    solo = [c['cases'][0] for c in cluster_actors() if c['n_cases'] == 1]
    L = ['🕵 ПОРТРЕТИ ЗЛОВМИСНИКІВ (крос-кейс)', '']
    if not actors:
        L.append('Поки що жодної групи повʼязаних кейсів не виявлено — потрібно ≥2 кейси з '
                 'надійними спільними слідами (той самий C2/хеш/акаунт, а не лише ходовий tool).')
    else:
        L.append('Виявлено окремих акторів (груп повʼязаних кейсів): %d' % len(actors))
        L.append('Тисни на актора нижче, щоб отримати його портрет.')
        L.append('')
        for a in actors:
            L.append('%s %s — %d кейс(и) · впевненість: %s'
                     % (_CONF_ICON.get(a['confidence'], '⚪'), a['label'], a['n_cases'], a['confidence']))
            L.append('   %s' % ', '.join(_pretty(c) for c in a['cases']))
    if solo:
        L.append('')
        L.append('◽ Неатрибутовані (без надійних спільних слідів): %d' % len(solo))
        L.append('   ' + ', '.join(_pretty(c) for c in solo[:25]))
    return '\n'.join(L), actors, solo


def build_actor_portrait(actor_uid, model, llm_url, refresh=False):
    """Portrait for ONE actor (its cluster of cases only) — reuses build_attacker_portrait
    scoped to that actor's cases (per-scope cached), so each attacker gets a SEPARATE portrait."""
    _ensure_actors_table()
    label, cases = None, []
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("SELECT label, case_keys FROM dfir_actors_v1 WHERE actor_uid=%s", (actor_uid,))
                r = cur.fetchone()
                if r:
                    label, cases = r[0], list(r[1] or [])
    except Exception:
        pass
    if not cases:
        return '🕵 Актора не знайдено (можливо, кейси перегрупувались). Відкрий «Портрети зловмисників» заново.'
    if len(cases) < 2:
        return '🕵 %s: замало повʼязаних кейсів для портрета.' % (label or actor_uid)
    body = build_attacker_portrait(model, llm_url, allowed_cases=sorted(cases), refresh=refresh)
    return '🕵 %s — %d повʼязаних кейсів\n\n' % (label or 'Актор', len(cases)) + body


def new_link_alert(case_key, force=False):
    """PROACTIVE autonomy: right after a case is analyzed, if it belongs to an actor cluster with
    >=2 cases, return a short Telegram alert («this new case is the same hand» — which actor, the
    other cases, the strongest shared indicator, confidence). None if it links to nothing yet."""
    try:
        for cl in cluster_actors():
            if cl['n_cases'] >= 2 and case_key in cl['cases']:
                others = ', '.join(_pretty(c) for c in cl['cases'] if c != case_key)
                links = sorted(cl['links'], key=lambda l: -l['weight'])
                top = links[0] if links else None
                top_s = '—'
                if top:
                    top_s = '%s: %s' % (_TYPE_UA.get(top['type'], top['type']), top['norm'])
                    if str(top['type']).startswith('hash'):
                        _nm = _hash_label(top['norm'])
                        if _nm:
                            top_s += ' (%s)' % _nm
                label = 'Актор'
                try:
                    for a in sync_actors():
                        if case_key in a['cases']:
                            label = a['label']; break
                except Exception:
                    pass
                # «Та сама рука» — надто сильна заява для слідства. Її дозволено лише коли
                # звʼязок тримає конкретний індикатор ваги 3 (машина/IP/акаунт/пошта/хеш файлу
                # в місці закидання), тобто confidence='висока'. Інакше — «спільні ознаки».
                _strong = cl['confidence'] == 'висока'
                _head = ('🔗 НОВИЙ ЗВʼЯЗОК — схоже на ту саму руку'
                         if _strong else
                         '🔗 СПІЛЬНІ ОЗНАКИ — можливий звʼязок, потребує перевірки')
                _foot = ('Спільна ознака — це ще не той самий виконавець: те саме ПЗ чи та сама '
                         'типова техніка трапляються у незалежних атак. Перевір «Портрет '
                         'зловмисника» і звір докази вручну.')
                _alert = '\n'.join([
                    _head, '',
                    '📁 %s' % _pretty(case_key),
                    '↔ спільні ознаки з: %s' % others,
                    '🕵 Група: %s · %d кейс(и) · впевненість: %s' % (label, cl['n_cases'], cl['confidence']),
                    '🔑 Найсильніший спільний слід: %s' % top_s, '',
                    _foot])
                # DEDUP: only alert when THIS link-state is new for this case, so re-running
                # DFIR on the same case does not re-send the same attacker-link notification.
                import hashlib as _hl_al
                _sig = _hl_al.md5(('|'.join(sorted(cl['cases'])) + '|' + str(top_s) + '|'
                                   + str(cl['confidence'])).encode('utf-8', 'ignore')).hexdigest()
                try:
                    with psycopg2.connect(PG_DSN) as _sc:
                        _sc.autocommit = True
                        with _sc.cursor() as _scur:
                            _scur.execute("CREATE TABLE IF NOT EXISTS dfir_link_alert_seen_v1("
                                          "case_key TEXT PRIMARY KEY, sig TEXT, alerted_at TIMESTAMPTZ DEFAULT now())")
                            _scur.execute("SELECT sig FROM dfir_link_alert_seen_v1 WHERE case_key=%s", (case_key,))
                            _row = _scur.fetchone()
                            if _row and _row[0] == _sig and not force:
                                return None
                            _scur.execute("INSERT INTO dfir_link_alert_seen_v1(case_key,sig,alerted_at) "
                                          "VALUES(%s,%s,now()) ON CONFLICT(case_key) DO UPDATE "
                                          "SET sig=EXCLUDED.sig, alerted_at=now()", (case_key, _sig))
                except Exception:
                    pass
                return _alert
    except Exception as e:
        _log.error('[attribution] new_link_alert: %s', repr(e)[:120])
    return None


def refresh_actor_portraits(model, llm_url):
    """AUTONOMY hook: recluster + (re)generate the portrait for every actor whose facts changed.
    Called in the background after IOC enrichment / new case, so per-actor portraits stay fresh
    without the user pressing anything. Cheap when nothing changed (build_attacker_portrait
    serves from cache on an unchanged facts-hash). Returns count of actors processed."""
    try:
        actors = sync_actors()
    except Exception as e:
        _log.error('[attribution] refresh actors: %s', repr(e)[:120])
        return 0
    n = 0
    for a in actors:
        try:
            build_attacker_portrait(model, llm_url, allowed_cases=sorted(a['cases']), refresh=False)
            n += 1
        except Exception as e:
            _log.warning('[attribution] regen %s: %s', a.get('uid'), repr(e)[:100])
    return n
