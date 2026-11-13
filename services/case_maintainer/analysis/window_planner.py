# -*- coding: utf-8 -*-
"""Candidate incident days, with a reason attached to each one.

_compute_incident_window collapses everything into a single start..end range. That hides
two things an investigator needs: WHY a day was chosen, and the fact that a case usually
has several distinct moments - delivery, foothold, detonation - which can sit weeks apart.
case_40's corrected window spans 2026-01-12..2026-03-18: analysing that as one block is
the "runs over the whole timeline" problem the owner described.

So instead of one window, produce a ranked list of candidate days, each carrying the kinds
of signal that fired on it and a concrete example. That list is small enough to put in
front of the model, which then decides which candidates are worth a window.

Everything here is read-only and exception-safe.
"""
import logging

import psycopg2

from core.config import PG_DSN

_log = logging.getLogger('app')


def _os_env(k, d):
    import os
    return os.environ.get(k, d)

_RANSOM_NAME = r"restore|decrypt|recover|how.{0,4}to|unlock|_readme|!!!"
_RANSOM_EXT = r"\.(txt|hta|html|htm)$"
_RANSOM_SKIP = (r"program files|programdata|winsxs|driverstore|recycle|"
                r"system volume information|appdata.local.packages")
_DROP_PATHS = r"temp|appdata|programdata|public|downloads"
# Software distribution unpacks itself into temp constantly. These paths are never an
# attacker's drop, and left in they dominate the tier: on case_40 the top candidate day
# was 149 Cellebrite installer files. Judgement calls beyond this belong to the model -
# the point of the candidate list is to be worth reading, not to be pre-decided.
_OWN_PATHS = (r"dfirtriage_|dfir_triage|vao_collector|kape_triage|"
              r"package cache|\\microsoft\\temp\\|systemtemp|"
              r"googleupdater|microsoftedgeupdate|_unpacker_|\\windows\\installer\\")
# What an attacker's PowerShell does that an administrator's normally does not.
_OBFUSCATED = (r"frombase64string|-enc |-encodedcommand|iex |invoke-expression|"
               r"downloadstring|downloadfile|bypass -|hidden -|webclient|"
               r"compression.deflatestream|char\[\]|-join")

# Each tier is (key, human label, weight, SQL). SQL returns (day, count, sample).
# Weights mirror how strongly a signal implies an incident rather than normal use.
_TIERS = (
    # Every Security-log ID below is qualified by channel='Security'. Without that, an
    # event ID is just a number other providers reuse: measured across this database,
    # 4625 has 310 hits in the Application channel from Microsoft-Windows-EventSystem
    # that are not failed logons at all.
    ('intrusion', 'вхід/облікові записи', 3,
     "SELECT event_ts::date AS d, count(*) AS c,"
     "       min(coalesce(target_user,'') || ' ' || coalesce(remote_host,'')) AS sample "
     "FROM event_logs_v2 "
     "WHERE case_key=%(ck)s AND event_ts IS NOT NULL "
     "  AND ((coalesce(channel,'')='Security' AND ("
     "          (event_id=4624 AND (logon_type ILIKE '%%remote interactive%%'"
     "                              OR logon_type ILIKE '%%RDP%%' OR logon_type='10'))"
     "          OR event_id=4625"
     "          OR event_id IN (4720,4728,4732,4756,4724,4738)))"
     "       OR (event_id=1149 AND channel ILIKE '%%TerminalServices%%')) "
     "GROUP BY 1"),

    ('defender', 'Defender: детект або втручання', 4,
     "SELECT event_ts::date AS d, count(*) AS c, min(coalesce(command_line, channel, '')) AS sample "
     "FROM event_logs_v2 "
     "WHERE case_key=%(ck)s AND event_ts IS NOT NULL "
     "  AND event_id IN (1116,1117,5001,5010,5012) "
     "  AND coalesce(provider,'') ILIKE '%%Windows Defender%%' "
     "GROUP BY 1"),

    # 1102 is "the audit log was cleared" only in the Security channel. Measured across
    # this database: 559 events carry ID 1102 and exactly 2 of them are the real thing -
    # the other 557 are TerminalServices-RDPClient and ShellCommon-StartLayoutPopulation.
    # At weight 5, counting those was 99.6% noise driving the highest-weighted signal.
    ('logclear', 'очищення журналу', 5,
     "SELECT event_ts::date AS d, count(*) AS c, min(coalesce(computer,'')) AS sample "
     "FROM event_logs_v2 "
     "WHERE case_key=%(ck)s AND event_ts IS NOT NULL AND event_id=1102 "
     "  AND coalesce(channel,'')='Security' "
     "GROUP BY 1"),

    # Counting PowerShell events by volume finds the days Windows was busy, not the days
    # someone attacked. Measured on case_40: ranking by raw 4104 volume produced a top
    # ten whose examples were "$global:?" and "$Host" - routine module loading - while the
    # day with the actual obfuscated payload ranked nowhere. Match on what the script
    # DOES instead.
    ('ps_obf', 'обфускований PowerShell', 4,
     "SELECT event_ts::date AS d, count(*) AS c,"
     "       min(left(payload::text, 70)) AS sample "
     "FROM event_logs_v2 "
     "WHERE case_key=%(ck)s AND event_ts IS NOT NULL "
     "  AND event_id=4104 AND channel ILIKE '%%PowerShell%%' "
     "  AND payload::text ~* %(obf)s "
     "GROUP BY 1"),

    ('service', 'встановлення служби', 3,
     "SELECT event_ts::date AS d, count(*) AS c,"
     "       min(coalesce(process_name, command_line, left(payload::text, 70))) AS sample "
     "FROM event_logs_v2 "
     "WHERE case_key=%(ck)s AND event_ts IS NOT NULL "
     "  AND ((event_id=7045 AND coalesce(channel,'')='System')"
     "       OR (event_id=4697 AND coalesce(channel,'')='Security')) "
     "GROUP BY 1"),

    ('ransom', 'записки викупу', 5,
     "SELECT event_ts::date AS d, count(*) AS c, min(file_name) AS sample "
     "FROM filesystem_v2 "
     "WHERE case_key=%(ck)s AND event_ts IS NOT NULL "
     "  AND lower(file_name) ~ %(rname)s AND lower(file_name) ~ %(rext)s "
     "  AND lower(coalesce(parent_path,'')) !~ %(rskip)s "
     "GROUP BY 1"),

    ('drop', 'виконуваний файл у тимчасовій теці', 3,
     "SELECT event_ts::date AS d, count(*) AS c, min(executable_name) AS sample "
     "FROM program_exec_v2 "
     "WHERE case_key=%(ck)s AND event_ts IS NOT NULL "
     "  AND lower(coalesce(full_path,'')) ~ %(drop)s "
     "  AND lower(coalesce(full_path,'')) !~ %(own)s "
     "GROUP BY 1"),
)


def _floor_and_ceiling(cur, case_key):
    """(earliest credible date, latest date) - nothing before the OS existed is real."""
    floor = ceiling = None
    try:
        cur.execute("SELECT install_date_utc FROM public.system_profile_v1 WHERE case_key=%s LIMIT 1",
                    (case_key,))
        r = cur.fetchone()
        if r and r[0]:
            s = str(r[0])[:10]
            if s[:2] in ('19', '20'):
                floor = s
    except Exception:
        pass
    try:
        cur.execute("SELECT min(event_ts)::date, max(event_ts)::date FROM public.event_logs_v2 "
                    "WHERE case_key=%s AND event_ts > '2000-01-01'", (case_key,))
        r = cur.fetchone()
        if r and r[1]:
            ceiling = str(r[1])
        # Without a system profile there is no install date, and filesystem/program_exec
        # tables carry junk stamps (1980-01-01, 1601-10-31) that otherwise rank as
        # candidate incident days. Fall back to where the event log actually starts.
        if not floor and r and r[0]:
            floor = str(r[0])
    except Exception:
        pass
    return floor, ceiling


def candidate_days(case_key, top=12):
    """Ranked candidate days: ([{date, score, kinds, signals}], floor_date)."""
    days = {}
    floor = ceiling = None
    params = {'ck': case_key, 'rname': _RANSOM_NAME, 'rext': _RANSOM_EXT,
              'rskip': _RANSOM_SKIP, 'drop': _DROP_PATHS, 'own': _OWN_PATHS,
              'obf': _OBFUSCATED}
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                floor, ceiling = _floor_and_ceiling(cur, case_key)
                for key, label, weight, sql in _TIERS:
                    try:
                        cur.execute(sql, params)
                        rows = cur.fetchall()
                    except Exception as e:
                        _log.error('[windows] tier %s failed: %s' % (key, e))
                        continue
                    for d, c, sample in rows:
                        if not d or not c:
                            continue
                        ds = str(d)
                        # Anything dated before the machine existed is a broken timestamp,
                        # not evidence. This is the check that would have prevented the
                        # 2025-08 anchor on a machine installed in 2025-11.
                        if floor and ds < floor:
                            continue
                        if ceiling and ds > ceiling:
                            continue
                        e = days.setdefault(ds, {'date': ds, 'score': 0, 'signals': []})
                        e['score'] += int(c) * weight
                        e['signals'].append({'tier': key, 'label': label, 'count': int(c),
                                             'sample': str(sample or '')[:70].replace('\n', ' ')})
    except Exception as e:
        _log.error('[windows] candidate_days failed: %s' % e)
        return [], floor

    # How ordinary is each kind of signal ON THIS MACHINE? Two obfuscated PowerShell blocks
    # look damning until you see the machine has 37 such days. Without that baseline the
    # model reads every candidate as an incident - measured: on a machine we classify as
    # clean it built an attack narrative out of Defender's own platform scripts.
    spread = {}
    for e in days.values():
        for s in e['signals']:
            spread[s['tier']] = spread.get(s['tier'], 0) + 1

    ranked = list(days.values())
    for e in ranked:
        e['kinds'] = len({s['tier'] for s in e['signals']})
        for s in e['signals']:
            s['days_seen'] = spread.get(s['tier'], 0)
    # A day backed by several DIFFERENT kinds of signal beats a day with one loud kind:
    # a benign software install spikes one tier, a real incident touches many.
    ranked.sort(key=lambda x: (x['kinds'], x['score']), reverse=True)
    return ranked[:top], floor


def render_candidates(cands, floor=None):
    """Compact block for the model - one line per candidate, with the reason."""
    if not cands:
        return ''
    out = ['КАНДИДАТИ НА ПЕРІОД ІНЦИДЕНТУ (спершу ті, де збіглося найбільше РІЗНИХ видів сигналу):']
    if floor:
        out.append('(усе, датоване раніше %s — коли ця машина почала існувати у доказах — '
                   'відкинуто як биті мітки часу)' % floor)
    for i, e in enumerate(cands, 1):
        sig = ', '.join(
            '%s x%d%s' % (s['label'], s['count'],
                          (' [такі дні на цій машині: %d]' % s['days_seen']) if s.get('days_seen') else '')
            for s in e['signals'])
        out.append('  [%d] %s  видів сигналу: %d  | %s' % (i, e['date'], e['kinds'], sig))
        best = max(e['signals'], key=lambda s: s['count'])
        if best.get('sample'):
            out.append('        приклад: %s' % best['sample'])
    return '\n'.join(out)


# ── The decision step ────────────────────────────────────────────────────────────
# Everything above is deterministic: it produces a list of candidate days and the reason
# each one is on the list. Choosing WHICH of them is worth an investigation window is a
# judgement call - "Cellebrite installer unpacked 149 files" and "6 obfuscated PowerShell
# blocks plus 6 service installs" score similarly and mean completely different things.
# That judgement is what the model is for, and it is the first point in the pipeline where
# its answer changes what gets collected rather than how the result is worded.

_MAX_SPAN_DAYS = 45


def _parse_day(s):
    from datetime import date
    try:
        p = str(s).strip()[:10].split('-')
        return date(int(p[0]), int(p[1]), int(p[2]))
    except Exception:
        return None


def _deterministic_says_compromised(case_key):
    """True when the SQL detection layer found something. None when it could not run."""
    try:
        import psycopg2 as _pg
        from analysis.threat_detect import detect_threats
        with _pg.connect(PG_DSN) as conn:
            conn.autocommit = True
            dets = detect_threats(case_key, conn) or []
        items = dets.get('detections') if isinstance(dets, dict) else dets
        items = items or []
        sev = set()
        for it in items:
            if isinstance(it, dict):
                sev.add(str(it.get('severity', '')).strip().lower())
        hard = bool(sev & {'high', 'critical'})
        _log.error('[windows] deterministic layer on %s: %d detection(s), severities=%s -> %s'
                   % (case_key, len(items), sorted(x for x in sev if x),
                      'incident' if hard else 'background'))
        return hard
    except Exception as e:
        _log.error('[windows] deterministic gate unavailable (%s) - not planning windows' % e)
        return None


def plan_windows(case_key, biography='', max_windows=2, margin_days=14, model=None):
    """Ask the model which candidate days deserve a window.

    Returns (windows, source) where windows is [{'start','end','why'}] and source is
    'llm' or 'fallback'. Never raises: on any failure the caller keeps the deterministic
    window it already had.
    """
    import json as _json
    import os as _os
    import urllib.request as _ur
    from datetime import timedelta

    from core.config import LLM_URL, LLM_FAST_MODEL, LLM_JSON_TEMPERATURE
    from core.model_router import build_chat_payload

    # The gate: a clean machine gets no window at all, because the model will invent one.
    if str(_os_env('DFIR_WINDOW_SKIP_GATE', '0')).strip() not in ('1', 'on', 'true', 'yes'):
        verdict = _deterministic_says_compromised(case_key)
        if verdict is not True:
            _log.error('[windows] nothing rated high/critical - not asking the model '
                       'where to dig, because on a quiet machine it invents somewhere')
            return [], 'clean'

    cands, floor = candidate_days(case_key, top=12)
    if not cands:
        return [], 'fallback'
    listing = render_candidates(cands, floor)

    prompt = (
        'Ти — старший DFIR-слідчий. Перед тобою рамка машини і перелік днів, де спрацювали '
        'ознаки. Твоє завдання — НЕ писати звіт, а вирішити, ДЕ саме копати.\n\n'
        + (biography + '\n\n' if biography else '')
        + listing + '\n\n'
        'Подумай як людина: встановлення легального софту теж створює файли в тимчасових '
        'теках і ставить служби. Атака зазвичай лишає збіг РІЗНИХ ознак і виглядає '
        'недоречно для цієї машини.\n'
        'ДИВИСЬ НА ЧИСЛО В ДУЖКАХ: якщо ознака трапляється на цій машині десятки днів — '
        'це її нормальний фон, а не інцидент. Підозрілим є ВІДХИЛЕННЯ від фону, а не сам '
        'факт спрацювання.\n'
        'БІЛЬШІСТЬ МАШИН, ЯКІ ПОТРАПЛЯЮТЬ НА ПЕРЕВІРКУ, ВИЯВЛЯЮТЬСЯ ЧИСТИМИ. Порожня '
        'відповідь {"windows": []} — це ПОВНОЦІННА правильна відповідь, а не поразка. '
        'Вигадати період, якого не було, гірше, ніж не знайти жодного: слідчий піде '
        'перевіряти порожнечу. Обирай період, тільки якщо можеш назвати конкретну ознаку, '
        'яку НЕ пояснює звичайна робота машини й встановлення софту.\n'
        'Обери НЕ БІЛЬШЕ %d періодів. Кожен має бути ВУЗЬКИМ (кілька днів), а не місяцями — '
        'два вузькі вікна кращі за одне широке: доставка і спрацювання зазвичай рознесені '
        'у часі, а все між ними — фон.\n\n'
        'Поверни ЛИШЕ JSON:\n'
        '{"windows": [{"start": "РРРР-ММ-ДД", "end": "РРРР-ММ-ДД", '
        '"why": "<чому саме цей період, 1 речення>"}], '
        '"rejected": "<які кандидати ти відкинув і чому, 1 речення>"}\n'
        'Якщо жоден кандидат не виглядає інцидентом — поверни {"windows": []}.'
    ) % max_windows

    raw = ''
    try:
        body = _json.dumps(build_chat_payload(
            model=(model or _os.getenv('DFIR_AGENT_JSON_MODEL') or LLM_FAST_MODEL),
            messages=[{'role': 'user', 'content': prompt}],
            role='json', temperature=LLM_JSON_TEMPERATURE,
            max_tokens=int(_os.environ.get('DFIR_WINDOW_MAX_TOKENS', '2000')),
            stream=False, reasoning_effort=_os.environ.get('DFIR_JSON_REASONING_EFFORT', 'low'),
        )).encode('utf-8')
        req = _ur.Request(LLM_URL.rstrip('/') + '/v1/chat/completions',
                          data=body, headers={'Content-Type': 'application/json'})
        with _ur.urlopen(req, timeout=int(_os.environ.get('DFIR_WINDOW_TIMEOUT', '240'))) as resp:
            data = _json.loads(resp.read().decode('utf-8', errors='ignore'))
        raw = (data.get('choices') or [{}])[0].get('message', {}).get('content', '') or ''
        st, en = raw.find('{'), raw.rfind('}')
        plan = _json.loads(raw[st:en + 1]) if st != -1 and en > st else {}
    except Exception as e:
        _log.error('[windows] planner call failed: %s raw=%r' % (e, raw[:150]))
        return [], 'fallback'

    floor_d = _parse_day(floor) if floor else None
    ceiling_d = _parse_day(cands[0]['date'])
    for c in cands:
        d = _parse_day(c['date'])
        if d and (not ceiling_d or d > ceiling_d):
            ceiling_d = d

    out = []
    for w in (plan.get('windows') or [])[:max_windows]:
        a, b = _parse_day(w.get('start')), _parse_day(w.get('end'))
        if not a or not b:
            continue
        if b < a:
            a, b = b, a
        # The model proposes the core period; the margin around it is ours, because
        # delivery reliably precedes what the candidate day actually shows.
        a = a - timedelta(days=margin_days)
        b = b + timedelta(days=max(3, margin_days // 4))
        # A window that reaches outside the evidence, or swallows months, is not a window.
        if floor_d and a < floor_d:
            a = floor_d
        if ceiling_d and b > ceiling_d:
            b = ceiling_d
        if (b - a).days > _MAX_SPAN_DAYS:
            b = a + timedelta(days=_MAX_SPAN_DAYS)
        out.append({'start': a.isoformat(), 'end': b.isoformat(),
                    'why': str(w.get('why', ''))[:300]})

    if not out:
        _log.error('[windows] model returned no usable window; rejected=%r'
                   % str(plan.get('rejected', ''))[:200])
        return [], 'fallback'
    _log.error('[windows] model chose %d window(s)' % len(out))
    for w in out:
        _log.error('[windows]   %s .. %s  %s' % (w['start'], w['end'], w['why'][:120]))
    return out, 'llm'
