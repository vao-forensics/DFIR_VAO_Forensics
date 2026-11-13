# reports/onset.py
# "ЯК ЦЕ ПОЧАЛОСЯ" — a deliberately RETROSPECTIVE pass that looks BEFORE the
# detonation window.
#
# Why this file exists at all: _incident_window() is anchored on the ransom-note
# drop, so on a ransomware case it collapses to a single day. That anchor is
# CORRECT for the moment of detonation and STRUCTURALLY BLIND to the way in --
# everything that happened earlier falls outside it. This module does not widen
# that window (it must stay tight); it adds a second, retrospective horizon and
# answers, in words, one question: what is the earliest HARD trace, and what do
# we still not know.
#
# Discipline enforced here:
#   * every timestamp is printed together with the KIND of time it is
#     (ShimCache = file modification, NOT execution; Amcache = first appearance;
#     Prefetch/BAM = real execution). Mislabelling these is how a report invents
#     an execution that never happened.
#   * the section SELF-OMITS unless there is a concrete pre-window signal.
#     Silence is the correct output for a case with no entry evidence.
#   * log clears are counted ONLY as 1102-in-Security and 104-from-Eventlog.
#     Raw 1102/104 across all channels is dominated by StateRepository /
#     Diagnosis-Scripted noise and would manufacture a "spike" on any machine.
import re
import psycopg2

try:
    from core.config import PG_DSN
except Exception:
    try:
        from config import PG_DSN
    except Exception:
        PG_DSN = None

NL = chr(10)

# How far back the retrospective horizon reaches from the start of the
# detonation window. Two years covers slow-dwell intrusions without turning the
# section into a dump of the machine's whole life -- and, just as important, it
# cuts off the 2018-style timestamps that ShimCache carries for copied or
# timestomped binaries. Without a floor those forged file times win the "earliest
# trace" slot and push the real chain out of the lead.
RETRO_DAYS = 730

_VOWELS = set('aeiouy')

# Software words that make a long consonant-heavy name legitimate. Without this
# the random-name test flags installer/uninstall/updater binaries, which is the
# single largest false-positive family (measured across 11 cases).
_BENIGN_TOKEN_RE = re.compile(
    r'install|uninst|updat|setup|plugin|wallpaper|launcher|crashpad|redist|'
    r'patcher|regtlib|package|driver|runtime|framework|report|service',
    re.I)

_USER_WRITABLE_RE = r'(temp|users..public|appdata|programdata)'

# Vendor software that legitimately registers services from under ProgramData.
# Windows Defender alone accounts for every hit this block produced on the
# case_47 case: it installs MpKslDrv.sys from a fresh GUID folder under
# `Definition Updates` on each signature update.
_VENDOR_SERVICE_RE = (r'windows defender|definition updates|mpksl|microsoft'
                      r'|program files|packages.plugins|dell|intel|nvidia|amd'
                      r'|kaspersky|eset|avast|mcafee|symantec|sophos|bitdefender')

# source_file -> (human label, is_execution). The bot ingests these artefacts
# from KAPE/EZ-Tools CSVs, and their time semantics differ fundamentally.
_ARTEFACT_KINDS = (
    ('amcache', 'Amcache — час першої появи файлу в системі', False),
    ('appcompatcache', 'ShimCache — час МОДИФІКАЦІЇ файлу, це НЕ час запуску', False),
    ('shimcache', 'ShimCache — час МОДИФІКАЦІЇ файлу, це НЕ час запуску', False),
    ('prefetch', 'Prefetch — час РЕАЛЬНОГО запуску', True),
    ('bam', 'BAM/DAM — час РЕАЛЬНОГО запуску', True),
    ('dam', 'BAM/DAM — час РЕАЛЬНОГО запуску', True),
    ('userassist', 'UserAssist — час РЕАЛЬНОГО запуску користувачем', True),
    ('srum', 'SRUM — час мережевої/ресурсної активності процесу', True),
)


def _q(cur, sql, args=()):
    try:
        cur.execute(sql, args)
        return cur.fetchall()
    except Exception:
        try:
            cur.connection.rollback()
        except Exception:
            pass
        return []


def _fmt_ts(ts):
    try:
        return ts.isoformat()[:19].replace('T', ' ')
    except Exception:
        return str(ts or '')[:19]


def _stem(name):
    low = (name or '').lower()
    for ext in ('.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.tmp', '.com'):
        if low.endswith(ext):
            return name[:-len(ext)]
    return name or ''


def _randomish(token):
    """True when a name looks machine-generated rather than chosen by a human:
    letters only, 7..18 chars, few vowels and at least one 3-consonant run.
    Measured on 11 live cases -- see the worklog entry for the false-positive
    count before and after the parent-folder requirement was added."""
    s = _stem(token)
    if not s or not s.isascii() or not s.isalpha():
        return False
    if not (7 <= len(s) <= 18):
        return False
    low = s.lower()
    vowels = sum(1 for ch in low if ch in _VOWELS)
    run = 0
    longest = 0
    for ch in low:
        if ch in _VOWELS:
            run = 0
        else:
            run += 1
            if run > longest:
                longest = run
    return (vowels / float(len(low))) <= 0.34 and longest >= 3


def _random_drop(path):
    """A randomly named executable sitting in a randomly named sub-folder.
    BOTH halves are required: a random folder alone is how legitimate
    installers unpack (GUID temp dirs full of dismhost.exe), and a random
    name alone matches vendor binaries like msmpeng.exe."""
    p = (path or '').replace('/', chr(92))
    low = p.lower()
    if low.startswith('c:' + chr(92) + 'windows' + chr(92)):
        return False
    if (chr(92) + 'windows' + chr(92)) in low and 'system32' in low:
        return False
    parts = [x for x in p.split(chr(92)) if x]
    if len(parts) < 2:
        return False
    name, parent = parts[-1], parts[-2]
    if _BENIGN_TOKEN_RE.search(name) or _BENIGN_TOKEN_RE.search(parent):
        return False
    if _stem(name).lower() == _stem(parent).lower():
        return False
    return _randomish(name) and _randomish(parent)


def _artefact_kind(source_file):
    low = (source_file or '').lower()
    for key, label, is_exec in _ARTEFACT_KINDS:
        if key in low:
            return label, is_exec
    return 'артефакт виконання', False


def _naive(d):
    """Event rows come back timezone-aware (+02:00 / +03:00 depending on the
    season the record was written in), while the incident window is a bare date.
    Comparing the two raises TypeError and silently kills the whole collection
    pass, so every comparison here goes through this."""
    try:
        return d.replace(tzinfo=None)
    except Exception:
        return d


def _iw_start_dt(iw_start):
    import datetime as _dt
    if not iw_start:
        return None
    try:
        v = iw_start
        if isinstance(v, _dt.datetime):
            return v
        return _dt.datetime.fromisoformat(str(v)[:19])
    except Exception:
        return None


def onset_evidence(case_key, iw_start):
    """Collect every pre-window signal. Pure reads, never raises."""
    import datetime as _dt
    ev = {
        'rat_tools': [],      # remote-access families first seen before the window (>=2 within RETRO_DAYS)
        'drops': [],          # randomly named executables planted before detonation
        'sessions': [],       # remote sessions that precede the window
        'rare_sessions': [],  # short isolated bursts among those
        'links': [],          # drop <-> session correlations
        'clears': [],         # real log-clear events
        'coverage': [],       # per-channel first record
        'security_blind': None,
        'accounts': [],       # accounts/services/tasks created before detonation
        'horizon': None,
    }
    start = _iw_start_dt(iw_start)
    if not start or not PG_DSN:
        return ev
    horizon = start - _dt.timedelta(days=RETRO_DAYS)
    ev['horizon'] = horizon
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            cur = conn.cursor()

            # (1) randomly named executables dropped into user-writable paths
            rows = _q(cur, """SELECT coalesce(full_path, executable_name) p, event_ts,
                       coalesce(source_file,'') sf
                FROM program_exec_v2
                WHERE case_key=%s AND event_ts IS NOT NULL
                  AND event_ts < %s AND event_ts >= %s
                  AND coalesce(full_path, executable_name) IS NOT NULL
                  AND lower(coalesce(full_path, executable_name)) ~ %s
                ORDER BY event_ts ASC LIMIT 20000""",
                (case_key, start, horizon, _USER_WRITABLE_RE))
            drops = {}
            for path, ts, sf in rows:
                if not _random_drop(path):
                    continue
                parts = [x for x in str(path).replace('/', chr(92)).split(chr(92)) if x]
                # de-duplicate the same planted file seen under Temp\ and Temp\4\
                key = (parts[-1].lower(), parts[-2].lower())
                d = drops.setdefault(key, {'path': path, 'times': []})
                label, is_exec = _artefact_kind(sf)
                d['times'].append((ts, label, is_exec))
                if len(str(path)) > len(str(d['path'])):
                    d['path'] = path
            for key in sorted(drops, key=lambda k: min(t[0] for t in drops[k]['times'])):
                d = drops[key]
                seen = {}
                for ts, label, is_exec in sorted(d['times'], key=lambda x: x[0]):
                    if label not in seen:
                        seen[label] = (ts, is_exec)
                ev['drops'].append({
                    'path': d['path'],
                    'name': key[0],
                    'folder': key[1],
                    'kinds': sorted(seen.items(), key=lambda x: x[1][0]),
                    'first': min(t[0] for t in d['times']),
                })

            # (2) remote sessions -- ALL of them, so "first seen" is honest, then
            # split into pre-window and rare bursts.
            rows = _q(cur, """SELECT coalesce(target_user,'?') u, coalesce(remote_host,'?') h,
                       min(event_ts) f, max(event_ts) l, count(*) n
                FROM event_logs_v2
                WHERE case_key=%s AND event_ts IS NOT NULL
                  AND (event_id IN (21,25,1149)
                       OR (event_id=4624 AND (logon_type ILIKE '%%remote%%'
                                              OR logon_type ILIKE '%%RDP%%' OR logon_type='10')))
                  AND coalesce(remote_host,'') <> ''
                GROUP BY 1,2 ORDER BY 3 ASC LIMIT 400""", (case_key,))
            for user, host, first, last, n in rows:
                if host in ('?', '-') or not first:
                    continue
                rec = {'user': user, 'host': host, 'first': first, 'last': last, 'n': int(n)}
                if _naive(first) < start:
                    ev['sessions'].append(rec)
                    span = (_naive(last) - _naive(first)).total_seconds() if last else 0
                    # a handful of connections inside a couple of days, never seen
                    # again -- the shape of a visit, not of daily work
                    if int(n) <= 8 and span <= 2 * 86400 and (last is None or _naive(last) < start):
                        ev['rare_sessions'].append(rec)

            # (3) correlate each planted file with the remote session it appeared in
            for d in ev['drops']:
                for label, (ts, _is_exec) in d['kinds']:
                    rows = _q(cur, """SELECT event_ts, event_id, coalesce(target_user,'?'),
                               coalesce(remote_host,'?')
                        FROM event_logs_v2
                        WHERE case_key=%s AND event_ts IS NOT NULL
                          AND event_id IN (21,25,1149)
                          AND coalesce(remote_host,'') <> ''
                          AND event_ts <= %s AND event_ts >= %s
                        ORDER BY event_ts DESC LIMIT 1""",
                        (case_key, ts, ts - _dt.timedelta(minutes=180)))
                    if rows:
                        s_ts, s_id, s_user, s_host = rows[0]
                        ev['links'].append({
                            'drop': d, 'kind': label, 'file_ts': ts,
                            'sess_ts': s_ts, 'sess_id': int(s_id),
                            'user': s_user, 'host': s_host,
                            'gap_sec': int((_naive(ts) - _naive(s_ts)).total_seconds()),
                        })

            # (4) REAL log clears only
            rows = _q(cur, """SELECT event_ts, event_id, coalesce(target_user,''), channel
                FROM event_logs_v2
                WHERE case_key=%s AND event_ts IS NOT NULL
                  AND ((event_id=1102 AND channel='Security')
                       OR (event_id=104 AND coalesce(provider,'') ILIKE '%%Eventlog%%'))
                ORDER BY event_ts ASC LIMIT 50""", (case_key,))
            ev['clears'] = [{'ts': r[0], 'eid': int(r[1]), 'user': r[2], 'channel': r[3]}
                            for r in rows]

            # (5) how far back the key channels actually reach
            for chan, human in (('Security', 'журнал безпеки (Security)'),
                                ('System', 'системний журнал (System)'),
                                ('Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
                                 'журнал сесій RDP (LocalSessionManager)'),
                                ('Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
                                 'журнал підключень RDP (RemoteConnectionManager)')):
                rows = _q(cur, """SELECT min(event_ts), max(event_ts), count(*)
                    FROM event_logs_v2 WHERE case_key=%s AND channel=%s AND event_ts IS NOT NULL""",
                    (case_key, chan))
                if rows and rows[0][0]:
                    ev['coverage'].append({'channel': chan, 'human': human,
                                           'first': rows[0][0], 'last': rows[0][1],
                                           'n': int(rows[0][2])})

            # (6) the blindness test: does the Security log BEGIN with its own wipe?
            sec = [c for c in ev['coverage'] if c['channel'] == 'Security']
            sec_clear = [c for c in ev['clears'] if c['channel'] == 'Security']
            if sec and sec_clear:
                if abs((_naive(sec[0]['first']) - _naive(sec_clear[0]['ts'])).total_seconds()) <= 2:
                    ev['security_blind'] = {'ts': sec_clear[0]['ts'],
                                            'user': sec_clear[0]['user'],
                                            'first': sec[0]['first']}

            # (7) accounts / services / tasks created BEFORE detonation.
            # 7045 is restricted to binaries that sit in a user-writable path AND
            # are not vendor software. Without the vendor exclusion this block
            # fills up with `MpKslDrv.sys` from `ProgramData\...\Windows Defender\
            # Definition Updates\{GUID}` -- the antivirus registering its own scan
            # driver on every signature update, once every day or two.
            rows = _q(cur, """SELECT event_ts, event_id, coalesce(target_user,''),
                       coalesce(process_name,'')
                FROM event_logs_v2
                WHERE case_key=%s AND event_ts IS NOT NULL AND event_ts < %s AND event_ts >= %s
                  AND (event_id IN (4720,4728,4732,4756,4698)
                       OR (event_id IN (7045,4697)
                           AND lower(coalesce(process_name,'')) ~ %s
                           AND lower(coalesce(process_name,'')) !~ %s
                           AND coalesce(process_name,'') ~ %s))
                ORDER BY event_ts ASC LIMIT 40""",
                (case_key, start, horizon, _USER_WRITABLE_RE, _VENDOR_SERVICE_RE,
                 '[' + chr(92) + chr(92) + '/]'))
            ev['accounts'] = [{'ts': r[0], 'eid': int(r[1]), 'user': r[2], 'proc': r[3]}
                              for r in rows]
    except Exception:
        return ev
    # remote-access tools that appeared before the window: one is normal IT, two or more within
    # RETRO_DAYS (holdout 14_04: LiteManager 2024-08, RMS + Remote Utilities 2025-11) is the beginning
    try:
        _FAM = [('AnyDesk', 'anydesk'), ('TeamViewer', 'teamviewer'),
                ('LiteManager', 'litemanager|romserver|romfusclient|romviewer'),
                ('RMS / Remote Utilities', 'remote manipulator|remote utilities|rutserv|rfusclient'),
                ('RustDesk', 'rustdesk'), ('Ammyy', 'ammyy'), ('Supremo', 'supremo'), ('Splashtop', 'splashtop'),
                ('ScreenConnect', 'screenconnect|connectwise'), ('MeshAgent', 'meshagent|meshcentral'),
                ('Radmin', 'radmin'), ('VNC', 'ultravnc|tightvnc|realvnc|winvnc|tvnserver'), ('DWAgent', 'dwagent')]
        _floor = start - __import__('datetime').timedelta(days=RETRO_DAYS)
        with psycopg2.connect(PG_DSN) as _c2:
            _c2.autocommit = True
            _cur2 = _c2.cursor()
            _found = []
            for _fam, _frx in _FAM:
                _r = _q(_cur2, """SELECT min(event_ts), min(coalesce(full_path, executable_name)) FROM program_exec_v2
                                  WHERE case_key=%s AND event_ts IS NOT NULL AND event_ts < %s AND event_ts >= %s
                                    AND lower(coalesce(full_path,'')||' '||coalesce(executable_name,'')) ~ %s
                                    AND lower(coalesce(full_path,'')) !~ '(unins|setup|install)'""",
                        (case_key, start, _floor, _frx))
                if _r and _r[0] and _r[0][0]:
                    _found.append({'ts': _r[0][0], 'family': _fam, 'path': _r[0][1] or ''})
            # TeamViewer + AnyDesk is the ordinary consumer pairing (Asus, case_56 are clean with both):
            # the retrospective needs an attacker-favoured family among them, same rule as the detector
            _strong = [x for x in _found if x['family'] not in ('TeamViewer', 'AnyDesk')]
            if len(_found) >= 2 and _strong:
                ev['rat_tools'] = sorted(_found, key=lambda x: x['ts'])
    except Exception:
        pass

    return ev


def _has_signal(ev):
    """The section renders only on a concrete pre-window finding: a randomly
    named executable in a randomly named folder, or a Security log that BEGINS
    with its own wipe.

    Two things are deliberately NOT triggers.

    Log coverage alone is not: a short log without a clear event is ordinary
    rotation, and calling that 'destroyed evidence' on a healthy machine is
    exactly the false positive that makes a report untrustworthy.

    Service/account creation alone is not, and this one was measured the hard
    way. With the horizon at 730 days the section fired on
    case_04 and filled itself with `MpKslDrv.sys` --
    Windows Defender's own kernel scan driver, which registers a service on
    every definition update. A section that answers 'how did it start?' with a
    list of antivirus updates is worse than no section. Account and service
    creation is still PRINTED, but only once something harder has already
    established that there is an intrusion to explain."""
    return bool(ev.get('drops') or ev.get('security_blind') or ev.get('rat_tools'))


def onset_section(case_key, iw_start):
    """Returns the '…ЯК ЦЕ ПОЧАЛОСЯ' section as a list of lines, or [] when the
    case has no evidence about the period before detonation."""
    try:
        ev = onset_evidence(case_key, iw_start)
    except Exception:
        return []
    if not _has_signal(ev):
        return []

    det = str(iw_start)[:10]
    L = []
    L.append('## 🚪 ЯК ЦЕ ПОЧАЛОСЯ — РЕТРОСПЕКТИВА ДО ДНЯ ДЕТОНАЦІЇ')
    L.append('')
    L.append('_Вікно інциденту (%s) прив\'язане до моменту спрацювання і навмисно вузьке. '
             'Ця секція дивиться РАНІШЕ за нього — на період до %s днів до детонації — '
             'і відповідає на питання «з чого все почалося»._' % (det, RETRO_DAYS))
    L.append('')

    # --- the answer, in words ---
    earliest = None
    if ev['links']:
        best = sorted(ev['links'], key=lambda x: x['file_ts'])[0]
        earliest = ('link', best)
    elif ev['drops']:
        earliest = ('drop', sorted(ev['drops'], key=lambda d: d['first'])[0])
    elif ev.get('rat_tools'):
        earliest = ('rat', ev['rat_tools'][0])
    elif ev['accounts']:
        earliest = ('acct', ev['accounts'][0])

    L.append('**Найраніший твердий слід до детонації:**')
    if earliest and earliest[0] == 'link':
        b = earliest[1]
        L.append('- `%s` — віддалена сесія з адреси `%s`, обліковий запис %s.'
                 % (_fmt_ts(b['sess_ts']), b['host'], _show_user(b['user'])))
        L.append('- `%s` — у цій самій сесії (через %s) у системі зʼявляється '
                 '`%s` за шляхом `%s`.'
                 % (_fmt_ts(b['file_ts']), _gap_text(b['gap_sec']),
                    b['drop']['name'], b['drop']['path']))
        L.append('- 👉 Тобто **сторонній доступ і поява стороннього файлу — це одна подія**, '
                 'і сталася вона за %s до шифрування.' % _human_gap(b['file_ts'], iw_start))
    elif earliest and earliest[0] == 'drop':
        d = earliest[1]
        L.append('- `%s` — у системі зʼявляється `%s` за шляхом `%s` — '
                 'випадкове імʼя файлу у випадково названій теці.'
                 % (_fmt_ts(d['first']), d['name'], d['path']))
        L.append('- 👉 Це за %s до шифрування. Хто і як його туди поклав — '
                 'з наявних артефактів не встановлено.' % _human_gap(d['first'], iw_start))
    elif earliest and earliest[0] == 'rat':
        r0 = earliest[1]
        L.append('- `%s` — вперше зʼявляється засіб віддаленого доступу **%s** (`%s`); далі — ще %d: %s.'
                 % (_fmt_ts(r0['ts']), r0['family'], str(r0['path']).split(chr(92))[-1], len(ev['rat_tools']) - 1,
                    ', '.join('%s (%s)' % (x['family'], _fmt_ts(x['ts'])[:10]) for x in ev['rat_tools'][1:])))
        L.append('- 👉 Це за %s до детонації. Кілька сімейств віддаленого доступу на одній машині — '
                 'не звичайне ІТ-обслуговування; перевірити, хто їх ставив.' % _human_gap(r0['ts'], iw_start))
    elif earliest:
        a = earliest[1]
        L.append('- `%s` — %s (%s).' % (_fmt_ts(a['ts']), _eid_label(a['eid']), a['user'] or '?'))
    L.append('')

    # --- planted files, each with the KIND of time ---
    if ev['drops']:
        L.append('**Файли з випадковими іменами, що зʼявилися ДО детонації:**')
        for d in ev['drops']:
            L.append('- `%s`' % d['path'])
            for label, (ts, is_exec) in d['kinds']:
                L.append('   - `%s` — %s' % (_fmt_ts(ts), label))
            runs = [1 for label, (ts, is_exec) in d['kinds'] if is_exec]
            if not runs:
                L.append('   - ⚠️ підтвердження **запуску** цього файлу немає: '
                         'усі мітки часу вище — це поява/модифікація файлу, а не виконання.')
        L.append('')

    # --- the session in which it happened ---
    if ev['rare_sessions']:
        L.append('**Разові віддалені сесії до детонації** (адреса зʼявляється '
                 'коротким сплеском і більше не повертається):')
        linked_hosts = set(l['host'] for l in ev['links'])
        for s in ev['rare_sessions'][:10]:
            mark = ' 🎯 **саме в цій сесії зʼявився сторонній файл**' if s['host'] in linked_hosts else ''
            L.append('- `%s` — `%s`, обліковий запис %s (підключень: %d)%s'
                     % (_fmt_ts(s['first']), s['host'], _show_user(s['user']), s['n'], mark))
        L.append('')

    # --- accounts / services / tasks ---
    if ev['accounts']:
        L.append('**Облікові записи, служби й завдання, створені ДО детонації:**')
        for a in ev['accounts'][:12]:
            extra = (' — `%s`' % a['proc']) if a['proc'] else ''
            L.append('- `%s` — %s%s%s' % (_fmt_ts(a['ts']), _eid_label(a['eid']),
                                          (' (%s)' % a['user']) if a['user'] else '', extra))
        L.append('')

    # --- what we CANNOT know, and why ---
    L.append('**Чого ми НЕ знаємо і чому:**')
    if ev['security_blind']:
        sb = ev['security_blind']
        L.append('- Журнал безпеки **очищено `%s`** (обліковий запис %s), і найперший '
                 'запис, який у ньому взагалі є, — це сама подія очищення. '
                 'Тобто **всі входи до цієї хвилини знищено**, і встановити перший вхід '
                 'за журналом безпеки неможливо.'
                 % (_fmt_ts(sb['ts']), _show_user(sb['user'])))
    elif ev['clears']:
        L.append('- Журнали очищали %d раз(и) — найраніше `%s`. Частину подій втрачено.'
                 % (len(ev['clears']), _fmt_ts(ev['clears'][0]['ts'])))
    for cov in ev['coverage']:
        human = cov['human']
        L.append('- %s%s містить записи лише з `%s` (усього %d) — про те, що було раніше, '
                 'цей журнал не свідчить ані «за», ані «проти».'
                 % (human[:1].upper(), human[1:], _fmt_ts(cov['first'])[:10], cov['n']))
    L.append('- Спосіб, у який зловмисник отримав ці облікові дані (підбір пароля, '
             'вкрадений пароль, витік), з наявних артефактів **не встановлено**. '
             'Це інше питання, ніж вхідна сесія з розділу 3: тут — **коли і звідки** він '
             'уперше зайшов, а не **як** здобув пароль.')
    L.append('')
    L.append('**Що треба зібрати, щоб закрити прогалину:** повний `$MFT` і `$J` (UsnJrnl) '
             'з диска; резервні копії `.evtx` до дати очищення; журнали шлюзу/маршрутизатора '
             'або VPN за відповідний період; знімок памʼяті; журнали RDP-шлюзу, якщо він є.')
    return L


def _human_gap(a, b):
    import datetime as _dt
    try:
        bb = _iw_start_dt(b)
        days = int((_naive(bb) - _naive(a)).total_seconds() / 86400)
        if days >= 60:
            return '~%d місяці' % max(2, int(round(days / 30.0)))
        if days >= 2:
            return '%d дн.' % days
        return 'менш ніж добу'
    except Exception:
        return 'певний час'


def _gap_text(seconds):
    """Seconds matter here. The gap between the remote logon and the appearance of
    the planted file IS the argument that the two are one event -- rounding 14
    seconds to '~0 хв' throws away the strongest number in the section."""
    try:
        s = int(seconds)
    except Exception:
        return 'невідомий час'
    if s < 90:
        return '%d с' % s
    if s < 5400:
        return '~%d хв' % int(round(s / 60.0))
    return '~%d год' % int(round(s / 3600.0))


def _show_user(user):
    """Print an account name so that INVISIBLE characters in it survive the
    report. On the case_66 server two accounts differ only by a trailing
    non-breaking space -- `WS2023\\Администратор` and `WS2023\\Администратор ` --
    and one of them is the operator's while the other is the intruder's. Any
    rendering that trims whitespace merges the two and destroys the distinction."""
    u = str(user or '?')
    stripped = u.rstrip()
    tail = u[len(stripped):]
    note = ''
    if tail:
        names = {chr(0xA0): 'нерозривний пробіл', ' ': 'звичайний пробіл',
                 chr(9): 'табуляцію', chr(0x200B): 'нульовий пробіл'}
        kinds = []
        for ch in tail:
            kinds.append(names.get(ch, 'символ U+%04X' % ord(ch)))
        note = ' ⚠️(ім\'я містить у кінці %s — це ІНШИЙ обліковий запис, ніж `%s`)' % (
            ', '.join(sorted(set(kinds))), stripped)
    return '`%s`%s' % (stripped or '?', note)


def _eid_label(eid):
    return {
        4720: 'створено обліковий запис',
        4728: 'обліковий запис додано до групи',
        4732: 'обліковий запис додано до локальної групи',
        4756: 'обліковий запис додано до універсальної групи',
        4698: 'створено заплановане завдання',
        7045: 'встановлено службу',
        4697: 'встановлено службу',
    }.get(int(eid or 0), 'подія %s' % eid)
