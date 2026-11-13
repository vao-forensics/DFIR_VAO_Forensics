# -*- coding: utf-8 -*-
"""Findings-first answers for the case chat (02.10.2026).

Stress test on case_03: «чи злили дані? скільки мегабайт?» went to the free LLM loop,
which saw a 50-row sample of SRUM and invented «30 / 47 / 50 МБ, разом 150-160 МБ, 16-20 лютого»;
the deterministic detector had the truth (not.exe 692 МБ, ngrok 444 МБ, nott.exe 54 МБ, jsc 18 МБ).
For security questions the chat now answers with the detector findings first - exact figures,
timestamps and paths - and only falls through to the old flow when no detector covers the topic.
"""
import logging
import re

import psycopg2

from core.config import PG_DSN

_log = logging.getLogger('app')

# intent -> (category regex, MITRE regex)
_MAP = {
    'exfiltration': (r'ексфільтр|витік|передач', r'^T(1048|1041|1567|1020|1030)'),
    'persistence': (r'закріплення|персистенс', r'^T(1547|1053|1543|1546|1136|1098|1037|1574)'),
    'c2': (r'віддаленого доступу|тунель|прихований канал|доступ \(rdp', r'^T(1219|1090|1572|1071|1133)'),
    'tampering': (r'анти-форензика|замітання слідів|захист вимикали|захист обходили', r'^T(1070|1562)'),
    'credential': (r'крадіжка облікових|доступ до кред', r'^T(1003|1558|1555|1552)'),
    'lateral_movement': (r'латеральн', r'^T(1021|1570|1550)'),
    'ransomware': (r'ransomware|знищення|анти-відновлення', r'^T(1486|1490|1561|1485)'),
    'rdp': (r'доступ \(rdp|rdp', r'^T(1133|1021\.001)'),
}
_SEV = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
_ICON = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '⚪', 'info': '⚪'}
_NOT_ATTACK = re.compile(r'дії реагування|\(інформаційно\)|стан системи', re.I)
# a question about ONE named tool/file is answered by the evidence about that tool, not by a list
_NAMED = re.compile(r'teamviewer|anydesk|ammyy|radmin|litemanager|rutserv|screenconnect|splashtop|'
                    r'[\w-]+\.(exe|dll|ps1|bat|vbs|js|msi)\b|\b\d{1,3}(\.\d{1,3}){3}\b', re.I)
_VERDICT_RX = re.compile(r'заражен\w*\s+(чи|або)\s+ні|чи\s+(\w+\s+){0,2}(заражен|скомпрометов|зламан)|'
                         r'чи\s+є\s+(ознаки\s+)?(зараж|компрометац|атак)|чи\s+чист\w*\s+(комп|пк|машин|систем)|'
                         r'був\w*\s+(атака|злам)\s*\?', re.I)


def is_verdict_question(q):
    return bool(_VERDICT_RX.search(str(q or '')))


_CRED_TOOL_RX = r'(mimikatz|mimilib|mimidrv|lazagne|procdump|nanodump|pwdump|gsecdump|fgdump|wce\.exe|safetykatz|' \
                r'sharpkatz|rubeus|kerberoast|mailpv|netpass|chromepass|webbrowserpassview|passrecpk|' \
                r'credentialsfileview|vaultpasswordview|dumpert|lsassy)'


def _cred_tool_files(case_key, limit=12):
    """Credential-theft tools present on disk / executed in THIS case, with paths and first time.
    Our own footprint (collector temp dirs, Sigma/THOR rule files) is excluded."""
    sql = """
      SELECT min(event_ts), src, path FROM (
        SELECT event_ts, 'запуск/реєстрація (program_exec)' src, coalesce(full_path, executable_name) path
          FROM program_exec_v2 WHERE case_key=%(c)s AND lower(coalesce(full_path, executable_name)) ~ %(rx)s
        UNION ALL
        SELECT event_ts, 'файл на диску ($MFT/$J)', coalesce(parent_path,'') || chr(92) || coalesce(file_name,'')
          FROM filesystem_v2 WHERE case_key=%(c)s AND lower(coalesce(file_name,'')) ~ %(rx)s
           AND lower(coalesce(extension,'')) ~ '^\\.?(exe|dll|sys|ps1|zip|7z|rar)$'
      ) x
      WHERE lower(path) !~ '(dfirtriage|vao_collector|kape|thor[0-9.]*lite|\\\\signatures\\\\|\\.ya?ml$|\\.yms$|sigma)'
      GROUP BY src, path ORDER BY 1 DESC LIMIT %(n)s"""
    try:
        with psycopg2.connect(PG_DSN) as c, c.cursor() as cur:
            cur.execute(sql, {'c': case_key, 'rx': _CRED_TOOL_RX, 'n': limit})
            # newest first in SQL (the moment of the attack, not the build stamps of 2006), shown in order
            return sorted(cur.fetchall(), key=lambda r: str(r[0]))
    except Exception as e:
        _log.warning('[findings_first] cred tools query failed: %s' % e)
        return []


def _findings(case_key):
    from analysis.threat_detect import detect_threats
    with psycopg2.connect(PG_DSN) as c:
        return detect_threats(case_key, c) or []


def _ts(v):
    s = str(v or '')
    return s[:16].replace('T', ' ')


def _fmt(f, n_ev=6):
    sev = str(f.get('severity') or 'info').lower()
    head = '%s **[%s] %s**%s' % (_ICON.get(sev, '•'), sev.upper(), str(f.get('title') or '').strip(),
                                 (' _(MITRE %s)_' % f['mitre']) if f.get('mitre') and f['mitre'] != '—' else '')
    out = [head]
    det = str(f.get('detail') or '').strip()
    if det:
        out.append('   ' + (det[:700] + ('…' if len(det) > 700 else '')))
    evs = [e for e in (f.get('events') or []) if isinstance(e, dict) and e.get('ts')]
    for e in sorted(evs, key=lambda e: str(e.get('ts')))[:n_ev]:
        src = e.get('source') or e.get('artifact') or ''
        out.append('   · %s — %s%s' % (_ts(e.get('ts')), str(e.get('label') or '')[:160], (' — ' + str(src)[:60]) if src else ''))
    if sev == 'medium':
        out.append('   _рівень medium: потребує перевірки, сам по собі не доводить атаку_')
    return '\n'.join(out)


_OTHER_CASES_RX = re.compile(r'інш\w*\s+(справ|кейс)|(пов|зв)\W?язан\w*\s+(з|із)\s+інш|той\s+самий\s+зловмисн', re.I)
_IOC_RX = re.compile(r'\bip\b|айпі|домен|адрес|\bioc\b|індикатор|хеш|\bhash|\burl\b|посилан', re.I)
_LOGCLEAR_Q = re.compile(r'журнал|\bлог', re.I)
_LOGCLEAR_F = re.compile(r'1102|(?<!\d)104(?!\d)|wevtutil|fsutil|clear-?eventlog|очищ\w*\s+журнал|журнал\w*\s+очищ', re.I)
_MANAGER_RX = re.compile(r'резюме|для\s+керівник|коротко\s+для|\d\s+речен|у\s+двох\s+словах', re.I)


def _other_cases_answer(case_key):
    try:
        from analysis.actor_portrait import portrait_section
        sec = portrait_section(case_key) or []
    except Exception as e:
        _log.warning('[findings_first] portrait failed for %s: %s' % (case_key, e))
        return None
    if not sec:
        return ('**Звʼязків з іншими справами не знайдено.** Звʼязок рахується лише за індикаторами, що '
                'вказують на конкретну особу чи файл (імʼя машини зловмисника, хеш бінарника, пошта, ID '
                'віддаленого доступу, адреса). Спільні публічні інструменти (rdpwrap, mimikatz, AnyDesk) '
                'звʼязком не вважаються.\n\n_✓ детерміновано з даних справ_')
    return '\n'.join(sec).replace('## ', '**', 1).replace('СПРАВАМИ', 'СПРАВАМИ**', 1) + '\n\n_✓ детерміновано з даних справ_'


def _manager_summary(attack):
    strong = [f for f in attack if _SEV.get(str(f.get('severity') or '').lower(), 0) >= 3]
    if not strong:
        mid = [f for f in attack if _SEV.get(str(f.get('severity') or '').lower(), 0) == 2]
        return ('Ознак компрометації детектори не знайшли%s. Висновок стосується лише зібраних артефактів. '
                'Для остаточного висновку потрібна перевірка фахівцем.'
                % ((' — є %d спірних моментів рівня medium, які варто перевірити' % len(mid)) if mid else ''))
    s1 = 'Компʼютер скомпрометовано: детектори знайшли %d знахідок високого або критичного рівня.' % len(strong)
    entry = None
    for f in attack:
        if re.search(r'початковий доступ|доставк|вкладен|фішинг|payload', str(f.get('category') or '') + ' ' + str(f.get('title') or ''), re.I):
            evs = sorted([e for e in (f.get('events') or []) if isinstance(e, dict) and e.get('ts')], key=lambda e: str(e['ts']))
            # a presence stamp («файл існував раніше», ShimCache/$MFT) is not the moment of entry
            anch = [e for e in evs if e.get('kind') != 'presence' and not re.search(r'існував раніше', str(e.get('label') or ''))]
            if anch or evs:
                e0 = (anch or evs)[0]
                entry = '%s — %s' % (_ts(e0['ts']), str(e0.get('label') or '')[:240])
                break
    s2 = ('Точка входу: %s.' % entry) if entry else 'Точку входу детерміновано не встановлено.'
    imp = []
    for f in strong:
        t = str(f.get('title') or '').replace('🔴', '').strip()
        if re.search(r'ексфільтр', str(f.get('category') or ''), re.I) and f.get('samples'):
            t += ' (' + ', '.join(str(x) for x in f['samples'][:3]) + ')'
        if t not in imp:
            imp.append(t)
    s3 = 'Головне далі: ' + '; '.join(imp[:3]) + '.'
    return ' '.join([s1, s2, s3])


def findings_first(case_key, question, intent):
    """Deterministic answer from the detector findings, or None to keep the normal chat flow."""
    q = str(question or '')
    if _OTHER_CASES_RX.search(q):
        return _other_cases_answer(case_key)
    if _MANAGER_RX.search(q):
        try:
            fs = [f for f in _findings(case_key) if isinstance(f, dict)]
        except Exception:
            return None
        att = [f for f in fs if not _NOT_ATTACK.search(str(f.get('category') or '') + ' ' + str(f.get('title') or ''))]
        att.sort(key=lambda f: -_SEV.get(str(f.get('severity') or '').lower(), 0))
        return '**Резюме:** ' + _manager_summary(att) + '\n\n_✓ детерміновано з даних справи (детектори загроз, без ШІ)_'
    if intent == 'c2' and _IOC_RX.search(q):
        return None  # indicator lists come from the IOC extractor, not from detector titles
    verdict = is_verdict_question(q)
    # «що робив зловмисник після проникнення?» on a machine with no attack: the honest answer is the
    # verdict, not a five-message dump of ordinary activity (case_56, stress test 02.10.2026)
    if not verdict and intent == 'timeline' and re.search(r'зловмисн|хакер|атакувальн|нападник', q, re.I):
        try:
            _fs0 = [f for f in _findings(case_key) if isinstance(f, dict)]
        except Exception:
            _fs0 = []
        if _fs0 and not any(_SEV.get(str(f.get('severity') or '').lower(), 0) >= 3
                           and not _NOT_ATTACK.search(str(f.get('category') or '') + ' ' + str(f.get('title') or ''))
                           for f in _fs0):
            verdict = True
    if not verdict and intent not in _MAP:
        return None
    if not verdict and _NAMED.search(q):
        return None
    try:
        fs = _findings(case_key)
    except Exception as e:
        _log.warning('[findings_first] detector failed for %s: %s' % (case_key, e))
        return None
    fs = [f for f in fs if isinstance(f, dict)]
    attack = [f for f in fs if not _NOT_ATTACK.search(str(f.get('category') or '') + ' ' + str(f.get('title') or ''))]
    attack.sort(key=lambda f: -_SEV.get(str(f.get('severity') or '').lower(), 0))
    foot = '\n\n_✓ детерміновано з даних справи (детектори загроз, без ШІ)_'

    if verdict:
        strong = [f for f in attack if _SEV.get(str(f.get('severity') or '').lower(), 0) >= 3]
        mid = [f for f in attack if _SEV.get(str(f.get('severity') or '').lower(), 0) == 2]
        if strong:
            lines = ['**Так — є ознаки компрометації.** Детектори знайшли %d знахідок рівня high/critical:' % len(strong)]
            for f in strong[:6]:
                lines.append('%s [%s] %s' % (_ICON.get(str(f.get('severity')).lower(), '•'), str(f.get('severity')).upper(),
                                             str(f.get('title') or '')[:140]))
            lines.append('')
            lines.append('Деталі по кожній — питайте окремо (точка входу, закріплення, ексфільтрація, віддалений доступ).')
        elif mid:
            # a detector may already state the verdict («Ознак стороннього втручання не виявлено — …»):
            # that is the conclusion, not one more suspicious item
            _calm = [f for f in mid if re.match(r'\s*ознак\w*\s+(стороннього\s+)?втручання\s+не\s+виявлено', str(f.get('title') or ''), re.I)]
            mid = [f for f in mid if f not in _calm]
            lines = ['**Однозначних ознак атаки немає.**']
            if _calm:
                lines.append(str(_calm[0].get('title') or '').strip() + '.')
            if mid:
                lines.append('')
                lines.append('Потребують перевірки (рівень medium, кожна сама по собі не доводить атаку):')
                for f in mid[:6]:
                    lines.append('🟡 %s' % str(f.get('title') or '')[:140])
        else:
            lines = ['**Ознак компрометації детектори не знайшли.** Це не гарантія чистоти: висновок '
                     'стосується лише зібраних артефактів і періоду, який вони охоплюють.']
        return '\n'.join(lines) + foot

    cat_rx, mitre_rx = _MAP[intent]
    hit = [f for f in attack
           if re.search(cat_rx, str(f.get('category') or '') + ' ' + str(f.get('title') or ''), re.I)
           or re.search(mitre_rx, str(f.get('mitre') or ''))]
    if intent == 'credential':
        # a credential-theft toolkit is usually filed under «Інструменти атакувальника» (T1588), not
        # under T1003 - case_66: mimikatz + passrecpk on disk, the chat still said «не було»
        for f in attack:
            if f not in hit and re.search(_CRED_TOOL_RX, ('%s %s %s' % (f.get('title') or '', f.get('detail') or '',
                                                                         ' '.join(str(x) for x in (f.get('samples') or [])))).lower()):
                hit.append(f)
    hit = [f for f in hit if _SEV.get(str(f.get('severity') or '').lower(), 0) >= 2]
    if intent == 'credential':
        files = _cred_tool_files(case_key)
        if files:
            lines = ['**Інструменти крадіжки паролів у цій справі (детерміновано):**']
            for ts, src, path in files:
                lines.append('· %s — %s — %s' % (_ts(ts), str(path)[:180], src))
            lines.append('_Наявність інструмента не доводить, що паролі вкрадено; доказом був би доступ до lsass '
                         '(4656/4663, Sysmon 10), дамп-файли або запуск з параметрами. Мітки ShimCache/Amcache '
                         'з датами років тому - це дата збірки файла, а не запуску._')
            body = '\n'.join(lines)
            if hit:
                body += '\n\n**Знахідки детекторів:**\n\n' + '\n\n'.join(_fmt(f) for f in hit[:4])
            return body + foot
    if intent == 'tampering' and _LOGCLEAR_Q.search(q):
        # «чи чистили журнали?» is about clearing only; firewall/Defender changes are another question
        hit = [f for f in hit if _LOGCLEAR_F.search('%s %s' % (f.get('title') or '', f.get('detail') or ''))]
    if not hit:
        return None
    body = '**Знахідки детекторів (детерміновано, без ШІ):**\n\n' + '\n\n'.join(_fmt(f) for f in hit[:5])
    if intent == 'exfiltration' and re.search(r'\bкуди\b|адрес|на який|на яку', q, re.I):
        body += ('\n\nℹ️ Куди саме: SRUM рахує байти на програму, але адресу призначення не зберігає. '
                 'Її шукають у мережевих журналах, проксі, DNS-кеші або на боці провайдера тунелю.')
    return body + foot


def premise_note(case_key, question):
    """A question that presumes an attacker on a machine where no detector sees an attack."""
    if not re.search(r'зловмисн|хакер|атакувальн|нападник', str(question or ''), re.I):
        return ''
    try:
        fs = _findings(case_key)
    except Exception:
        return ''
    strong = [f for f in fs if isinstance(f, dict)
              and _SEV.get(str(f.get('severity') or '').lower(), 0) >= 3
              and not _NOT_ATTACK.search(str(f.get('category') or '') + ' ' + str(f.get('title') or ''))]
    if strong:
        return ''
    return ('⚠️ Зауваження до питання: детектори не знайшли на цій машині ознак атаки (жодної знахідки '
            'рівня high/critical). Нижче — факти з артефактів; вони НЕ доводять, що це зробив зловмисник.\n\n')
