#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Turn a MemProcFS forensic dump into an investigation, not a folder of CSVs.

The owner's logic, and it is the right one: MemProcFS produces structured files (csv/json/
findevil/timeline); the interesting part is those files; feed them to the model and have it
INVESTIGATE - correlate the memory against what is already in the case, and write a report
in Markdown that says, for every claim, where the fact came from.

So this does three things:
  1. reads the forensic tree and pulls the high-signal rows (findevil, processes with command
     lines, network connections + IPs, scheduled tasks, services, drivers, DNS) into a
     compact FILTERED evidence block - not raw CSV dumps, which used to be truncated away;
  2. pulls the CASE's own indicators from Postgres - IOCs, suspicious executables, network
     addresses seen on disk - so the model can link "process X in memory" to "file Y on
     disk" to "IOC Z";
  3. asks the local reasoner to write the report, REQUIRING that each finding cites its
     source (which forensic file / which case table).

If the model is unreachable, a deterministic report is written from the rows themselves -
the user always gets the IPs / tasks / processes, and it never invents facts.
"""
import csv
import glob
import io
import json
import os
import time
import urllib.request

LLM_URL = os.environ.get('DFIR_LLM_URL', 'http://192.168.100.1:1234')
LLM_MODEL = os.environ.get('DFIR_RAM_MODEL', 'reasoner-31b')
LLM_TIMEOUT = int(os.environ.get('DFIR_RAM_LLM_TIMEOUT', '900'))

csv.field_size_limit(10 * 1024 * 1024)


def log(m):
    print('%s [ram-report] %s' % (time.strftime('%H:%M:%S'), m), flush=True)


# ------------------------------------------------------------------ csv helpers
def _find(out_dir, *needles):
    """The first csv whose name contains ALL needles, searched under csv/ and the root."""
    for base in (os.path.join(out_dir, 'forensic', 'csv'), os.path.join(out_dir, 'csv'),
                 os.path.join(out_dir, 'forensic'), out_dir):
        for p in sorted(glob.glob(os.path.join(base, '*.csv'))):
            low = os.path.basename(p).lower()
            if all(n in low for n in needles):
                return p
    return ''


def _rows(path, cap=100000):
    out = []
    try:
        with io.open(path, encoding='utf-8', errors='replace') as fh:
            for i, row in enumerate(csv.DictReader(fh)):
                if i >= cap:
                    break
                out.append(row)
    except Exception:
        pass
    return out


def _is_local_ip(ip):
    ip = (ip or '').strip()
    if not ip or ip in ('***', '0.0.0.0', '::', '::1', '127.0.0.1'):
        return True
    low = ip.lower()
    return (ip.startswith('127.') or ip.startswith('169.254.') or ip == '255.255.255.255'
            or low.startswith('fe80:') or low.startswith('ff0') or low.startswith('fec0:'))


def _is_rfc1918(ip):
    ip = (ip or '').strip()
    if ip.startswith('10.') or ip.startswith('192.168.'):
        return True
    if ip.startswith('172.'):
        try:
            return 16 <= int(ip.split('.')[1]) <= 31
        except (ValueError, IndexError):
            return False
    return False


_NOTABLE_PORTS = {'5985', '5986', '3389', '445', '139', '135', '4444', '443', '53',
                  '1080', '8080', '8443', '9001', '22', '23', '21', '389', '636', '88'}


# ------------------------------------------------------------------ per-artefact extractors
def _network(out_dir):
    """Interesting connections only: drop loopback/empty/listener-noise, dedupe, and put
    external addresses and notable ports (WinRM 5985, RDP 3389, SMB 445, C2-ish) first."""
    p = _find(out_dir, 'net') or _find(out_dir, 'tcp')
    if not p:
        return []
    seen, items = set(), []
    for r in _rows(p, 200000):
        proto = (r.get('Proto') or '').strip()
        if not proto or proto == 'Proto' or proto.endswith('0'):
            continue
        dst = (r.get('DstAddr') or '').strip()
        dport = (r.get('DstPort') or '').strip()
        if _is_local_ip(dst) or dport in ('', '0'):
            continue
        proc = (r.get('Process') or '').strip() or ('PID ' + (r.get('PID') or '?'))
        key = (dst, dport, proc)
        if key in seen:
            continue
        seen.add(key)
        ext = not _is_rfc1918(dst)
        score = (2 if ext else 0) + (1 if dport in _NOTABLE_PORTS else 0)
        state = (r.get('State') or '').strip()
        when = (r.get('Time') or '').strip()[:19]
        items.append((score, u'%s %s:%s ← %s [%s] %s'
                      % (proto, dst, dport, proc, state, when)))
    items.sort(key=lambda x: -x[0])
    return [t for _s, t in items[:40]]


_SUSP_PROC = ('powershell', 'cmd.exe', 'rundll32', 'regsvr32', 'mshta', 'wscript',
              'cscript', 'wmic', 'psexec', 'net.exe', 'net1.exe', 'at.exe', 'schtasks',
              'certutil', 'bitsadmin', 'nltest', 'whoami', 'stun', 'ngrok', 'anydesk',
              'rclone', '7z', 'procdump', 'mimikatz', 'lazagne')
_SUSP_ARG = ('-enc', '-e ', 'frombase64', 'downloadstring', 'invoke-', 'iex', 'hidden',
             'bypass', 'webclient', 'temp\\', 'appdata', 'programdata', 'public\\',
             '\\users\\', 'http://', 'https://', '.ps1', 'rar$')


def _procs(out_dir):
    """Processes with their command lines; suspicious ones (LOLBINs, encoded PS, temp paths,
    remote tools) float to the top so the model and the reader see them first."""
    p = _find(out_dir, 'process') or _find(out_dir, 'pslist')
    if not p:
        return []
    susp, rest = [], []
    for r in _rows(p, 100000):
        name = (r.get('Name') or r.get('ShortName') or '').strip()
        if not name or name == 'Name':
            continue
        cmd = (r.get('CommandLine') or '').strip().strip('"')
        low = (name + ' ' + cmd).lower()
        line = u'%s (PID %s←%s, %s): %s' % (
            name, (r.get('PID') or '?'), (r.get('PPID') or '?'),
            (r.get('User') or '?'), (cmd or '—')[:160])
        if any(s in low for s in _SUSP_PROC) or any(a in low for a in _SUSP_ARG):
            susp.append(line)
        else:
            rest.append(line)
    return susp[:35] + rest[:15]


def _tasks(out_dir):
    """Scheduled tasks that are NOT stock \\Microsoft\\ tasks, or whose action points at a
    shell / temp / user path - the ones an attacker plants (stun.exe & friends)."""
    p = _find(out_dir, 'task')
    if not p:
        return []
    out = []
    for r in _rows(p, 100000):
        vals = list(r.values())
        name = ''
        for k in ('Name', 'TaskName', 'Task'):
            if r.get(k):
                name = r[k].strip()
                break
        path = ''
        for v in vals:
            if v and '\\' in v and ('\\Microsoft\\' in v or v.startswith('\\')):
                path = v.strip()
                break
        blob = (' '.join(v for v in vals if v)).lower()
        # show a task only if it carries a real attacker-ish indicator, and is not a known
        # stock updater/maintenance task — that keeps the Edge/Pca/CompatTel noise out.
        suspicious = any(s in blob for s in (
            'temp\\', 'appdata', 'public\\', '\\users\\', 'powershell', '.ps1', 'stun',
            'ngrok', 'http://', 'https://', 'vssadmin', 'wbadmin', 'bcdedit', 'wmic',
            'mshta', 'wscript', 'cscript', 'regsvr32', '.bat', '.vbs', '.hta'))
        stocklike = any(s in blob for s in (
            'microsoftedge', 'googleupdate', 'onedrive', '.net framework', 'compattel',
            'programdataupdater', 'pcapatch', 'startupapp', 'mapsupdate', 'silcollector',
            'windows defender', 'appxdeployment', 'servicing', 'clip', 'feedback',
            'office automatic', 'aad', 'devicecensus'))
        if not suspicious or stocklike:
            continue
        # compact: name + the fields that look like the action/args
        action = ' '.join(v.strip() for v in vals
                          if v and (v.endswith('.exe') or '.exe ' in v or '/c ' in v
                                    or '\\' in v) and '\\Microsoft\\' not in v)[:180]
        out.append(u'%s : %s' % (name or (path or '?')[:60], action or blob[:120]))
        if len(out) >= 30:
            break
    return out


def _services(out_dir):
    p = _find(out_dir, 'service')
    if not p:
        return []
    out = []
    for r in _rows(p, 100000):
        blob = ' '.join(v for v in r.values() if v)
        low = blob.lower()
        name = (r.get('Name') or r.get('ServiceName') or '').strip()
        # skip obviously-Microsoft signed system services; keep unusual binary paths
        interesting = any(s in low for s in (
            'temp\\', 'appdata', 'programdata\\', 'public\\', '\\users\\', 'powershell',
            'cmd.exe', 'rundll32', '.bat', '.ps1', 'svchost -k none'))
        if not interesting and ('\\windows\\system32' in low or '\\windows\\' in low):
            continue
        out.append((name or '?') + ' : ' + blob[:160])
        if len(out) >= 25:
            break
    return out


def _dns(out_dir):
    p = _find(out_dir, 'netdns') or _find(out_dir, 'dns')
    if not p:
        return []
    out, seen = [], set()
    for r in _rows(p, 100000):
        dom = ''
        for k in ('Name', 'Host', 'Domain', 'Query'):
            if r.get(k):
                dom = r[k].strip()
                break
        if not dom:
            dom = ' '.join(v for v in r.values() if v)[:80]
        if dom and dom not in seen:
            seen.add(dom)
            out.append(dom)
        if len(out) >= 30:
            break
    return out


def _timeline(out_dir):
    """Merged, time-sorted high-signal chronology from MemProcFS timeline_*.csv: process
    creations, notable network connections, non-stock scheduled-task changes. Each line is
    'YYYY-MM-DD HH:MM:SS · TYPE · what' — the dated story the report needs."""
    events = []

    def _tl(needle):
        p = _find(out_dir, needle)
        return _rows(p, 400000) if p else []

    for r in _tl('timeline_process'):
        t = (r.get('Time') or '').strip('"').strip()
        if not t or t[:4] == '1970':
            continue
        events.append((t, u'⚙️ PROC %s · %s'
                       % ((r.get('Action') or '').strip(), (r.get('Text') or '').strip()[:120])))

    seen = set()
    for r in _tl('timeline_net'):
        t = (r.get('Time') or '').strip('"').strip()
        txt = (r.get('Text') or '').strip()
        low = txt.lower()
        if not t or t[:4] == '1970' or 'fe80' in low or '[::1]' in txt:
            continue
        if not any((':' + p) in txt for p in _NOTABLE_PORTS):
            continue                                    # else 5000+ rows of noise
        key = txt[:60]
        if key in seen:
            continue
        seen.add(key)
        events.append((t, u'🌐 NET · %s' % txt[:120]))

    _tsusp = ('appdata', 'powershell', '.ps1', 'stun', 'ngrok', 'vssadmin', 'wbadmin',
              'bcdedit', 'wmic', 'mshta', 'wscript', 'cscript', '.bat', '.vbs', '.hta',
              'nishang', 'empire', 'invoke-')
    for r in _tl('timeline_task'):
        t = (r.get('Time') or '').strip('"').strip()
        txt = (r.get('Text') or '').strip()
        if not t or t[:4] == '1970':
            continue
        if not any(sx in txt.lower() for sx in _tsusp):
            continue
        events.append((t, u'📅 TASK %s · %s'
                       % ((r.get('Action') or '').strip(), txt[:110])))

    events.sort(key=lambda e: e[0])
    return [u'%s · %s' % (t, d) for t, d in events]


def _clean_findings(findings):
    """Drop the two false positives seen on dc01: findevil YARA hits that actually matched
    MemProcFS's OWN documentation (readme), and a veracrypt 'passphrase' whose detail is just
    the Volatility header row (no real password)."""
    out = []
    for f in findings or []:
        kind = f.get('kind', '')
        src = (f.get('source', '') or '').lower()
        det = (f.get('detail', '') or '')
        if kind == 'yara_hit' and ('readme' in src or 'findevil' in det.lower()
                                   or 'yara rules' in det.lower() or 'anti-virus scans' in det.lower()):
            continue
        if kind == 'veracrypt_passphrase' and ('offset' in det.lower() and 'password' in det.lower()
                                               and 'length' in det.lower()):
            continue
        out.append(f)
    return out


def forensic_evidence(out_dir):
    """A compact, high-signal, FILTERED view of the memory image."""
    ev = {}
    summ = {}
    try:
        summ = json.load(io.open(os.path.join(out_dir, 'summary.json'), encoding='utf-8'))
    except Exception:
        pass
    ev['findings'] = _clean_findings(summ.get('findings') or [])
    ev['network'] = _network(out_dir)
    ev['processes'] = _procs(out_dir)
    ev['tasks'] = _tasks(out_dir)
    ev['services'] = _services(out_dir)
    ev['dns'] = _dns(out_dir)
    ev['timeline'] = _timeline(out_dir)

    fe = []
    fdir = os.path.join(out_dir, 'forensic', 'findevil')
    if not os.path.isdir(fdir):
        fdir = os.path.join(out_dir, 'findevil')
    if os.path.isdir(fdir):
        for p in glob.glob(os.path.join(fdir, '*')):
            base = os.path.basename(p).lower()
            if 'readme' in base:          # MemProcFS's own docs — not evidence
                continue
            try:
                fe.append(os.path.basename(p) + ':\n'
                          + io.open(p, encoding='utf-8', errors='replace').read()[:3000])
            except Exception:
                pass
    ev['findevil_raw'] = fe
    return ev


# ------------------------------------------------------------------ case correlation
def case_context(conn, case_key):
    """What the case already knows, so memory can be cross-referenced against it."""
    ctx = {'iocs': [], 'suspicious_files': [], 'network': []}
    with conn.cursor() as cur:
        try:
            cur.execute("SELECT ioc_type, ioc_value FROM public.case_iocs "
                        "WHERE case_key=%s LIMIT 80", (case_key,))
            ctx['iocs'] = [{'type': r[0], 'value': str(r[1])[:120]} for r in cur.fetchall() or []]
        except Exception:
            pass
        try:
            cur.execute("SELECT DISTINCT executable_name FROM public.program_exec_v2 "
                        "WHERE case_key=%s AND executable_name IS NOT NULL LIMIT 60", (case_key,))
            ctx['suspicious_files'] = [str(r[0])[:160] for r in cur.fetchall() or []]
        except Exception:
            pass
        try:
            cur.execute("SELECT DISTINCT payload->>'RemoteAddress' FROM public.raw_fallback_v2 "
                        "WHERE case_key=%s AND parser_family LIKE '%%network%%' "
                        "AND payload->>'RemoteAddress' IS NOT NULL LIMIT 40", (case_key,))
            ctx['network'] = [str(r[0]) for r in cur.fetchall() or [] if r[0]]
        except Exception:
            pass
    return ctx


# ------------------------------------------------------------------ the model call
def _llm(system, user):
    body = json.dumps({
        'model': LLM_MODEL, 'temperature': 0.1, 'max_tokens': 4000,
        'messages': [{'role': 'system', 'content': system},
                     {'role': 'user', 'content': user}]}).encode('utf-8')
    req = urllib.request.Request(LLM_URL.rstrip('/') + '/v1/chat/completions', data=body,
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as r:
        d = json.loads(r.read().decode('utf-8', 'replace'))
    return d['choices'][0]['message']['content']


SYSTEM = (
    u'Ти досвідчений DFIR-аналітик. Пишеш звіт українською у форматі Markdown за фактами. '
    u'ЗАБОРОНЕНО вигадувати: кожне твердження має спиратися на конкретний рядок доказу, і '
    u'ти мусиш вказати ДЖЕРЕЛО (який файл MemProcFS: net.csv, process.csv, tasks.csv, '
    u'services.csv, findevil — або яка таблиця кейсу). Якщо доказів бракує — так і пиши. '
    u'Обовʼязково розбери МЕРЕЖУ (зовнішні IP, порти 5985/3389/445 = WinRM/RDP/SMB — '
    u'ознака бокового руху), ПРОЦЕСИ з командними рядками (powershell -enc, cmd, rundll32, '
    u'запуск із Temp/AppData), ЗАПЛАНОВАНІ ЗАДАЧІ (нестандартні = закріплення). Звʼязуй '
    u'знахідки з памʼяті з тим, що вже відомо у справі (IOC, файли, адреси). '
    u'ЗАСТЕРЕЖЕННЯ ПРОТИ ХИБНИХ ВИСНОВКІВ: (1) explorer.exe як батько cmd/powershell/mmc = ІНТЕРАКТИВНА сесія користувача/адміна (dsa.msc, gpmc.msc, ServerManager — адмін-інструменти), а НЕ доказ атаки без шкідливого артефакту; (2) на КОНТРОЛЕРІ ДОМЕНУ зʼєднання lsass до інших хостів на динамічних високих портах — НОРМАЛЬНА реплікація AD/RPC, а не дамп облікових (дамп — лише за наявності procdump/comsvcs/mimikatz); (3) PE_PATCHED за ОДНАКОВОЮ адресою в багатьох процесах = зазвичай спільний хук EDR/AV/AMSI — пиши «потребує перевірки», не «інʼєкція»; (4) PRIVATE_RWX часто .NET/JIT — не роздувай. РЕАЛЬНО важливі: YR_VULNDRIVER (BYOVD), PE_INJECT, PROC_NOLINK, THREAD.')


def _sec(title, items, cap=40):
    if not items:
        return u''
    return u'\n### %s\n' % title + '\n'.join(u'- `%s`' % str(x)[:200] for x in items[:cap])


def _deterministic(case_key, ev, ctx):
    """A report from the rows themselves, when the model cannot be reached. Now includes the
    network / tasks / processes, so the user always gets the IPs and the scheduled tasks."""
    md = [u'# Звіт з аналізу оперативної памʼяті — %s' % case_key,
          u'_MemProcFS forensic · %s · (детермінований — LLM недоступний)_\n'
          % time.strftime('%Y-%m-%d %H:%M')]
    hi = [f for f in ev.get('findings', []) if f.get('severity') in ('high', 'critical')]
    md.append(u'## Знахідки findevil / детекції')
    if hi:
        for f in hi:
            md.append(u'- **[%s]** %s x%s — %s\n  _джерело: %s_'
                      % (f.get('severity'), f.get('kind'), f.get('count', 1), f.get('why', ''),
                         f.get('evidence', f.get('source', 'findevil'))))
    else:
        md.append(u'_findevil не позначив нічого високого рівня._')
    md.append(_sec(u'🌐 Мережеві зʼєднання (net.csv) — зовнішні/цікаві', ev.get('network')))
    md.append(_sec(u'🌐 DNS-запити (netdns.csv)', ev.get('dns')))
    md.append(_sec(u'⚙️ Підозрілі процеси + командні рядки (process.csv)', ev.get('processes')))
    md.append(_sec(u'📅 Заплановані задачі (tasks.csv)', ev.get('tasks')))
    md.append(_sec(u'🔧 Служби (services.csv)', ev.get('services')))
    if ctx.get('iocs'):
        md.append(u'\n## IOC справи (для звірки вручну)')
        for i in ctx['iocs'][:20]:
            md.append(u'- %s: `%s`' % (i['type'], i['value']))
    _tl = ev.get('timeline') or []
    if _tl:
        md.append(u'\n## 🕒 ХРОНОЛОГІЯ (timeline_*.csv)')
        md.extend(u'- `%s`' % e for e in _tl[:150])
    md.append(u'\n_Повний структурований вивід MemProcFS — в архіві, що додається._')
    return '\n'.join(m for m in md if m)


def build(conn, case_key, out_dir):
    ev = forensic_evidence(out_dir)
    ctx = case_context(conn, case_key) if conn else {}

    # compact, labelled evidence blocks (NOT one giant JSON that gets truncated)
    def _blk(title, items):
        return (u'\n=== %s ===\n' % title + '\n'.join('- ' + str(x) for x in items)) if items else u''
    ev_txt = (
        _blk(u'МЕРЕЖА (net.csv: proto dst:port <- процес [стан] час)', ev.get('network'))
        + _blk(u'DNS (netdns.csv)', ev.get('dns'))
        + _blk(u'ПРОЦЕСИ + CMDLINE (process.csv, підозрілі зверху)', ev.get('processes'))
        + _blk(u'ЗАПЛАНОВАНІ ЗАДАЧІ (tasks.csv, нестандартні)', ev.get('tasks'))
        + _blk(u'СЛУЖБИ (services.csv)', ev.get('services'))
        + _blk(u'FINDEVIL / ДЕТЕКЦІЇ (MemProcFS, з посиланнями на джерело)', [
            u'[%s] %s x%s — %s | ДЖЕРЕЛО: %s' % (
                f.get('severity'), f.get('kind'), f.get('count', 1), f.get('why', ''),
                f.get('evidence', f.get('source', '')))
            for f in ev.get('findings', [])])
    )
    tl = ev.get('timeline') or []
    tl_txt = u'\n=== ХРОНОЛОГІЯ ПОДІЙ (timeline_*.csv, час · тип · подія) ===\n' + '\n'.join(tl[:180]) if tl else u''
    user = (u'СПРАВА: %s\n%s\n%s\n\n=== ЩО ВЖЕ ВІДОМО У СПРАВІ (диск, логи) ===\n%s\n\n'
            u'Напиши ДЕТАЛЬНИЙ звіт Markdown. РОЗДІЛИ:\n'
            u'1) 📌 ЗАГАЛЬНИЙ ВИСНОВОК — 2-4 абзаци з КОНКРЕТИКОЮ: ХТО (акаунти), КОЛИ '
            u'(конкретні дати й час ключових подій із хронології), ЗВІДКИ/КУДИ (IP, хости, '
            u'порти), ЩО САМЕ (шкідливі/підозрілі файли, служби, драйвери, задачі — з іменами), '
            u'ЯК (вектор: WinRM/BYOVD/тощо). Не загально — з датами, іменами, адресами.\n'
            u'2) 🌐 Мережа (зовнішні IP+порти: 5985=WinRM,3389=RDP,445=SMB — боковий рух);\n'
            u'3) ⚙️ Процеси та командні рядки (з часом запуску, батьком, користувачем);\n'
            u'4) 📅 Задачі та служби (закріплення);\n'
            u'5) findevil (vuln driver/інʼєкції — з адресами);\n'
            u'6) ЗВʼЯЗКИ памʼяті зі справою;\n'
            u'7) що перевірити далі;\n'
            u'8) 🕒 ХРОНОЛОГІЯ — таблиця/список час→подія за наведеною хронологією, від '
            u'найранішого до останнього, лише значущі події.\n'
            u'Для КОЖНОГО факту — ДЖЕРЕЛО дослівно (net.csv, process.csv, tasks.csv, findevil.csv).'
            % (case_key, ev_txt[:12000], tl_txt[:9000],
               json.dumps(ctx, ensure_ascii=False)[:2500]))
    try:
        md = _llm(SYSTEM, user)
        if md and len(md) > 200:
            md = (u'# Звіт з аналізу оперативної памʼяті — %s\n'
                  u'_MemProcFS forensic + звірка зі справою · %s_\n\n'
                  % (case_key, time.strftime('%Y-%m-%d %H:%M'))) + md
            # always append the raw high-signal evidence so IPs/tasks are never lost to a
            # terse model answer
            md += u'\n\n---\n## 📎 Сирі докази (для перевірки вручну)\n'
            md += _sec(u'🌐 Мережа (net.csv)', ev.get('network'))
            md += _sec(u'🌐 DNS', ev.get('dns'))
            md += _sec(u'⚙️ Процеси + cmdline', ev.get('processes'))
            md += _sec(u'📅 Задачі', ev.get('tasks'))
            md += _sec(u'🔧 Служби', ev.get('services'))
            _tl = ev.get('timeline') or []
            if _tl:
                md += u'\n\n## 🕒 ХРОНОЛОГІЯ (timeline_*.csv, сирі події)\n' \
                      + '\n'.join(u'- `%s`' % e for e in _tl[:150])
            log('звіт LLM готовий, %d символів' % len(md))
            return md
        log('LLM повернув замало — беру детермінований звіт')
    except Exception as e:
        log('LLM недоступний (%s) — детермінований звіт' % repr(e)[:80])
    return _deterministic(case_key, ev, ctx)


if __name__ == '__main__':
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else '/tmp/mpfs_out'
    ck = sys.argv[2] if len(sys.argv) > 2 else 'TEST'
    print(build(None, ck, out))
