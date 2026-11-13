#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Turn a memory dump into findings, then get rid of the dump.

The collector has been able to capture RAM since v4.2 and tells the operator it goes to
the bot - and until now there was nothing on this side to take it. A dump is also the one
artefact we must not keep: it is the size of the machine's memory, it contains everything
that was open at that moment, and it is worth nothing to us once the plugins have run.

TOOL CHOICE. Volatility 3, because DumpIt writes a Microsoft crash dump and Volatility
reads that format directly. MemProcFS was tried before and does not read what we produce.

HOW IT BEHAVES:
  * every plugin runs with its own timeout - one plugin that hangs must not cost the whole
    analysis, and on a 32 GB image several of them legitimately take minutes;
  * results are written per plugin as JSON, so a partial run is still useful;
  * the first run on a new Windows build downloads symbol tables from the Volatility
    server. Without internet that plugin fails and says so - it is not a crash;
  * the dump is deleted only after at least one plugin produced rows. Deleting evidence
    because our tooling failed would be the worst possible outcome.
"""
import argparse
import io
import json
import os
import subprocess
import sys
import time

VOL = os.environ.get('DFIR_VOL_BIN', '/opt/vol3/bin/vol')

# (plugin, timeout seconds, what it answers)
PLUGINS = [
    ('windows.info', 300, u'що це за система і коли знято'),
    ('windows.pslist', 900, u'які процеси працювали'),
    ('windows.pstree', 900, u'хто кого запустив'),
    ('windows.cmdline', 900, u'з якими аргументами'),
    ('windows.netscan', 1200, u'мережеві зʼєднання і порти'),
    ('windows.svcscan', 1200, u'служби'),
    ('windows.malfind', 1800, u'ділянки памʼяті з ознаками впровадженого коду'),
    ('windows.psscan', 900, u'процеси через сканування пулу (бачить приховані)'),
    ('windows.driverscan', 900, u'драйвери ядра'),
]


def log(msg):
    print('%s [ram] %s' % (time.strftime('%H:%M:%S'), msg), flush=True)


def run_plugin(dump, plugin, timeout, out_dir):
    """One plugin. Returns (rows, seconds, error)."""
    t0 = time.time()
    out_path = os.path.join(out_dir, plugin.replace('.', '_') + '.json')
    cmd = [VOL, '-q', '-r', 'json', '-f', dump, plugin]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 0, time.time() - t0, 'timeout after %ds' % timeout
    except Exception as e:
        return 0, time.time() - t0, repr(e)[:160]

    raw = (p.stdout or b'').decode('utf-8', 'replace').strip()
    if not raw:
        err = (p.stderr or b'').decode('utf-8', 'replace').strip()
        short = err.splitlines()[-1][:200] if err else 'no output'
        return 0, time.time() - t0, short
    try:
        rows = json.loads(raw)
    except ValueError:
        # Volatility prints its real complaint as plain text on stdout. Keep the lines
        # that carry meaning rather than reporting the shape of the output.
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        why = ''
        for l in lines:
            low = l.lower()
            if 'symbol' in low and ('not' in low or 'unable' in low or 'missing' in low):
                why = u'немає таблиці символів для цієї збірки Windows ' \
                      u'(перший запуск качає їх з мережі)'
                break
            if 'unable to validate' in low or 'requirement' in low:
                why = u'плагін не зміг розпізнати образ: %s' % l[:120]
                break
            if 'not a supported' in low or 'invalid' in low or 'no suitable' in low:
                why = u'формат образу не підтримується: %s' % l[:120]
                break
        if not why:
            why = lines[-1][:180] if lines else 'no output'
        return 0, time.time() - t0, why
    io.open(out_path, 'w', encoding='utf-8').write(
        json.dumps(rows, ensure_ascii=False, indent=1))
    return (len(rows) if isinstance(rows, list) else 1), time.time() - t0, ''


def _load(out_dir, plugin):
    try:
        return json.load(io.open(os.path.join(out_dir, plugin.replace('.', '_') + '.json'),
                                 encoding='utf-8'))
    except Exception:
        return []


def _write_findings(out_dir, summary):
    """Rows a human should look at first, written where the worker can pick them up."""
    findings = []
    pslist = _load(out_dir, 'windows.pslist')
    psscan = _load(out_dir, 'windows.psscan')
    malfind = _load(out_dir, 'windows.malfind')

    # HIDDEN PROCESSES: in the pool scan but not in the linked list = actively hidden.
    def _key(r):
        return (r.get('PID'), str(r.get('ImageFileName') or r.get('Name') or '').lower())
    live = {_key(r) for r in pslist if isinstance(r, dict)}
    for r in psscan:
        if not isinstance(r, dict):
            continue
        if _key(r) not in live and r.get('PID'):
            findings.append({
                'severity': 'high', 'kind': 'hidden_process',
                'pid': r.get('PID'), 'name': r.get('ImageFileName') or r.get('Name'),
                'ppid': r.get('PPID'),
                'why': u'процес видно лише скануванням пулу, у звичайному списку його немає '
                       u'— ознака приховування (руткіт або завершений процес)'})

    # INJECTED CODE: malfind flags executable private memory - the classic injection sign.
    seen = set()
    for r in malfind:
        if not isinstance(r, dict):
            continue
        pid = r.get('PID')
        if pid in seen:
            continue
        seen.add(pid)
        findings.append({
            'severity': 'high', 'kind': 'injected_code',
            'pid': pid, 'name': r.get('Process') or r.get('ImageFileName'),
            'protection': r.get('Protection'),
            'why': u'у памʼяті процесу знайдено виконуваний приватний регіон — типова ознака '
                   u'впровадженого коду (process injection / hollowing)'})

    io.open(os.path.join(out_dir, 'findings.json'), 'w', encoding='utf-8').write(
        json.dumps(findings, ensure_ascii=False, indent=1))
    log('знахідок: %d (прихованих процесів + впроваджений код)' % len(findings))
    return findings


def analyse(dump, out_dir, keep=False):
    os.makedirs(out_dir, exist_ok=True)
    size_gb = os.path.getsize(dump) / 1024.0 ** 3
    log('дамп %s (%.1f ГБ)' % (os.path.basename(dump), size_gb))

    summary = {'dump': os.path.basename(dump), 'size_gb': round(size_gb, 2),
               'started': time.strftime('%Y-%m-%d %H:%M:%S'), 'plugins': {}}
    produced = 0
    for plugin, timeout, what in PLUGINS:
        rows, secs, err = run_plugin(dump, plugin, timeout, out_dir)
        summary['plugins'][plugin] = {'rows': rows, 'seconds': round(secs, 1),
                                      'error': err, 'answers': what}
        if err:
            log('  %-20s ПОМИЛКА за %.0fс: %s' % (plugin, secs, err[:120]))
        else:
            produced += rows
            log('  %-20s %d рядків за %.0fс' % (plugin, rows, secs))

    summary['total_rows'] = produced
    summary['finished'] = time.strftime('%Y-%m-%d %H:%M:%S')
    io.open(os.path.join(out_dir, 'summary.json'), 'w', encoding='utf-8').write(
        json.dumps(summary, ensure_ascii=False, indent=1))

    # Turn raw plugin output into findings the report can cite - the memprocfs-findevil
    # idea: a process the normal list hides, and memory that carries injected code.
    try:
        _write_findings(out_dir, summary)
    except Exception as _fe:
        log('findings step failed: %s' % repr(_fe)[:120])

    if produced and not keep:
        try:
            os.remove(dump)
            log('дамп видалено: %d рядків уже витягнуто, тримати його немає сенсу' % produced)
            summary['dump_deleted'] = True
        except OSError as e:
            log('не вдалося видалити дамп: %s' % repr(e)[:100])
    elif not produced:
        log('ЖОДЕН плагін нічого не дав - дамп ЗБЕРЕЖЕНО, це наша проблема, не його')
        summary['dump_deleted'] = False
    return summary


def main():
    ap = argparse.ArgumentParser(description='Run Volatility over a memory dump')
    ap.add_argument('dump')
    ap.add_argument('--out', default='')
    ap.add_argument('--keep', action='store_true', help='do not delete the dump afterwards')
    a = ap.parse_args()
    if not os.path.exists(a.dump):
        log('немає такого файлу: %s' % a.dump)
        return 2
    out = a.out or os.path.join('/srv/dfir/var/ram_results',
                                os.path.basename(a.dump) + '_' + time.strftime('%Y%m%d_%H%M%S'))
    s = analyse(a.dump, out, keep=a.keep)
    log('готово: %d рядків усього, результати в %s' % (s['total_rows'], out))
    return 0 if s['total_rows'] else 1


if __name__ == '__main__':
    sys.exit(main())
