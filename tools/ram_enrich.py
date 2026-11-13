# -*- coding: utf-8 -*-
"""The detections MemProcFS-Analyzer adds beyond findevil - ported to Linux, pure Python.

MemProcFS forensic gives us process/network/module CSVs and recovered files. MemProcFS-
Analyzer (Windows) then reasons over them: masquerading process names, suspicious network,
packed modules, ClamAV signatures, bad parent/child chains. Those that need no Windows tool
are reimplemented here so our Linux pipeline reaches close to the same value:

  * MASQUERADE - a system process name from the wrong path, or a near-miss spelling
    (svch0st.exe, scvhost.exe): the oldest trick, and findevil does not catch a name typo.
  * NETWORK - a connection to a public address, a known-bad port, and - most important -
    a remote IP that MATCHES an IOC already in the case. That last one is the link the
    owner keeps asking for: memory to case.
  * ENTROPY - a recovered/injected module whose bytes are near-random is packed or
    encrypted, the usual state of a payload.
  * BAD PARENT - a shell or script host launched by a browser or office app.
  * CLAMAV - if clamscan is installed, the recovered files are signature-scanned. Optional:
    absent ClamAV simply skips this, it is not required.

Everything returns the same finding shape the case already uses, so the worker writes them
into the case beside the findevil ones.
"""
import csv
import glob
import io
import math
import os
import re
import subprocess

# Windows processes malware likes to impersonate, with the directory they legitimately
# run from (lowercased, partial match).
SYSTEM_PROCS = {
    'svchost.exe': 'windows\\system32', 'lsass.exe': 'windows\\system32',
    'csrss.exe': 'windows\\system32', 'services.exe': 'windows\\system32',
    'winlogon.exe': 'windows\\system32', 'smss.exe': 'windows\\system32',
    'wininit.exe': 'windows\\system32', 'spoolsv.exe': 'windows\\system32',
    'taskhostw.exe': 'windows\\system32', 'explorer.exe': 'windows',
    'dllhost.exe': 'windows\\system32', 'conhost.exe': 'windows\\system32',
    'rundll32.exe': 'windows\\system32',
}
SUSPICIOUS_PORTS = {'4444', '1337', '31337', '5555', '6666', '6667', '8443', '9001', '1080'}
SHELL_PROCS = {'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe',
               'mshta.exe', 'rundll32.exe', 'regsvr32.exe'}
BAD_PARENTS = {'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe',
               'chrome.exe', 'msedge.exe', 'firefox.exe', 'acrord32.exe'}


def _dl_distance(a, b):
    """Damerau-Levenshtein - counts a transposition (scvhost) as one edit."""
    a, b = a.lower(), b.lower()
    if a == b:
        return 0
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def _read_csv(path, limit=4000):
    rows = []
    try:
        with io.open(path, encoding='utf-8', errors='replace') as fh:
            for i, row in enumerate(csv.DictReader(fh)):
                if i >= limit:
                    break
                rows.append(row)
    except Exception:
        pass
    return rows


def _col(row, *names):
    low = {k.lower(): v for k, v in row.items() if k}
    for n in names:
        if n in low and low[n]:
            return str(low[n])
    return ''


def _find_csv(out_dir, *needles):
    for base in (os.path.join(out_dir, 'forensic', 'csv'), os.path.join(out_dir, 'forensic'),
                 out_dir):
        for p in glob.glob(os.path.join(base, '*.csv')):
            low = os.path.basename(p).lower()
            if any(n in low for n in needles):
                yield p


def _masquerade(out_dir):
    out = []
    for p in _find_csv(out_dir, 'process', 'pslist'):
        for r in _read_csv(p):
            name = _col(r, 'name', 'imagefilename', 'process').lower()
            path = _col(r, 'path', 'fullpath', 'imagepath', 'fullname').lower()
            if not name.endswith('.exe'):
                continue
            # exact system name from a wrong directory
            if name in SYSTEM_PROCS and path:
                if SYSTEM_PROCS[name] not in path:
                    out.append({'severity': 'high', 'kind': 'masquerade_path',
                                'name': name, 'detail': path[:200],
                                'why': u'системний процес %s запущено з нетипового шляху '
                                       u'(%s) — типова підміна' % (name, path[:80])})
            # near-miss spelling of a system name
            for sysname in SYSTEM_PROCS:
                if name != sysname and _dl_distance(name, sysname) == 1 \
                        and abs(len(name) - len(sysname)) <= 1:
                    out.append({'severity': 'high', 'kind': 'masquerade_name',
                                'name': name, 'detail': u'схоже на %s' % sysname,
                                'why': u'імʼя процесу %s — за одну літеру від системного %s '
                                       u'(маскування)' % (name, sysname)})
                    break
    return out


def _network(out_dir, case_iocs):
    out = []
    ioc_set = {str(v).strip().lower() for v in (case_iocs or [])}
    for p in _find_csv(out_dir, 'net', 'tcp', 'connection'):
        for r in _read_csv(p):
            remote = _col(r, 'remoteaddress', 'remote', 'dst', 'foreignaddress')
            port = _col(r, 'remoteport', 'port', 'dstport')
            proc = _col(r, 'process', 'name', 'imagefilename')
            ip = re.split(r'[:%]', remote)[0].strip('[]') if remote else ''
            if not ip:
                continue
            public = not (ip.startswith(('10.', '127.', '169.254.', '192.168.', '::1', 'fe80'))
                          or re.match(r'172\.(1[6-9]|2\d|3[01])\.', ip) or ip in ('0.0.0.0', '::'))
            # the link that matters: a live connection to a case IOC
            if ip.lower() in ioc_set:
                out.append({'severity': 'high', 'kind': 'net_ioc_match',
                            'name': proc, 'detail': '%s:%s' % (ip, port),
                            'why': u'процес %s тримав зʼєднання з %s — це IOC самої справи '
                                   u'(звʼязок памʼяті з диском/логами)' % (proc or '?', ip)})
            elif public and port in SUSPICIOUS_PORTS:
                out.append({'severity': 'medium', 'kind': 'net_bad_port',
                            'name': proc, 'detail': '%s:%s' % (ip, port),
                            'why': u'зʼєднання %s:%s — порт часто вживають бекдори' % (ip, port)})
    return out


def _bad_parent(out_dir):
    out = []
    for p in _find_csv(out_dir, 'process', 'pslist'):
        rows = _read_csv(p)
        by_pid = {}
        for r in rows:
            pid = _col(r, 'pid')
            if pid:
                by_pid[pid] = _col(r, 'name', 'imagefilename', 'process').lower()
        for r in rows:
            name = _col(r, 'name', 'imagefilename', 'process').lower()
            ppid = _col(r, 'ppid', 'parentpid')
            parent = by_pid.get(ppid, '')
            if name in SHELL_PROCS and parent in BAD_PARENTS:
                out.append({'severity': 'high', 'kind': 'bad_parent',
                            'name': name, 'detail': u'батько: %s' % parent,
                            'why': u'%s запущено з %s — офісний/браузерний процес не має '
                                   u'запускати оболонку (ознака фішингу/експлойта)'
                                   % (name, parent)})
    return out


def _entropy_of(path, cap=2 * 1024 * 1024):
    try:
        data = io.open(path, 'rb').read(cap)
    except Exception:
        return 0.0
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _packed_modules(out_dir):
    out = []
    fdir = os.path.join(out_dir, 'forensic', 'files')
    if not os.path.isdir(fdir):
        return out
    checked = 0
    for root, _dirs, files in os.walk(fdir):
        for f in files:
            if checked >= 200:
                return out
            fp = os.path.join(root, f)
            try:
                if os.path.getsize(fp) < 4096:
                    continue
            except OSError:
                continue
            checked += 1
            ent = _entropy_of(fp)
            if ent >= 7.2:
                out.append({'severity': 'medium', 'kind': 'high_entropy',
                            'name': f, 'detail': 'entropy=%.2f' % ent,
                            'why': u'відновлений модуль %s має ентропію %.2f — запакований '
                                   u'або зашифрований (типовий стан payload)' % (f[:60], ent)})
    return out


_BS = chr(92)
SUSPICIOUS_PATHS = tuple(_BS + p + (_BS if t else '') for p, t in (
    ('temp', 1), ('appdata', 1), ('downloads', 1), ('programdata', 1),
    ('public', 1), ('users' + _BS + 'public', 0), ('windows' + _BS + 'temp', 0),
    ('$recycle', 0), ('perflogs', 0)))


def _amcache(out_dir):
    """Application execution history MemProcFS recovered from memory. An executable that
    ran from a temp/appdata/downloads path is the classic drop-and-run, and Amcache proves
    it ran even if the file is gone from disk."""
    out = []
    for p in _find_csv(out_dir, 'amcache'):
        for r in _read_csv(p, 2000):
            path = _col(r, 'fullpath', 'path', 'name', 'filepath').lower()
            if not path.endswith('.exe'):
                continue
            if any(sp in path for sp in SUSPICIOUS_PATHS):
                sha = _col(r, 'sha1', 'sha-1', 'hash')
                out.append({'severity': 'medium', 'kind': 'amcache_suspicious_exec',
                            'name': path.split(chr(92))[-1][:60], 'detail': path[:200],
                            'why': u'Amcache (з памʼяті) фіксує запуск %s із підозрілого '
                                   u'шляху%s — виконання, навіть якщо файл уже видалено'
                                   % (path[:90], (' · sha1 ' + sha[:16]) if sha else '')})
    return out


def _read_text(out_dir, *names):
    """A forensic text file (web.txt / ntfs_files.txt), searched under forensic/ and root."""
    import glob as _g
    for base in (os.path.join(out_dir, 'forensic'), os.path.join(out_dir, 'forensic', 'csv'),
                 out_dir):
        for nm in names:
            fp = os.path.join(base, nm)
            if os.path.exists(fp):
                try:
                    return io.open(fp, encoding='utf-8', errors='replace').read()
                except Exception:
                    pass
        for fp in _g.glob(os.path.join(base, '*.txt')) + _g.glob(os.path.join(base, '*.csv')):
            if any(n.split('.')[0] in os.path.basename(fp).lower() for n in names):
                try:
                    return io.open(fp, encoding='utf-8', errors='replace').read()
                except Exception:
                    pass
    return ''


_DL_EXT = ('.exe', '.scr', '.js', '.jse', '.hta', '.ps1', '.vbs', '.bat', '.dll', '.jar', '.msi')
_URL_RE = re.compile('https?://([A-Za-z0-9.\\-]+)(/[^\\s<>"\']*)?', re.I)


def _web(out_dir, case_iocs):
    """Browsing history MemProcFS recovered from memory (web.txt). The point: a download
    of an executable, or a URL whose host is already an IOC in this case - the delivery
    step, straight from RAM."""
    out = []
    text = _read_text(out_dir, 'web.txt', 'web.csv')
    if not text:
        return out
    ioc_set = {str(v).strip().lower() for v in (case_iocs or [])}
    seen = set()
    for m in _URL_RE.finditer(text):
        host = m.group(1).lower()
        path = (m.group(2) or '').lower()
        url = (host + path)[:200]
        if url in seen:
            continue
        seen.add(url)
        if host in ioc_set or host.rstrip('.') in ioc_set:
            out.append({'severity': 'high', 'kind': 'web_ioc_match',
                        'name': host, 'detail': url,
                        'why': u'у памʼяті збережено відвідування %s — цей домен є IOC справи '
                               u'(канал доставки)' % host})
        elif any(path.endswith(e) for e in _DL_EXT):
            out.append({'severity': 'medium', 'kind': 'web_download',
                        'name': host, 'detail': url,
                        'why': u'з памʼяті: завантаження виконуваного файлу з %s%s — '
                               u'типова точка зараження через браузер' % (host, path[:60])})
        if len(out) >= 40:
            break
    return out


def _ntfs(out_dir):
    """Files MemProcFS reconstructed from the NTFS MFT in memory. A recovered executable in
    a temp/appdata/downloads path is a dropped payload - and here we have proof it existed
    even if it was wiped from disk."""
    out = []
    text = _read_text(out_dir, 'ntfs_files.txt', 'files.csv')
    if not text:
        return out
    seen = set()
    for line in text.splitlines():
        low = line.lower()
        if not any(low.rstrip().endswith(e) for e in _DL_EXT):
            # the path may have trailing columns; check for the ext anywhere late in line
            if not any((e + ' ') in low or (e + chr(9)) in low or low.endswith(e) for e in _DL_EXT):
                continue
        if not any(sp in low for sp in SUSPICIOUS_PATHS):
            continue
        key = low[:120]
        if key in seen:
            continue
        seen.add(key)
        out.append({'severity': 'medium', 'kind': 'ntfs_recovered_exec',
                    'name': line.strip().split(chr(92))[-1][:60], 'detail': line.strip()[:200],
                    'why': u'з MFT у памʼяті відновлено виконуваний файл у підозрілому шляху '
                           u'— доказ, що файл існував, навіть якщо його стерли з диску'})
        if len(out) >= 30:
            break
    return out


def _clamav(out_dir):
    """Signature scan of recovered files, if ClamAV is installed. Optional."""
    fdir = os.path.join(out_dir, 'forensic', 'files')
    if not os.path.isdir(fdir):
        return []
    clam = None
    for c in ('clamdscan', 'clamscan'):
        if subprocess.run(['which', c], capture_output=True).returncode == 0:
            clam = c
            break
    if not clam:
        return []
    to = int(os.environ.get('DFIR_CLAMAV_TIMEOUT', '300'))
    out = []
    try:
        if clam == 'clamdscan':
            cmd = [clam, '--multiscan', '--no-summary', '--infected', '-r', fdir]
        else:
            # no daemon: scanning every recovered file is too slow, so cap to a bounded set
            # of executable-like files - the only ones a signature scan meaningfully helps.
            _exts = ('.exe', '.dll', '.sys', '.scr', '.ps1', '.vbs', '.js', '.bat',
                     '.hta', '.cmd', '.jar', '.dat', '.tmp', '.bin')
            _cap = int(os.environ.get('DFIR_CLAMAV_MAXFILES', '1500'))
            _files = []
            for _root, _d, _fs in os.walk(fdir):
                for _f in _fs:
                    if _f.lower().endswith(_exts):
                        _files.append(os.path.join(_root, _f))
                if len(_files) >= _cap:
                    break
            if not _files:
                return []
            cmd = [clam, '--no-summary', '--infected'] + _files[:_cap]
        r = subprocess.run(cmd, capture_output=True, timeout=to)
        for line in (r.stdout or b'').decode('utf-8', 'replace').splitlines():
            if line.strip().endswith('FOUND'):
                parts = line.rsplit(':', 1)
                fname = os.path.basename(parts[0])
                sig = parts[1].replace('FOUND', '').strip() if len(parts) > 1 else ''
                out.append({'severity': 'high', 'kind': 'clamav_hit',
                            'name': fname, 'detail': sig,
                            'why': u'ClamAV впізнав відомий шкідник у відновленому файлі '
                                   u'%s: %s' % (fname[:60], sig)})
    except Exception:
        pass
    return out


def enrich(out_dir, case_iocs=None):
    """All portable detections merged into the case findings shape."""
    findings = []
    for fn in (_masquerade, _bad_parent, _packed_modules, _amcache, _ntfs, _clamav):
        try:
            findings += fn(out_dir)
        except Exception:
            pass
    try:
        findings += _network(out_dir, case_iocs)
    except Exception:
        pass
    try:
        findings += _web(out_dir, case_iocs)
    except Exception:
        pass
    # de-duplicate on (kind, detail)
    seen, uniq = set(), []
    for f in findings:
        k = (f.get('kind'), str(f.get('detail'))[:120])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return uniq


if __name__ == '__main__':
    import json
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else '/tmp/mpfs_out'
    print(json.dumps(enrich(out), ensure_ascii=False, indent=1))
