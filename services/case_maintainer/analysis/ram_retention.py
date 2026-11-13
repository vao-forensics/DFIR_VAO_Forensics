# -*- coding: utf-8 -*-
"""RAM-dump lifecycle (owner policy 2026-09-13).

After a memory analysis the server keeps the light results (CSV/JSON/text/report/keys) and a
passport of the dump (name, size, mtime, SHA-256, MD5) in the case; the uploaded archive and the
heavy extracts (registry hive images, dumped binaries, the full forensic ZIP) are removed either
on the owner's button or automatically after RETENTION_DAYS. The user is told to keep their own
copy of the dump — the server keeps the passport and the results only.

Pure filesystem module, shared by tools/ram_worker.py (VM host) and app.py (container): both see
the case library; the results tree is on the host side only, so the endpoint leaves a marker in
the case and the worker does the slimming on its next tick.
"""
import hashlib
import io
import json
import os
import re
import shutil
import time
import zipfile

RETENTION_DAYS = 7
SLIM_MARKER = '.ram_slim_requested'          # in cases/<case>/reports — «delete now» was pressed
SLIM_DONE = 'slim_done.json'                 # in ram_results/<case>_job<N>
MANIFEST = 'dump_manifest.json'

KEEP_EXT = {'csv', 'json', 'txt', 'log', 'md', 'html', 'htm', 'xml', 'yaml', 'yml', 'evtx', 'ini', 'reg'}
HEAVY_EXT = {'hivemem', 'dll', 'exe', 'sys', 'wim', 'bin', 'dat', 'pf', 'ocx', 'drv', 'mui', 'cab',
             'img', 'raw', 'dmp', 'mem', 'vmem', 'pdb', 'msi', 'so', 'pyd', 'jar', 'zip', '7z', 'rar',
             'cpl', 'scr', 'efi', 'nls', 'tlb', 'winmd', 'lib'}
DUMP_EXT = ('.raw', '.mem', '.dmp', '.vmem', '.bin', '.img', '.dump', '.lime', '.aff4', '.e01')
HEAVY_NOEXT_MIN = 256 * 1024          # a file without extension above this is a dumped object
HEAVY_ANY_MIN = 64 * 1024 * 1024      # anything this big that is not a kept text/CSV type


def _ext(name):
    n = name.lower()
    return n.rsplit('.', 1)[1] if '.' in n else ''


def is_heavy(path, size=None):
    """True for a file the retention removes: hive images, dumped binaries, big non-text blobs."""
    if size is None:
        try:
            size = os.path.getsize(path)
        except OSError:
            return False
    e = _ext(os.path.basename(path))
    if e in KEEP_EXT:
        return False
    if e in HEAVY_EXT:
        return True
    if e == '' and size >= HEAVY_NOEXT_MIN:
        return True
    return size >= HEAVY_ANY_MIN


def _hash_stream(fobj, progress=None, total=0, label=''):
    h256, hmd5, done, last = hashlib.sha256(), hashlib.md5(), 0, 0.0
    while True:
        b = fobj.read(8 * 1024 * 1024)
        if not b:
            break
        h256.update(b)
        hmd5.update(b)
        done += len(b)
        if progress and total and time.time() - last > 5:
            last = time.time()
            try:
                progress(min(99, int(done * 100.0 / total)), label)
            except Exception:
                pass
    return h256.hexdigest(), hmd5.hexdigest(), done


def file_passport(path, progress=None, label=u'хешування дампа'):
    st = os.stat(path)
    with open(path, 'rb') as f:
        s256, md5, n = _hash_stream(f, progress, st.st_size, label)
    return {'name': os.path.basename(path), 'size': st.st_size,
            'mtime': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime)),
            'sha256': s256, 'md5': md5}


def dump_members(zpath):
    """Members of an archive that look like memory dumps / pagefiles (by name or by size)."""
    out = []
    with zipfile.ZipFile(zpath) as z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        for i in infos:
            base = os.path.basename(i.filename).lower()
            if base.endswith(DUMP_EXT) or base in ('pagefile.sys', 'swapfile.sys', 'hiberfil.sys') \
                    or 'memory' in base or 'memdump' in base or 'physmem' in base:
                out.append(i)
        if not out and infos:
            out = [max(infos, key=lambda i: i.file_size)]
    return out


def passport_from_archive(zpath, progress=None):
    """Passport of the dump(s) INSIDE a ZIP without extracting them (streamed hashing)."""
    entries = []
    with zipfile.ZipFile(zpath) as z:
        for i in dump_members(zpath):
            with z.open(i) as f:
                s256, md5, n = _hash_stream(f, progress, i.file_size,
                                            u'хешування %s' % os.path.basename(i.filename)[:40])
            entries.append({'name': os.path.basename(i.filename), 'path_in_archive': i.filename,
                            'size': i.file_size, 'mtime': '%04d-%02d-%02d %02d:%02d:%02d' % i.date_time,
                            'sha256': s256, 'md5': md5})
    return entries


def build_manifest(job_id, case_key, dump_path=None, archive_path=None, pagefiles=None,
                   engine='', progress=None):
    m = {'job_id': job_id, 'case_key': case_key, 'engine': engine,
         'created_at': time.strftime('%Y-%m-%d %H:%M:%S'),
         'retention_days': RETENTION_DAYS,
         'delete_after': time.strftime('%Y-%m-%d', time.localtime(time.time() + RETENTION_DAYS * 86400)),
         'dump': None, 'pagefiles': [], 'archive': None}
    if dump_path and os.path.isfile(dump_path):
        m['dump'] = file_passport(dump_path, progress)
    for p in (pagefiles or []):
        try:
            m['pagefiles'].append(file_passport(p, progress, u'хешування pagefile'))
        except Exception:
            pass
    if archive_path and os.path.isfile(archive_path):
        a = file_passport(archive_path, progress, u'хешування архіву')
        if archive_path != dump_path and not m['dump'] and archive_path.lower().endswith('.zip'):
            try:
                inside = passport_from_archive(archive_path, progress)
                if inside:
                    m['dump'] = inside[0]
                    m['dump_members'] = inside
            except Exception:
                pass
        m['archive'] = a
    return m


def write_manifest(manifest, out_dir, case_reports_dir):
    txt = json.dumps(manifest, ensure_ascii=False, indent=1)
    for d, name in ((out_dir, MANIFEST),
                    (os.path.join(out_dir, 'report'), MANIFEST),
                    (case_reports_dir, 'dump_manifest_job%s.json' % manifest.get('job_id'))):
        try:
            os.makedirs(d, exist_ok=True)
            io.open(os.path.join(d, name), 'w', encoding='utf-8').write(txt)
        except Exception:
            pass


def manifest_text(m):
    """The passport as the user reads it in Telegram."""
    def _gb(n):
        return '%.2f ГБ' % (n / 1024.0 ** 3) if n >= 1024 ** 3 else '%.1f МБ' % (n / 1024.0 ** 2)
    L = []
    d = m.get('dump')
    if d:
        L.append(u'🧾 Паспорт дампа: %s — %s, змінено %s' % (d['name'], _gb(d['size']), d['mtime']))
        L.append(u'SHA-256: %s' % d['sha256'])
        L.append(u'MD5: %s' % d['md5'])
    for p in m.get('pagefiles') or []:
        L.append(u'pagefile: %s — %s, SHA-256 %s' % (p['name'], _gb(p['size']), p['sha256']))
    a = m.get('archive')
    if a and (not d or a['sha256'] != d['sha256']):
        L.append(u'Завантажений архів: %s — %s, SHA-256 %s' % (a['name'], _gb(a['size']), a['sha256']))
    return '\n'.join(L)


def heavy_files(out_dir):
    """Files the slimming removes, with sizes."""
    res = []
    hives = os.path.join(out_dir, 'hives')
    for root, _d, files in os.walk(out_dir):
        for f in files:
            p = os.path.join(root, f)
            try:
                sz = os.path.getsize(p)
            except OSError:
                continue
            if root.startswith(hives) or is_heavy(p, sz):
                res.append((p, sz))
    return res


def make_light_zip(out_dir, zpath):
    """CSV/JSON/text results + report + keys, no binaries — the part that stays in the case."""
    n = 0
    with zipfile.ZipFile(zpath, 'w', zipfile.ZIP_DEFLATED) as z:
        for sub in ('forensic', 'report', 'keys'):
            d = os.path.join(out_dir, sub)
            for root, _dd, files in os.walk(d):
                for f in files:
                    p = os.path.join(root, f)
                    try:
                        sz = os.path.getsize(p)
                    except OSError:
                        continue
                    if root.startswith(os.path.join(out_dir, 'hives')) or is_heavy(p, sz):
                        continue
                    z.write(p, os.path.join(sub, os.path.relpath(p, d)))
                    n += 1
        for name in (MANIFEST, 'summary.json', 'findings.json', 'memory_context.json'):
            p = os.path.join(out_dir, name)
            if os.path.isfile(p):
                z.write(p, name)
                n += 1
    return n


def slim(out_dir, case_reports_dir, job_id):
    """Remove heavy extracts and the full ZIP; keep a light ZIP + manifest. Returns a dict."""
    freed, removed = 0, 0
    light = os.path.join(case_reports_dir, 'memprocfs_job%s_light.zip' % job_id)
    if not os.path.isfile(light):
        try:
            os.makedirs(case_reports_dir, exist_ok=True)
            make_light_zip(out_dir, light)
        except Exception:
            pass
    for p, sz in heavy_files(out_dir):
        try:
            os.remove(p)
            freed += sz
            removed += 1
        except OSError:
            pass
    hives = os.path.join(out_dir, 'hives')
    if os.path.isdir(hives):
        shutil.rmtree(hives, ignore_errors=True)
    full = os.path.join(case_reports_dir, 'memprocfs_job%s.zip' % job_id)
    if os.path.isfile(full):
        try:
            freed += os.path.getsize(full)
            os.remove(full)
            removed += 1
        except OSError:
            pass
    # empty directories left behind
    for root, dirs, files in os.walk(out_dir, topdown=False):
        for d in dirs:
            try:
                os.rmdir(os.path.join(root, d))
            except OSError:
                pass
    info = {'slimmed_at': time.strftime('%Y-%m-%d %H:%M:%S'), 'freed_bytes': freed,
            'removed_files': removed, 'light_zip': light if os.path.isfile(light) else None}
    try:
        io.open(os.path.join(out_dir, SLIM_DONE), 'w', encoding='utf-8').write(json.dumps(info, ensure_ascii=False, indent=1))
    except Exception:
        pass
    return info


def delete_uploaded_archive(cases_root, case_key):
    """Remove cases/<case>/uploads/ram (the uploaded dump archive). Returns freed bytes."""
    d = os.path.join(cases_root, case_key, 'uploads', 'ram')
    if not os.path.isdir(d):
        return 0
    total = 0
    for root, _dd, files in os.walk(d):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    shutil.rmtree(d, ignore_errors=True)
    return total


def find_uploaded_archive(cases_root, case_key):
    d = os.path.join(cases_root, case_key, 'uploads', 'ram')
    if not os.path.isdir(d):
        return None
    files = []
    for root, _dd, names in os.walk(d):
        for f in names:
            p = os.path.join(root, f)
            try:
                files.append((os.path.getsize(p), p))
            except OSError:
                pass
    return max(files)[1] if files else None


_JOB_RX = re.compile(r'^(?P<case>.+)_job(?P<job>\d+)$')


def parse_job_dir(name):
    m = _JOB_RX.match(name)
    return (m.group('case'), int(m.group('job'))) if m else (None, None)


def job_age_days(out_dir):
    created = None
    p = os.path.join(out_dir, MANIFEST)
    if os.path.isfile(p):
        try:
            created = time.mktime(time.strptime(json.load(io.open(p, encoding='utf-8'))['created_at'], '%Y-%m-%d %H:%M:%S'))
        except Exception:
            created = None
    if created is None:
        try:
            created = os.stat(out_dir).st_mtime
        except OSError:
            return 0
    return (time.time() - created) / 86400.0


def retention_pass(results_root, cases_root, days=RETENTION_DAYS, now_marker_only=False):
    """One tick: slim every job that is older than `days` or whose case carries the «delete now»
    marker. Returns a list of action dicts (empty when nothing to do)."""
    actions = []
    if not os.path.isdir(results_root):
        return actions
    for name in sorted(os.listdir(results_root)):
        out_dir = os.path.join(results_root, name)
        if not os.path.isdir(out_dir):
            continue
        case_key, job_id = parse_job_dir(name)
        if not case_key:
            continue
        # the results dir name truncates the case key to 40 chars — resolve against the library
        real_case = case_key
        if not os.path.isdir(os.path.join(cases_root, real_case)):
            try:
                cands = [c for c in os.listdir(cases_root) if c.startswith(case_key)]
                if len(cands) == 1:
                    real_case = cands[0]
            except OSError:
                pass
        reports = os.path.join(cases_root, real_case, 'reports')
        marker = os.path.join(reports, SLIM_MARKER)
        done = os.path.isfile(os.path.join(out_dir, SLIM_DONE))
        requested = os.path.isfile(marker)
        age = job_age_days(out_dir)
        due = requested or (age >= days and not now_marker_only)
        if not due:
            continue
        act = {'case_key': real_case, 'job_id': job_id, 'age_days': round(age, 1),
               'requested': requested, 'freed_bytes': 0}
        # legacy job without a passport: hash the uploaded archive (and the dump inside it)
        # BEFORE anything is deleted, so the case keeps the evidence of what was analysed
        if not os.path.isfile(os.path.join(out_dir, MANIFEST)):
            arch = find_uploaded_archive(cases_root, real_case)
            if arch:
                try:
                    m = build_manifest(job_id, real_case, archive_path=arch)
                    write_manifest(m, out_dir, reports)
                    act['manifest'] = manifest_text(m)
                except Exception:
                    pass
        if not done:
            info = slim(out_dir, reports, job_id)
            act['freed_bytes'] += info.get('freed_bytes', 0)
            act['light_zip'] = info.get('light_zip')
        if age >= days or requested:
            act['freed_bytes'] += delete_uploaded_archive(cases_root, real_case)
        if requested:
            try:
                os.remove(marker)
            except OSError:
                pass
        if act['freed_bytes'] or not done:
            actions.append(act)
    return actions
