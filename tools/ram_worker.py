#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Take the memory jobs the bot queued and run them on the machine that can.

Volatility lives on the host, the bot lives in a container, and a single image takes
minutes to hours - so the bot records a job and this picks it up, exactly as the VPN work
does. One job at a time: two Volatility runs over multi-gigabyte images would compete for
the same disk and finish slower than one after the other.

Space is checked before unpacking, because a memory archive is the size of the machine it
came from and the failure mode of getting that wrong is a full disk.

The unpacked dump is deleted by the analyser once something has been extracted from it.
The uploaded ARCHIVE is left alone: deleting somebody's evidence because we are finished
with it is not our call, so the report says how much room it is taking and lets the owner
decide.
"""
import io
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import zipfile
import fcntl
import threading

RAM_WORKER_LOCK = '/tmp/dfir_ram_worker.lock'

ROOT = '/srv/dfir'
WORK = os.path.join(ROOT, 'ram_inbox')
RESULTS = os.path.join(ROOT, 'ram_results')
ANALYSER = os.path.join(ROOT, 'tools', 'ram_analyze.py')
OWNER = 'CHANGE_ME_OWNER_CHAT_ID'
TOKEN_FILE = '/root/.dfir_bot_token'
MEM_EXT = ('.dmp', '.raw', '.mem', '.vmem', '.core', '.bin', '.lime',
           '.img', '.dd', '.raw64', '.vmsn', '.vmss', '.save')
# A memory image is always the biggest file in a capture; if nothing matches a
# known extension, fall back to the largest file over this size.
DUMP_FALLBACK_MIN = int(os.environ.get('DFIR_RAM_MIN_DUMP_BYTES', str(100 * 1024 * 1024)))
# the stage label every keys step shows in the progress bar
KEYS_STAGE = u'Витяг ключів і секретів'
MIN_FREE = 30 * 1024 ** 3


RETENTION_MOD = os.path.join(ROOT, 'services', 'case_maintainer', 'analysis', 'ram_retention.py')


def _load_retention():
    import importlib.util
    spec = importlib.util.spec_from_file_location('ram_retention', RETENTION_MOD)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def log(msg):
    print('%s [ram-worker] %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), msg), flush=True)


def _host_dsn(root='/srv/dfir'):
    """The bot's own database login (user=dfir), as seen from the host.

    24.10.2026: this used to take the FIRST PG_DSN= line of docker-compose.yml. Since 18.10 that
    line belongs to dfir-mcp - the read-only role, with its password written as
    ${MCP_PG_PASSWORD} - so every login failed and VPN access requests / RAM jobs silently
    stopped. Now: the line whose user is dfir, with ${VAR} filled in from .env.
    """
    import re as _re
    env = {}
    try:
        for line in io.open(root + '/.env', encoding='utf-8'):
            if '=' in line and not line.lstrip().startswith('#'):
                k, v = line.rstrip('\n').split('=', 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    except IOError:
        pass
    cands = []
    if env.get('PG_DSN'):
        cands.append(env['PG_DSN'])
    try:
        for line in io.open(root + '/docker-compose.yml', encoding='utf-8'):
            line = line.strip().lstrip('-').strip()
            if line.startswith('PG_DSN='):
                cands.append(line.split('=', 1)[1].strip())
    except IOError:
        pass
    for d in cands:
        if _re.search(r'\buser=dfir\b', d):
            d = _re.sub(r'\$\{(\w+)(?::-([^}]*))?\}', lambda m: env.get(m.group(1), m.group(2) or ''), d)
            return d.replace('host=logdb', 'host=127.0.0.1').replace('port=5432', 'port=5433')
    return ''


def dsn():
    return _host_dsn(ROOT)


def tell(text):
    try:
        token = io.open(TOKEN_FILE, encoding='utf-8').read().strip()
    except IOError:
        return
    data = urllib.parse.urlencode({'chat_id': OWNER, 'text': text}).encode('utf-8')
    try:
        urllib.request.urlopen(
            urllib.request.Request('https://api.telegram.org/bot%s/sendMessage' % token,
                                   data=data), timeout=30)
    except Exception as e:
        log('could not notify: %s' % repr(e)[:100])


def _tg(method, params):
    """One Telegram Bot API call, best-effort. Returns the parsed JSON or {}."""
    try:
        token = io.open(TOKEN_FILE, encoding='utf-8').read().strip()
    except IOError:
        return {}
    data = urllib.parse.urlencode(params).encode('utf-8')
    try:
        r = urllib.request.urlopen(
            urllib.request.Request('https://api.telegram.org/bot%s/%s' % (token, method),
                                   data=data), timeout=30)
        return json.loads(r.read().decode('utf-8', 'replace'))
    except Exception:
        return {}


def _tg_document(path, caption=u''):
    """Send a file to the owner as a Telegram document (multipart)."""
    try:
        token = io.open(TOKEN_FILE, encoding='utf-8').read().strip()
        blob = open(path, 'rb').read()
    except Exception:
        return
    boundary = '----dfirRAM%d' % int(time.time())
    buf = io.BytesIO()

    def _w(x):
        buf.write(x.encode('utf-8') if isinstance(x, str) else x)
    _w('--%s\r\n' % boundary)
    _w('Content-Disposition: form-data; name="chat_id"\r\n\r\n%s\r\n' % OWNER)
    if caption:
        _w('--%s\r\n' % boundary)
        _w('Content-Disposition: form-data; name="caption"\r\n\r\n%s\r\n' % caption[:1000])
    _w('--%s\r\n' % boundary)
    _w('Content-Disposition: form-data; name="document"; filename="%s"\r\n' % os.path.basename(path))
    _w('Content-Type: text/markdown\r\n\r\n')
    _w(blob)
    _w('\r\n--%s--\r\n' % boundary)
    try:
        urllib.request.urlopen(urllib.request.Request(
            'https://api.telegram.org/bot%s/sendDocument' % token, data=buf.getvalue(),
            headers={'Content-Type': 'multipart/form-data; boundary=%s' % boundary}), timeout=60)
    except Exception as e:
        log('sendDocument не вдалося: %s' % repr(e)[:100])


class Progress(object):
    """A single editable Telegram message that shows the memory job moving through stages.

    Same look as the DFIR progress: a 16-wide ▓/░ bar, a percent, the current stage and a
    short line of detail. .set() is safe to call from anywhere (including the MemProcFS
    heartbeat) - it never raises and de-duplicates identical text so Telegram is not spammed.
    """
    def __init__(self, case_key):
        self.case = case_key
        self.mid = None
        self._last = ''
        r = _tg('sendMessage', {'chat_id': OWNER, 'text': self._text(0, u'У черзі', u'')})
        try:
            self.mid = r.get('result', {}).get('message_id')
        except Exception:
            self.mid = None

    def _text(self, pct, stage, detail):
        pct = max(0, min(100, int(pct)))
        filled = int(round(pct / 100.0 * 16))
        bar = u'\u2593' * filled + u'\u2591' * (16 - filled)
        out = (u'\U0001f9e0 Аналіз оперативної памʼяті\n'
               u'Справа: %s\n[%s] %d%%\n%s' % (self.case, bar, pct, stage))
        if detail:
            out += u'\n%s' % detail
        return out

    def set(self, pct, stage, detail=u''):
        try:
            txt = self._text(pct, stage, detail)
            if txt == self._last:
                return
            self._last = txt
            if self.mid:
                _tg('editMessageText', {'chat_id': OWNER, 'message_id': self.mid, 'text': txt})
            else:
                r = _tg('sendMessage', {'chat_id': OWNER, 'text': txt})
                self.mid = r.get('result', {}).get('message_id')
        except Exception:
            pass



class _Ticker(object):
    """Keep the progress bar alive during a long blocking stage. Ticks elapsed time every
    20s from a daemon thread, so enrich/keys never look frozen even when they run for minutes."""
    def __init__(self, prog, pct, stage):
        self.prog, self.pct, self.stage = prog, pct, stage
        self._stop = threading.Event()
        self._t0 = time.time()
        self._th = threading.Thread(target=self._run, daemon=True)
        self._th.start()

    def _run(self):
        while not self._stop.wait(20):
            try:
                el = int(time.time() - self._t0)
                self.prog.set(self.pct, self.stage, u'працює %d хв %02d с' % (el // 60, el % 60))
            except Exception:
                pass

    def stop(self):
        self._stop.set()


def free_bytes(path):
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


def find_dump(folder):
    """The biggest thing that looks like memory. Page and hibernation files count.

    Idiot-proof fallback: when nothing matches a known extension, the single biggest file
    over DUMP_FALLBACK_MIN is taken as the dump anyway - a capture's largest file always IS
    the image, whatever odd name (or missing extension) it was given.
    """
    best, best_size = '', 0
    biggest, biggest_size = '', 0
    for root, _dirs, files in os.walk(folder):
        for f in files:
            p = os.path.join(root, f)
            low = f.lower()
            try:
                sz = os.path.getsize(p)
            except OSError:
                continue
            if sz > biggest_size:
                biggest, biggest_size = p, sz
            if low.endswith(MEM_EXT) or low in ('pagefile.sys', 'hiberfil.sys', 'swapfile.sys'):
                if sz > best_size:
                    best, best_size = p, sz
    if not best and biggest_size >= DUMP_FALLBACK_MIN:
        log('дамп за розширенням не впізнано — беру найбільший файл: %s (%.1f ГБ)'
            % (os.path.basename(biggest), biggest_size / 1024.0 ** 3))
        return biggest, biggest_size
    return best, best_size


def host_path(path):
    """The bot records the path it sees; this process sees a different one.

    /data/case_library inside the container is /srv/dfir/cases here. Translating
    in one place beats teaching the bot about the host layout, which it should not know.
    """
    return (path or '').replace('/data/case_library', ROOT + '/cases')                        .replace('/tusd_uploads', ROOT + '/uploads')


def _find_pagefiles(folder):
    """pagefile.sys / swapfile.sys / hiberfil.sys anywhere in the unpacked archive.
    Ordered so pagefile is index 0 and swapfile index 1, as MemProcFS expects."""
    order = {'pagefile.sys': 0, 'swapfile.sys': 1, 'hiberfil.sys': 2}
    found = {}
    for root, _dirs, files in os.walk(folder):
        for f in files:
            lf = f.lower()
            if lf in order and lf not in found:
                found[lf] = os.path.join(root, f)
    return [found[k] for k in sorted(found, key=lambda x: order[x])]


def handle(conn, job_id, case_key, chat_id, archive):
    archive = host_path(archive)
    if not os.path.exists(archive):
        return 'failed', 'архів не знайдено на диску: %s' % archive[:120], 0

    size = os.path.getsize(archive)
    free = free_bytes(ROOT)
    if free - size * 2 < MIN_FREE:
        return ('failed',
                'замало місця: вільно %.0f ГБ, для розпакування треба ще ~%.0f ГБ'
                % (free / 1024.0 ** 3, size * 2 / 1024.0 ** 3), 0)

    work = os.path.join(WORK, 'job_%d' % job_id)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work, exist_ok=True)

    prog = Progress(case_key)
    prog.set(5, u'Розпакування архіву', u'дістаю дамп памʼяті та pagefile зі ZIP')

    if archive.lower().endswith('.zip'):
        log('розпаковую %s (%.1f ГБ)' % (os.path.basename(archive), size / 1024.0 ** 3))
        try:
            with zipfile.ZipFile(archive) as z:
                z.extractall(work)
        except Exception as e:
            shutil.rmtree(work, ignore_errors=True)
            return 'failed', 'не вдалося розпакувати: %s' % repr(e)[:120], 0
        dump, dump_size = find_dump(work)
        pagefiles = _find_pagefiles(work)
        if pagefiles:
            log('знайдено pagefile: %s' % ', '.join(os.path.basename(p) for p in pagefiles))
    else:
        dump, dump_size = archive, size          # a raw dump was uploaded directly
        pagefiles = []

    if not dump:
        shutil.rmtree(work, ignore_errors=True)
        return 'failed', 'усередині немає файлу, схожого на дамп памʼяті', 0

    out = os.path.join(RESULTS, '%s_job%d' % (case_key[:40], job_id))
    log('аналізую %s (%.1f ГБ)' % (os.path.basename(dump), dump_size / 1024.0 ** 3))
    keep = ['--keep'] if dump == archive else []      # never delete what the user uploaded
    prog.set(12, u'Запуск MemProcFS', u'монтую образ памʼяті у forensic-режимі')
    engine = 'memprocfs'
    ok = False
    try:
        import sys as _s
        _s.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import ram_memprocfs as _mp
        if _mp.available():
            summ = _mp.analyse(dump, out, pagefiles=pagefiles, progress=prog.set)
            ok = bool(summ.get('ok'))
            if not ok:
                log('MemProcFS не впорався (%s) — переходжу на Volatility'
                    % str(summ.get('error'))[:80])
    except Exception as _me:
        log('MemProcFS помилка: %s — переходжу на Volatility' % repr(_me)[:100])

    if not ok:
        engine = 'volatility'
        prog.set(20, u'Резервний рушій Volatility', u'MemProcFS не впорався — запускаю Volatility3 (це довше)')
        try:
            subprocess.run([sys.executable, ANALYSER, dump, '--out', out] + keep,
                           timeout=6 * 3600)
        except subprocess.TimeoutExpired:
            shutil.rmtree(work, ignore_errors=True)
            return 'failed', 'аналіз не вклався у 6 годин', 0

    rows, lines = 0, []
    lines.append('движок: %s' % engine)
    try:
        s = json.load(io.open(os.path.join(out, 'summary.json'), encoding='utf-8'))
        if engine == 'memprocfs':
            fnd = s.get('findings') or []
            rows = len(fnd)
            lines.append('• forensic-скан завершено, знахідок findevil: %d' % rows)
        else:
            rows = int(s.get('total_rows') or 0)
            for name, info in sorted(s.get('plugins', {}).items()):
                if info.get('error'):
                    lines.append('• %s — %s' % (name, info['error'][:70]))
                else:
                    lines.append('• %s — %d' % (name, info.get('rows', 0)))
    except Exception as e:
        lines.append('не вдалося прочитати підсумок: %s' % repr(e)[:80])

    # Findings into the case, like any other artefact. A memory analysis that only
    # reaches a chat message is invisible to every later question.
    found = []
    try:
        found = json.load(io.open(os.path.join(out, 'findings.json'), encoding='utf-8'))
    except Exception:
        found = []
    if not found:
        try:
            _s2 = json.load(io.open(os.path.join(out, 'summary.json'), encoding='utf-8'))
            found = _s2.get('findings') or []
        except Exception:
            found = []

    # Ported MemProcFS-Analyzer detections (masquerade / bad-parent / entropy / ClamAV /
    # network-vs-IOC). Only meaningful for a real forensic tree, so guard on the engine.
    if engine == 'memprocfs' and ok:
        prog.set(74, u'Детекції загроз', u'маскування процесів, мережа проти IOC, ентропія, ClamAV')
        try:
            import sys as _s4
            _s4.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import ram_enrich as _en
            _iocs = []
            try:
                with conn.cursor() as _ic:
                    _ic.execute("SELECT ioc_value FROM public.case_iocs WHERE case_key=%s "
                                "AND ioc_type ILIKE %s LIMIT 200", (case_key, '%ip%'))
                    _iocs = [str(r[0]) for r in _ic.fetchall() or [] if r[0]]
            except Exception:
                _iocs = []
            _tk = _Ticker(prog, 74, u'Детекції загроз')
            try:
                _extra = _en.enrich(out, case_iocs=_iocs)
            finally:
                _tk.stop()
            if _extra:
                found = (found or []) + _extra
                # keep summary.json and findings.json in sync so the report sees them too
                try:
                    _sp = os.path.join(out, 'summary.json')
                    _sj = json.load(io.open(_sp, encoding='utf-8'))
                    _sj['findings'] = found
                    _sj['enriched'] = len(_extra)
                    io.open(_sp, 'w', encoding='utf-8').write(
                        json.dumps(_sj, ensure_ascii=False, indent=1))
                    io.open(os.path.join(out, 'findings.json'), 'w', encoding='utf-8').write(
                        json.dumps(found, ensure_ascii=False, indent=1))
                except Exception:
                    pass
                log('додано детекцій (masquerade/network/entropy/clamav): %d' % len(_extra))
        except Exception as _ee:
            log('enrich не спрацював: %s' % repr(_ee)[:120])

        # Key / secret recovery is SLOW (aeskeyfind scans the whole image; Volatility cred
        # plugins are minutes each), so it is OFF by default. The user runs it on demand via
        # the "🔑 Шукати ключі" button (a separate keys job). DFIR_RAM_INLINE_KEYS=1 restores
        # the old inline behaviour.
        if str(os.environ.get('DFIR_RAM_INLINE_KEYS', '0')).lower() in ('1', 'true', 'yes', 'on'):
            prog.set(80, u'Витяг ключів і секретів', u'AES / BitLocker / VeraCrypt, NTLM / LSA / DPAPI')
            try:
                import ram_keys as _rk
                _tk2 = _Ticker(prog, 80, u'Витяг ключів і секретів')
                try:
                    _kf = _rk.extract(dump, out)
                finally:
                    _tk2.stop()
                if _kf:
                    found = (found or []) + _kf
                    try:
                        _sp = os.path.join(out, 'summary.json')
                        _sj = json.load(io.open(_sp, encoding='utf-8'))
                        _sj['findings'] = found
                        io.open(_sp, 'w', encoding='utf-8').write(
                            json.dumps(_sj, ensure_ascii=False, indent=1))
                        io.open(os.path.join(out, 'findings.json'), 'w', encoding='utf-8').write(
                            json.dumps(found, ensure_ascii=False, indent=1))
                    except Exception:
                        pass
                    log('знайдено ключів/секретів: %d' % len(_kf))
            except Exception as _ke:
                log('витяг ключів не спрацював: %s' % repr(_ke)[:120])
    if found:
        try:
            with conn.cursor() as _c:
                # memory-only cases have no cases row (that is created by log ingest), so
                # ensure the FK target exists before writing findings.
                _c.execute("INSERT INTO public.cases(case_key, case_name) VALUES(%s, %s) "
                           "ON CONFLICT (case_key) DO NOTHING", (case_key, case_key))
                _c.execute("DELETE FROM public.raw_fallback_v2 WHERE case_key=%s "
                           "AND parser_family='memory_analysis'", (case_key,))
                for f in found:
                    _c.execute("INSERT INTO public.raw_fallback_v2 "
                               "(case_key,parser_family,source_file,payload) "
                               "VALUES(%s,'memory_analysis',%s,%s)",
                               (case_key, 'ram_job_%d' % job_id,
                                json.dumps(f, ensure_ascii=False)))
            conn.commit()
            log('у справу записано знахідок памʼяті: %d' % len(found))
        except Exception as _de:
            log('не вдалося записати знахідки в справу: %s' % repr(_de)[:120])

    _hi = [f for f in found if f.get('severity') == 'high']
    _flag = ''
    if _hi:
        _flag = ('\n\n\U0001f6a8 ' + str(len(_hi)) + ' знахідок високого рівня:\n'
                 + '\n'.join('\u2022 ' + str(f.get('why', ''))[:90] for f in _hi[:6]))

    _manifest = None
    try:
        _rr_ret = _load_retention()
        prog.set(85, u'Паспорт дампа', u'рахую SHA-256/MD5 дампа та архіву — кілька хвилин')
        _manifest = _rr_ret.build_manifest(job_id, case_key, dump_path=dump, archive_path=archive,
                                           pagefiles=pagefiles, engine=engine,
                                           progress=lambda pct, lab: prog.set(85, u'Паспорт дампа', lab))
        _rr_ret.write_manifest(_manifest, out, os.path.join(ROOT, 'cases', case_key, 'reports'))
        log('паспорт дампа записано (job %d)' % job_id)
    except Exception as _mfe:
        log('паспорт дампа не вдалося скласти: %s' % repr(_mfe)[:120])
    shutil.rmtree(work, ignore_errors=True)
    detail = '\n'.join(lines)[:900] + _flag

    # Package + report, but only when a forensic scan actually produced a tree.
    links = []
    if engine == 'memprocfs' and ok:
        prog.set(90, u'Пакування архіву', u'збираю forensic + report + keys у ZIP для завантаження')
        try:
            rep_dir = os.path.join(ROOT, 'cases', case_key, 'reports')
            os.makedirs(rep_dir, exist_ok=True)
            zpath = os.path.join(rep_dir, 'memprocfs_job%d.zip' % job_id)
            with zipfile.ZipFile(zpath, 'w', zipfile.ZIP_DEFLATED) as z:
                for sub in ('forensic', 'report', 'keys'):
                    d = os.path.join(out, sub)
                    for r2, _dd, ff in os.walk(d):
                        for f in ff:
                            fp = os.path.join(r2, f)
                            z.write(fp, os.path.join(sub, os.path.relpath(fp, d)))
            links.append(os.environ.get('DFIR_VIEW_BASE', 'http://CHANGE_ME_DFIR_LINK_IP:8080/view')
                         + '/%s/reports/memprocfs_job%d.zip' % (case_key, job_id))
            log('forensic-архів: %s' % zpath)
            try:
                tell(u'📁 Архів forensic готовий — можеш качати вже зараз, поки ШІ пише '
                     u'висновок:\n%s' % links[-1])
            except Exception:
                pass
        except Exception as _ze:
            log('пакування forensic не вдалося: %s' % repr(_ze)[:120])

        try:
            import sys as _s3
            _s3.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import ram_report as _rr
            prog.set(95, u'Формування ШІ-звіту', u'модель складає висновок по памʼяті та звʼязує з кейсом')
            try:
                import ram_report as _rr0
                _ctx = {'case_key': case_key,
                        'evidence': _rr0.forensic_evidence(out),
                        'case': _rr0.case_context(conn, case_key) if conn else {}}
                io.open(os.path.join(out, 'memory_context.json'), 'w',
                        encoding='utf-8').write(json.dumps(_ctx, ensure_ascii=False, indent=1))
            except Exception as _cxe:
                log('memory_context не зібрано: %s' % repr(_cxe)[:100])
            md = _rr.build(conn, case_key, out)
            # a report/ folder inside the forensic output, so the archive the
            # user downloads has the processed artefacts in one obvious place
            _rep = os.path.join(out, 'report')
            os.makedirs(_rep, exist_ok=True)
            try:
                shutil.copy2(os.path.join(out, 'memory_context.json'),
                             os.path.join(_rep, 'memory_context.json'))
            except Exception:
                pass
            io.open(os.path.join(_rep, 'memory_report.md'), 'w', encoding='utf-8',
                    newline='\n').write(md)
            try:
                shutil.copy2(os.path.join(out, 'findings.json'),
                             os.path.join(_rep, 'findings.json'))
            except Exception:
                pass
            try:
                shutil.copy2(os.path.join(out, 'summary.json'),
                             os.path.join(_rep, 'summary.json'))
            except Exception:
                pass
            mpath = os.path.join(ROOT, 'cases', case_key, 'reports',
                                 'memory_report_job%d.md' % job_id)
            io.open(mpath, 'w', encoding='utf-8', newline='\n').write(md)
            links.append(os.environ.get('DFIR_VIEW_BASE', 'http://CHANGE_ME_DFIR_LINK_IP:8080/view')
                         + '/%s/reports/memory_report_job%d.md' % (case_key, job_id))
            log('звіт памʼяті: %s (%d символів)' % (mpath, len(md)))
            try:
                _tg_document(mpath, u'🧠 Звіт памʼяті (ШІ-висновок) — %s' % case_key)
            except Exception:
                pass
        except Exception as _re:
            log('звіт памʼяті не вдалося зібрати: %s' % repr(_re)[:120])

    if links:
        detail = detail + '\n\n\U0001f4c1 Завантажити:\n' + '\n'.join(links)
    prog.set(100, u'Готово \u2705', u'звіт і архів сформовано')
    _pass = ''
    _until = ''
    try:
        if _manifest:
            _pass = _rr_ret.manifest_text(_manifest)
            _until = _manifest.get('delete_after') or ''
    except Exception:
        _pass = ''
    _policy = (u'\n\n🗂 Що зберігаємо у справі: CSV/JSON-результати MemProcFS, звіт, ключі та паспорт дампа (хеші вище).\n'
               u'🗑 Що буде видалено з сервера %s (через 7 днів) або раніше кнопкою «Видалити дамп памʼяті» в інфо кейсу: '
               u'завантажений архів (%.1f ГБ) та важкі витяги (образи реєстру, витягнуті бінарні файли, повний ZIP).\n'
               u'💾 Збережи копію дампа в себе на ПК — на сервері після цього лишаться лише паспорт і результати.'
               % ((u'до ' + _until) if _until else u'автоматично', size / 1024.0 ** 3))
    _done_text = (u'🧠 Памʼять опрацьовано — завдання #%d\nСправа: %s\n\n%s\n\n'
                  u'Усього рядків: %d' % (job_id, case_key, detail, rows)
                  + ((u'\n\n' + _pass) if _pass else u'') + _policy)
    _kb = json.dumps({'inline_keyboard': [
        [{'text': u'ℹ️ Інфо по кейсу (там кнопка видалення)', 'callback_data': 'show_stats'}],
        [{'text': u'⬅️ Меню кейсу', 'callback_data': 'case_menu'}]]})
    _tg('sendMessage', {'chat_id': OWNER, 'text': _done_text[:4000], 'reply_markup': _kb})
    return ('done' if rows else 'failed',
            detail[:400] if not rows else 'ok', rows)


def _extract_dump_only(archive, work, prog):
    """Unpack just the memory image out of the archive - not the whole capture.

    A keys run needs the image and nothing else, and these archives are tens of gigabytes;
    pulling only the member that IS the dump turns a ten-minute unpack into a short one.
    Falls back to the biggest member when no name looks like memory, exactly as find_dump
    does on disk.
    """
    if not archive.lower().endswith('.zip'):
        return archive, os.path.getsize(archive), False       # a raw dump was uploaded
    with zipfile.ZipFile(archive) as z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        if not infos:
            return '', 0, False
        named = [i for i in infos
                 if i.filename.lower().endswith(MEM_EXT)
                 or os.path.basename(i.filename).lower() in
                 ('pagefile.sys', 'hiberfil.sys', 'swapfile.sys')]
        pick = max(named or infos, key=lambda i: i.file_size)
        # the archive is compressed - what matters is the room the IMAGE needs
        if free_bytes(ROOT) - pick.file_size < MIN_FREE:
            raise IOError(u'розпакований дамп займе %.1f ГБ — на диску замало місця'
                          % (pick.file_size / 1024.0 ** 3))
        prog.set(10, u'Розпакування дампа',
                 u'дістаю %s (%.1f ГБ)' % (os.path.basename(pick.filename),
                                           pick.file_size / 1024.0 ** 3))
        z.extract(pick, work)
        return os.path.join(work, pick.filename), pick.file_size, True


def _previous_forensic_out(case_key):
    """The out/ folder an earlier full run left, if it is still there.

    secretsdump works on the registry hives MemProcFS recovered into that tree, so reusing
    it is the difference between finding hashes and finding none. Newest first.
    """
    pref = '%s_job' % case_key[:40]
    try:
        cands = [os.path.join(RESULTS, d) for d in os.listdir(RESULTS) if d.startswith(pref)]
    except OSError:
        return ''
    cands = [d for d in cands if os.path.isdir(os.path.join(d, 'forensic'))]
    cands.sort(key=lambda d: os.path.getmtime(d), reverse=True)
    return cands[0] if cands else ''


def handle_keys(conn, job_id, case_key, chat_id, archive):
    """Key/secret recovery on demand - the "🔑 Шукати ключі" button.

    The full analysis deliberately skips this: aeskeyfind reads the entire image and each
    Volatility credential plugin costs minutes, which is not worth paying on every upload.
    When the investigator actually wants keys, only this runs. The dump itself is gone by
    then (the full run deletes it), so the archive is opened again - but just for the one
    member that is the image, and the earlier forensic tree is reused for the hives.
    """
    archive = host_path(archive)
    if not os.path.exists(archive):
        return 'failed', u'архів не знайдено на диску: %s' % archive[:120], 0

    size = os.path.getsize(archive)
    if free_bytes(ROOT) - size < MIN_FREE:
        return ('failed', u'замало місця: для розпакування дампа треба ще ~%.0f ГБ'
                % (size / 1024.0 ** 3), 0)

    work = os.path.join(WORK, 'keys_%d' % job_id)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work, exist_ok=True)

    prog = Progress(case_key)
    prog.set(5, KEYS_STAGE, u'готую дамп памʼяті')
    try:
        dump, dump_size, _unpacked = _extract_dump_only(archive, work, prog)
    except Exception as e:
        shutil.rmtree(work, ignore_errors=True)
        return 'failed', u'не вдалося розпакувати: %s' % repr(e)[:120], 0
    if not dump or not os.path.exists(dump):
        shutil.rmtree(work, ignore_errors=True)
        return 'failed', u'усередині немає файлу, схожого на дамп памʼяті', 0

    out = _previous_forensic_out(case_key) or os.path.join(
        RESULTS, '%s_keys%d' % (case_key[:40], job_id))
    os.makedirs(out, exist_ok=True)
    log(u'ключі: дамп %s (%.1f ГБ), out=%s'
        % (os.path.basename(dump), dump_size / 1024.0 ** 3, out))

    prog.set(30, KEYS_STAGE, u'AES / BitLocker / VeraCrypt, NTLM / LSA / DPAPI — це довго')
    tick = _Ticker(prog, 30, KEYS_STAGE)
    # the size guard that keeps aeskeyfind out of every routine analysis has no business
    # here: this job exists because somebody asked for the slow scan
    os.environ['DFIR_FORCE_AESKEYFIND'] = '1'
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import ram_keys as _rk
        found = _rk.extract(dump, out) or []
    except Exception as e:
        tick.stop()
        shutil.rmtree(work, ignore_errors=True)
        return 'failed', u'витяг ключів впав: %s' % repr(e)[:160], 0
    finally:
        tick.stop()

    # into the case, replacing only what an earlier KEYS run wrote - the findings from the
    # full memory analysis share parser_family and must survive this
    if found:
        try:
            with conn.cursor() as _c:
                _c.execute("INSERT INTO public.cases(case_key, case_name) VALUES(%s,%s) "
                           "ON CONFLICT (case_key) DO NOTHING", (case_key, case_key))
                _c.execute("DELETE FROM public.raw_fallback_v2 WHERE case_key=%s "
                           "AND parser_family='memory_analysis' "
                           "AND source_file LIKE 'ram_keys_job_%%'", (case_key,))
                for f in found:
                    _c.execute("INSERT INTO public.raw_fallback_v2 "
                               "(case_key,parser_family,source_file,payload) "
                               "VALUES(%s,'memory_analysis',%s,%s)",
                               (case_key, 'ram_keys_job_%d' % job_id,
                                json.dumps(f, ensure_ascii=False)))
            conn.commit()
            log(u'у справу записано ключів/секретів: %d' % len(found))
        except Exception as e:
            log(u'не вдалося записати ключі в справу: %s' % repr(e)[:120])

    prog.set(90, u'Пакування', u'збираю keys/ у ZIP для завантаження')
    link = ''
    try:
        rep_dir = os.path.join(ROOT, 'cases', case_key, 'reports')
        os.makedirs(rep_dir, exist_ok=True)
        zpath = os.path.join(rep_dir, 'memory_keys_job%d.zip' % job_id)
        keys_dir = os.path.join(out, 'keys')
        with zipfile.ZipFile(zpath, 'w', zipfile.ZIP_DEFLATED) as z:
            for r2, _dd, ff in os.walk(keys_dir):
                for f in ff:
                    fp = os.path.join(r2, f)
                    z.write(fp, os.path.join('keys', os.path.relpath(fp, keys_dir)))
        link = (os.environ.get('DFIR_VIEW_BASE', 'http://CHANGE_ME_DFIR_LINK_IP:8080/view')
                + '/%s/reports/memory_keys_job%d.zip' % (case_key, job_id))
    except Exception as e:
        log(u'пакування ключів не вдалося: %s' % repr(e)[:120])

    shutil.rmtree(work, ignore_errors=True)          # the re-extracted dump goes away again

    kinds = {}
    for f in found:
        kinds[f.get('kind', '?')] = kinds.get(f.get('kind', '?'), 0) + 1
    head = (u'\U0001f511 Ключі та секрети, справа %s (завдання #%d)' % (case_key, job_id))
    if found:
        msg = head + u'\n\n' + u'\n'.join(u'• %s: %d' % (k, v)
                                           for k, v in sorted(kinds.items()))
    else:
        msg = (head + u'\n\nНічого не знайдено. Це НЕ означає, що диск не розшифрувати: '
               u'ключ живе в памʼяті лише якщо був резидентним у мить зняття дампа.')
    if link:
        msg += u'\n\n\U0001f4c1 %s' % link
    tell(msg)
    prog.set(100, u'Готово', u'знайдено %d ключів/секретів' % len(found))
    return 'done', u'ключів/секретів: %d' % len(found), len(found)


def main():
    # One worker at a time. If we get the lock, no other worker is alive, so any row still
    # marked 'running' is an orphan left by a killed/crashed worker — reclaim it below.
    _lock_fh = open(RAM_WORKER_LOCK, 'w')
    try:
        fcntl.flock(_lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (IOError, OSError):
        return 0                                      # another worker is busy — leave it be
    try:
        _rr_ret = _load_retention()
        for _a in _rr_ret.retention_pass(RESULTS, os.path.join(ROOT, 'cases')):
            _gb = _a.get('freed_bytes', 0) / 1024.0 ** 3
            log('retention: %s job %s -> звільнено %.1f ГБ (%s)'
                % (_a.get('case_key'), _a.get('job_id'), _gb, 'кнопка' if _a.get('requested') else 'термін 7 днів'))
            tell(u'🗑 Памʼять, справа %s (завдання #%s): %s — видалено завантажений архів і важкі витяги, '
                 u'звільнено %.1f ГБ. У справі лишились CSV/JSON, звіт, ключі та паспорт дампа%s.%s'
                 % (_a.get('case_key'), _a.get('job_id'),
                    u'за кнопкою' if _a.get('requested') else u'минуло 7 днів',
                    _gb, (u' (memprocfs_job%s_light.zip)' % _a.get('job_id')) if _a.get('light_zip') else u'',
                    (u'\n\n' + _a['manifest']) if _a.get('manifest') else u''))
    except Exception as _rte:
        log('retention pass failed: %s' % repr(_rte)[:160])
    d = dsn()
    if not d:
        log('NO DATABASE: PG_DSN not found - cannot pick up jobs')
        return 1
    import psycopg2
    conn = psycopg2.connect(d)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("SELECT to_regclass('public.ram_jobs_v1')")
        if not (cur.fetchone() or [None])[0]:
            return 0                                  # nothing has ever been queued
        # crash recovery: a 'running' row with no live worker (we hold the only lock) is dead
        cur.execute("UPDATE public.ram_jobs_v1 SET status='pending' WHERE status='running'")
        if cur.rowcount:
            log('відновлено %d осиротілих завдань (воркер помер посеред роботи) -> pending' % cur.rowcount)
        # keys-only jobs arrive on the same queue, told apart by kind
        cur.execute("ALTER TABLE public.ram_jobs_v1 "
                    "ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'full'")
        cur.execute("SELECT id, case_key, COALESCE(chat_id,''), archive_path, "
                    "COALESCE(kind,'full') "
                    "FROM public.ram_jobs_v1 WHERE status='pending' ORDER BY id LIMIT 1")
        row = cur.fetchone()
    if not row:
        return 0

    job_id, case_key, chat_id, archive, kind = row
    with conn.cursor() as cur:
        cur.execute("UPDATE public.ram_jobs_v1 SET status='running' WHERE id=%s", (job_id,))
    log('завдання #%d (%s), справа %s' % (job_id, kind, case_key))
    try:
        runner = handle_keys if kind == 'keys' else handle
        status, result, rows = runner(conn, job_id, case_key, chat_id, archive)
    except Exception as e:
        status, result, rows = 'failed', repr(e)[:200], 0
        log('завдання #%d впало: %s' % (job_id, result))
    with conn.cursor() as cur:
        cur.execute("UPDATE public.ram_jobs_v1 SET status=%s, result=%s, rows_found=%s, "
                    "handled_at=now() WHERE id=%s", (status, result[:500], rows, job_id))
    log('завдання #%d -> %s (%d рядків)' % (job_id, status, rows))
    if status == 'failed':
        tell(u'⚠️ Памʼять, завдання #%d (%s): %s' % (job_id, case_key, result[:300]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
