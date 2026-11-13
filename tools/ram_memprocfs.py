#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Analyse a memory dump with MemProcFS forensic mode - the strong engine, on Linux.

Why this replaces the Volatility path as the primary engine:
  * MemProcFS reads exactly what the collector produces. The earlier note that "MemProcFS
    does not read our format" was about AFF4 (WinPmem); DumpIt writes a Microsoft crash
    dump / raw image, which MemProcFS reads directly (confirmed: v5.18.5 on this VM).
  * its forensic mode does in one pass what a dozen Volatility plugins do separately, and
    adds what they do not: FINDEVIL - hidden processes, injected PE, patched modules,
    suspicious threads - plus a full timeline, a handle/module/registry dump, and an
    optional YARA scan of memory against our own rules.
  * the output is a clean tree of CSV/JSON under <mount>/forensic, which is what the owner
    wanted: structured folders, not a wall of text.

It runs headless: mount over FUSE, wait for the forensic scan to finish, copy the tree
out, unmount. No interaction, no GUI. Volatility remains the fallback for the case where
MemProcFS cannot open a particular image.

The dump is deleted only after the scan produced output - deleting evidence because our
tooling failed is the worst outcome, the same rule the Volatility path follows.
"""
import io
import json
import os
import shutil
import signal
import subprocess
import time

MPFS_DIR = os.environ.get('DFIR_MEMPROCFS_DIR', '/home/dfir-bot/memprocfs')
MPFS_BIN = os.path.join(MPFS_DIR, 'memprocfs')
YARA_RULES = os.environ.get('DFIR_MEMPROCFS_YARA',
                            '/srv/dfir/services/tools_sidecar/dfir_rules.yar')
SCAN_TIMEOUT = int(os.environ.get('DFIR_MEMPROCFS_TIMEOUT', str(4 * 3600)))


def log(msg):
    print('%s [memprocfs] %s' % (time.strftime('%H:%M:%S'), msg), flush=True)


def available():
    return os.path.exists(MPFS_BIN)


def _unmount(mount):
    for cmd in (['fusermount3', '-u', mount], ['fusermount', '-u', mount]):
        try:
            if subprocess.run(cmd, capture_output=True, timeout=30).returncode == 0:
                return
        except Exception:
            continue


def analyse(dump, out_dir, pagefiles=None, progress=None):
    """Run forensic mode, harvest the tree, return a summary dict. Never raises."""
    os.makedirs(out_dir, exist_ok=True)
    mount = '/tmp/mpfs_%d' % int(time.time())
    os.makedirs(mount, exist_ok=True)

    cmd = ['./memprocfs', '-f', dump, '-forensic', '1', '-mount', mount, '-waitinitialize']
    # MemProcFS ships Elastic Security's malware YARA rules for FindEvil but keeps them OFF
    # until the licence is accepted. Without this flag it logs "FindEvil results may be
    # degraded"; with it, findevil uses the full professional ruleset - the same rules
    # MemProcFS-Analyzer relies on. Free quality, one flag.
    cmd += ['-license-accept-elastic-license-2.0']
    # Pagefiles let MemProcFS reconstruct paged-out memory - the thing Volatility cannot do
    # and the reason a dump+pagefile archive is worth more than a dump alone.
    for i, pf in enumerate(pagefiles or []):
        if pf and os.path.exists(pf) and i <= 9:
            cmd += ['-pagefile%d' % i, pf]
    if os.path.exists(YARA_RULES):
        cmd += ['-forensic-yara-rules', YARA_RULES]
    env = dict(os.environ, LD_LIBRARY_PATH=MPFS_DIR)
    log('запускаю forensic: %s (%.1f ГБ)' % (os.path.basename(dump),
                                            os.path.getsize(dump) / 1024.0 ** 3))

    logf = io.open(os.path.join(out_dir, 'memprocfs.log'), 'wb')
    proc = subprocess.Popen(cmd, cwd=MPFS_DIR, env=env, stdout=logf,
                            stderr=subprocess.STDOUT)

    summary = {'engine': 'memprocfs', 'dump': os.path.basename(dump),
               'size_gb': round(os.path.getsize(dump) / 1024.0 ** 3, 2),
               'started': time.strftime('%Y-%m-%d %H:%M:%S')}
    forensic = os.path.join(mount, 'forensic')
    done = False
    exited = False
    t0 = time.time()
    try:
        # MemProcFS prints "FORENSIC MODE: COMPLETED" and fills forensic/csv when finished.
        while time.time() - t0 < SCAN_TIMEOUT:
            if proc.poll() is not None:            # it exited (usually an unreadable image)
                exited = True
                break
            blob = b''
            try:
                blob = io.open(os.path.join(out_dir, 'memprocfs.log'), 'rb').read()
                if b'forensic mode completed' in blob.lower():   # matches MemProcFS '[FORENSIC] Forensic mode completed in Ns.'
                    done = True
                    if progress:
                        try:
                            progress(70, u'MemProcFS forensic — завершено', '')
                        except Exception:
                            pass
                    break
            except IOError:
                pass
            if progress:
                try:
                    import re as _re
                    pct = None
                    for m in _re.finditer(rb'(\d{1,3})\s?%', blob[-400:]):
                        pct = int(m.group(1))
                    el = int(time.time() - t0)
                    # map MemProcFS 0..100 onto our 15..68 band for this stage
                    band = 15 + int((pct or 0) * 0.53) if pct is not None else 15
                    progress(min(68, band),
                             u'MemProcFS forensic — аналіз образу',
                             u'працює %d хв%s' % (el // 60, (' · %d%%' % pct) if pct is not None else ''))
                except Exception:
                    pass
            time.sleep(15)
    finally:
        pass

    if done and os.path.isdir(forensic):
        # settle, then copy the WHOLE forensic tree out - the owner wants everything
        # MemProcFS produced, not a chosen subset.
        time.sleep(5)
        try:
            shutil.copytree(forensic, os.path.join(out_dir, 'forensic'), dirs_exist_ok=True)
        except Exception as e:
            log('копія forensic не вдалася: %s' % repr(e)[:100])
        # Registry hives, while the mount is still up: MemProcFS exposes SAM/SECURITY/
        # SYSTEM under registry/hive_files. secretsdump reads exactly these to recover
        # hashes, LSA secrets, cached creds and DPAPI keys - the professional path, and
        # what MemProcFS-Analyzer does with EZTools on Windows.
        try:
            hdst = os.path.join(out_dir, 'hives')
            os.makedirs(hdst, exist_ok=True)
            copied = 0
            for hroot in (os.path.join(mount, 'registry', 'hive_files'),
                          os.path.join(mount, 'registry', 'hive_memory')):
                if not os.path.isdir(hroot):
                    continue
                for hv in os.listdir(hroot):
                    up = hv.upper()
                    if any(t in up for t in ('SAM', 'SECURITY', 'SYSTEM', 'SOFTWARE', 'NTUSER')):
                        try:
                            shutil.copy2(os.path.join(hroot, hv), os.path.join(hdst, hv))
                            copied += 1
                        except Exception:
                            pass
            log('скопійовано реєстрових вуликів: %d' % copied)
        except Exception as e:
            log('копія вуликів не вдалася: %s' % repr(e)[:100])
        # BitLocker: MemProcFS's OWN plugin (m_misc_bitlocker) recovers the FVEK from
        # memory and writes it as misc/bitlocker/<addr>.fvek - NOT via a generic AES scan.
        # This is the reliable path; the .fvek then unlocks the disk with `dislocker`.
        try:
            bsrc = os.path.join(mount, 'misc', 'bitlocker')
            if os.path.isdir(bsrc):
                bdst = os.path.join(out_dir, 'keys', 'bitlocker')
                os.makedirs(bdst, exist_ok=True)
                nfvek = 0
                for f in os.listdir(bsrc):
                    if f.lower().endswith('.fvek'):
                        try:
                            shutil.copy2(os.path.join(bsrc, f), os.path.join(bdst, f))
                            nfvek += 1
                        except Exception:
                            pass
                if nfvek:
                    log('BitLocker FVEK відновлено: %d файл(ів)' % nfvek)
                    summary.setdefault('findings', [])
                    summary['findings'].append({
                        'severity': 'high', 'kind': 'bitlocker_fvek',
                        'name': 'BitLocker FVEK', 'detail': '%d .fvek у keys/bitlocker/' % nfvek,
                        'why': u'MemProcFS відновив ключ шифрування тому BitLocker (FVEK) з '
                               u'памʼяті — диск можна розшифрувати: '
                               u'dislocker -k keys/bitlocker/<файл>.fvek /dev/<диск> /mnt/out'})
        except Exception as e:
            log('BitLocker-крок не вдався: %s' % repr(e)[:100])
        summary['findings'] = summary.get('findings', []) + _findevil(out_dir)
        summary['completed'] = time.strftime('%Y-%m-%d %H:%M:%S')
        summary['ok'] = True
    else:
        tail = ''
        try:
            tail = io.open(os.path.join(out_dir, 'memprocfs.log'), 'rb').read()[-400:]\
                .decode('utf-8', 'replace')
        except IOError:
            pass
        summary['ok'] = False
        if exited:
            reason = 'MemProcFS не зміг відкрити образ (див. лог)'
        elif not done:
            reason = 'forensic не завершився за %d с' % SCAN_TIMEOUT
        else:
            reason = 'forensic завершився, але тека forensic порожня'
        summary['error'] = reason + (' | ' + tail[-200:] if tail else '')
        log('НЕ вдалось: %s' % summary['error'][:160])

    # tear down: kill the mounted process, unmount, remove the empty mount dir
    try:
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=30)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    _unmount(mount)
    try:
        os.rmdir(mount)
    except OSError:
        pass

    io.open(os.path.join(out_dir, 'summary.json'), 'w', encoding='utf-8').write(
        json.dumps(summary, ensure_ascii=False, indent=1))
    return summary


# MemProcFS findevil labels -> what a person should read, and how bad it is.
_EVIL = {
    'YR_VULNDRIVER': ('high', 'vuln_driver', u'вразливий драйвер (BYOVD) — YARA-збіг MemProcFS'),
    'PE_INJECT':     ('high', 'injected_pe', u'у процес впроваджено PE-модуль (process injection)'),
    'PROC_NOLINK':   ('high', 'hidden_process', u'прихований процес (unlinked зі списку)'),
    'THREAD':        ('high', 'suspicious_thread', u'потік із підозрілою точкою входу (можливий shellcode)'),
    'AV_DISABLED':   ('high', 'av_off', u'ознаки вимкненого антивірусу'),
    'PE_PATCHED':    ('medium', 'pe_patched', u'пропатчений PE-образ у памʼяті (можливий хук/інлайн-інʼєкція)'),
    'PROC_NOIMAGE':  ('medium', 'no_image', u'процес без образу на диску'),
    'PROC_BASE':     ('medium', 'no_image', u'процес без образу на диску'),
    'PROC_PARENT':   ('medium', 'bad_parent', u'нетиповий батьківський процес'),
    'DRIVER_PATH':   ('medium', 'driver_path', u'драйвер із нетипового шляху'),
    'PRIVATE_RWX':   ('low', 'private_rwx', u'RWX-память (часто .NET/JIT; масово в дивному процесі — можливий шелкод)'),
    'PRIVATE_RX':    ('low', 'private_rx', u'RX-память процесу'),
    'PROC_DEBUG':    ('low', 'proc_debug', u'процес із прапорцем налагодження'),
    'PROC_USER':     ('low', 'user_context', u'нетиповий контекст користувача'),
}

# Drivers loaded by memory-acquisition tools themselves — our own artefact, not an attack.
_CAPTURE_DRV = ('mnemosyne', 'winpmem', 'dumpit', 'pcileech', 'ram_capture', 'magnet', 'ftk')


def _findevil(out_dir):
    """Parse findevil.csv by column and aggregate per (type, process). Every finding cites
    findevil.csv with the PID and address so the report can reference it. Never raises."""
    import csv as _csv
    path = ''
    for base in (os.path.join(out_dir, 'forensic', 'csv'), os.path.join(out_dir, 'csv'),
                 os.path.join(out_dir, 'forensic'), out_dir):
        p = os.path.join(base, 'findevil.csv')
        if os.path.exists(p):
            path = p
            break
    if not path:
        return []
    groups = {}
    try:
        with io.open(path, encoding='utf-8', errors='replace') as fh:
            for row in _csv.DictReader(fh):
                typ = (row.get('Type') or '').strip().upper()
                if not typ:
                    continue
                proc = (row.get('ProcessName') or '').strip() or '-'
                pid = (row.get('PID') or '').strip()
                addr = (row.get('Address') or '').strip()
                desc = (row.get('Description') or '').strip()
                if typ == 'DRIVER_PATH' and any(c in desc.lower() for c in _CAPTURE_DRV):
                    continue                                   # acquisition driver — skip
                g = groups.setdefault((typ, proc),
                                      {'count': 0, 'pids': set(), 'addr': addr, 'desc': desc})
                g['count'] += 1
                if pid:
                    g['pids'].add(pid)
                if not g['desc'] and desc:
                    g['desc'] = desc
    except Exception:
        return []
    findings = []
    for (typ, proc), g in groups.items():
        meta = _EVIL.get(typ) or ('low', 'findevil_' + typ.lower(), u'MemProcFS FindEvil: ' + typ)
        sev, kind, why = meta
        pids = ','.join(sorted(g['pids'])[:6]) or '-'
        ev = u'findevil.csv · %s · %s · PID %s · %s' % (typ, proc, pids, (g['addr'] or '')[:18])
        detail = u'%s у процесі %s (PID %s), збігів: %d; %s' % (
            typ, proc, pids, g['count'], (g['desc'] or '')[:120])
        findings.append({'severity': sev, 'kind': kind, 'source': 'findevil.csv',
                         'evidence': ev, 'detail': detail, 'why': why, 'count': g['count']})
    _rank = {'high': 0, 'medium': 1, 'low': 2}
    findings.sort(key=lambda f: (_rank.get(f['severity'], 3), -f['count']))
    log('findevil знахідок (згруповано по процесах): %d' % len(findings))
    return findings


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('usage: ram_memprocfs.py <dump> [out_dir]')
        raise SystemExit(2)
    d = sys.argv[1]
    o = sys.argv[2] if len(sys.argv) > 2 else '/tmp/mpfs_out'
    s = analyse(d, o)
    print(json.dumps(s, ensure_ascii=False, indent=1))
    raise SystemExit(0 if s.get('ok') else 1)
