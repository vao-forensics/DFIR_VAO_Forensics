#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Publish the collector to the bot, with its version attached.

Two problems this closes.

The copy was manual. I put the EXE on the VM by hand once; rebuild it and the VM keeps
serving yesterday's binary with nothing to show that it has. The hashes happened to match
today, which is luck, not a process.

And the download said nothing about itself. The bot handed out a link and no version, so
"is this the latest?" could only be answered by comparing 643 MB of bytes.

This copies the EXE and writes collector.json beside it - version, build date, size,
sha256 - which /config/public-base then serves, so the bot can say what it is handing out.
Run it after every build:  python publish_collector.py
"""
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import time

# The Windows console here is cp1252; Ukrainian output would raise before printing a
# single useful line. Say so once, in UTF-8, and carry on.
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

EXE = os.environ.get('DFIR_COLLECTOR_EXE', r'C:\DFIR\DFIR_Collector_v4.exe')
UI_CS = os.environ.get('DFIR_COLLECTOR_UI', r'C:\DFIR\pybuild\v4\Ui.cs')
VM = os.environ.get('DFIR_VM_HOST', 'dfir-vm')
DEST_DIR = '/srv/dfir/var/dist'


def version_from_source():
    """The version the collector prints in its own banner, so the two cannot disagree."""
    try:
        text = io.open(UI_CS, encoding='utf-8', errors='replace').read()
    except IOError:
        return ''
    m = re.search(r'VER\s*=\s*"([^"]+)"', text)
    return m.group(1) if m else ''


def sha256(path, buf=1 << 22):
    h = hashlib.sha256()
    with io.open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(buf), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    if not os.path.exists(EXE):
        print('немає файлу: %s' % EXE)
        return 2
    size = os.path.getsize(EXE)
    built = time.strftime('%Y-%m-%d %H:%M', time.localtime(os.path.getmtime(EXE)))
    ver = version_from_source() or 'unknown'
    print('EXE:     %s' % EXE)
    print('версія:  %s' % ver)
    print('зібрано: %s' % built)
    print('розмір:  %.0f МБ' % (size / 1024.0 ** 2))
    print('рахую sha256...')
    digest = sha256(EXE)
    print('sha256:  %s' % digest)

    manifest = {'version': ver, 'built': built, 'size_bytes': size, 'sha256': digest,
                'published': time.strftime('%Y-%m-%d %H:%M')}
    local_manifest = os.path.join(os.path.dirname(EXE), 'collector.json')
    io.open(local_manifest, 'w', encoding='utf-8', newline='\n').write(
        json.dumps(manifest, ensure_ascii=False, indent=1))

    # is the VM already serving this exact build?
    remote = subprocess.run(['ssh', VM, 'sha256sum %s/collector.exe 2>/dev/null | cut -c1-64'
                             % DEST_DIR], capture_output=True)
    current = (remote.stdout or b'').decode().strip()
    if current == digest:
        print('на VM уже ця сама збірка - копіюю лише маніфест')
    else:
        print('копіюю %.0f МБ на VM...' % (size / 1024.0 ** 2))
        r = subprocess.run(['scp', '-q', EXE, '%s:%s/collector.exe.new' % (VM, DEST_DIR)])
        if r.returncode:
            print('копіювання не вдалося')
            return 1
        # swap only after the whole file has arrived: a half-copied 643 MB download is
        # worse than an old one
        subprocess.run(['ssh', VM, 'mv %s/collector.exe.new %s/collector.exe'
                        % (DEST_DIR, DEST_DIR)])

    subprocess.run(['scp', '-q', local_manifest, '%s:%s/collector.json' % (VM, DEST_DIR)])
    check = subprocess.run(['ssh', VM, 'sha256sum %s/collector.exe | cut -c1-64' % DEST_DIR],
                           capture_output=True)
    got = (check.stdout or b'').decode().strip()
    print('перевірка на VM: %s' % ('збігається' if got == digest else 'НЕ ЗБІГАЄТЬСЯ (%s)' % got[:16]))
    return 0 if got == digest else 1


if __name__ == '__main__':
    sys.exit(main())
