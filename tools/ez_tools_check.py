#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tell the owner when the Zimmerman tools in the collector have gone stale.

Case case_08 lost all 414 of its Prefetch records because the collector shipped
PECmd 1.5, which cannot read the format Windows 11 build 26200 writes; it answered
"Unknown version 0000001F" and wrote nothing, and no one knew a newer PECmd existed. The
tools had been current when they were packed. Nothing watched them afterwards.

This does the watching. It asks the download server for each tool's headers - no file is
fetched - and compares etag/last-modified/size with the baseline recorded when the
collector was last built. A change means a new build is out.

    ez_tools_check.py --set-baseline    record today's remote state as "what we ship"
    ez_tools_check.py                   compare and message the owner if anything moved
    ez_tools_check.py --dry-run         compare and print, message nobody

Owner-only by construction: CHAT is fixed, exactly as tools/dfir_disk_watch.sh does it.
"""
import json
import os
import sys
import time
import urllib.parse
import urllib.error
import urllib.request

BASE = 'https://download.ericzimmermanstools.com/'
BASELINE = '/srv/dfir/state/config/ez_tools_baseline.json'
MANIFEST = '/srv/dfir/tools/tools_manifest.json'   # copied from the host at build time
TOKEN_FILE = '/root/.dfir_bot_token'
CHAT = 'CHANGE_ME_OWNER_CHAT_ID'                                # owner only - never broadcast

# AmcacheParser left: since 2026-10 the root zip is 404 (only the .NET 9 build under /net/ is
# left), the builder takes the last .NET Framework build from the mirror (tools.json).
TOOLS = ['AppCompatCacheParser', 'bstrings', 'EvtxECmd', 'JLECmd',
         'LECmd', 'MFTECmd', 'PECmd', 'RBCmd', 'RECmd', 'RecentFileCacheParser',
         'SBECmd', 'SrumECmd', 'SumECmd', 'rla']


def remote(tool):
    """Headers only. Returns {} when the server cannot be reached - a network blip must
    never look like a new release."""
    req = urllib.request.Request(BASE + tool + '.zip', method='HEAD')
    req.add_header('User-Agent', 'dfir-collector-toolcheck/1.0')
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            h = r.headers
            return {'etag': (h.get('ETag') or '').strip('"'),
                    'last_modified': h.get('Last-Modified') or '',
                    'size': int(h.get('Content-Length') or 0)}
    except urllib.error.HTTPError as e:
        # 404/410 is not a blip: the author removed the file (AmcacheParser, 2026-10) and a
        # fresh builder would get nothing - that has to reach the owner
        if e.code in (404, 410):
            return {'gone': e.code}
        return {'error': str(e)[:120]}
    except Exception as e:
        return {'error': str(e)[:120]}


def load(path, default):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default


def notify(text):
    try:
        with open(TOKEN_FILE, encoding='utf-8') as f:
            token = f.read().strip()
    except Exception:
        print('no token file, not sending')
        return False
    data = urllib.parse.urlencode({'chat_id': CHAT, 'text': text}).encode()
    try:
        urllib.request.urlopen(
            'https://api.telegram.org/bot' + token + '/sendMessage', data=data, timeout=20).read()
        return True
    except Exception as e:
        print('send failed: ' + str(e)[:120])
        return False


def main():
    set_baseline = '--set-baseline' in sys.argv
    dry = '--dry-run' in sys.argv

    cur = {}
    errors = []
    for t in TOOLS:
        cur[t] = remote(t)
        if 'error' in cur[t]:
            errors.append(t)
        time.sleep(0.3)

    if set_baseline:
        os.makedirs(os.path.dirname(BASELINE), exist_ok=True)
        keep = {t: v for t, v in cur.items() if 'error' not in v}
        with open(BASELINE, 'w', encoding='utf-8') as f:
            json.dump({'recorded': time.strftime('%Y-%m-%d %H:%M:%S'), 'tools': keep},
                      f, ensure_ascii=False, indent=1, sort_keys=True)
        print('baseline recorded for %d tools (%d unreachable)' % (len(keep), len(errors)))
        return 0

    base = load(BASELINE, {}).get('tools') or {}
    if not base:
        print('no baseline yet - run with --set-baseline after a collector build')
        return 0

    shipped = (load(MANIFEST, {}).get('tools') or {})
    gone = [t for t in TOOLS if 'gone' in (cur.get(t) or {})]
    changed = []
    for t in TOOLS:
        c, b = cur.get(t) or {}, base.get(t)
        if not b or 'error' in c or 'gone' in c:
            continue
        if c.get('etag') != b.get('etag') or c.get('size') != b.get('size'):
            changed.append((t, (shipped.get(t) or {}).get('version') or '?',
                            b.get('last_modified', ''), c.get('last_modified', '')))

    if gone:
        msg = ('\u26a0\ufe0f Зникли з сайту автора (%d): %s\n'
               'Builder візьме їх із дзеркала (tools/collector_mirror_sync.py) або з кешу; '
               'перевірте tools.json.' % (len(gone), ', '.join(gone)))
        print(msg)
        if not dry and not set_baseline:
            notify(msg)
    if not changed:
        print('up to date (%d tools checked, %d unreachable)' % (len(TOOLS) - len(errors), len(errors)))
        return 0

    lines = ['\U0001f527 Вийшли нові версії інструментів збирача (%d):' % len(changed), '']
    for t, ver, was, now in changed:
        lines.append('• %s — у нас %s, на сайті оновлено %s' % (t, ver, now or 'нещодавно'))
    lines += ['',
              'Що це означає: збирач може не прочитати артефакти нових збірок Windows —',
              'саме так кейс Asus втратив увесь Prefetch.',
              '',
              'Оновити: перезібрати збирач у DFIR Collector Builder - він сам бере найновіші',
              'версії з сайту автора й перевіряє підпис ZimTech (TOOLS_PROVENANCE.txt), потім',
              'записати новий базовий стан: ez_tools_check.py --set-baseline']
    text = '\n'.join(lines)
    print(text)
    if not dry:
        notify(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
