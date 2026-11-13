#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rewrite every reference to the old layout, in one pass, from one table.

The directories did not merely move - most of them were also RENAMED into a category:
uploads became var/uploads, uploader became src/uploader, GOLD became backups/GOLD. A
blind prefix substitution would therefore produce paths that do not exist, and the symlink
would hide that from us until something failed at three in the morning.

So: one mapping, longest match first, applied everywhere - compose, systemd, cron, the
firewall scripts, and the code. Dry run prints what would change and touches nothing.
"""
import io
import os
import re
import shutil
import subprocess
import sys
import time

OLD_ROOT = '/home/dfir-bot/dfir'
NEW_ROOT = '/srv/dfir'

# old relative path -> new relative path
MAP = {}
for d in ('cases', 'services', 'tools', 'state', 'backups', 'users'):
    MAP[d] = d
for d in ('uploads', 'quarantine', 'ram_inbox', 'ram_results', 'logs', 'tmp', 'dfir_tmp',
          'sidecar_tmp', 'n8n_work', '_staging', 'bookidx_inbox', 'translate_inbox',
          'translate_output', 'audio_results', 'dist', 'files', 'knowledge', 'attic'):
    MAP[d] = 'var/' + d
for d in ('docs', 'refs', 'COORDINATION', 'backlog_patches', 'sed_corpus', 'branding',
          'tests', 'reports'):
    MAP[d] = 'docs/' + d
for d in ('collector_src', 'collector_mirror', 'uploader', 'docker', 'vendor'):
    MAP[d] = 'src/' + d
MAP['GOLD'] = 'backups/GOLD'
MAP['scripts'] = 'tools/legacy_scripts'
MAP['config'] = 'state/config'
# loose files that stayed at the top
for f in ('docker-compose.yml', 'docker-compose.webhookgate.yml', '.env', '.gitignore',
          'Makefile'):
    MAP[f] = f
# logs that were written into the root now live in var
for f in ('audio_reconcile.log', 'maintenance.log', 'disk_watch.log', 'ram_worker.log',
          'vpn_sync.log', 'NIGHT_WORKLOG.md'):
    MAP[f] = 'var/logs/' + f if f.endswith('.log') else 'docs/legacy/' + f

KEYS = sorted(MAP, key=len, reverse=True)
PAT = re.compile(re.escape(OLD_ROOT) + r'(/[A-Za-z0-9_.\-]+)?')


def new_path(m):
    tail = m.group(1) or ''
    if not tail:
        return NEW_ROOT
    name = tail.lstrip('/')
    for k in KEYS:
        if name == k:
            return NEW_ROOT + '/' + MAP[k]
    return NEW_ROOT + '/' + name          # unknown leaf: keep the name, new root


def rewrite(path, dry=True):
    try:
        src = io.open(path, encoding='utf-8', errors='replace').read()
    except (IOError, IsADirectoryError):
        return 0
    if OLD_ROOT not in src:
        return 0
    out = PAT.sub(new_path, src)
    n = len(PAT.findall(src))
    if dry:
        print('  %-58s %d' % (path[-58:], n))
        return n
    shutil.copy2(path, path + '.bak.repath.' + time.strftime('%Y%m%d_%H%M%S'))
    io.open(path, 'w', encoding='utf-8', newline='\n').write(out)
    print('  %-58s %d' % (path[-58:], n))
    return n


def targets():
    out = ['/srv/dfir/docker-compose.yml', '/srv/dfir/docker-compose.webhookgate.yml']
    for d in ('/etc/systemd/system',):
        for f in sorted(os.listdir(d)):
            if f.startswith('dfir') and (f.endswith('.service') or f.endswith('.timer')):
                out.append(os.path.join(d, f))
    for f in sorted(os.listdir('/usr/local/sbin')):
        if f.startswith('dfir'):
            out.append('/usr/local/sbin/' + f)
    for root, dirs, files in os.walk('/srv/dfir'):
        # backups and GOLD hold HISTORICAL copies - rewriting them would falsify the
        # record of what the system looked like at the time they were taken.
        dirs[:] = [d for d in dirs
                   if d not in ('.git', 'node_modules', '__pycache__', 'attic', 'legacy',
                                'logdb', 'qdrant', 'n8n', 'pgadmin', 'GOLD', 'cases',
                                'backups', 'docs')]
        for f in files:
            if f.endswith(('.py', '.sh', '.conf', '.env', '.yml', '.service', '.timer')) \
                    and '.bak' not in f:
                out.append(os.path.join(root, f))
    return out


def main():
    dry = '--apply' not in sys.argv
    total = files = 0
    print('=== файли з посиланнями на старий шлях ===')
    for t in targets():
        n = rewrite(t, dry)
        if n:
            total += n
            files += 1

    print('=== crontab ===')
    cron = subprocess.run(['crontab', '-l'], capture_output=True).stdout.decode(
        'utf-8', 'replace')
    if OLD_ROOT in cron:
        n = len(PAT.findall(cron))
        print('  рядків із посиланнями: %d' % n)
        if not dry:
            io.open('/tmp/cron_new', 'w', encoding='utf-8').write(PAT.sub(new_path, cron))
            subprocess.run(['crontab', '/tmp/cron_new'])
            print('  crontab оновлено')
        total += n
        files += 1

    print('\n%d посилань у %d файлах%s' % (total, files, '' if not dry else
                                           ' (сухий прогін; --apply щоб застосувати)'))


if __name__ == '__main__':
    main()
