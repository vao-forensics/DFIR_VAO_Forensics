#!/usr/bin/env python3
"""Snapshot the ACTIVE n8n workflows into infra/n8n/workflows.json (what install.sh imports).

  sudo python3 tools/n8n_snapshot.py          write the file, print what changed
  sudo python3 tools/n8n_snapshot.py --check  exit 1 if the repo copy is older than the live n8n

Only active workflows go in: the inactive ones in n8n are old drafts (FT Builder v1-3, an old
v24 copy) and importing them on a new install would only confuse. Credentials are NOT exported:
the workflow keeps a reference (id + name) and install.sh creates the credential with that id.
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'infra', 'n8n', 'workflows.json')
DROP = ('shared', 'tags', 'versionId', 'activeVersionId', 'triggerCount', 'createdAt', 'meta', 'isArchived')


def live():
    subprocess.run(['docker', 'exec', 'n8n', 'n8n', 'export:workflow', '--all', '--output=/tmp/_wf_snapshot.json'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    raw = subprocess.run(['docker', 'exec', 'n8n', 'cat', '/tmp/_wf_snapshot.json'], check=True,
                         stdout=subprocess.PIPE).stdout
    subprocess.run(['docker', 'exec', 'n8n', 'rm', '-f', '/tmp/_wf_snapshot.json'])
    wfs = [w for w in json.loads(raw) if w.get('active')]
    for w in wfs:
        for k in DROP:
            w.pop(k, None)
    return sorted(wfs, key=lambda w: w['id'])


def main():
    wfs = live()
    body = json.dumps(wfs, ensure_ascii=False, indent=1, sort_keys=True) + '\n'
    old = open(OUT, encoding='utf-8').read() if os.path.exists(OUT) else ''
    if '--check' in sys.argv:
        print('n8n snapshot up to date' if old == body else 'n8n snapshot STALE: run tools/n8n_snapshot.py')
        return 0 if old == body else 1
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    open(OUT, 'w', encoding='utf-8').write(body)
    for w in wfs:
        print('%s  %-45s %3d nodes  updated %s' % (w['id'], w['name'], len(w['nodes']), w.get('updatedAt')))
    print('written %s (%s)' % (OUT, 'unchanged' if old == body else 'changed'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
