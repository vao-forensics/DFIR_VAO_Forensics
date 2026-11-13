#!/usr/bin/env python3
"""Credentials file for `n8n import:credentials`, matching what the workflows reference.

  n8n_creds.py WORKFLOWS_JSON > creds.json      (token from env DFIR_TG_BOT_TOKEN)

A workflow keeps only {id, name} of each credential; import:workflow does not create them. We
create every referenced credential with the SAME id, so the imported nodes find it. n8n encrypts
the plain `data` object with its own key on import, so the token never sits in its database in clear.
Prints the active workflow ids on stderr for the activation step.
"""
import json
import os
import sys

# baseUrl: outbound Telegram calls through tg-i18n (per-user language); it passes the source language through
FILL = {'telegramApi': lambda: {'accessToken': os.environ['DFIR_TG_BOT_TOKEN'], 'baseUrl': 'http://tg-i18n:8098'}}


def main():
    wfs = json.load(open(sys.argv[1], encoding='utf-8'))
    wfs = wfs if isinstance(wfs, list) else [wfs]
    creds, unknown = {}, set()
    for w in wfs:
        for n in w.get('nodes', []):
            for ctype, ref in (n.get('credentials') or {}).items():
                if ctype not in FILL:
                    unknown.add('%s (%s)' % (ctype, ref.get('name')))
                    continue
                creds[ref['id']] = {'id': ref['id'], 'name': ref.get('name') or ctype, 'type': ctype, 'data': FILL[ctype]()}
    if unknown:
        print('n8n: no automatic setup for credentials: %s - add them in the n8n editor' % ', '.join(sorted(unknown)),
              file=sys.stderr)
    print(' '.join(w['id'] for w in wfs if w.get('active')), file=sys.stderr)
    json.dump(list(creds.values()), sys.stdout)


if __name__ == '__main__':
    main()
