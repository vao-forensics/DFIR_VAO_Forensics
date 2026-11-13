#!/usr/bin/env python3
"""Telegram helpers for install.sh (standard library only).

  telegram.py me TOKEN               print the bot's @username, exit 1 if Telegram rejects the token
  telegram.py wait-start TOKEN SECS  wait for someone to send /start to the bot, print their chat_id
                                     (and their name on stderr)
  telegram.py send TOKEN CHAT TEXT   send a message (the install summary)

wait-start works only while no webhook is set (a fresh bot); n8n sets the webhook later, when
the workflow is activated. A webhook left from an earlier install is reported, not deleted.
"""
import json
import os
import sys
import time
import urllib.parse
import urllib.request


def api(token, method, **params):
    # DFIR_TG_API: a local Telegram stub for install tests (never a real bot's token in a test)
    base = os.environ.get('DFIR_TG_API', 'https://api.telegram.org').rstrip('/')
    url = '%s/bot%s/%s' % (base, token, method)
    data = urllib.parse.urlencode(params).encode() if params else None
    try:
        with urllib.request.urlopen(url, data=data, timeout=40) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return json.load(e)
        except Exception:
            return {'ok': False, 'description': str(e)}
    except Exception as e:
        return {'ok': False, 'description': str(e)}


def main():
    cmd, token = sys.argv[1], sys.argv[2]
    if cmd == 'me':
        r = api(token, 'getMe')
        if not r.get('ok'):
            sys.exit('Telegram: %s' % r.get('description'))
        print(r['result']['username'])
    elif cmd == 'wait-start':
        hook = api(token, 'getWebhookInfo').get('result', {}).get('url')
        if hook:
            sys.exit('у бота вже є вебхук (%s): chat_id введіть вручну' % hook)
        deadline = time.time() + int(sys.argv[3])
        offset = 0
        while time.time() < deadline:
            r = api(token, 'getUpdates', offset=offset, timeout=25, allowed_updates='["message"]')
            for u in r.get('result', []):
                offset = u['update_id'] + 1
                m = u.get('message') or {}
                if m.get('text', '').startswith('/start') and m.get('chat', {}).get('type') == 'private':
                    api(token, 'getUpdates', offset=offset, timeout=0)   # acknowledge, so n8n does not replay it
                    who = m['from'].get('username') or m['from'].get('first_name', '')
                    print('chat_id %s (%s)' % (m['chat']['id'], who), file=sys.stderr)
                    print(m['chat']['id'])
                    return
        sys.exit('за відведений час /start не надійшов')
    elif cmd == 'webhook':
        # prints the host the bot currently delivers to (empty = free); never the token
        r = api(token, 'getWebhookInfo')
        url = ((r or {}).get('result') or {}).get('url') or ''
        print(url.split('/')[2] if url.count('/') >= 2 else '')
    elif cmd == 'send':
        r = api(token, 'sendMessage', chat_id=sys.argv[3], text=sys.argv[4])
        if not r.get('ok'):
            sys.exit('Telegram: %s' % r.get('description'))


if __name__ == '__main__':
    main()
