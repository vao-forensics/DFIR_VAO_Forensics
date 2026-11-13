# -*- coding: utf-8 -*-
"""Manage dfir-mcp access tokens (stored as sha256 only; the token itself is shown ONCE).

  docker exec dfir-mcp python /srv/mcp_tokens.py add  "owner-agent" --cases '*'
  docker exec dfir-mcp python /srv/mcp_tokens.py add  "analyst-ivan" --cases 14_04_2026_x,02_09_2026_y
  docker exec dfir-mcp python /srv/mcp_tokens.py list
  docker exec dfir-mcp python /srv/mcp_tokens.py disable "analyst-ivan"
"""
import hashlib, json, os, secrets, sys, time

P = os.environ.get('MCP_TOKENS', '/data/state/mcp_tokens.json')


def load():
    try:
        return json.load(open(P, encoding='utf-8'))
    except Exception:
        return {}


def save(d):
    tmp = P + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, P)


def main(a):
    d = load()
    if a[:1] == ['add'] and len(a) >= 2:
        cases = '*'
        if '--cases' in a:
            v = a[a.index('--cases') + 1]
            cases = '*' if v == '*' else [x.strip() for x in v.split(',') if x.strip()]
        tok = 'dfir_' + secrets.token_urlsafe(32)
        d[hashlib.sha256(tok.encode()).hexdigest()] = {'name': a[1], 'cases': cases,
                                                       'created': time.strftime('%Y-%m-%d %H:%M')}
        save(d)
        print('token for %s (shown once, store it in the agent config):\n%s' % (a[1], tok))
    elif a[:1] == ['list']:
        for h, t in d.items():
            print('%-24s cases=%-12s created=%s %s' % (t.get('name'), 'ALL' if t.get('cases') == '*'
                  else len(t.get('cases') or []), t.get('created'), 'DISABLED' if t.get('disabled') else ''))
    elif a[:1] == ['disable'] and len(a) >= 2:
        n = 0
        for t in d.values():
            if t.get('name') == a[1]:
                t['disabled'] = True; n += 1
        save(d); print('disabled %d token(s)' % n)
    else:
        print(__doc__)


if __name__ == '__main__':
    main(sys.argv[1:])
