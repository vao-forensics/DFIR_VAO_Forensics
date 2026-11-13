# -*- coding: utf-8 -*-
"""llm-gw keys (sha256 only; the key is shown ONCE).
  docker exec llm-gw python /srv/keys.py add owner-agent --admin --max-concurrent 3
  docker exec llm-gw python /srv/keys.py add analyst-x --models agent-30b,gpt-small-20b --daily-tokens 2000000
  docker exec llm-gw python /srv/keys.py list | disable NAME
  docker exec llm-gw python /srv/keys.py grace on|off|ip 10.8.0.7
"""
import hashlib, json, os, secrets, sys, time
S = os.environ.get('STATE_DIR', '/data'); K = os.path.join(S, 'keys.json'); C = os.path.join(S, 'gw.json')
def load(p):
    try: return json.load(open(p, encoding='utf-8'))
    except Exception: return {}
def save(p, d):
    t = p + '.tmp'; json.dump(d, open(t, 'w', encoding='utf-8'), ensure_ascii=False, indent=1); os.chmod(t, 0o600); os.replace(t, p)
def opt(a, n, d=None):
    return a[a.index(n) + 1] if n in a else d
a = sys.argv[1:]
if a[:1] == ['add'] and len(a) > 1:
    k = load(K); key = 'llm_' + secrets.token_urlsafe(32)
    m = opt(a, '--models', '*')
    k[hashlib.sha256(key.encode()).hexdigest()] = {
        'name': a[1], 'models': '*' if m == '*' else m.split(','), 'admin': '--admin' in a,
        'max_concurrent': int(opt(a, '--max-concurrent', 2)), 'daily_tokens': int(opt(a, '--daily-tokens', 0)),
        'created': time.strftime('%Y-%m-%d %H:%M')}
    save(K, k); print('key for %s (shown once):\n%s' % (a[1], key))
elif a[:1] == ['list']:
    for v in load(K).values():
        print('%-22s models=%-10s admin=%-5s conc=%s daily=%s %s %s' % (v['name'], 'ALL' if v['models'] == '*' else len(v['models']),
              v.get('admin'), v.get('max_concurrent'), v.get('daily_tokens') or '∞', v.get('created'), 'DISABLED' if v.get('disabled') else ''))
    print('grace:', load(C))
elif a[:1] == ['disable'] and len(a) > 1:
    k = load(K); n = 0
    for v in k.values():
        if v['name'] == a[1]: v['disabled'] = True; n += 1
    save(K, k); print('disabled', n)
elif a[:1] == ['grace'] and len(a) > 1:
    c = load(C)
    if a[1] in ('on', 'off'): c['grace_all'] = a[1] == 'on'
    elif a[1] == 'ip' and len(a) > 2: c.setdefault('grace_ips', []).append(a[2])
    save(C, c); print(c)
else:
    print(__doc__)
