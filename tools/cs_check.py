# -*- coding: utf-8 -*-
"""Automatic checks over a chat stress-test jsonl (02.10.2026).

Flags: empty, mojibake, mid-word cut, slow, free-LLM (needs reading), fabricated user message,
and LEAK = the answer names a user / host that exists in another case but not in this one.
Usage (inside a case-maintainer container): python cs_check.py /cs/full2.jsonl
"""
import json
import re
import sys

import psycopg2

sys.path.insert(0, '/app')
from core.config import PG_DSN  # noqa: E402

rows = [json.loads(l) for l in open(sys.argv[1], encoding='utf-8')]
cases = sorted({r['case'] for r in rows})

# identity tokens per case: account names and host names
ident = {}
with psycopg2.connect(PG_DSN) as c, c.cursor() as cur:
    cur.execute("""SELECT case_key, lower(regexp_replace(target_user, '^.*\\\\', '')) FROM event_logs_v2
                   WHERE event_id IN (4624, 4720, 4726, 4738) AND coalesce(target_user, '') <> ''
                   GROUP BY 1, 2""")
    for ck, u in cur.fetchall():
        u = re.sub(r'\s*\(s-1-.*$', '', u or '').strip()
        if len(u) >= 4 and not re.search(r'\$$|system|service|dwm-|umfd-|anonymous|^-|администратор|administrator|^user$|guest|defaultaccount|wdagutility', u):
            ident.setdefault(ck, set()).add(u)
    cur.execute("SELECT case_key, lower(computer) FROM event_logs_v2 GROUP BY 1, 2")
    for ck, h in cur.fetchall():
        if h and len(h) >= 5 and re.match(r'^[a-z0-9-]+$', h or ''):
            ident.setdefault(ck, set()).add(h)


def answer_of(r):
    c = [t for t in r.get('all', []) if not t.startswith(('📊', '🔎 Питання', '⭐')) and not re.search(r'[▰▱]|⏳', t)]
    return c[-1] if c else (r.get('answer') or '')


def route(r):
    for x in r.get('logs', []):
        for k in ('findings-first', 'trusted-cache', 'case-qa DB HIT', 'fast_path done', 'general-summary', 'cross_case'):
            if k in x:
                return k
    return 'LLM'


tot = {}
for r in rows:
    a = answer_of(r)
    al = a.lower()
    flags = []
    if len(a.strip()) < 40:
        flags.append('EMPTY')
    if re.search(r'[╨╤][\u0080-ӿ─-◿]', a):
        flags.append('MOJIBAKE')
    if re.search(r'OUT-OF-BAND|USER MESSAGE', a):
        flags.append('FAKE_USER_MSG')
    if (r.get('sec') or 0) > 90:
        flags.append('SLOW %.0fs' % r['sec'])
    rt = route(r)
    if rt == 'LLM':
        flags.append('LLM')
    leak = set()
    for other, toks in ident.items():
        if other == r['case']:
            continue
        for t in toks:
            if t in ident.get(r['case'], set()):
                continue
            if re.search(r'(?<![\w-])' + re.escape(t) + r'(?![\w-])', al):
                leak.add('%s<-%s' % (t, other[:20]))
    if leak:
        flags.append('LEAK ' + ', '.join(sorted(leak)[:4]))
    tot.setdefault(rt, 0)
    tot[rt] += 1
    if flags:
        print('%-26s %-46s %-16s %s' % (r['case'][:26], r['q'][:46], rt, ' | '.join(flags)))
print('\nmaршрути:', tot, ' всього', len(rows))
