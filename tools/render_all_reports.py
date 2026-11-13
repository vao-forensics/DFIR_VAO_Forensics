r"""Render the full report for every case and look for damage after tonight's changes.

Twenty-odd commits touched detection, rendering, ingest routing, the chat tools and the
self-learning workers. Both guards are green, but a green guard says "the things I check did
not break". The failures that actually mattered tonight were found by rendering a finished
report and reading it - an empty timeline on all eleven cases, malicious drivers hidden by a
borrowed filter, the ransom email printed as the owner's address.

So: render everything, count sections, and flag anything that looks like a hole.
"""
import os
import re
import sys

sys.path.insert(0, '/app')
import psycopg2

import reports.reshape as R

c = psycopg2.connect(os.environ['PG_DSN'])
c.autocommit = True
cur = c.cursor()
cur.execute("SELECT case_key FROM cases WHERE case_key NOT LIKE 'ZZ%%' ORDER BY 1")
cases = [r[0] for r in cur.fetchall()]

fn = None
for name in ('reshape_client_report', 'build_client_report', 'render_report'):
    if hasattr(R, name):
        fn = getattr(R, name)
        break
if fn is None:
    print('не знайшов функцію рендеру; кандидати:',
          [n for n in dir(R) if 'report' in n.lower()][:10])
    raise SystemExit(1)
print('рендерю через %s\n' % fn.__name__)

# a report with any of these is broken in a way a guard would not notice
HOLES = [
    ('порожня хронологія', re.compile(r'(?i)хронолог[іи][^\n]*\n\s*(?:_?\(?(?:немає|порожньо))')),
    ('слід трейсбека', re.compile(r'Traceback|Exception|psycopg2\.')),
    ('невиконаний шаблон', re.compile(r'\{[a-z_]+\}')),
    ('мохібейк', re.compile(r'[À-ÿ]{4,}')),
]

bad = 0
for ck in cases:
    try:
        out = fn(ck)
    except Exception as e:
        print('%-36s ВИНЯТОК: %s: %s' % (ck[:36], type(e).__name__, str(e)[:60]))
        bad += 1
        continue
    if isinstance(out, (list, tuple)):
        out = '\n'.join(str(x) for x in out)
    out = out or ''
    secs = len(re.findall(r'(?m)^##+\s', out))
    flags = [name for name, rx in HOLES if rx.search(out)]
    print('%-36s %7d символів  %2d секцій  %s'
          % (ck[:36], len(out), secs, ('⚠ ' + ', '.join(flags)) if flags else 'ок'))
    if flags:
        bad += 1

print()
print('справ із проблемами: %d з %d' % (bad, len(cases)))
