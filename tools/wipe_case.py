# -*- coding: utf-8 -*-
"""Delete every trace of one case from the database, leaving the uploaded archive alone.

Usage: wipe_case.py <case_key> [--apply]

Finds the tables by schema rather than by a hand-written list, so nothing is missed when
the schema grows. Prints what it would delete first; nothing happens without --apply.
"""
import os
import sys

import psycopg2

CK = sys.argv[1]
APPLY = '--apply' in sys.argv

c = psycopg2.connect(os.environ['PG_DSN'])
c.autocommit = True
cur = c.cursor()
cur.execute("SET statement_timeout='600000'")

cur.execute("""SELECT table_name FROM information_schema.columns
               WHERE table_schema='public' AND column_name='case_key'
               ORDER BY table_name""")
tables = [r[0] for r in cur.fetchall()]
print('таблиць із колонкою case_key: %d' % len(tables))

total = 0
plan = []
for t in tables:
    try:
        cur.execute('SELECT count(*) FROM "%s" WHERE case_key=%%s' % t, (CK,))
        n = cur.fetchone()[0]
    except Exception:
        c.rollback()
        n = 0
    if n:
        plan.append((t, n))
        total += n

for t, n in sorted(plan, key=lambda x: -x[1]):
    print('   %-32s %d' % (t, n))
print('УСЬОГО рядків: %d' % total)

if not APPLY:
    print('(вхолосту — нічого не видалено)')
    sys.exit(0)

# children first, cases last (foreign keys)
for t, n in sorted(plan, key=lambda x: (x[0] == 'cases', -x[1])):
    if t == 'cases':
        continue
    cur.execute('DELETE FROM "%s" WHERE case_key=%%s' % t, (CK,))
    print('   видалено %-30s %d' % (t, cur.rowcount))
try:
    cur.execute('DELETE FROM cases WHERE case_key=%s', (CK,))
    print('   видалено cases %d' % cur.rowcount)
except Exception as e:
    print('   cases не видалено: %s' % str(e)[:80])
print('ГОТОВО. Архів на диску НЕ чіпали.')
