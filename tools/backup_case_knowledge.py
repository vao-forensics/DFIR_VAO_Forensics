# -*- coding: utf-8 -*-
"""Back up everything small a case carries, before a destructive test.

Deleting a case does not only remove evidence: case_learnings_v1, dfir_lessons_learned_v1,
dfir_agent_learnings, dfir_qa_feedback (the human вірно/невірно verdicts) and
dfir_finetune_dataset_v1 (a training pair) all hang off case_key. The bot's own admin menu
distinguishes «видалити повністю» from «архівувати — лишити знання» for exactly this
reason.

Everything with fewer than 5000 rows is dumped to JSON so it can be restored verbatim.

Usage: backup_case_knowledge.py <case_key> <out.json>
"""
import datetime
import decimal
import json
import os
import sys

import psycopg2

CK = sys.argv[1]
OUT = sys.argv[2]


def _enc(o):
    if isinstance(o, (datetime.datetime, datetime.date)):
        return o.isoformat()
    if isinstance(o, decimal.Decimal):
        return float(o)
    if isinstance(o, (bytes, bytearray)):
        return o.decode('utf-8', 'replace')
    if isinstance(o, (dict, list, tuple)):
        # Hand these back untouched so json.dump serialises them as JSON. str() here would
        # emit Python repr - {'k': 'v'} with single quotes - which Postgres refuses on
        # restore, and the failure is swallowed: 80 verified findings once came back as 0.
        return list(o) if isinstance(o, tuple) else o
    return str(o)


c = psycopg2.connect(os.environ['PG_DSN'])
c.autocommit = True
cur = c.cursor()
cur.execute("SET statement_timeout='300000'")
cur.execute("""SELECT table_name FROM information_schema.columns
               WHERE table_schema='public' AND column_name='case_key' ORDER BY table_name""")
tables = [r[0] for r in cur.fetchall()]

dump = {}
for t in tables:
    try:
        cur.execute('SELECT count(*) FROM "%s" WHERE case_key=%%s' % t, (CK,))
        n = cur.fetchone()[0]
    except Exception:
        c.rollback()
        continue
    if not n or n > 5000:
        continue
    try:
        cur.execute('SELECT * FROM "%s" WHERE case_key=%%s' % t, (CK,))
        cols = [d[0] for d in cur.description]
        dump[t] = {'columns': cols,
                   'rows': [[_enc(v) if not isinstance(v, (int, float, bool, type(None), str))
                             else v for v in row] for row in cur.fetchall()]}
    except Exception as e:
        c.rollback()
        dump[t] = {'error': str(e)[:120]}

json.dump(dump, open(OUT, 'w'), ensure_ascii=False, default=_enc)
print('збережено таблиць: %d' % len(dump))
for t in sorted(dump, key=lambda x: -len(dump[x].get('rows', []))):
    print('   %-32s %d' % (t, len(dump[t].get('rows', []))))
print('файл:', OUT, os.path.getsize(OUT), 'байт')
