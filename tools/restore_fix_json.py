# -*- coding: utf-8 -*-
"""Restore the rows whose JSON columns my own backup mangled.

The backup serialised dict/list values with str(), producing a Python repr with single
quotes — which Postgres rejects for a json/jsonb column:

    invalid input syntax for type json ... Token "'" is invalid

Fixed here rather than silently skipped: any string that parses as a Python literal and is
a dict or list is re-encoded as real JSON before insert. The backup script itself should
keep JSON as JSON; noted so it is not repeated.

Usage: restore_fix_json.py <backup.json> <case_key> <table> [--apply]
"""
import ast
import json
import os
import sys

import psycopg2

BK = json.load(open(sys.argv[1]))
CK = sys.argv[2]
TABLE = sys.argv[3]
APPLY = '--apply' in sys.argv

blob = BK[TABLE]
cols, rows = blob['columns'], blob['rows']

c = psycopg2.connect(os.environ['PG_DSN'])
c.autocommit = True
cur = c.cursor()

# which columns are json/jsonb
cur.execute("""SELECT column_name, data_type FROM information_schema.columns
               WHERE table_schema='public' AND table_name=%s""", (TABLE,))
types = {r[0]: r[1] for r in cur.fetchall()}
jsoncols = {i for i, cname in enumerate(cols) if types.get(cname) in ('json', 'jsonb')}
print('json-колонки:', [cols[i] for i in jsoncols] or '—')


def fix(v, is_json):
    if not is_json or v is None:
        return v
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False)
    s = str(v)
    try:
        parsed = ast.literal_eval(s)
        if isinstance(parsed, (dict, list)):
            return json.dumps(parsed, ensure_ascii=False)
    except Exception:
        pass
    return s


collist = ','.join('"%s"' % x for x in cols)
ph = ','.join(['%s'] * len(cols))
ins = err = 0
for r in rows:
    vals = [fix(v, i in jsoncols) for i, v in enumerate(r)]
    if not APPLY:
        continue
    try:
        cur.execute('INSERT INTO "%s" (%s) VALUES (%s) ON CONFLICT DO NOTHING'
                    % (TABLE, collist, ph), vals)
        ins += cur.rowcount
    except Exception as e:
        c.rollback()
        err += 1
        if err == 1:
            print('перша помилка:', str(e)[:150])
print('%s: у дампі %d, вставлено %d, помилок %d %s'
      % (TABLE, len(rows), ins, err, '' if APPLY else '(вхолосту)'))
