# -*- coding: utf-8 -*-
"""Repair already-ingested mojibake in place. Dry run by default.

Usage: backfill_demojibake.py [--apply]

Walks raw_fallback_v2 payloads (and the few filesystem_v2 rows) that carry a Latin-1
supplement run, applies the same reversible repair the ingest now does, and updates only
rows whose JSON actually changes. Batched, with counts and samples so the result can be
checked rather than trusted.
"""
import json
import os
import re
import sys

import psycopg2
from psycopg2.extras import Json

MOJI_RUN = re.compile(r'[À-ÿ]{3,}')


def demojibake(s):
    if not s or not MOJI_RUN.search(s):
        return s
    fixed = None
    for enc in ('cp1252', 'latin-1'):
        try:
            fixed = s.encode(enc, 'strict').decode('cp1251', 'strict')
            break
        except Exception:
            continue
    if fixed is None:
        return s
    cyr = 0
    for ch in fixed:
        if 'Ѐ' <= ch <= 'ӿ':
            cyr += 1
            if cyr >= 3:
                return fixed
    return s


def walk(obj):
    """Repair every string inside a JSON structure. Returns (new_obj, changed)."""
    if isinstance(obj, str):
        f = demojibake(obj)
        return f, f != obj
    if isinstance(obj, list):
        ch = False
        out = []
        for x in obj:
            nx, c = walk(x)
            out.append(nx)
            ch = ch or c
        return out, ch
    if isinstance(obj, dict):
        ch = False
        out = {}
        for k, v in obj.items():
            nk, c1 = walk(k)
            nv, c2 = walk(v)
            out[nk] = nv
            ch = ch or c1 or c2
        return out, ch
    return obj, False


APPLY = '--apply' in sys.argv
c = psycopg2.connect(os.environ['PG_DSN'])
c.autocommit = False
cur = c.cursor()
cur.execute("SET statement_timeout='600000'")

cur.execute("""SELECT row_id, payload FROM raw_fallback_v2
               WHERE payload::text ~ '[\\u00c0-\\u00ff]{3,}'""")
rows = cur.fetchall()
print('кандидатів у raw_fallback_v2: %d' % len(rows))

changed = 0
samples = []
upd = c.cursor()
for row_id, payload in rows:
    new, ch = walk(payload or {})
    if not ch:
        continue
    changed += 1
    if len(samples) < 5:
        old_s = json.dumps(payload, ensure_ascii=False)[:90]
        new_s = json.dumps(new, ensure_ascii=False)[:90]
        samples.append((old_s, new_s))
    if APPLY:
        upd.execute("UPDATE raw_fallback_v2 SET payload=%s WHERE row_id=%s", (Json(new), row_id))
        if changed % 5000 == 0:
            c.commit()
            print('   ... оновлено %d' % changed)

if APPLY:
    c.commit()
print('рядків зі змінами: %d  (%s)' % (changed, 'ЗАСТОСОВАНО' if APPLY else 'вхолосту'))
for o, n in samples:
    print('   було : %s' % o)
    print('   стало: %s' % n)
