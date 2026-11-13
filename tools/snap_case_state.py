# -*- coding: utf-8 -*-
"""Snapshot everything a case currently holds, so a full delete + re-ingest + re-analysis
can be compared against it row by row.

Usage: snap_case_state.py <case_key> <out.json>
"""
import hashlib
import json
import os
import sys

import psycopg2

CK = sys.argv[1]
OUT = sys.argv[2]

TABLES = ['event_logs_v2', 'filesystem_v2', 'program_exec_v2', 'srum_v2',
          'raw_fallback_v2', 'tool_alerts_v2', 'case_iocs', 'communications_v1',
          'dfir_case_qa_v1', 'ingest_jobs', 'dfir_run_jobs_v2']

c = psycopg2.connect(os.environ['PG_DSN'])
c.autocommit = True
cur = c.cursor()
cur.execute("SET statement_timeout='180000'")

snap = {'case_key': CK, 'tables': {}, 'families': {}, 'archive': {}}
for t in TABLES:
    try:
        cur.execute('SELECT count(*) FROM %s WHERE case_key=%%s' % t, (CK,))
        snap['tables'][t] = cur.fetchone()[0]
    except Exception:
        c.rollback()
        snap['tables'][t] = None

cur.execute("""SELECT parser_family, count(*) FROM raw_fallback_v2
               WHERE case_key=%s GROUP BY 1 ORDER BY 1""", (CK,))
snap['families'] = {r[0]: r[1] for r in cur.fetchall()}

# the archive must survive untouched — record its hash
base = '/data/case_library/%s/uploads/logs' % CK
if os.path.isdir(base):
    for fn in sorted(os.listdir(base)):
        p = os.path.join(base, fn)
        if os.path.isfile(p):
            h = hashlib.sha256()
            with open(p, 'rb') as f:
                for chunk in iter(lambda: f.read(1 << 20), b''):
                    h.update(chunk)
            snap['archive'][fn] = {'size': os.path.getsize(p), 'sha256': h.hexdigest()}

try:
    from analysis.threat_detect import detect_threats
    f = detect_threats(CK, c) or []
    snap['findings'] = [[x.get('severity'), x.get('title'), x.get('count')] for x in f]
except Exception as e:
    snap['findings'] = ['ERROR %s' % str(e)[:80]]

try:
    from reports.reshape import reshape_client_report
    t = reshape_client_report(CK, 'СЛУЖБОВІ ДАНІ')
    snap['report_len'] = len(t)
    snap['report_sections'] = [l for l in t.split('\n') if l.startswith('## ')]
except Exception as e:
    snap['report_len'] = 'ERROR %s' % str(e)[:80]

json.dump(snap, open(OUT, 'w'), ensure_ascii=False, indent=1)
print('знято:', OUT)
print('  таблиці:', {k: v for k, v in snap['tables'].items() if v})
print('  сімей у fallback:', len(snap['families']))
print('  знахідок:', len(snap.get('findings') or []))
print('  довжина звіту:', snap.get('report_len'))
print('  архів:', list(snap['archive'].keys()))
