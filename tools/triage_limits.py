# -*- coding: utf-8 -*-
"""Separate the dangerous LIMITs from the harmless ones, empirically.

75 places use LIMIT without ORDER BY, but most are narrowly filtered — a query asking for
`%ngrok%` will not have 300 matches, so its limit never truncates and the arbitrary order
never shows. The one that did real damage had a BROAD filter (every row with a command
line) and truncated on six of eleven cases.

So the test is not "does it have a LIMIT" but "does the matching set actually exceed it".
This rewrites each candidate as a COUNT and runs it against every case.
"""
import io
import os
import re

import psycopg2

ROOT = '/app'
SQL_RE = re.compile(r'(?is)"""\s*(SELECT\b.{0,3000}?\bLIMIT\s+(\d+))\s*"""')

c = psycopg2.connect(os.environ['PG_DSN'])
c.autocommit = True
cur = c.cursor()
cur.execute("SET statement_timeout='30000'")
cur.execute("SELECT case_key FROM cases WHERE case_key NOT LIKE 'ZZ_%' ORDER BY 1")
CASES = [r[0] for r in cur.fetchall()]

FILES = ['analysis/assemblers.py', 'reports/reshape.py', 'analysis/threat_detect.py',
         'analysis/agent_tools.py', 'analysis/chat.py']

danger = []
checked = 0
for rel in FILES:
    p = os.path.join(ROOT, rel)
    if not os.path.exists(p):
        continue
    src = io.open(p, encoding='utf-8', errors='replace').read()
    for m in SQL_RE.finditer(src):
        sql, lim = m.group(1), int(m.group(2))
        if re.search(r'(?i)\bORDER\s+BY\b', sql):
            continue
        if not re.search(r'(?i)\bFROM\s+(event_logs_v2|filesystem_v2|program_exec_v2|'
                         r'raw_fallback_v2|srum_v2|tool_alerts_v2)', sql):
            continue
        n_params = sql.count('%s')
        if n_params != 1:          # only the simple case_key-only queries can be counted safely
            continue
        cnt_sql = re.sub(r'(?is)^SELECT\b.*?\bFROM\b', 'SELECT count(*) FROM', sql, count=1)
        cnt_sql = re.sub(r'(?i)\bLIMIT\s+\d+\s*$', '', cnt_sql).strip()
        line = src.count('\n', 0, m.start()) + 1
        worst = 0
        worst_case = ''
        for ck in CASES:
            try:
                cur.execute(cnt_sql, (ck,))
                n = cur.fetchone()[0]
            except Exception:
                c.rollback()
                n = -1
            if n > worst:
                worst, worst_case = n, ck
        checked += 1
        if worst > lim:
            danger.append((rel, line, lim, worst, worst_case,
                           re.sub(r'\s+', ' ', sql)[:130]))

print('перевірено запитів (широкий фільтр, один параметр): %d' % checked)
print('З НИХ ТРУНКУЮТЬ ДАНІ: %d\n' % len(danger))
for rel, line, lim, worst, ck, sql in sorted(danger, key=lambda x: -(x[3] / max(x[2], 1))):
    print('%-28s рядок %-6d LIMIT %-5d а рядків до %-7d (%s)' % (rel, line, lim, worst, ck[:26]))
    print('    %s' % sql)
