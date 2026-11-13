# -*- coding: utf-8 -*-
"""How much more does the new taxonomy see than the old patterns, on real cases?"""
import os

import psycopg2
from analysis.attack_tools import (CATEGORIES, HIGH_SIGNAL_CATEGORIES, all_tools_regex,
                                   category_regex, categorize)

OLD = (r'rustdesk|psexec|anydesk|ngrok|rutserv|rfusclient|rdpwinst|rdpwrap|'
       r'mimikatz|try[.]exe|nltest|chromepass|nirsoft|7za|litemanager|'
       r'screenconnect|atera|teamviewer|meterpreter|cobalt|procdump|rclone')

c = psycopg2.connect(os.environ['PG_DSN'])
c.autocommit = True
cur = c.cursor()
cur.execute("SET statement_timeout='120000'")
cur.execute("SELECT case_key FROM cases WHERE case_key NOT LIKE 'ZZ_%' ORDER BY 1")
for (ck,) in cur.fetchall():
    cur.execute("""SELECT DISTINCT lower(regexp_replace(coalesce(full_path, executable_name),
                                                        '^.*[\\\\/]', ''))
                   FROM program_exec_v2 WHERE case_key=%s
                     AND coalesce(full_path, executable_name) IS NOT NULL""", (ck,))
    names = [r[0] for r in cur.fetchall() if r[0]]
    import re
    old_hits = sorted({n for n in names if re.search(OLD, n, re.I)})
    new_hits = {}
    for n in names:
        for cat in categorize(n):
            new_hits.setdefault(cat, set()).add(n)
    extra = sorted({n for s in new_hits.values() for n in s} - set(old_hits))
    hi = [c2 for c2 in new_hits if c2 in HIGH_SIGNAL_CATEGORIES]
    print('%-46s старий=%-3d новий=%-3d  високосигнальні категорії: %s'
          % (ck[:46], len(old_hits), len({n for s in new_hits.values() for n in s}),
             ', '.join(hi) or '—'))
    if extra:
        print('      нове, чого не бачили: %s' % ', '.join(extra[:10]))
