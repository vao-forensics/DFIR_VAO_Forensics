# -*- coding: utf-8 -*-
"""End-to-end integration check after a long night of patches.

Renders the finished report for every case and reports: exceptions, section presence, and
placeholder sections (the silent-failure signature that hid the empty timeline earlier).
"""
import os
import re
import traceback

import psycopg2
from reports.reshape import reshape_client_report

PLACEHOLDERS = (
    'Недостатньо чітких подій',
    'Явних IOC у нормалізованих логах не виділено',
    'Точну першу точку зараження не вдалося',
)
SECTIONS = ('## 1.', '## 2.', '## 3.', '## 4.', '## 5.', '## 6.', '## 7.')

c = psycopg2.connect(os.environ['PG_DSN'])
c.autocommit = True
cur = c.cursor()
cur.execute("SELECT case_key FROM cases WHERE case_key NOT LIKE 'ZZ_%' ORDER BY 1")
bad = 0
for (ck,) in cur.fetchall():
    try:
        t = reshape_client_report(ck, 'СЛУЖБОВІ ДАНІ')
    except Exception:
        bad += 1
        print('%-46s ВИНЯТОК' % ck[:46])
        traceback.print_exc()
        continue
    missing = [s for s in SECTIONS if s not in t]
    ph = [p for p in PLACEHOLDERS if p in t]
    extra = [s for s in ('УМОВИ ЗБОРУ', 'ДОКУМЕНТИ, НОСІЇ', 'СЛІДИ ЗАПУСКУ',
                         'Хто власник', 'Комунікації') if s in t]
    flag = ''
    if missing:
        flag = ' !! БРАКУЄ РОЗДІЛІВ: %s' % ','.join(missing)
        bad += 1
    print('%-46s %6d симв. | заглушки: %-2d | додаткові секції: %s%s'
          % (ck[:46], len(t), len(ph), ','.join(extra) or '-', flag))
    for p in ph:
        print('        заглушка: %s' % p)
print()
print('справ із проблемами:', bad)
