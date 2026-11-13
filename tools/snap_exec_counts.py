r"""Знімок усього, що читач бачить як число, — до і після правки рахування.

Дублі в `program_exec_v2` законні (два набори керування ControlSet001/002, іноді два експорти
реєстру), тож лікуємо рахування, а не дані. Щоб довести, що жодна знахідка не зникла, потрібен
знімок ПО ВСІХ справах: набір знахідок (severity/category/title) окремо від їхніх чисел, і
повний текст звіту.

Usage: snap_exec_counts.py <out_dir>
Read-only.
"""
import json
import os
import sys

sys.path.insert(0, '/app')
import psycopg2

OUT = sys.argv[1]
ONLY_FINDINGS = '--findings-only' in sys.argv
os.makedirs(OUT, exist_ok=True)

c = psycopg2.connect(os.environ['PG_DSN'])
c.autocommit = True
cur = c.cursor()
cur.execute("SET statement_timeout='180000'")
cur.execute("SELECT case_key FROM cases WHERE case_key NOT LIKE 'ZZ%%' ORDER BY 1")
cases = [r[0] for r in cur.fetchall()]

import analysis.threat_detect as TD
import reports.reshape as R

STUB = ('# Звіт\n\nТехнічний текст-заглушка для рендеру: reshape збирає всі числа з бази, '
        'а не з цього тексту.\n')

summary = {}
for ck in cases:
    rec = {'findings': [], 'report_chars': 0, 'report_sections': 0, 'errors': []}
    try:
        conn = psycopg2.connect(os.environ['PG_DSN'])
        conn.autocommit = True
        fnd = TD.detect_threats(ck, conn)
        conn.close()
        for f in fnd:
            rec['findings'].append({
                'severity': f.get('severity'), 'category': f.get('category'),
                'mitre': f.get('mitre'), 'title': f.get('title'),
                'count': f.get('count'), 'detail': str(f.get('detail') or ''),
                'samples': [str(s) for s in (f.get('samples') or [])],
            })
    except Exception as e:
        rec['errors'].append('detect_threats: %s: %s' % (type(e).__name__, str(e)[:200]))
    try:
        if ONLY_FINDINGS:
            raise KeyboardInterrupt
        txt = R.reshape_client_report(ck, STUB) or ''
        rec['report_chars'] = len(txt)
        rec['report_sections'] = txt.count('\n## ')
        with open(os.path.join(OUT, ck + '.report.txt'), 'w', encoding='utf-8') as fh:
            fh.write(txt)
    except KeyboardInterrupt:
        pass                      # --findings-only: звіт не рендеримо
    except Exception as e:
        rec['errors'].append('reshape: %s: %s' % (type(e).__name__, str(e)[:200]))
    summary[ck] = rec
    print('%-42s знахідок %-3d звіт %6d символів %2d секцій %s'
          % (ck[:42], len(rec['findings']), rec['report_chars'], rec['report_sections'],
             ('ПОМИЛКА: ' + '; '.join(rec['errors'])) if rec['errors'] else 'ок'))

with open(os.path.join(OUT, '_findings.json'), 'w', encoding='utf-8') as fh:
    json.dump(summary, fh, ensure_ascii=False, indent=1, sort_keys=True)
print('\nзаписано у %s' % OUT)
