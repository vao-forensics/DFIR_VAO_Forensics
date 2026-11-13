r"""Split the remaining unordered LIMITs in threat_detect.py into safe and unsafe.

The agent that fixed the Startup nondeterminism deliberately stopped here, and its reasoning
was right: 11 queries carry a LIMIT with no ORDER BY and 7 sort by an aggregate where equal
counts tie. Adding ORDER BY everywhere would be reckless, because where the LIMIT genuinely
truncates it changes WHICH rows the report sees - and then "nothing else changed" becomes
unprovable, since you cannot tell your own damage from your own fix.

But the two cases are separable by measurement, and that is the whole point:

  * if the qualifying rows NEVER reach the limit on any case, then ORDER BY cannot change the
    membership of the result - only its order. Provably safe, and it removes the parallel-Gather
    nondeterminism that already bit us once.
  * if they do reach it, the change is real evidence-selection and needs its own justification
    per site. Those are reported, not touched.

This script only measures.
"""
import ast
import io
import os
import re

import psycopg2

P = '/app/analysis/threat_detect.py'
src = io.open(P, encoding='utf-8', errors='replace').read()

c = psycopg2.connect(os.environ['PG_DSN'])
c.autocommit = True
cur = c.cursor()
cur.execute("SET statement_timeout='45000'")
cur.execute("SELECT case_key FROM cases WHERE case_key NOT LIKE 'ZZ%%' ORDER BY 1")
CASES = [r[0] for r in cur.fetchall()]

# every SQL string constant that ends in a LIMIT
SQL_RE = re.compile(r'(?is)(SELECT\b.{0,4000}?\bLIMIT\s+(\d+))')
tree = ast.parse(src)
found = []
for node in ast.walk(tree):
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        continue
    v = node.value
    if 'LIMIT' not in v.upper() or 'SELECT' not in v.upper():
        continue
    for m in SQL_RE.finditer(v):
        sql, lim = m.group(1), int(m.group(2))
        has_order = re.search(r'(?i)\bORDER\s+BY\b', sql)
        found.append((node.lineno, sql, lim, bool(has_order)))

print('запитів із LIMIT у threat_detect.py: %d' % len(found))
safe, unsafe, skipped = [], [], []
for line, sql, lim, has_order in found:
    n_params = sql.count('%s')
    if n_params != 1:
        skipped.append((line, lim, 'параметрів %d — не рахую автоматично' % n_params))
        continue
    body = re.sub(r'(?is)^SELECT\b.*?\bFROM\b', 'SELECT count(*) FROM', sql, count=1)
    body = re.sub(r'(?is)\bORDER\s+BY\b.*?(?=\bLIMIT\b)', '', body)
    body = re.sub(r'(?i)\bLIMIT\s+\d+\s*$', '', body).strip()
    if re.search(r'(?i)\bGROUP\s+BY\b', body):
        body = 'SELECT count(*) FROM (%s) _t' % re.sub(
            r'(?is)^SELECT count\(\*\) FROM', 'SELECT 1 FROM', body)
    worst, worst_ck = 0, ''
    err = None
    for ck in CASES:
        try:
            cur.execute(body, (ck,))
            n = cur.fetchone()[0]
        except Exception as e:
            c.rollback()
            err = str(e).strip().split('\n')[0][:50]
            break
        if n > worst:
            worst, worst_ck = n, ck
    if err:
        skipped.append((line, lim, 'не порахувати: ' + err))
    elif worst > lim:
        unsafe.append((line, lim, worst, worst_ck, has_order))
    else:
        safe.append((line, lim, worst, has_order))

print()
print('=== БЕЗПЕЧНІ: ліміт ніколи не досягається, тож ORDER BY змінить лише порядок ===')
for line, lim, worst, has_order in sorted(safe):
    print('   рядок %-6d LIMIT %-5d максимум рядків %-6d %s'
          % (line, lim, worst, 'вже має ORDER BY' if has_order else '<- ДОДАТИ ORDER BY'))
print()
print('=== НЕБЕЗПЕЧНІ: ліміт РІЖЕ, ORDER BY змінить склад доказів — руками ===')
for line, lim, worst, ck, has_order in sorted(unsafe):
    print('   рядок %-6d LIMIT %-5d а рядків до %-7d (%s) %s'
          % (line, lim, worst, ck[:26], 'має ORDER BY' if has_order else 'БЕЗ ORDER BY'))
print()
print('=== не порахував автоматично ===')
for line, lim, why in sorted(skipped):
    print('   рядок %-6d LIMIT %-5d %s' % (line, lim, why))
