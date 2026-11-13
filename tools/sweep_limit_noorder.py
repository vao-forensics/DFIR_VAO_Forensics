# -*- coding: utf-8 -*-
"""Find every LIMIT without ORDER BY — the defect class that silently ate evidence.

One such query fed twenty-two detection signatures an arbitrary third of the command lines
on six of eleven cases, and changed which third on every run. Nothing failed, nothing
logged; findings just came and went. The same shape anywhere else has the same effect.

Not every hit is a bug. A LIMIT is fine when the query only asks "does any row exist", when
it is bounded by a unique key, or when the rows are aggregated afterwards. What matters is
whether the rows are then USED as evidence — which is why this prints context instead of a
verdict.
"""
import io
import os
import re

ROOT = '/srv/dfir/services/case_maintainer'
SQL_RE = re.compile(r'(?is)\bSELECT\b.{0,4000}?\bLIMIT\b\s*(\d+|%s)')

# a LIMIT is harmless in these shapes
HARMLESS = (
    re.compile(r'(?i)\bLIMIT\s*1\b'),                    # existence check
    re.compile(r'(?i)\bcount\s*\(', re.I),               # aggregate, LIMIT irrelevant
)

hits = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in ('__pycache__', 'vendor')]
    for fn in filenames:
        if not fn.endswith('.py') or '.bak' in fn:
            continue
        p = os.path.join(dirpath, fn)
        rel = os.path.relpath(p, ROOT)
        src = io.open(p, encoding='utf-8', errors='replace').read()
        for m in SQL_RE.finditer(src):
            sql = m.group(0)
            if re.search(r'(?i)\bORDER\s+BY\b', sql):
                continue
            if any(h.search(sql) for h in HARMLESS):
                continue
            line = src.count('\n', 0, m.start()) + 1
            flat = re.sub(r'\s+', ' ', sql).strip()
            hits.append((rel, line, m.group(1), flat))

print('знайдено запитів LIMIT без ORDER BY (без очевидно нешкідливих): %d\n' % len(hits))
by_file = {}
for rel, line, lim, flat in hits:
    by_file.setdefault(rel, []).append((line, lim, flat))

for rel in sorted(by_file, key=lambda r: -len(by_file[r])):
    print('=== %s  (%d)' % (rel, len(by_file[rel])))
    for line, lim, flat in by_file[rel][:6]:
        print('   рядок %-6d LIMIT %-6s %s' % (line, lim, flat[:150]))
    if len(by_file[rel]) > 6:
        print('   … ще %d' % (len(by_file[rel]) - 6))
