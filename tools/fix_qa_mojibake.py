# -*- coding: utf-8 -*-
"""Repair the mangled Cyrillic inside stored Q&A answers.

11 answers in each of dfir_case_qa_v1 and dfir_qa_cache_v1 quote file names that were
damaged before tonight's ingest fix. Unlike the five answers deleted earlier — those
stated a wrong CONCLUSION about the examiner's own tool — these are correct analyses that
merely quote garbled names, so the text is repaired in place and the analysis is kept.
"""
import os
import re
import sys

import psycopg2

# U+00A0-U+00BF matters for Ukrainian: CP1251 і ї є ґ І Ї Є Ґ land there
# (0xB3 -> і, 0xBF -> ї, 0xBA -> є, 0xB4 -> ґ), so a run that stops at U+00C0
# leaves 'квитанц³ÿ' half-repaired.
MOJI_RUN = re.compile(r'[ -ÿ]{3,}')
APPLY = '--apply' in sys.argv


def demojibake_text(s):
    """Repair every damaged run inside a longer text, leaving the rest untouched."""
    if not s:
        return s
    out = []
    pos = 0
    for m in MOJI_RUN.finditer(s):
        # extend the run to include CP1252 punctuation that belongs to it
        start, end = m.start(), m.end()
        while end < len(s) and s[end] in '’‘“”–— ':
            end += 1
        frag = s[start:end]
        fixed = frag
        for enc in ('cp1252', 'latin-1'):
            try:
                cand = frag.encode(enc, 'strict').decode('cp1251', 'strict')
            except Exception:
                continue
            if sum(1 for ch in cand if 'Ѐ' <= ch <= 'ӿ') >= 3:
                fixed = cand
            break
        out.append(s[pos:start])
        out.append(fixed)
        pos = end
    out.append(s[pos:])
    return ''.join(out)


c = psycopg2.connect(os.environ['PG_DSN'])
c.autocommit = False
cur = c.cursor()
upd = c.cursor()
total = 0
for table, key in (('dfir_case_qa_v1', 'id'), ('dfir_qa_cache_v1', 'id')):
    try:
        cur.execute("SELECT %s, answer FROM %s WHERE answer ~ '[\\u00c0-\\u00ff]{3,}'"
                    % (key, table))
        rows = cur.fetchall()
    except Exception as e:
        c.rollback()
        print('%s: %s' % (table, str(e)[:70]))
        continue
    n = 0
    for rid, ans in rows:
        fixed = demojibake_text(ans)
        if fixed == ans:
            continue
        n += 1
        if n == 1:
            i = MOJI_RUN.search(ans).start()
            print('  %s зразок було : ...%s...' % (table, ans[max(0, i - 20):i + 50].replace('\n', ' ')))
            j = MOJI_RUN.search(ans).start()
            print('  %s зразок стало: ...%s...' % (table, fixed[max(0, j - 20):j + 50].replace('\n', ' ')))
        if APPLY:
            upd.execute("UPDATE %s SET answer=%%s WHERE %s=%%s" % (table, key), (fixed, rid))
    print('%-20s змінено %d з %d' % (table, n, len(rows)))
    total += n
if APPLY:
    c.commit()
print('усього %d (%s)' % (total, 'ЗАСТОСОВАНО' if APPLY else 'вхолосту'))
