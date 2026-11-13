# -*- coding: utf-8 -*-
"""Розкласти споживачів `executable_name` на три групи — по ЗАПИТАХ, не по рядках грепу.

A — колонка читається лише разом зі шляхом (конкатенація або той самий предикат і на
    full_path): зміна семантики нейтральна, бо кожен токен старого значення лишається в fp.
B — колонка лише у SELECT (друкується): зміна = покращення.
C — предикат/ключ по executable_name БЕЗ пари на full_path, або DISTINCT/GROUP BY по ній:
    саме тут зміна може змінити поведінку.

Read-only, нічого не імпортує з бота.
"""
import os
import re
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else '/srv/dfir'
FILES = []
for sub in ('services/case_maintainer',):
    for dp, dn, fn in os.walk(os.path.join(ROOT, sub)):
        if 'backups' in dp or '__pycache__' in dp:
            continue
        for f in fn:
            if f.endswith('.py'):
                FILES.append(os.path.join(dp, f))

BLOCK = re.compile(r'"""(.*?)"""|\'\'\'(.*?)\'\'\'', re.S)

groups = {'A': [], 'B': [], 'C': []}
for path in sorted(FILES):
    txt = open(path, encoding='utf-8', errors='replace').read()
    rel = os.path.relpath(path, ROOT)
    cand = [m.group(1) or m.group(2) or '' for m in BLOCK.finditer(txt)]
    # однорядкові/склеєні запити: беремо вікно рядків навколо згадки
    lines = txt.split('\n')
    for i, ln in enumerate(lines):
        if 'executable_name' in ln and '"""' not in ln and "'''" not in ln:
            cand.append('\n'.join(lines[max(0, i - 6):i + 7]))
    seen = set()
    for sql in cand:
        if 'executable_name' not in sql or 'program_exec_v2' not in sql:
            continue
        key = re.sub(r'\s+', ' ', sql)[:400]
        if key in seen:
            continue
        seen.add(key)
        low = sql.lower()
        # позиція першої згадки — щоб назвати місце
        ln_no = txt[:txt.find(sql)].count('\n') + 1 if sql in txt else 0
        where = '%s:%d' % (rel, ln_no)
        # C1: ключ групування/розрізнення саме по executable_name
        is_key = bool(re.search(r'distinct on \([^)]*executable_name', low)
                      or re.search(r'distinct\s+(lower\()?\s*(coalesce\()?\s*executable_name', low)
                      or re.search(r'group by[^;]*executable_name', low)
                      or re.search(r'string_agg\(distinct executable_name', low))
        # C2: предикат по executable_name, у якому поруч НЕ згадано full_path
        preds = re.findall(r'[^\n]*executable_name[^\n]*(?:like|~|ilike)[^\n]*', low)
        lone = [p for p in preds if 'full_path' not in p and '||' not in p]
        # чи є в цьому ж запиті дзеркальний предикат по full_path з тим самим токеном
        has_fp_pred = bool(re.search(r'full_path[^\n]*(like|~|ilike)', low))
        if is_key or (lone and not has_fp_pred):
            groups['C'].append((where, 'ключ' if is_key else 'предикат-соло', len(lone)))
        elif lone and has_fp_pred:
            groups['C'].append((where, 'предикат-соло (є fp-гілка поруч)', len(lone)))
        elif preds or '||' in low:
            groups['A'].append((where, '', 0))
        else:
            groups['B'].append((where, '', 0))

def cluster(items):
    """Одне МІСЦЕ ЗАПИТУ, а не одне влучання: сусідні рядки того самого файлу — це один запит."""
    by_file = {}
    for w, why, n in items:
        f, l = w.rsplit(':', 1)
        by_file.setdefault(f, []).append((int(l), why))
    out = []
    for f in sorted(by_file):
        last = -99
        for l, why in sorted(by_file[f]):
            if l - last > 12:
                out.append(('%s:%d' % (f, l), why))
            last = l
    return out


# місце запиту може потрапити і в A, і в C (різні вікна) — C має пріоритет
cl = {g: cluster(groups[g]) for g in ('A', 'B', 'C')}
cpos = {w.rsplit(':', 1)[0] + ':' + str(int(w.rsplit(':', 1)[1]) // 12) for w, _ in cl['C']}
for g in ('A', 'B'):
    cl[g] = [(w, y) for w, y in cl[g]
             if (w.rsplit(':', 1)[0] + ':' + str(int(w.rsplit(':', 1)[1]) // 12)) not in cpos]

for g in ('A', 'B', 'C'):
    print('\n===== ГРУПА %s — %d місць запиту =====' % (g, len(cl[g])))
    if g == 'C':
        for w, why in cl[g]:
            print('  %-56s %s' % (w.replace('services/case_maintainer/', ''), why))
