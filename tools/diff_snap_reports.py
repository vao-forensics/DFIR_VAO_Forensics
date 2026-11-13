# -*- coding: utf-8 -*-
"""Порівняння знімків «до» і «після»: набір знахідок має бути ТОЙ САМИЙ, числа — лише менші.

Usage: diff_snap.py <before_dir> <after_dir>
"""
import difflib
import json
import os
import sys

B, A = sys.argv[1], sys.argv[2]
b = json.load(open(os.path.join(B, '_findings.json'), encoding='utf-8'))
a = json.load(open(os.path.join(A, '_findings.json'), encoding='utf-8'))

bad = 0
print('=== знахідки: склад і числа ===')
for ck in sorted(b):
    fb, fa = b[ck]['findings'], a.get(ck, {}).get('findings', [])
    kb = sorted((f['severity'], f['category'], f['title']) for f in fb)
    ka = sorted((f['severity'], f['category'], f['title']) for f in fa)
    lost = [x for x in kb if x not in ka]
    new = [x for x in ka if x not in kb]
    cb = {(f['severity'], f['category'], f['title']): f['count'] for f in fb}
    ca = {(f['severity'], f['category'], f['title']): f['count'] for f in fa}
    changed = [(k, cb[k], ca[k]) for k in cb if k in ca and cb[k] != ca[k]]
    grew = [x for x in changed if x[2] > x[1]]
    flag = ''
    if lost or new or grew:
        flag = '  <-- РОЗБІЖНІСТЬ'
        bad += 1
    print('%-42s знахідок %2d -> %2d | зникло %d | нових %d | чисел змінено %d (зросло %d)%s'
          % (ck[:42], len(fb), len(fa), len(lost), len(new), len(changed), len(grew), flag))
    for k, o, n in changed:
        print('        %-58s %s -> %s' % ((k[2] or '')[:58], o, n))
    for x in lost:
        print('        ЗНИКЛА: %s' % (x,))
    for x in new:
        print('        НОВА:   %s' % (x,))

print()
print('=== текст звітів ===')
for ck in sorted(b):
    p1, p2 = os.path.join(B, ck + '.report.txt'), os.path.join(A, ck + '.report.txt')
    if not (os.path.exists(p1) and os.path.exists(p2)):
        print('%-42s ФАЙЛ ВІДСУТНІЙ' % ck[:42])
        bad += 1
        continue
    t1 = open(p1, encoding='utf-8').read().split('\n')
    t2 = open(p2, encoding='utf-8').read().split('\n')
    d = [x for x in difflib.unified_diff(t1, t2, lineterm='', n=0)
         if x.startswith(('+', '-')) and not x.startswith(('+++', '---'))]
    print('%-42s %6d -> %6d символів, різних рядків: %d'
          % (ck[:42], len('\n'.join(t1)), len('\n'.join(t2)), len(d)))
    for x in d[:8]:
        print('        %s' % x[:170])

print()
print('справ із розбіжностями (втрата/поява/зростання): %d' % bad)
