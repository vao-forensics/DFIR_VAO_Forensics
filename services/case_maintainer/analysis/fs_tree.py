"""Folder tree of the examined disk, built from the $MFT rows already in the database.

Owner's idea (07.08.2026): «дерево файлів і папок структуровано і красиво ... в боті опція, щоб
видавало txt». The collector writes filesystem_tree.txt since v1.7, but the ingest keeps it out
of the database and older archives never had it. Building it from filesystem_v2 (action='MFT')
works for every case already ingested: one aggregate per folder, ~3 s for 840 k MFT rows.

What the TXT shows
  * a summary and the folders worth a look first: executables or scripts in places where
    software does not normally live (Temp, Downloads, Public, ProgramData root, AppData roots,
    Rar$ extraction folders, the recycle bin);
  * the directory tree (folders only - the per-file list is the MFT CSV itself) with the
    number of files, their size, and [DEL n] for deleted MFT records in that folder.
Caps: depth 12, 200 000 lines, with a notice when hit.
"""
import re

MAX_DEPTH = 12
MAX_LINES = 200000
EXEC_EXT = ('exe', 'dll', 'scr', 'ps1', 'vbs', 'js', 'jse', 'hta', 'bat', 'cmd', 'msi', 'lnk', 'sys', 'com', 'pif')
# last path segment that attackers favour (compared as a whole segment: «Templates» is not «Temp»)
HOT_SEG = re.compile(r'^(temp|tmp|downloads|public|perflogs|\$recycle\.bin|recycler|rar\$[^\\]*|7z[a-z0-9]+|'
                     r'appdata|local|roaming|locallow|programdata|tasks|fonts|debug|intel|nvidia)$', re.I)

SQL = """
SELECT parent_path,
       count(*) FILTER (WHERE coalesce(payload->>'is_dir','') NOT ILIKE 'true')                         AS files,
       coalesce(sum(CASE WHEN coalesce(payload->>'is_dir','') NOT ILIKE 'true'
                         AND (payload->>'file_size') ~ '^[0-9]+$' THEN (payload->>'file_size')::bigint END), 0) AS bytes,
       count(*) FILTER (WHERE payload->>'in_use' ILIKE 'false')                                          AS deleted,
       count(*) FILTER (WHERE lower(extension) = ANY(%s) AND coalesce(payload->>'is_dir','') NOT ILIKE 'true') AS execs
FROM filesystem_v2
WHERE case_key=%s AND action='MFT' AND parent_path IS NOT NULL
GROUP BY parent_path
"""


def _size(n):
    for unit, k in (('ГБ', 1 << 30), ('МБ', 1 << 20), ('КБ', 1 << 10)):
        if n >= k:
            return '%.1f %s' % (n / k, unit)
    return '%d Б' % n


def _parts(p):
    p = (p or '').strip()
    if p.startswith('.\\'):
        p = p[2:]
    elif p == '.':
        p = ''
    return [x for x in p.split('\\') if x]


def build(case_key, cur):
    """Returns (text, stats) or (None, reason)."""
    cur.execute("SET statement_timeout='120000'")
    cur.execute(SQL, (list(EXEC_EXT), case_key))
    rows = cur.fetchall()
    if not rows:
        return None, 'no_mft'

    # tree of dicts: name -> node; node = {'_': [files, bytes, deleted, execs], children...}
    root = {'_': [0, 0, 0, 0]}
    for pp, files, size, deleted, execs in rows:
        node = root
        for seg in _parts(pp):
            node = node.setdefault(seg, {'_': [0, 0, 0, 0]})
        st = node['_']
        st[0] += files
        st[1] += int(size or 0)
        st[2] += deleted
        st[3] += execs

    def total(node):
        t = list(node['_'])
        for k, v in node.items():
            if k != '_':
                c = total(v)
                for i in range(4):
                    t[i] += c[i]
        node['T'] = t
        return t
    tot = total(root)

    hot = []

    def walk_hot(node, path):
        for k, v in node.items():
            if k in ('_', 'T'):
                continue
            p = path + '\\' + k
            if v['_'][3] and HOT_SEG.match(k):
                hot.append((p, v['_'][3], v['_'][0]))
            walk_hot(v, p)
    walk_hot(root, '')
    hot.sort(key=lambda x: (-x[1], x[0]))

    out = ['ДЕРЕВО ТЕК ДИСКА — справа %s' % case_key,
           'Джерело: таблиця $MFT (MFTECmd), зібрана збирачем. Показано теки; кількість і розмір — файли',
           'безпосередньо в теці та (у дужках) разом з підтеками. [DEL n] — видалені записи MFT у теці.',
           '',
           'Разом: тек %d, файлів %d (%s), видалених записів %d, виконуваних файлів і сценаріїв %d.'
           % (len(rows), tot[0], _size(tot[1]), tot[2], tot[3]),
           '']
    if hot:
        out.append('СПЕРШУ ГЛЯНУТИ: виконувані файли або сценарії в теках, де програми зазвичай не живуть')
        out.append('(Temp, Downloads, Public, корінь ProgramData/AppData, Rar$, кошик). Не вирок — перелік для перевірки.')
        for p, n, f in hot[:60]:
            out.append('  (*) C:%s  — виконуваних %d із %d файлів' % (p, n, f))
        if len(hot) > 60:
            out.append('  ... ще %d тек' % (len(hot) - 60))
        out.append('')
    out.append('ДЕРЕВО')
    out.append('[корінь тому] (NTFS-метафайли в корені великі: $BadClus розріджений і має розмір усього тому)')
    truncated = [False]

    def render(node, prefix, depth):
        kids = sorted((k for k in node if k not in ('_', 'T')), key=lambda s: s.lower())
        for i, k in enumerate(kids):
            if len(out) >= MAX_LINES:
                truncated[0] = True
                return
            v = node[k]
            last = i == len(kids) - 1
            own, t = v['_'], v['T']
            line = '%s%s%s  <%d ф., %s' % (prefix, '`-- ' if last else '+-- ', k, own[0], _size(own[1]))
            if t[0] != own[0]:
                line += ' (з підтеками %d ф., %s)' % (t[0], _size(t[1]))
            line += '>'
            if own[2]:
                line += ' [DEL %d]' % own[2]
            if own[3] and HOT_SEG.match(k):
                line += ' (*)'
            out.append(line)
            if depth + 1 < MAX_DEPTH:
                render(v, prefix + ('    ' if last else '|   '), depth + 1)
            elif len(v) > 2:
                out.append(prefix + ('    ' if last else '|   ') + '... глибше %d рівня не показано' % MAX_DEPTH)
    render(root, '', 0)
    if truncated[0]:
        out.append('')
        out.append('!! Дерево обрізано на %d рядках. Повний перелік файлів — у CSV MFTECmd в архіві справи.' % MAX_LINES)
    stats = {'dirs': len(rows), 'files': tot[0], 'bytes': tot[1], 'deleted': tot[2], 'execs': tot[3],
             'hot': len(hot), 'lines': len(out), 'truncated': truncated[0]}
    return '\n'.join(out) + '\n', stats
