# -*- coding: utf-8 -*-
"""Завантаження, які ніхто не проаналізував.

НАВІЩО. 19.09 випадково знайшлося: у справі `case_39` лежить
`kape.csv` на 2,9 МБ, а в базі по ній **нуль рядків** - тобто людина залила матеріал, аналіз
не запустився, і ніхто про це не дізнався. Для системи, куди інші люди вантажать докази, це
найтихіший спосіб втратити справу: файл на місці, а роботи не було.

Модуль просто відповідає на питання «де є завантажений файл, але немає жодного рядка
доказів». Він нічого не запускає сам: рішення, чи аналізувати, лишається за людиною -
серед знахідок бувають і помилкові завантаження (фото, документ), які аналізувати не треба.
"""
import os

try:
    import psycopg2
except Exception:
    psycopg2 = None

SKIP_EXT = ('.info.json',)


def _case_upload_stats(case_dir):
    files, mb = 0, 0.0
    up = os.path.join(case_dir, 'uploads')
    if not os.path.isdir(up):
        return 0, 0.0, []
    names = []
    for root, _dirs, fs in os.walk(up):
        for f in fs:
            if f.endswith(SKIP_EXT):
                continue
            files += 1
            names.append(f)
            try:
                mb += os.path.getsize(os.path.join(root, f)) / 1048576.0
            except OSError:
                pass
    return files, mb, names[:4]


def find(case_lib, pg_dsn, min_mb=0.2):
    """[{case_key, files, mb, names}] - завантаження без жодного рядка доказів.

    `min_mb` відсікає дрібні вкладення на кшталт знімка екрана: це майже завжди не матеріал
    для аналізу, і показувати їх власникові щотижня - шум.
    """
    out = []
    if psycopg2 is None or not os.path.isdir(case_lib):
        return out
    conn = psycopg2.connect(pg_dsn)
    conn.autocommit = True
    try:
        for d in sorted(os.listdir(case_lib)):
            case_dir = os.path.join(case_lib, d)
            if not os.path.isdir(case_dir) or d.startswith(('_', 'zz_', '.')):
                continue
            files, mb, names = _case_upload_stats(case_dir)
            if not files or mb < min_mb:
                continue
            try:
                with conn.cursor() as cur:
                    cur.execute("SET statement_timeout='20s'")
                    cur.execute(
                        "SELECT (SELECT count(*) FROM event_logs_v2 WHERE case_key=%s), "
                        "       (SELECT count(*) FROM raw_fallback_v2 WHERE case_key=%s), "
                        "       (SELECT count(*) FROM filesystem_v2 WHERE case_key=%s)",
                        (d, d, d))
                    ev, rf, fs = cur.fetchone()
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                continue
            if (ev or 0) + (rf or 0) + (fs or 0) == 0:
                out.append({'case_key': d, 'files': files, 'mb': round(mb, 1),
                            'names': names})
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return out


def report(case_lib, pg_dsn):
    """Готовий текст для людини, або порожній рядок, якщо все проаналізовано."""
    rows = find(case_lib, pg_dsn)
    if not rows:
        return ''
    lines = ['⚠ Завантажено, але НЕ проаналізовано (%d):' % len(rows)]
    for r in rows:
        lines.append('   %s — %d файл(и), %.1f МБ: %s'
                     % (r['case_key'], r['files'], r['mb'], ', '.join(r['names'])[:70]))
    lines.append('   Це або забутий аналіз, або файл потрапив у справу помилково.')
    return '\n'.join(lines)


if __name__ == '__main__':
    import sys
    sys.path.insert(0, '/app')
    from core.config import PG_DSN
    print(report(os.environ.get('CASE_LIBRARY', '/data/case_library'), PG_DSN)
          or 'Усі завантаження проаналізовані.')
