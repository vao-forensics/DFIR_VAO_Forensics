# -*- coding: utf-8 -*-
"""Завантаження, які tusd прийняв, а справа так і не отримала.

НАВІЩО. Хук tusd має вікно повторів; якщо служба саме перезапускається й не встигає
відповісти, повтори вичерпуються - і завантаження гине тихо: браузер отримав «успішно»,
а файлу в справі немає. Спіймано 18.09 на власному тесті, за 16 секунд після рестарту.

Вікно повторів розширено (3 с -> до 2 хв), але це не гарантія: служба може лежати довше.
Тому тут - звірка. tusd лишає свою копію в `var/uploads` разом із `.info`, де записано
імʼя файлу, справа й режим. Отже завжди можна спитати: цей файл доїхав?

Нічого не видаляє і нічого не надсилає без прямої команди: копія в tusd - це останній шанс
на матеріал, який людина вважає завантаженим.

    python3 tusd_reconcile.py            показати, що не доїхало
    python3 tusd_reconcile.py --repost   надіслати їх у бота ще раз
"""
import json
import os
import re
import sys
import urllib.request

UPLOADS = os.environ.get('TUSD_DIR', '/srv/dfir/var/uploads')
CASE_LIB = os.environ.get('CASE_LIB_HOST', '/srv/dfir/cases')
STORE_URL = os.environ.get('STORE_URL', 'http://192.168.100.128:8097/store-tusd')


# Ключі, які не є справами: службові завдання інструментів і наші ж перевірки.
_IGNORE_CASE_RX = re.compile(
    r'^(tooljob-|zz_|ZZ_)|(_test|_check|_probe|gate_test)$', re.I)


def uploads():
    """[(id, meta, size)] для завершених завантажень."""
    out = []
    for f in sorted(os.listdir(UPLOADS)):
        if not f.endswith('.info'):
            continue
        path = os.path.join(UPLOADS, f)
        try:
            info = json.load(open(path, encoding='utf-8'))
        except Exception:
            continue
        blob = path[:-5]
        if not os.path.isfile(blob):
            continue
        meta = info.get('MetaData') or {}
        size = info.get('Size') or 0
        done = os.path.getsize(blob) >= int(size or 0) > 0
        if done:
            out.append((os.path.basename(blob), meta, int(size)))
    return out


def audit_verdicts():
    """{імʼя файлу: вердикт} з журналу прийому. Порожньо - якщо журналу немає."""
    out = {}
    try:
        sys.path.insert(0, '/srv/dfir/services/case_maintainer')
        import psycopg2
        from core.config import PG_DSN
        # `logdb` - імʼя з docker-мережі; з ВМ база видна на опублікованому порту
        # форма DSN: 'host=logdb port=5432 dbname=... user=...'
        PG_DSN = PG_DSN.replace('host=logdb', 'host=127.0.0.1').replace(
            'port=5432', 'port=5433')
        conn = psycopg2.connect(PG_DSN)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout='20s'")
            cur.execute("SELECT file_name, case_key, verdict FROM upload_audit_v1")
            for fn, ck, verdict in cur.fetchall():
                out[(str(ck or ''), str(fn or ''))] = verdict
        conn.close()
    except Exception as e:
        print('   (журнал прийому недоступний: %s)' % repr(e)[:80])
    return out


def landed(meta, size):
    """Чи лежить цей файл у справі. Порівнюємо за розміром, а не лише за імʼям:
    імʼя може бути змінене при збереженні (дедуплікація додає суфікс)."""
    case = (meta.get('case_key') or '').strip()
    name = (meta.get('filename') or '').strip()
    if not case or not name:
        return None                      # без цього не перевірити - хай людина гляне
    root = os.path.join(CASE_LIB, case)
    if not os.path.isdir(root):
        return False
    stem = os.path.splitext(name)[0][:40]
    for base, _dirs, files in os.walk(root):
        for f in files:
            if f.endswith('.info.json'):
                continue
            if f == name or stem and f.startswith(stem):
                return True
            try:
                if size and os.path.getsize(os.path.join(base, f)) == size:
                    return True
            except OSError:
                pass
    return False


def repost(uid, meta):
    body = json.dumps({'upload_id': uid, 'case_key': meta.get('case_key'),
                       'mode': meta.get('mode'), 'file_name': meta.get('filename'),
                       'chat_id': meta.get('chat_id') or ''}).encode('utf-8')
    req = urllib.request.Request(STORE_URL, data=body,
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=600) as r:
        return r.getcode(), r.read()[:200].decode('utf-8', 'replace')


def main(argv):
    rows = uploads()
    verdicts = audit_verdicts()
    lost, refused, gone, service = [], 0, 0, 0
    for uid, meta, size in rows:
        case = (meta.get('case_key') or '').strip()
        name = (meta.get('filename') or '').strip()
        verdict = verdicts.get((case, name))
        if verdict == 'rejected':
            refused += 1                 # відхилено за задумом - не втрата
            continue
        if landed(meta, size):
            continue
        if verdict == 'accepted':
            gone += 1                    # прийнято, але у справі немає: справу видалили
            continue
        if _IGNORE_CASE_RX.search(case):
            service += 1                 # завдання інструмента або наша ж перевірка
            continue
        lost.append((uid, meta, size))
    print('завершених завантажень у tusd: %d' % len(rows))
    print('відхилено воротами (за задумом): %d;  прийнято, але справу видалено: %d;'
          % (refused, gone))
    print('службові/тестові (не справи): %d' % service)
    print('ВТРАЧЕНО (жодного запису про прийом): %d' % len(lost))
    for uid, meta, size in lost:
        print('  %s  %-28s %-8s %7.1f МБ  %s'
              % (uid[:12], (meta.get('case_key') or '?')[:28], meta.get('mode') or '?',
                 size / 1048576.0, (meta.get('filename') or '?')[:40]))
    if '--repost' in argv and lost:
        print()
        for uid, meta, size in lost:
            try:
                code, body = repost(uid, meta)
                print('  надіслано %s -> %s %s' % (uid[:12], code, body[:80]))
            except Exception as e:
                print('  НЕ вдалось %s: %s' % (uid[:12], repr(e)[:90]))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
