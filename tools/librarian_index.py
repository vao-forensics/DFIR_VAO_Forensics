# -*- coding: utf-8 -*-
"""Індекс бібліотекаря: усе, що ми ВЖЕ зʼясували по кожній справі — в одному місці.

НАВІЩО. Загальний чат має роль бібліотекаря: знати, де що лежить, і памʼятати, що ми вже
з'ясували. Виміряно 18.09: семантично проіндексовано звіти лише **5 справ із 24**, а
`kb_cases` містив 178 із 185 точок з ОДНОГО кейсу. Тому на питання «що ми вирішили у справі
X» або «де ми вже таке бачили» бібліотекар відповісти не міг — знаходив лише випадкові збіги
слів у сирих артефактах.

ЩО ІНДЕКСУЄМО (тільки те, що написали МИ САМІ):
  * звіти, які згенерував бот           — файли .md у теці справи
  * питання й відповіді по справі       — dfir_qa_cache_v1, dfir_case_qa_v1
  * перевірені висновки                 — dfir_case_verified_findings
  * журнал розслідування                — dfir_investigation_journal_v1

ЧОГО НЕ ІНДЕКСУЄМО І ЧОМУ. Завантажені PDF/DOCX (експертні висновки, довідки, листування)
не читаються цим інструментом: у них персональні дані людей, і діє правило не тягнути їх
вміст туди, де він може виринути у відповіді на стороннє питання. Сирі артефакти теж не
індексуються — по них уже працює точний пошук по базі, і він для цього кращий.

ІДЕМПОТЕНТНО: перед записом справи її старі точки видаляються, тож повторний запуск нічого
не дублює. Можна ганяти після кожного аналізу.

Запуск:
    python3 tools/librarian_index.py --stats          що вже проіндексовано
    python3 tools/librarian_index.py --case <ключ>    одна справа
    python3 tools/librarian_index.py --all            усі справи
"""
import hashlib
import io
import json
import os
import re
import sys
import time
import urllib.request

sys.path.insert(0, '/app')

from core.config import PG_DSN, QDRANT_URL          # noqa: E402
import psycopg2                                      # noqa: E402

COLL = 'kb_librarian_v1'
DIM = int(os.environ.get('DFIR_EMBED_DIM', '4096'))
EMBED_URL = os.environ.get('DFIR_EMBED_URL', 'http://192.168.100.1:5899').rstrip('/')
EMBED_MODEL = os.environ.get('DFIR_EMBED_MODEL', 'text-embedding-qwen3-embedding-8b-cpu')
CASE_LIB = os.environ.get('CASE_LIBRARY', '/data/case_library')

CHUNK = 1800            # символів на фрагмент: одна думка, а не сторінка
OVERLAP = 120
MAX_TEXT = 20000        # зі звіту беремо початок: висновки в ньому завжди на початку


def _q(method, path, body=None, timeout=60):
    req = urllib.request.Request(
        QDRANT_URL.rstrip('/') + path,
        data=json.dumps(body).encode('utf-8') if body is not None else None,
        headers={'Content-Type': 'application/json'}, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode('utf-8', 'replace'))


def ensure_collection():
    try:
        _q('GET', '/collections/' + COLL, timeout=10)
        return False
    except Exception:
        _q('PUT', '/collections/' + COLL,
           {'vectors': {'size': DIM, 'distance': 'Cosine'}})
        # за кейсом фільтруємо в кожному запиті - без індексу це скан усієї колекції
        try:
            _q('PUT', '/collections/%s/index' % COLL,
               {'field_name': 'case_key', 'field_schema': 'keyword'})
        except Exception:
            pass
        return True


def embed(text):
    body = json.dumps({'model': EMBED_MODEL, 'input': (text or '')[:2000]}).encode('utf-8')
    req = urllib.request.Request(EMBED_URL + '/v1/embeddings', data=body,
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.loads(r.read().decode('utf-8', 'ignore'))['data'][0]['embedding']


def embed_many(texts, batch=16):
    """Вектори для списку фрагментів. Один запит на пакет - окремі запити з контейнера на
    хост коштували 2,2 с на фрагмент при 0,26 с у самого ембеддера."""
    out = []
    for i in range(0, len(texts), batch):
        part = [t[:2000] for t in texts[i:i + batch]]
        body = json.dumps({'model': EMBED_MODEL, 'input': part}).encode('utf-8')
        req = urllib.request.Request(EMBED_URL + '/v1/embeddings', data=body,
                                     headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=900) as r:
            data = json.loads(r.read().decode('utf-8', 'ignore'))['data']
        # порядок не гарантований специфікацією - впорядковуємо за index
        data.sort(key=lambda d: d.get('index', 0))
        out.extend(d['embedding'] for d in data)
    return out


def chunks(text, size=CHUNK, overlap=OVERLAP):
    text = re.sub(r'\n{3,}', '\n\n', (text or '').strip())
    if not text:
        return []
    out, i = [], 0
    while i < len(text):
        piece = text[i:i + size]
        if len(piece.strip()) > 80:
            out.append(piece.strip())
        i += max(1, size - overlap)
    return out


# ------------------------------------------------------------------ що збираємо
def _report_files(case_key):
    """Звіти, які згенерував БОТ. Завантажені PDF/DOCX свідомо не чіпаємо."""
    root = os.path.join(CASE_LIB, case_key)
    out = []
    for base, _dirs, files in os.walk(root):
        if '/uploads/' in base.replace('\\', '/'):
            continue                      # там лежить те, що прислала людина
        for f in files:
            if f.lower().endswith(('.md', '.txt')) and not f.startswith('.'):
                out.append(os.path.join(base, f))
    return sorted(out)[:12]


def collect(case_key, conn):
    """[(kind, title, text, source)] - усе, що ми самі написали про цю справу."""
    items = []

    for path in _report_files(case_key):
        try:
            txt = io.open(path, encoding='utf-8', errors='replace').read()[:MAX_TEXT]
        except Exception:
            continue
        if len(txt.strip()) < 200:
            continue
        items.append(('report', os.path.basename(path), txt, os.path.basename(path)))

    def rows(sql, args=()):
        try:
            with conn.cursor() as cur:
                cur.execute("SET statement_timeout='20s'")
                cur.execute(sql, args)
                return cur.fetchall()
        except Exception as e:
            try:
                conn.rollback()
            except Exception:
                pass
            print('   (пропущено: %s)' % repr(e)[:90])
            return []

    for q, a in rows("SELECT question, answer FROM dfir_qa_cache_v1 "
                     "WHERE case_key=%s AND answer IS NOT NULL", (case_key,)):
        if q and a and len(str(a)) > 60:
            items.append(('qa', str(q)[:200], u'Питання: %s\nВідповідь: %s' % (q, a), 'Q&A'))

    for q, a in rows("SELECT question, answer FROM dfir_case_qa_v1 "
                     "WHERE case_key=%s AND answer IS NOT NULL", (case_key,)):
        if q and a and len(str(a)) > 60:
            items.append(('qa', str(q)[:200], u'Питання: %s\nВідповідь: %s' % (q, a), 'Q&A'))

    # dfir_case_verified_findings: title/value, а не summary/detail. Схему я вгадав
    # неправильно, і перший же прогін це показав — тепер за фактичними колонками.
    for r in rows("SELECT finding_type, title, value, confidence FROM "
                  "dfir_case_verified_findings WHERE case_key=%s", (case_key,)):
        ft, title, value, conf = (list(r) + [None] * 4)[:4]
        body = u'%s: %s\n%s' % (ft or '', title or '', value or '')
        if len(body.strip()) > 60:
            items.append(('finding', str(title or ft or '')[:200], body,
                          u'висновок (%s)' % (conf or '?')))

    # журнал: беремо лише РОЗДУМИ моделі, не сирі результати інструментів
    for r in rows("SELECT kind, tool, reasoning FROM dfir_investigation_journal_v1 "
                  "WHERE case_key=%s AND reasoning IS NOT NULL", (case_key,)):
        kind, tool, reasoning = (list(r) + [None] * 3)[:3]
        if reasoning and len(str(reasoning)) > 80:
            items.append(('journal', ('%s %s' % (kind or '', tool or ''))[:120],
                          str(reasoning), 'журнал'))

    return items


def _fresh_conn(conn):
    """Живе зʼєднання: довгий прогін рве старе, і тоді справа мовчки втрачає Q&A."""
    try:
        if conn is not None and not conn.closed:
            with conn.cursor() as cur:
                cur.execute('SELECT 1')
            return conn
    except Exception:
        pass
    try:
        if conn is not None:
            conn.close()
    except Exception:
        pass
    c = psycopg2.connect(PG_DSN)
    c.autocommit = True
    return c


def index_case(case_key, conn, verbose=True):
    conn = _fresh_conn(conn)
    items = collect(case_key, conn)
    if not items:
        if verbose:
            print('  %-44s нічого індексувати' % case_key[:44])
        return 0

    # 1) усі фрагменти справи
    meta, texts = [], []
    for item_no, (kind, title, text, source) in enumerate(items):
        for ci, piece in enumerate(chunks(text)):
            meta.append((kind, title, source, ci, item_no))
            texts.append(piece)
    if not texts:
        return 0

    # 2) один прохід ембеддером - пакетами
    try:
        vecs = embed_many(texts)
    except Exception as e:
        print('   ембеддер не відповів: %s' % repr(e)[:90])
        return -1
    if len(vecs) != len(texts):
        print('   ембеддер повернув %d векторів на %d фрагментів - пропускаю справу'
              % (len(vecs), len(texts)))
        return -1

    # 3) старі точки цієї справи геть, нові - на місце (щоб повтор не дублював)
    _q('POST', '/collections/%s/points/delete?wait=true' % COLL,
       {'filter': {'must': [{'key': 'case_key', 'match': {'value': case_key}}]}})

    points = []
    for (kind, title, source, ci, item_no), piece, vec in zip(meta, texts, vecs):
        pid = hashlib.sha1(
            ('%s|%s|%d|%d' % (case_key, kind, item_no, ci)).encode('utf-8')).hexdigest()
        points.append({'id': int(pid[:15], 16), 'vector': vec,
                       'payload': {'case_key': case_key, 'kind': kind, 'title': title,
                                   'text': piece, 'source': source, 'chunk': ci,
                                   'indexed_at': time.strftime('%Y-%m-%dT%H:%M:%S')}})
        if len(points) >= 64:
            _q('PUT', '/collections/%s/points?wait=true' % COLL, {'points': points})
            points = []
    if points:
        _q('PUT', '/collections/%s/points?wait=true' % COLL, {'points': points})

    if verbose:
        kinds = {}
        for k, _t, _x, _s in items:
            kinds[k] = kinds.get(k, 0) + 1
        print('  %-44s %4d фрагментів  (%s)'
              % (case_key[:44], len(texts),
                 ', '.join('%s:%d' % kv for kv in sorted(kinds.items()))), flush=True)
    return len(texts)


def _existing_ids(ids):
    """Які з цих ідентифікаторів уже лежать у колекції."""
    have = set()
    for i in range(0, len(ids), 256):
        part = ids[i:i + 256]
        try:
            r = _q('POST', '/collections/%s/points' % COLL,
                   {'ids': part, 'with_payload': False, 'with_vector': False})
            for p in r.get('result') or []:
                have.add(p['id'])
        except Exception:
            pass
    return have


def repair_case(case_key, conn, verbose=True):
    """Дописати лише відсутні фрагменти справи. Нічого не видаляє."""
    conn = _fresh_conn(conn)
    items = collect(case_key, conn)
    meta, texts, ids = [], [], []
    for item_no, (kind, title, text, source) in enumerate(items):
        for ci, piece in enumerate(chunks(text)):
            pid = hashlib.sha1(
                ('%s|%s|%d|%d' % (case_key, kind, item_no, ci)).encode('utf-8')).hexdigest()
            meta.append((kind, title, source, ci, item_no))
            texts.append(piece)
            ids.append(int(pid[:15], 16))
    if not ids:
        return 0

    have = _existing_ids(ids)
    todo = [i for i, pid in enumerate(ids) if pid not in have]
    if not todo:
        if verbose:
            print('  %-44s уже повна (%d)' % (case_key[:44], len(ids)), flush=True)
        return 0

    try:
        vecs = embed_many([texts[i] for i in todo])
    except Exception as e:
        print('   ембеддер не відповів: %s' % repr(e)[:90])
        return -1

    points = []
    for n, i in enumerate(todo):
        kind, title, source, ci, item_no = meta[i]
        points.append({'id': ids[i], 'vector': vecs[n],
                       'payload': {'case_key': case_key, 'kind': kind, 'title': title,
                                   'text': texts[i], 'source': source, 'chunk': ci,
                                   'indexed_at': time.strftime('%Y-%m-%dT%H:%M:%S')}})
        if len(points) >= 64:
            _q('PUT', '/collections/%s/points?wait=true' % COLL, {'points': points})
            points = []
    if points:
        _q('PUT', '/collections/%s/points?wait=true' % COLL, {'points': points})
    if verbose:
        print('  %-44s дописано %4d з %d' % (case_key[:44], len(todo), len(ids)), flush=True)
    return len(todo)


def stats():
    try:
        info = _q('GET', '/collections/' + COLL, timeout=10)['result']
    except Exception:
        print('Колекції %s ще немає.' % COLL)
        return
    total = info.get('points_count')
    per = {}
    off = None
    while True:
        body = {'limit': 1000, 'with_payload': ['case_key', 'kind'], 'with_vector': False}
        if off:
            body['offset'] = off
        r = _q('POST', '/collections/%s/points/scroll' % COLL, body)['result']
        for p in r['points']:
            pl = p.get('payload') or {}
            per.setdefault(pl.get('case_key', '?'), {}).setdefault(pl.get('kind', '?'), 0)
            per[pl.get('case_key', '?')][pl.get('kind', '?')] += 1
        off = r.get('next_page_offset')
        if not off:
            break
    print('%s: %s фрагментів, справ: %d' % (COLL, total, len(per)))
    for ck in sorted(per):
        print('  %-44s %s' % (ck[:44],
                              ', '.join('%s:%d' % kv for kv in sorted(per[ck].items()))))


def real_cases():
    """Справи, а не сміття: тека з датою в імені або з результатами аналізу."""
    out = []
    for d in sorted(os.listdir(CASE_LIB)):
        p = os.path.join(CASE_LIB, d)
        if not os.path.isdir(p) or d.startswith(('_', 'zz_', '.')):
            continue
        if re.match(r'^\d{2}_\d{2}_\d{4}', d) or _report_files(d):
            out.append(d)
    return out


def main(argv):
    if '--stats' in argv:
        stats()
        return 0
    created = ensure_collection()
    if created:
        print('створено колекцію %s (%d вимірів)' % (COLL, DIM))

    # Зʼєднання відкривається вручну, БЕЗ `with`: на довгому прогоні воно вмирає, а
    # _fresh_conn() підмінює його новим - контекстний менеджер потім спіткнувся б об
    # старий обʼєкт (саме так прогін і впав 18.09).
    conn = psycopg2.connect(PG_DSN)
    conn.autocommit = True
    try:
        if '--case' in argv:
            ck = argv[argv.index('--case') + 1]
            return 0 if index_case(ck, conn) >= 0 else 1
        if '--repair' in argv:
            cases = real_cases()
            print('ремонтую %d справ...' % len(cases), flush=True)
            t0, total = time.time(), 0
            for ck in cases:
                conn = _fresh_conn(conn)
                r = repair_case(ck, conn)
                if r > 0:
                    total += r
            print('дописано %d фрагментів за %.0f с' % (total, time.time() - t0))
            return 0
        if '--all' in argv:
            cases = real_cases()
            print('індексую %d справ...' % len(cases), flush=True)
            t0, total, failed = time.time(), 0, []
            for ck in cases:
                conn = _fresh_conn(conn)
                r = index_case(ck, conn)
                if r < 0:
                    failed.append(ck)
                    continue          # одна справа не має спиняти решту
                total += r
            print('готово: %d фрагментів за %.0f с' % (total, time.time() - t0))
            if failed:
                print('НЕ проіндексовано (%d): %s' % (len(failed), ', '.join(failed)))
                return 1
            return 0
    finally:
        try:
            conn.close()
        except Exception:
            pass
    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
