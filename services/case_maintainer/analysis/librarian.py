# -*- coding: utf-8 -*-
"""Памʼять бібліотекаря: пошук по тому, що ми ВЖЕ зʼясували в усіх справах.

Точний пошук по базі відповідає на питання «де зустрічається rustdesk» — він шукає слово в
артефактах. Але на питання «що ми вирішили у справі X» або «де ми вже бачили таке саме» він
безсилий: там треба шукати за змістом, а не за буквою. Для цього є індекс `kb_librarian_v1`
(будує `tools/librarian_index.py`): звіти, які написав бот, питання-відповіді по справах,
перевірені висновки та журнал розслідування.

ПРАВИЛО ЦЬОГО МОДУЛЯ: він повертає ЦИТАТИ з назвою справи й джерела, а не власні висновки.
Семантичний пошук легко приносить «схоже, але не те», тому останнє слово лишається за
людиною, яка бачить, звідки взято рядок. Тому ж тут немає жодного узагальнення кількох
справ в одну відповідь.
"""
import json
import logging
import os
import urllib.request

COLL = 'kb_librarian_v1'
_log = logging.getLogger(__name__)

QDRANT_URL = os.environ.get('QDRANT_URL', 'http://qdrant:6333').rstrip('/')
EMBED_URL = os.environ.get('DFIR_EMBED_URL', 'http://192.168.100.1:5899').rstrip('/')
EMBED_MODEL = os.environ.get('DFIR_EMBED_MODEL', 'text-embedding-qwen3-embedding-8b-cpu')

KIND_LABEL = {'report': 'звіт', 'qa': 'питання-відповідь',
              'finding': 'перевірений висновок', 'journal': 'журнал розслідування'}


# Швидкий ембеддер на відеокарті; якщо його немає - штатний на CPU.
FAST_EMBED_URL = os.environ.get('DFIR_EMBED_FAST_URL', 'http://192.168.100.1:5898').rstrip('/')


def _embed_at(url, text, timeout):
    body = json.dumps({'model': EMBED_MODEL, 'input': (text or '')[:2000]}).encode('utf-8')
    req = urllib.request.Request(url + '/v1/embeddings', data=body,
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode('utf-8', 'ignore'))['data'][0]['embedding']


def _embed(text, timeout=90):
    """Спершу швидкий, потім повільний. 0,26 с проти 12-21 с - виміряно 18.09."""
    if FAST_EMBED_URL:
        try:
            return _embed_at(FAST_EMBED_URL, text, 15)
        except Exception as e:
            _log.info('[librarian] швидкий ембеддер недоступний (%s), йду на повільний',
                      repr(e)[:80])
    return _embed_at(EMBED_URL, text, timeout)


def available():
    """Чи є взагалі що шукати - щоб не обіцяти памʼять, якої немає."""
    try:
        req = urllib.request.Request(QDRANT_URL + '/collections/' + COLL)
        with urllib.request.urlopen(req, timeout=5) as r:
            return int(json.loads(r.read())['result'].get('points_count') or 0)
    except Exception:
        return 0


def recall(question, allowed_cases=None, top=5, min_score=0.55, case_key=None):
    """[(score, case_key, kind, title, text)] - найближче за змістом, або []."""
    if not question or available() <= 0:
        return []
    try:
        vec = _embed(question)
    except Exception as e:
        _log.warning('[librarian] ембеддер не відповів: %s', repr(e)[:120])
        return []

    body = {'vector': vec, 'limit': max(top * 3, 12), 'with_payload': True}
    must = []
    if case_key:
        must.append({'key': 'case_key', 'match': {'value': case_key}})
    elif allowed_cases is not None:
        must.append({'key': 'case_key', 'match': {'any': list(allowed_cases)}})
    if must:
        body['filter'] = {'must': must}

    try:
        req = urllib.request.Request(QDRANT_URL + '/collections/%s/points/search' % COLL,
                                     data=json.dumps(body).encode('utf-8'),
                                     headers={'Content-Type': 'application/json'},
                                     method='POST')
        with urllib.request.urlopen(req, timeout=30) as r:
            hits = json.loads(r.read().decode('utf-8', 'replace'))['result']
    except Exception as e:
        _log.warning('[librarian] пошук не вдався: %s', repr(e)[:120])
        return []

    out, seen = [], set()
    for h in hits:
        if float(h.get('score') or 0) < min_score:
            continue
        pl = h.get('payload') or {}
        ck = pl.get('case_key') or '?'
        # одна цитата на справу+тип: п'ять фрагментів одного звіту - це не п'ять відповідей
        key = (ck, pl.get('kind'))
        if key in seen:
            continue
        seen.add(key)
        out.append((float(h['score']), ck, pl.get('kind') or '?',
                    pl.get('title') or '', pl.get('text') or ''))
        if len(out) >= top:
            break
    return out


def format_recall(hits, pretty_name=None, header=None):
    """Готовий блок для відповіді. Порожній рядок, якщо немає чого показати."""
    if not hits:
        return ''
    name = pretty_name or (lambda c: c)
    lines = [header or '🧠 З того, що ми вже зʼясували раніше:']
    for score, ck, kind, title, text in hits:
        snippet = ' '.join((text or '').split())[:300]
        lines.append('')
        lines.append('📁 %s — %s%s' % (name(ck), KIND_LABEL.get(kind, kind),
                                       (': ' + title[:80]) if title else ''))
        lines.append('   %s' % snippet)
    lines.append('')
    lines.append('⚠ Це збіг за змістом, а не доказ: перевіряй у самій справі.')
    return '\n'.join(lines)
