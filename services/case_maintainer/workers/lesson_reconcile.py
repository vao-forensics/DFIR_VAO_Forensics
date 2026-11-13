"""Theme B4: reconcile Postgres <-> Qdrant lesson drift.

dfir_lessons_learned_v1 exists in BOTH Postgres (rows, id) and Qdrant (points,
payload.lesson_id). The two drift (PG rows missing a Qdrant point; Qdrant points
whose lesson_id no longer exists in PG). This worker diffs the id sets and:
  - for PG rows missing in Qdrant -> embed + upsert a point
  - for Qdrant points whose lesson_id is not in PG -> delete the point
Idempotent, batched, logs counts. Never runs during an active production run
(reuses learnings._has_active_production_run()).
"""
import json
import logging
import os
import urllib.request
import uuid

try:
    import psycopg2
except ImportError:
    psycopg2 = None

from core.config import PG_DSN, LLM_URL, EMBED_URL, EMBED_MODEL, QDRANT_URL
from analysis.learnings import _has_active_production_run

_log = logging.getLogger('app')
_COLL = 'dfir_lessons_learned_v1'


def _pg():
    if psycopg2 is None:
        raise RuntimeError('psycopg2 not installed')
    return psycopg2.connect(PG_DSN)


def _embed(text):
    body = json.dumps({'model': EMBED_MODEL, 'input': (text or '')[:500]}).encode()
    req = urllib.request.Request(EMBED_URL.rstrip('/') + '/v1/embeddings',
                                 data=body, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.loads(r.read().decode('utf-8', 'ignore'))['data'][0]['embedding']


def _scroll_qdrant_points():
    """Return list of (point_id, lesson_id) for all points in the collection."""
    base = QDRANT_URL.rstrip('/')
    out = []
    offset = None
    while True:
        body = {'limit': 256, 'with_payload': ['lesson_id'], 'with_vector': False}
        if offset is not None:
            body['offset'] = offset
        req = urllib.request.Request(f'{base}/collections/{_COLL}/points/scroll',
                                     data=json.dumps(body).encode(),
                                     headers={'Content-Type': 'application/json'}, method='POST')
        with urllib.request.urlopen(req, timeout=30) as r:
            res = json.loads(r.read().decode()).get('result', {})
        for p in res.get('points', []):
            lid = (p.get('payload') or {}).get('lesson_id')
            out.append((p.get('id'), lid))
        offset = res.get('next_page_offset')
        if not offset:
            break
    return out


def reconcile_lessons(dry_run=True, skip_production_check=False):
    summary = {'dry_run': dry_run, 'pg_rows': 0, 'qdrant_points': 0,
               'missing_in_qdrant': 0, 'embedded': 0,
               'orphan_points': 0, 'deleted': 0, 'errors': []}
    if not skip_production_check and _has_active_production_run():
        summary['errors'].append('active production run — skipped')
        return summary

    # PG side
    pg_rows = {}
    try:
        with _pg() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, case_key, intent, lesson_type, lesson_text "
                            "FROM dfir_lessons_learned_v1")
                for rid, ck, intent, lt, ltext in cur.fetchall():
                    pg_rows[rid] = (ck, intent, lt, ltext)
    except Exception as e:
        summary['errors'].append(f'pg read: {str(e)[:120]}')
        return summary
    summary['pg_rows'] = len(pg_rows)

    # Qdrant side
    try:
        qpts = _scroll_qdrant_points()
    except Exception as e:
        summary['errors'].append(f'qdrant scroll: {str(e)[:120]}')
        return summary
    summary['qdrant_points'] = len(qpts)
    q_lesson_ids = set(lid for _, lid in qpts if lid is not None)

    # 1. PG rows missing in Qdrant -> embed+upsert
    base = QDRANT_URL.rstrip('/')
    missing = [rid for rid in pg_rows if rid not in q_lesson_ids]
    summary['missing_in_qdrant'] = len(missing)
    for rid in missing:
        ck, intent, lt, ltext = pg_rows[rid]
        if not ltext or len(ltext.strip()) < 20:
            continue
        if dry_run:
            continue
        try:
            vec = _embed(ltext)
            pt = json.dumps({'points': [{'id': str(uuid.uuid4()), 'vector': vec,
                'payload': {'lesson_id': rid, 'case_key': ck, 'intent': intent,
                            'lesson_type': lt, 'lesson_text': ltext}}]}).encode()
            req = urllib.request.Request(f'{base}/collections/{_COLL}/points',
                                         data=pt, headers={'Content-Type': 'application/json'},
                                         method='PUT')
            with urllib.request.urlopen(req, timeout=15) as r:
                r.read()
            summary['embedded'] += 1
        except Exception as e:
            summary['errors'].append(f'embed id={rid}: {str(e)[:100]}')

    # 2. Qdrant points whose lesson_id not in PG -> delete
    pg_ids = set(pg_rows.keys())
    orphans = [pid for pid, lid in qpts if lid is not None and lid not in pg_ids]
    summary['orphan_points'] = len(orphans)
    if orphans and not dry_run:
        try:
            req = urllib.request.Request(f'{base}/collections/{_COLL}/points/delete',
                                         data=json.dumps({'points': orphans}).encode(),
                                         headers={'Content-Type': 'application/json'}, method='POST')
            with urllib.request.urlopen(req, timeout=30) as r:
                r.read()
            summary['deleted'] = len(orphans)
        except Exception as e:
            summary['errors'].append(f'delete orphans: {str(e)[:120]}')

    _log.info(f'[lesson_reconcile] {summary}')
    return summary


if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.INFO)
    dr = '--apply' not in sys.argv
    print(json.dumps(reconcile_lessons(dry_run=dr, skip_production_check=True),
                     ensure_ascii=False, indent=2))
