"""Theme C2: one-time idempotent Qdrant payload indexes on the book collection.

Creates keyword payload indexes on case_key / source_file / doc_type for
kb_text_qwen3e8b_v1 so the Theme C1 LESSONS filter (and future facets) are
indexed rather than full-scanned. No re-embed. Safe to call at app startup —
fully wrapped so a missing collection / Qdrant down never crashes boot.
"""
import json
import logging
import os
import urllib.request

try:
    from core.config import QDRANT_URL, TEXT_COLL_PRIMARY
except Exception:  # keep importable host-side
    QDRANT_URL = os.getenv('DFIR_QDRANT_URL', 'http://qdrant:6333')
    TEXT_COLL_PRIMARY = os.getenv('DFIR_TEXT_COLL_PRIMARY', 'kb_text_qwen3e8b_v1')

_log = logging.getLogger('app')

_INDEX_FIELDS = ('case_key', 'source_file', 'doc_type')


def ensure_book_indexes(collection=None):
    """Create keyword payload indexes on the book collection. Idempotent:
    swallows 'already exists' and any error. Returns dict field->status."""
    coll = collection or TEXT_COLL_PRIMARY
    base = QDRANT_URL.rstrip('/')
    out = {}
    for f in _INDEX_FIELDS:
        try:
            body = json.dumps({'field_name': f, 'field_schema': 'keyword'}).encode()
            req = urllib.request.Request(
                f'{base}/collections/{coll}/index?wait=true',
                data=body, headers={'Content-Type': 'application/json'}, method='PUT')
            with urllib.request.urlopen(req, timeout=15) as r:
                r.read()
            out[f] = 'created'
        except Exception as e:
            msg = ''
            try:
                msg = e.read().decode('utf-8', 'ignore') if hasattr(e, 'read') else str(e)
            except Exception:
                msg = str(e)
            if 'already exists' in msg.lower() or getattr(e, 'code', None) == 200:
                out[f] = 'exists'
            else:
                out[f] = f'skip: {str(msg)[:120]}'
                _log.warning(f'[themebc_setup] index {f} on {coll}: {msg[:160]}')
    _log.info(f'[themebc_setup] ensure_book_indexes({coll}) -> {out}')
    return out


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    print(ensure_book_indexes())
