"""Shared lesson storage and retrieval — used by synthesis, chat, and idle workers."""
import json, logging, uuid, urllib.request
try:
    import psycopg2
except ImportError:  # keep host-side unit tests importable without DB driver
    psycopg2 = None  # type: ignore[assignment]


def _pg_connect(*args, **kwargs):
    if psycopg2 is None:
        raise RuntimeError('psycopg2 is not installed')
    return psycopg2.connect(*args, **kwargs)

from core.config import PG_DSN, LLM_URL, EMBED_URL, EMBED_MODEL, QDRANT_URL
_log = logging.getLogger('app')

_KB_CASE_KNOWLEDGE = 'kb_case_knowledge'


def _ensure_kb_case_knowledge():
    """Create kb_case_knowledge Qdrant collection if not exists (dim=4096, Cosine)."""
    try:
        _cr = urllib.request.Request(f'{QDRANT_URL}/collections/{_KB_CASE_KNOWLEDGE}', method='GET')
        with urllib.request.urlopen(_cr, timeout=5) as r:
            r.read()
    except Exception as _e:
        if getattr(_e, 'code', None) == 404:
            try:
                _body = json.dumps({'vectors': {'size': 4096, 'distance': 'Cosine'}}).encode()
                _pr = urllib.request.Request(
                    f'{QDRANT_URL}/collections/{_KB_CASE_KNOWLEDGE}',
                    data=_body, headers={'Content-Type': 'application/json'}, method='PUT'
                )
                with urllib.request.urlopen(_pr, timeout=10) as r:
                    r.read()
                _log.info(f"[learnings] Created Qdrant collection {_KB_CASE_KNOWLEDGE}")
            except Exception as _ce:
                _log.error(f"[learnings] Failed to create {_KB_CASE_KNOWLEDGE}: {_ce}")


def _has_active_production_run():
    """Return True if any DFIR job is currently queued or running."""
    try:
        with _pg_connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) FROM dfir_run_jobs_v2
                    WHERE status IN ('queued','running')
                    AND created_at >= NOW() - INTERVAL '2 hours'
                """)
                return cur.fetchone()[0] > 0
    except Exception:
        return False


def _idle_semantic_lessons(case_key, question_text, limit=5, skip_production_check=False):
    """Semantic search in Qdrant dfir_lessons_learned_v1 for relevant lessons."""
    if not skip_production_check and _has_active_production_run():
        return []
    try:
        llm_url = EMBED_URL
        embed_model = EMBED_MODEL
        _eb = json.dumps({'model': embed_model, 'input': question_text[:500]}).encode('utf-8')
        _er = urllib.request.Request(
            llm_url.rstrip('/') + '/v1/embeddings',
            data=_eb, headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(_er, timeout=10) as _resp:
            vec = json.loads(_resp.read().decode())['data'][0]['embedding']

        _sb = json.dumps({
            'vector': vec, 'limit': limit, 'with_payload': True,
            'filter': {'should': [
                {'key': 'case_key', 'match': {'value': case_key}},
                {'key': 'lesson_type', 'match': {'any': ['gap_from_self_eval', 'good_answer', 'seed', 'user_approved']}}
            ]}
        }).encode('utf-8')
        _sr = urllib.request.Request(
            f'{QDRANT_URL}/collections/dfir_lessons_learned_v1/points/search',
            data=_sb, headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(_sr, timeout=10) as _sresp:
            pts = json.loads(_sresp.read().decode()).get('result', [])
        return [p['payload'].get('lesson_text', '') for p in pts if p.get('payload', {}).get('lesson_text')]
    except Exception:
        return []


def _save_lesson(case_key, intent, lesson_type, lesson_text, source_tables, source_artifacts, query_hints, conn=None):
    """Save lesson to PostgreSQL and Qdrant. Filters out garbage before saving."""
    # Quality filter: skip empty, too short, or LLM garbage (>40% question marks)
    if not lesson_text or len(lesson_text.strip()) < 40:
        return
    q_ratio = lesson_text.count('?') / max(len(lesson_text), 1)
    if q_ratio > 0.3:
        return
    close_conn = False
    if conn is None:
        conn = _pg_connect(PG_DSN)
        close_conn = True
    try:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO dfir_lessons_learned_v1
                (case_key, intent, lesson_type, lesson_text, source_tables, source_artifacts, reusable_query_hints)
                VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                (case_key, intent, lesson_type, lesson_text,
                 json.dumps(source_tables), json.dumps(source_artifacts), json.dumps(query_hints)))
            lesson_id = cur.fetchone()[0]
            conn.commit()

        # Embed and store in Qdrant
        try:
            embed_base = EMBED_URL
            embed_model = EMBED_MODEL
            _embed_body = json.dumps({'model': embed_model, 'input': lesson_text[:500]}).encode('utf-8')
            _embed_req = urllib.request.Request(
                f'{embed_base.rstrip("/")}/v1/embeddings',
                data=_embed_body, headers={'Content-Type': 'application/json'}
            )
            with urllib.request.urlopen(_embed_req, timeout=600) as _er:
                _edata = json.loads(_er.read().decode('utf-8', errors='ignore'))
            vec = _edata['data'][0]['embedding']
            _pt_body = json.dumps({'points': [{'id': str(uuid.uuid4()), 'vector': vec,
                'payload': {'lesson_id': lesson_id, 'case_key': case_key, 'intent': intent,
                            'lesson_type': lesson_type, 'lesson_text': lesson_text}}]}).encode('utf-8')
            _pt_req = urllib.request.Request(
                f'{QDRANT_URL}/collections/dfir_lessons_learned_v1/points',
                data=_pt_body, headers={'Content-Type': 'application/json'}, method='PUT'
            )
            with urllib.request.urlopen(_pt_req, timeout=10) as _pr:
                _pr.read()
        except Exception as _ee:
            _log.error(f"[idle] _save_lesson embed/qdrant error: {_ee}")

        return lesson_id
    finally:
        if close_conn:
            try: conn.close()
            except: pass


def _lesson_dedup_upsert(case_key, intent, lesson_type, lesson_text,
                         source_tables=None, source_event_ids=None, tools=None,
                         approved_by_user=False, conn=None):
    """Compat shim for workers.report_extractor (Theme B): map the dedup-upsert
    call onto _save_lesson (which already quality-filters; cross-run dedup is
    handled by lesson_reconcile). Returns truthy when a lesson was saved."""
    res = _save_lesson(case_key, intent, lesson_type, lesson_text,
                       source_tables or [], source_event_ids or [], tools or [], conn=conn)
    return res if res is not None else True


def _get_relevant_lessons(case_key, intent_hint='', limit=5, for_synthesis=False):
    """Fetch relevant lessons — semantic Qdrant search first, fallback to keyword + cross-case."""
    results = []
    # 1. Semantic search (case-specific first).
    # for_synthesis=True bypasses production-run guard so synthesis can get lessons mid-run.
    if intent_hint and len(intent_hint) > 10:
        try:
            semantic = _idle_semantic_lessons(case_key, intent_hint, limit=limit,
                                              skip_production_check=for_synthesis)
            if semantic:
                results.extend(semantic)
        except Exception:
            pass
    # 2. Fallback: keyword match for this case in PostgreSQL
    if len(results) < limit:
        try:
            with _pg_connect(PG_DSN) as conn:
                with conn.cursor() as cur:
                    if intent_hint:
                        cur.execute("""SELECT lesson_text FROM dfir_lessons_learned_v1
                            WHERE case_key=%s AND intent ILIKE %s ORDER BY created_at DESC LIMIT %s""",
                            (case_key, f'%{intent_hint}%', limit - len(results)))
                    else:
                        cur.execute("""SELECT lesson_text FROM dfir_lessons_learned_v1
                            WHERE case_key=%s ORDER BY created_at DESC LIMIT %s""",
                            (case_key, limit - len(results)))
                    results.extend(r[0] for r in cur.fetchall())
        except Exception:
            pass
    # 3. Cross-case: if still not enough, search similar cases by intent keyword
    if len(results) < 3 and intent_hint and len(intent_hint) > 10:
        try:
            with _pg_connect(PG_DSN) as conn:
                with conn.cursor() as cur:
                    cur.execute("""SELECT lesson_text FROM dfir_lessons_learned_v1
                        WHERE case_key != %s AND lesson_type IN ('qa_pass','self_qa','gap_from_self_eval','seed','good_answer','user_approved')
                        AND (intent ILIKE %s OR lesson_text ILIKE %s)
                        ORDER BY created_at DESC LIMIT %s""",
                        (case_key, f'%{intent_hint[:40]}%', f'%{intent_hint[:40]}%', 3 - len(results)))
                    cross = [r[0] for r in cur.fetchall()]
                    if cross:
                        results.extend(f'[з іншого кейсу] {l}' for l in cross)
        except Exception:
            pass
    return results[:limit]


def _save_case_knowledge(case_key: str, fact_type: str, content: str,
                         source: str = '', confirmed_by: str = '') -> bool:
    """Save a confirmed fact to kb_case_knowledge Qdrant collection.
    fact_type: 'confirmed_answer' | 'confirmed_fact' | 'gap_finding' | 'wrong_approach'
    Returns True on success."""
    if not content or len(content.strip()) < 20:
        return False
    try:
        _ensure_kb_case_knowledge()
        _eb = json.dumps({'model': EMBED_MODEL, 'input': content[:500]}).encode()
        _er = urllib.request.Request(
            EMBED_URL.rstrip('/') + '/v1/embeddings',
            data=_eb, headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(_er, timeout=30) as r:
            vec = json.loads(r.read().decode())['data'][0]['embedding']

        _pb = json.dumps({'points': [{'id': str(uuid.uuid4()), 'vector': vec, 'payload': {
            'case_key': case_key, 'fact_type': fact_type,
            'content': content[:1000], 'source': source,
            'confirmed_by': confirmed_by,
        }}]}).encode()
        _pr = urllib.request.Request(
            f'{QDRANT_URL}/collections/{_KB_CASE_KNOWLEDGE}/points',
            data=_pb, headers={'Content-Type': 'application/json'}, method='PUT'
        )
        with urllib.request.urlopen(_pr, timeout=10) as r:
            r.read()
        return True
    except Exception as _e:
        _log.error(f"[learnings] _save_case_knowledge error: {_e}")
        return False


def _get_case_knowledge(case_key: str, query_text: str, limit: int = 3) -> list[str]:
    """Semantic search in kb_case_knowledge for confirmed facts about this case.
    Returns list of content strings, or [] on error / empty."""
    if not query_text or not case_key:
        return []
    try:
        _eb = json.dumps({'model': EMBED_MODEL, 'input': query_text[:500]}).encode()
        _er = urllib.request.Request(
            EMBED_URL.rstrip('/') + '/v1/embeddings',
            data=_eb, headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(_er, timeout=15) as r:
            vec = json.loads(r.read().decode())['data'][0]['embedding']

        _sb = json.dumps({
            'vector': vec, 'limit': limit, 'with_payload': True,
            'filter': {'must': [{'key': 'case_key', 'match': {'value': case_key}}]}
        }).encode()
        _sr = urllib.request.Request(
            f'{QDRANT_URL}/collections/{_KB_CASE_KNOWLEDGE}/points/search',
            data=_sb, headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(_sr, timeout=10) as r:
            pts = json.loads(r.read().decode()).get('result', [])
        return [p['payload']['content'] for p in pts if p.get('payload', {}).get('content')]
    except Exception:
        return []


def _get_relevant_playbook_suggestions(intent_hint='', limit=3):
    """Fetch APPROVED playbook suggestions — human-approved cross-case investigative
    methodology distilled from expert gold reports. Returns suggested_change strings,
    injected into the answerer prompt as 'how to investigate' hints."""
    out = []
    try:
        words = [w.strip('.,;:!?()[]"\'').lower() for w in str(intent_hint or '').split()]
        toks = [w for w in words if len(w) >= 5][:8]
        with _pg_connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                rows = []
                if toks:
                    clause = ' OR '.join(
                        ['suggested_change ILIKE %s OR title ILIKE %s OR problem ILIKE %s'] * len(toks))
                    params = []
                    for t in toks:
                        like = '%' + t + '%'
                        params += [like, like, like]
                    cur.execute(
                        "SELECT DISTINCT suggested_change FROM dfir_playbook_suggestions "
                        "WHERE status='approved' AND coalesce(suggested_change,'')<>'' AND ("
                        + clause + ") LIMIT %s", params + [limit])
                    rows = [r[0] for r in cur.fetchall()]
                if len(rows) < limit:
                    cur.execute(
                        "SELECT suggested_change FROM dfir_playbook_suggestions "
                        "WHERE status='approved' AND coalesce(suggested_change,'')<>'' "
                        "ORDER BY created_at DESC LIMIT %s", (limit,))
                    for r in cur.fetchall():
                        if r[0] not in rows:
                            rows.append(r[0])
                        if len(rows) >= limit:
                            break
                out = [str(s).strip()[:220] for s in rows[:limit] if s]
    except Exception:
        pass
    return out


def _get_provenance_hint(intent):
    """Theme A (step 4): on a cache MISS, map intent -> dfir_reusable_playbooks and
    return a short Ukrainian 'scan these first' hint string for the ReAct planner.
    Reads preferred_tables/preferred_event_ids/preferred_tools of the active playbook
    for the given intent. Returns '' on no match / error (graceful degrade)."""
    if not intent:
        return ''
    try:
        with _pg_connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT preferred_tables, preferred_event_ids, preferred_tools "
                    "FROM dfir_reusable_playbooks "
                    "WHERE intent_name=%s AND status='active' "
                    "ORDER BY success_count DESC LIMIT 1",
                    (intent,))
                row = cur.fetchone()
        if not row:
            return ''
        tables, eids, tools = row
        parts = []
        if tables:
            parts.append('Спершу перевір таблиці: ' + ', '.join(str(t) for t in tables[:6]))
        if eids:
            parts.append('EID: ' + ', '.join(str(e) for e in eids[:10]))
        if tools:
            parts.append('інструменти: ' + ', '.join(str(t) for t in tools[:6]))
        if not parts:
            return ''
        return '\n\n[ПІДКАЗКА З ПЛЕЙБУКА (де шукати — за минулими підтвердженими відповідями)]\n' + '; '.join(parts)
    except Exception:
        return ''
