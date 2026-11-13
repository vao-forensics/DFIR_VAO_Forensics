"""QA cache — lookup, save, seed from evaluation results."""
import json, logging
import psycopg2
from core.config import PG_DSN
_log = logging.getLogger('app')

_REACT_MARKERS = ('THINK:', 'ACTION:', 'OBSERVATION:')


def _has_react_scratchpad(text: str) -> bool:
    return any(m in text for m in _REACT_MARKERS)


def _ensure_qa_cache_table():
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS dfir_qa_cache_v1 (
                    id bigserial PRIMARY KEY,
                    case_key text NOT NULL,
                    question text NOT NULL,
                    answer text NOT NULL,
                    source text NOT NULL DEFAULT 'user',
                    confidence real NOT NULL DEFAULT 1.0,
                    used_count integer NOT NULL DEFAULT 0,
                    analysis_ts timestamptz,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now(),
                    status text NOT NULL DEFAULT 'active'
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_qa_cache_case ON dfir_qa_cache_v1(case_key)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_qa_cache_trgm ON dfir_qa_cache_v1 USING gin(question gin_trgm_ops)")
            cur.execute("ALTER TABLE dfir_qa_cache_v1 ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active'")


def _qa_cache_lookup(case_key, question):
    """Check persistent Q&A cache.
    Returns (answer, created_at, similarity, is_direct) or None.
    is_direct=True → similarity >= 0.90 (return immediately).
    is_direct=False → 0.70-0.89 (use as context hint for LLM).
    Only returns records with status='active' and no ReAct scratchpad.
    """
    try:
        with psycopg2.connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT answer, created_at, similarity(question, %s) AS sim, id,
                           verified, provenance
                    FROM dfir_qa_cache_v1
                    WHERE case_key = %s
                      AND status = 'active'
                      AND similarity(question, %s) > 0.70
                      AND answer NOT ILIKE '%%THINK:%%'
                      AND answer NOT ILIKE '%%ACTION:%%'
                      AND answer NOT ILIKE '%%OBSERVATION:%%'
                    ORDER BY sim DESC
                    LIMIT 1
                """, (question, case_key, question))
                row = cur.fetchone()
                if not row:
                    return None
                answer, created_at, sim, row_id, row_verified, row_prov = row
                cur.execute("UPDATE dfir_qa_cache_v1 SET used_count=used_count+1, updated_at=now() WHERE id=%s", (row_id,))
                return {'answer': answer, 'created_at': created_at, 'sim': float(sim),
                        'is_direct': float(sim) >= 0.90,
                        'verified': bool(row_verified), 'provenance': row_prov}
    except Exception:
        return None


def _qa_cache_save(case_key, question, answer, source='user', confidence=1.0, provenance=None):
    """Save Q&A pair to persistent cache. Updates if similar question exists (sim>=0.90).
    Skips saving if answer contains ReAct scratchpad markers.
    Theme A: optional `provenance` dict (where/how the answer was found) is stored in
    the jsonb `provenance` column. `verified` stays default false until a human 👍.
    """
    if not answer or len(answer) < 30:
        return
    if _has_react_scratchpad(answer):
        _log.info(f'[qa_cache] skip save: ReAct scratchpad in answer')
        return
    _prov_json = json.dumps(provenance) if provenance else None
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # Check for near-duplicate
                cur.execute("""
                    SELECT id FROM dfir_qa_cache_v1
                    WHERE case_key=%s AND similarity(question, %s) >= 0.90
                    LIMIT 1
                """, (case_key, question))
                existing = cur.fetchone()
                if existing:
                    cur.execute("""
                        UPDATE dfir_qa_cache_v1
                        SET answer=%s, source=%s, confidence=%s, updated_at=now(),
                            provenance=COALESCE(%s, provenance)
                        WHERE id=%s
                    """, (answer, source, confidence, _prov_json, existing[0]))
                else:
                    # Get last analysis timestamp for this case
                    cur.execute("""
                        SELECT finished_at FROM dfir_run_jobs_v2
                        WHERE case_key=%s AND status='completed'
                        ORDER BY finished_at DESC LIMIT 1
                    """, (case_key,))
                    ts_row = cur.fetchone()
                    analysis_ts = ts_row[0] if ts_row else None
                    cur.execute("""
                        INSERT INTO dfir_qa_cache_v1(case_key, question, answer, source, confidence, analysis_ts, provenance)
                        VALUES(%s, %s, %s, %s, %s, %s, %s)
                    """, (case_key, question, answer, source, confidence, analysis_ts, _prov_json))
    except Exception as e:
        _log.info(f'[qa_cache] save error: {e}')


def _qa_cache_invalidate_case(case_key):
    """Theme A (step 5): on evidence re-ingest, demote all verified cache rows for a
    case back to verified=false (keeps the provenance hint). Returns rows touched."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("UPDATE dfir_qa_cache_v1 SET verified=false, updated_at=now() WHERE case_key=%s AND verified=true", (case_key,))
                return cur.rowcount
    except Exception as e:
        _log.info(f'[qa_cache] invalidate error: {e}')
        return 0


def _qa_cache_seed_from_eval():
    """Seed cache from existing dfir_eval_answers_v1 pass answers."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT a.case_key, q.question, a.bot_answer
                    FROM dfir_eval_answers_v1 a
                    JOIN dfir_eval_questions_v1 q ON q.id = a.question_id
                    WHERE a.id NOT IN (
                        SELECT answer_id FROM dfir_eval_failures_v1
                        WHERE answer_id IS NOT NULL
                    )
                    AND length(a.bot_answer) > 50
                """)
                rows = cur.fetchall()
        seeded = 0
        for case_key, question, answer in rows:
            _qa_cache_save(case_key, question, answer, source='qa_worker', confidence=0.85)
            seeded += 1
        if seeded:
            _log.info(f'[qa_cache] seeded {seeded} answers from eval_answers')
    except Exception as e:
        _log.info(f'[qa_cache] seed error: {e}')


