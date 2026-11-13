"""QA answer tracking, feedback handling, reusable playbooks."""
import json, logging, uuid as _uuid
import psycopg2
from core.config import PG_DSN

_log = logging.getLogger('app')


def _ensure_qa_answer_tables():
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS dfir_qa_answers (
                    id bigserial PRIMARY KEY,
                    answer_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
                    case_key text NOT NULL,
                    chat_id text NOT NULL,
                    user_id text,
                    question text NOT NULL,
                    normalized_question text,
                    answer_markdown text NOT NULL,
                    confidence real DEFAULT 1.0,
                    status text NOT NULL DEFAULT 'pending',
                    evidence_json jsonb,
                    search_trace_json jsonb,
                    tools_used text[],
                    tables_checked text[],
                    source_files text[],
                    validation_status text NOT NULL DEFAULT 'not_checked',
                    validation_reason text,
                    not_in_report boolean NOT NULL DEFAULT false,
                    conflict_with_report boolean NOT NULL DEFAULT false,
                    source_ref text,
                    model_used text,
                    model_role text,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    approved_at timestamptz,
                    rejected_at timestamptz
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_qa_ans_case ON dfir_qa_answers(case_key)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_qa_ans_aid ON dfir_qa_answers(answer_id)")
            # Idempotent migration for existing installations
            for col, defn in [
                ('validation_status', "text NOT NULL DEFAULT 'not_checked'"),
                ('validation_reason', 'text'),
                ('not_in_report', 'boolean NOT NULL DEFAULT false'),
                ('conflict_with_report', 'boolean NOT NULL DEFAULT false'),
                ('source_ref', 'text'),
                ('model_used', 'text'),
                ('model_role', 'text'),
            ]:
                try:
                    cur.execute(f"ALTER TABLE dfir_qa_answers ADD COLUMN IF NOT EXISTS {col} {defn}")
                except Exception:
                    pass

            cur.execute("""
                CREATE TABLE IF NOT EXISTS dfir_qa_feedback (
                    id bigserial PRIMARY KEY,
                    answer_id uuid NOT NULL,
                    case_key text,
                    chat_id text,
                    user_id text,
                    feedback text NOT NULL,
                    comment text,
                    corrected_answer text,
                    created_at timestamptz NOT NULL DEFAULT now()
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_qa_fb_aid ON dfir_qa_feedback(answer_id)")

            cur.execute("""
                CREATE TABLE IF NOT EXISTS dfir_reusable_playbooks (
                    id bigserial PRIMARY KEY,
                    playbook_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
                    intent_name text NOT NULL,
                    trigger_examples text[],
                    question_pattern text,
                    artifact_types text[],
                    preferred_tables text[],
                    preferred_event_ids text[],
                    preferred_registry_paths text[],
                    preferred_tools text[],
                    sql_templates jsonb,
                    evidence_requirements jsonb,
                    output_template text,
                    example_case_key text,
                    example_question text,
                    example_answer_summary text,
                    example_evidence_json jsonb,
                    success_count integer NOT NULL DEFAULT 1,
                    fail_count integer NOT NULL DEFAULT 0,
                    status text NOT NULL DEFAULT 'active',
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now()
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_pb_intent ON dfir_reusable_playbooks(intent_name)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_pb_status ON dfir_reusable_playbooks(status)")

            cur.execute("""
                CREATE TABLE IF NOT EXISTS dfir_qa_corrections_pending (
                    id bigserial PRIMARY KEY,
                    answer_id uuid NOT NULL,
                    chat_id text NOT NULL,
                    case_key text,
                    waiting_for_correction boolean NOT NULL DEFAULT true,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    expires_at timestamptz NOT NULL DEFAULT now() + interval '1 hour'
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_qa_corr_chat ON dfir_qa_corrections_pending(chat_id, waiting_for_correction)")


def _qa_answer_save(case_key, chat_id, question, answer_markdown, findings=None,
                    tools_used=None, model_used=None, model_role=None,
                    validation_status='not_checked', validation_reason=None,
                    provenance=None):
    """Save QA answer, return answer_id UUID string.
    Theme A: when `provenance` (a dict of where/how the answer was found) is given,
    populate tables_checked / source_files / evidence_json from it. Falls back to the
    legacy findings[:10] behavior for source_files when provenance is None."""
    import re
    norm_q = re.sub(r'\s+', ' ', question.lower().strip())[:200]
    aid = str(_uuid.uuid4())
    source_files = list(findings[:10]) if findings else []
    tables_checked = None
    evidence_json = None
    if provenance:
        try:
            tables_checked = list(provenance.get('tables') or []) or None
            _pf = list(provenance.get('source_files') or [])
            if _pf:
                source_files = _pf
            evidence_json = json.dumps(provenance)
        except Exception:
            tables_checked = None
            evidence_json = None
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO dfir_qa_answers
                        (answer_id, case_key, chat_id, question, normalized_question,
                         answer_markdown, status, source_files, tools_used,
                         model_used, model_role, validation_status, validation_reason,
                         tables_checked, evidence_json)
                    VALUES (%s, %s, %s, %s, %s, %s, 'pending', %s, %s, %s, %s, %s, %s, %s, %s)
                """, (aid, case_key, str(chat_id), question, norm_q,
                      answer_markdown, source_files, list(tools_used or []),
                      model_used, model_role, validation_status, validation_reason,
                      tables_checked, evidence_json))
    except Exception as e:
        _log.error(f"[qa_answers] save error: {e}")
    return aid


def _qa_feedback_correct(answer_id, case_key, chat_id, user_id=''):
    """Approve answer and upsert reusable playbook."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("SELECT question, answer_markdown, tools_used, evidence_json FROM dfir_qa_answers WHERE answer_id=%s", (answer_id,))
                row = cur.fetchone()
                if not row:
                    return False
                question, answer_md, tools_used, _evidence = row

                cur.execute("UPDATE dfir_qa_answers SET status='approved', approved_at=now() WHERE answer_id=%s", (answer_id,))
                # Theme A (EDIT 11): mark validation confirmed + promote the cache row
                try:
                    cur.execute("UPDATE dfir_qa_answers SET validation_status='confirmed' WHERE answer_id=%s", (answer_id,))
                except Exception:
                    pass
                cur.execute("INSERT INTO dfir_qa_feedback (answer_id, case_key, chat_id, user_id, feedback) VALUES (%s,%s,%s,%s,'correct')",
                            (answer_id, case_key, str(chat_id), str(user_id)))

                # Theme A: parse structured provenance saved at answer time
                _prov = None
                _prov_tables = []
                _prov_eids = []
                _prov_tools = []
                try:
                    if _evidence:
                        _prov = _evidence if isinstance(_evidence, dict) else json.loads(_evidence)
                        _prov_tables = list(_prov.get('tables') or [])
                        _prov_eids = list(_prov.get('event_ids') or [])
                        _prov_tools = list(_prov.get('tools') or [])
                except Exception:
                    _prov = None

                # Theme A (EDIT 11): promote the matching cache row → verified + provenance
                try:
                    _prov_json = json.dumps(_prov) if _prov else None
                    cur.execute(
                        "UPDATE dfir_qa_cache_v1 SET verified=true, "
                        "provenance=COALESCE(%s, provenance), updated_at=now() "
                        "WHERE case_key=%s AND similarity(question,%s) >= 0.90",
                        (_prov_json, case_key, question))
                except Exception:
                    pass

                from analysis.chat import _detect_question_topic
                intent = _detect_question_topic(question) or 'general_qa'

                cur.execute("SELECT id FROM dfir_reusable_playbooks WHERE intent_name=%s AND status='active' LIMIT 1", (intent,))
                pb = cur.fetchone()
                if pb:
                    # Theme A (EDIT 12): merge structured provenance into the playbook
                    # (DISTINCT unnest to avoid unbounded duplicate accumulation).
                    cur.execute("""UPDATE dfir_reusable_playbooks
                        SET success_count=success_count+1, updated_at=now(),
                            example_case_key=COALESCE(example_case_key,%s),
                            example_question=COALESCE(example_question,%s),
                            preferred_tables=(SELECT array(SELECT DISTINCT unnest(coalesce(preferred_tables,'{}') || %s::text[]))),
                            preferred_event_ids=(SELECT array(SELECT DISTINCT unnest(coalesce(preferred_event_ids,'{}') || %s::text[]))),
                            preferred_tools=(SELECT array(SELECT DISTINCT unnest(coalesce(preferred_tools,'{}') || %s::text[])))
                        WHERE id=%s""",
                        (case_key, question[:200], _prov_tables, _prov_eids,
                         (_prov_tools or list(tools_used or [])), pb[0]))
                else:
                    cur.execute("""INSERT INTO dfir_reusable_playbooks
                        (intent_name, trigger_examples, preferred_tables, preferred_event_ids,
                         preferred_tools, example_case_key,
                         example_question, example_answer_summary, status)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'active')""",
                        (intent, [question[:100]], _prov_tables, _prov_eids,
                         (_prov_tools or list(tools_used or [])), case_key,
                         question[:200], (answer_md or '')[:300]))

        # Save confirmed Q&A to per-case knowledge base (kb_case_knowledge Qdrant)
        lesson_text = f"Q: {question[:300]}\nA: {(answer_md or '')[:600]}"

        # the knowledge base needs an embedding (shared LLM queue, seconds to minutes), so it is
        # filled in the background: the Telegram button must answer within n8n's 15 s
        def _kb_bg(_intent=intent):
            try:
                from analysis.learnings import _save_case_knowledge, _save_lesson
                _save_case_knowledge(
                    case_key,
                    'confirmed_answer',
                    lesson_text,
                    source='qa_correct',
                    confirmed_by=str(user_id),
                )
                # Also save to dfir_lessons_learned_v1 so synthesis picks it up next run
                _save_lesson(
                    case_key, _intent or 'confirmed_answer', 'good_answer',
                    lesson_text, [], [], {},
                )
            except Exception as _e_kb:
                _log.warning('[qa_answers] knowledge save failed: %s' % _e_kb)
        import threading as _thr_kb
        _thr_kb.Thread(target=_kb_bg, daemon=True).start()
        return True
    except Exception as e:
        _log.error(f"[qa_answers] feedback_correct error: {e}")
        return False


def _qa_feedback_wrong(answer_id, case_key, chat_id, user_id=''):
    """Reject answer and wait for correction."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("UPDATE dfir_qa_answers SET status='rejected', rejected_at=now() WHERE answer_id=%s", (answer_id,))
                cur.execute("INSERT INTO dfir_qa_feedback (answer_id, case_key, chat_id, user_id, feedback) VALUES (%s,%s,%s,%s,'wrong')",
                            (answer_id, case_key, str(chat_id), str(user_id)))
                cur.execute("""INSERT INTO dfir_qa_corrections_pending (answer_id, chat_id, case_key)
                    VALUES (%s,%s,%s)""", (answer_id, str(chat_id), case_key))
                # Theme A (EDIT 14): retire the matching cache row on 👎 (degrade gracefully)
                try:
                    cur.execute("SELECT question FROM dfir_qa_answers WHERE answer_id=%s", (answer_id,))
                    _qr = cur.fetchone()
                    if _qr and _qr[0]:
                        cur.execute(
                            "UPDATE dfir_qa_cache_v1 SET status='retired', verified=false, updated_at=now() "
                            "WHERE case_key=%s AND similarity(question,%s) >= 0.90",
                            (case_key, _qr[0]))
                except Exception:
                    pass
        return True
    except Exception as e:
        _log.error(f"[qa_answers] feedback_wrong error: {e}")
        return False


def _qa_feedback_unknown(answer_id, case_key, chat_id, user_id=''):
    """Mark answer as unknown — not used for training."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("UPDATE dfir_qa_answers SET status='unknown' WHERE answer_id=%s", (answer_id,))
                cur.execute("INSERT INTO dfir_qa_feedback (answer_id, case_key, chat_id, user_id, feedback) VALUES (%s,%s,%s,%s,'unknown')",
                            (answer_id, case_key, str(chat_id), str(user_id)))
        return True
    except Exception as e:
        _log.error(f"[qa_answers] feedback_unknown error: {e}")
        return False


def _qa_check_pending_correction(chat_id):
    """Return {answer_id, case_key} if correction is pending for this chat, else None."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT answer_id, case_key FROM dfir_qa_corrections_pending
                    WHERE chat_id=%s AND waiting_for_correction=true AND expires_at > now()
                    ORDER BY created_at DESC LIMIT 1
                """, (str(chat_id),))
                row = cur.fetchone()
                return {'answer_id': str(row[0]), 'case_key': row[1]} if row else None
    except Exception:
        return None


def _qa_save_correction(answer_id, chat_id, correction_text):
    """Attach correction text to a rejected answer."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("UPDATE dfir_qa_feedback SET corrected_answer=%s WHERE answer_id=%s AND feedback='wrong'",
                            (correction_text, answer_id))
                cur.execute("UPDATE dfir_qa_answers SET status='needs_review' WHERE answer_id=%s", (answer_id,))
                cur.execute("UPDATE dfir_qa_corrections_pending SET waiting_for_correction=false WHERE chat_id=%s AND answer_id=%s",
                            (str(chat_id), answer_id))
        return True
    except Exception as e:
        _log.error(f"[qa_answers] save_correction error: {e}")
        return False
