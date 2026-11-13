"""Real-time journal of the agentic investigation.

Why this exists: the investigate loop used to run entirely in memory. If the planner
timed out, or the container was recreated mid-run, everything the agent had asked for
and learned was lost silently - the report still came out, filled in by the
deterministic coverage sweep, so nobody noticed the agent had contributed nothing.

Every planner round, every tool call and every failure is written here as it happens,
so a run can be inspected while it is still going and reconstructed after a break.
Also stores a snapshot of the collected evidence so a resumed run does not have to
redo the expensive phase-1 sweep.

Every function is exception-safe: journalling must never break the report path.
"""
import json
import logging
import os

import psycopg2
from psycopg2.extras import Json

from core.config import PG_DSN

_log = logging.getLogger('app')

TABLE = 'public.dfir_investigation_journal_v1'
SNAP_TABLE = 'public.dfir_investigation_snapshot_v1'

RETENTION_DAYS = int(os.getenv('DFIR_JOURNAL_RETENTION_DAYS', '30'))

_ensured = False


def ensure_tables():
    """Create the journal + snapshot tables once per process."""
    global _ensured
    if _ensured:
        return True
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS %s (
                        id          bigserial PRIMARY KEY,
                        case_key    text NOT NULL,
                        job_id      text,
                        round_no    int,
                        kind        text NOT NULL,
                        tool        text,
                        args        jsonb,
                        reasoning   text,
                        result_head text,
                        result_len  int,
                        ok          boolean,
                        detail      text,
                        created_at  timestamptz NOT NULL DEFAULT now()
                    )
                """ % TABLE)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_invjournal_case ON %s (case_key, created_at DESC)" % TABLE)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_invjournal_job ON %s (job_id, id)" % TABLE)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS %s (
                        case_key    text NOT NULL,
                        job_id      text NOT NULL,
                        phase       text NOT NULL,
                        collected   jsonb,
                        trace       text,
                        updated_at  timestamptz NOT NULL DEFAULT now(),
                        PRIMARY KEY (job_id, phase)
                    )
                """ % SNAP_TABLE)
                # One prune per process start. The journal writes on every run and nothing
                # else would ever delete a row; a snapshot is ~33 kB, so a year of runs is
                # small but unbounded, and unbounded is what eventually fills a disk.
                try:
                    cur.execute("DELETE FROM %s WHERE created_at < now() - interval '%d days'"
                                % (TABLE, RETENTION_DAYS))
                    cur.execute("DELETE FROM %s WHERE updated_at < now() - interval '%d days'"
                                % (SNAP_TABLE, RETENTION_DAYS))
                except Exception as _pe:
                    _log.error('[journal] prune failed: %s' % _pe)
        _ensured = True
        return True
    except Exception as e:
        _log.error('[journal] ensure_tables failed: %s' % e)
        return False


def log(case_key, job_id, kind, round_no=None, tool=None, args=None,
        reasoning=None, result=None, ok=None, detail=None):
    """Append one journal row. Never raises."""
    try:
        if not ensure_tables():
            return
        res = '' if result is None else str(result)
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO %s (case_key, job_id, round_no, kind, tool, args, reasoning,"
                    " result_head, result_len, ok, detail) VALUES (%%s,%%s,%%s,%%s,%%s,%%s,%%s,%%s,%%s,%%s,%%s)" % TABLE,
                    (str(case_key or '')[:200], str(job_id or '')[:100], round_no, str(kind)[:40],
                     (str(tool)[:80] if tool else None),
                     (Json(args) if isinstance(args, dict) else None),
                     (str(reasoning)[:2000] if reasoning else None),
                     (res.strip().replace('\n', ' ')[:500] if res else None),
                     (len(res) if result is not None else None),
                     ok, (str(detail)[:1000] if detail else None)))
    except Exception as e:
        _log.error('[journal] log(%s) failed: %s' % (kind, e))


def snapshot(case_key, job_id, phase, collected, trace=''):
    """Store the evidence gathered so far so a resumed run can skip re-collecting it."""
    try:
        if not ensure_tables() or not job_id:
            return
        # keep the snapshot bounded - per-tool output is already capped upstream
        safe = {}
        for k, v in (collected or {}).items():
            safe[str(k)[:200]] = str(v or '')[:20000]
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO %s (case_key, job_id, phase, collected, trace) VALUES (%%s,%%s,%%s,%%s,%%s) "
                    "ON CONFLICT (job_id, phase) DO UPDATE SET collected=EXCLUDED.collected,"
                    " trace=EXCLUDED.trace, updated_at=now()" % SNAP_TABLE,
                    (str(case_key or '')[:200], str(job_id)[:100], str(phase)[:40],
                     Json(safe), str(trace or '')[:200000]))
        _log.error('[journal] snapshot %s: %d tools, %d trace chars' % (phase, len(safe), len(trace or '')))
    except Exception as e:
        _log.error('[journal] snapshot failed: %s' % e)


def load_snapshot(case_key, job_id, phase):
    """Return (collected, trace) previously snapshotted, or (None, '') when absent."""
    try:
        if not ensure_tables() or not job_id:
            return None, ''
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("SELECT collected, trace FROM %s WHERE job_id=%%s AND phase=%%s" % SNAP_TABLE,
                            (str(job_id)[:100], str(phase)[:40]))
                r = cur.fetchone()
                if not r:
                    return None, ''
                return (r[0] if isinstance(r[0], dict) else None), (r[1] or '')
    except Exception as e:
        _log.error('[journal] load_snapshot failed: %s' % e)
        return None, ''


def load_recent_case_snapshot(case_key, phase, max_age_minutes=120):
    """Phase-1 evidence for this case, if a recent run already gathered it.

    Phase 1 is a deterministic sweep of ~40 tools over the case database - roughly the
    bulk of a 26-minute run - and it produces the same answer every time as long as the
    case has not been re-ingested. So a run that died after phase 1 (container recreate,
    llama-swap restart, power loss) should not pay for it twice.

    Returns (collected, trace, age_minutes) or (None, '', None). The caller must still
    check that no new ingest happened since; see fresher_ingest_since().
    """
    try:
        if not ensure_tables():
            return None, '', None
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT collected, trace, EXTRACT(EPOCH FROM (now()-updated_at))/60.0 "
                    "FROM %s WHERE case_key=%%s AND phase=%%s "
                    "  AND updated_at > now() - (%%s * interval '1 minute') "
                    "ORDER BY updated_at DESC LIMIT 1" % SNAP_TABLE,
                    (str(case_key or '')[:200], str(phase)[:40], int(max_age_minutes)))
                r = cur.fetchone()
                if not r or not isinstance(r[0], dict):
                    return None, '', None
                return r[0], (r[1] or ''), float(r[2] or 0)
    except Exception as e:
        _log.error('[journal] load_recent_case_snapshot failed: %s' % e)
        return None, '', None


def ingest_changed_since(case_key, minutes):
    """True when the case received new data in the last `minutes` - a snapshot older than
    that is stale and must not be reused."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) FROM public.ingest_files "
                    "WHERE case_key=%s AND ingested_at > now() - (%s * interval '1 minute')",
                    (str(case_key or '')[:200], int(minutes)))
                r = cur.fetchone()
                return bool(r and int(r[0]) > 0)
    except Exception as e:
        _log.error('[journal] ingest_changed_since failed: %s' % e)
        return True  # unknown -> assume changed, so we never reuse stale evidence


def summary(job_id):
    """Compact health line for a finished run - used to surface planner failures."""
    try:
        if not ensure_tables() or not job_id:
            return {}
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("SELECT kind, count(*) FROM %s WHERE job_id=%%s GROUP BY kind" % TABLE,
                            (str(job_id)[:100],))
                return {row[0]: row[1] for row in cur.fetchall()}
    except Exception:
        return {}
