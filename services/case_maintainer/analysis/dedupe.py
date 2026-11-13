# -*- coding: utf-8 -*-
"""Ingest de-duplication.

A KAPE triage often ships TWO overlapping EvtxECmd CSV exports of the same
event logs (e.g. a full export + a second partial export). Both get ingested,
so every event lands TWICE in event_logs_v2 — which doubles every deterministic
count (log-clears, ScriptBlock, services...) and floods the LLM context with
identical rows. This module removes EXACT-duplicate rows (identical in every
content column, ignoring the surrogate row_id / per-file file_id / created_at),
keeping the lowest row_id of each group. Removing a byte-identical row is always
safe: within one evtx channel the RecordNumber is unique, so two identical rows
are the same event seen twice — never two distinct events.

Idempotent: after the first pass there are no duplicates, so re-running deletes 0.
"""
import logging
import psycopg2
from core.config import PG_DSN

_log = logging.getLogger('app')

# table -> content columns that define row identity (row_id/file_id/created_at excluded)
_DEDUP_KEYS = {
    'event_logs_v2': (
        "event_id, event_ts, channel, provider, computer, remote_host, "
        "target_user, logon_type, process_name, command_line, payload, source_file"
    ),
    'program_exec_v2': (
        "event_ts, executable_name, full_path, hash_sha1, payload, source_file"
    ),
    'tool_alerts_v2': (
        "tool, severity, rule, event_ts, computer, user_name, ioc_value, "
        "details, payload, source_file"
    ),
}


def dedupe_case(case_key, tables=None):
    """Delete exact-duplicate rows for one case. Returns {table: removed_count}.

    Safe to call before every report run (idempotent). Skips filesystem_v2 by
    default — the $MFT/$J ship as single CSVs (not doubled) and the table is huge.
    """
    removed = {}
    keys = tables or list(_DEDUP_KEYS.keys())
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            for tbl in keys:
                cols = _DEDUP_KEYS.get(tbl)
                if not cols:
                    continue
                sql = (
                    f"DELETE FROM {tbl} a USING ("
                    f"  SELECT ctid, row_number() OVER ("
                    f"    PARTITION BY {cols} ORDER BY row_id"
                    f"  ) AS rn FROM {tbl} WHERE case_key=%s"
                    f") d WHERE a.ctid = d.ctid AND d.rn > 1"
                )
                try:
                    with conn.cursor() as cur:
                        cur.execute(sql, (case_key,))
                        removed[tbl] = cur.rowcount or 0
                except Exception as e:
                    _log.warning(f"[dedupe] {tbl} {case_key}: {repr(e)[:160]}")
                    try:
                        conn.rollback()
                    except Exception:
                        pass
        total = sum(removed.values())
        if total:
            _log.error(f"[dedupe] {case_key}: removed {total} duplicate rows {removed}")
    except Exception as e:
        _log.error(f"[dedupe] {case_key} failed: {repr(e)[:160]}")
    return removed
