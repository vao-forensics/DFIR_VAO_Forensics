"""Case memory helpers: analyst-approved facts and reusable case context."""
from __future__ import annotations

import json
import logging
from typing import Any

import psycopg2
from psycopg2.extras import Json

from core.config import PG_DSN

_log = logging.getLogger('app')


def get_verified_case_context(case_key: str, limit: int = 20) -> str:
    """Return compact analyst-approved facts for prompts/QA.

    These are not model-generated truths. They are only facts that were
    explicitly approved or otherwise marked verified by workflow/analyst.
    """
    case_key = str(case_key or '').strip()
    if not case_key:
        return ''
    try:
        with psycopg2.connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT finding_type, coalesce(event_ts::text,''), title, coalesce(value,''),
                           coalesce(source_kind,''), coalesce(confidence,1.0)
                    FROM dfir_case_verified_findings
                    WHERE case_key=%s AND approval_status IN ('approved','verified')
                    ORDER BY event_ts NULLS LAST, approved_at DESC NULLS LAST, created_at DESC
                    LIMIT %s
                    """,
                    (case_key, int(limit)),
                )
                rows = cur.fetchall()
        if not rows:
            return ''
        lines = ['[ПЕРЕВІРЕНІ ФАКТИ КЕЙСУ — використовуй як пріоритетний контекст, не регенеруй заново]']
        for ftype, ts, title, value, source, conf in rows:
            bits = []
            if ts:
                bits.append(str(ts)[:19])
            if ftype:
                bits.append(str(ftype))
            head = ' / '.join(bits) if bits else 'fact'
            detail = str(value or title or '').strip()
            if len(detail) > 220:
                detail = detail[:217].rstrip() + '…'
            src = f' source={source}' if source else ''
            lines.append(f'- {head}: {str(title or "")[:160]} — {detail}{src}; confidence={float(conf or 0):.2f}')
        return '\n'.join(lines)
    except Exception as e:
        _log.warning(f'[case_memory] verified context lookup failed case={case_key}: {e}')
        return ''


def upsert_verified_finding(
    case_key: str,
    finding_key: str,
    finding_type: str,
    title: str,
    value: str = '',
    event_ts: str | None = None,
    evidence: dict[str, Any] | None = None,
    source_kind: str = 'analyst',
    approval_status: str = 'approved',
    approved_by: str = '',
    confidence: float = 1.0,
) -> bool:
    """Create/update one verified finding. Safe idempotent upsert."""
    case_key = str(case_key or '').strip()
    finding_key = str(finding_key or '').strip()
    if not case_key or not finding_key or not title:
        return False
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO dfir_case_verified_findings
                      (case_key, finding_key, finding_type, title, value, event_ts,
                       evidence_json, source_kind, approval_status, approved_by,
                       approved_at, confidence, updated_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                            CASE WHEN %s IN ('approved','verified') THEN now() ELSE NULL END,
                            %s, now())
                    ON CONFLICT (case_key, finding_key) DO UPDATE SET
                      finding_type=EXCLUDED.finding_type,
                      title=EXCLUDED.title,
                      value=EXCLUDED.value,
                      event_ts=COALESCE(EXCLUDED.event_ts, dfir_case_verified_findings.event_ts),
                      evidence_json=EXCLUDED.evidence_json,
                      source_kind=EXCLUDED.source_kind,
                      approval_status=EXCLUDED.approval_status,
                      approved_by=EXCLUDED.approved_by,
                      approved_at=CASE WHEN EXCLUDED.approval_status IN ('approved','verified') THEN now() ELSE dfir_case_verified_findings.approved_at END,
                      confidence=EXCLUDED.confidence,
                      updated_at=now()
                    """,
                    (
                        case_key, finding_key, finding_type or 'fact', title[:240], value[:50000],
                        event_ts, Json(evidence or {}), source_kind or 'analyst', approval_status or 'approved',
                        approved_by or '', approval_status or 'approved', float(confidence or 1.0),
                    ),
                )
        return True
    except Exception as e:
        _log.error(f'[case_memory] upsert verified finding failed case={case_key}: {e}')
        return False
