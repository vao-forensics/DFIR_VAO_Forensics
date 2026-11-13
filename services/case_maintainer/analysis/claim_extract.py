# -*- coding: utf-8 -*-
"""S2 (feedback loop): SELECT the key human-verifiable claims for a finished DFIR
analysis. Claims are ALREADY extracted by the pipeline into dfir_claims_v1
(~90/case). We do NOT re-extract — we CURATE: the analyst verifies CONCLUSIONS
(verdict + finding signatures) plus a few top IOC/timeline items, not every raw
artifact. Returned claims keep their existing dfir_claims_v1.claim_id (UUID) so
human verdicts in case_feedback reference the same id.
See docs/FEEDBACK_LOOP_PLAN.md."""
import psycopg2

# priority (lower = shown first) and per-type caps for the review set
_PRIO = {'verdict': 0, 'finding': 1, 'ioc': 2, 'timeline': 3}
_CAPS = {'verdict': 99, 'finding': 99, 'ioc': 6, 'timeline': 6}
_MAX_TOTAL = 16


def select_review_claims(case_key, job_id, dsn):
    """Curated [{claim_id, claim_type, claim_text, status}] for human review.
    Verdict+finding shown in full; IOC/timeline capped; text-deduped. Never raises."""
    rows = []
    try:
        with psycopg2.connect(dsn) as c:
            c.autocommit = True
            with c.cursor() as cur:
                cur.execute("""
                    SELECT claim_id, claim_type, claim_text, COALESCE(status,''), created_at
                    FROM dfir_claims_v1 WHERE job_id=%s
                """, (str(job_id),))
                rows = cur.fetchall()
    except Exception:
        return []

    rows.sort(key=lambda r: (_PRIO.get(r[1], 4), r[4] or ''))
    out, seen, per = [], set(), {}
    for cid, ctype, ctext, status, _ in rows:
        norm = ' '.join(str(ctext or '').split())
        key = norm.lower()[:120]
        if not norm or key in seen:
            continue
        if per.get(ctype, 0) >= _CAPS.get(ctype, 6):
            continue
        seen.add(key)
        per[ctype] = per.get(ctype, 0) + 1
        out.append({'claim_id': cid, 'claim_type': ctype,
                    'claim_text': norm[:400], 'status': status})
        if len(out) >= _MAX_TOTAL:
            break
    return out
