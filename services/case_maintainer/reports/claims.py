"""Claims layer: persist and load structured evidence slices."""
import json, logging, re, psycopg2
from core.config import PG_DSN

_log = logging.getLogger('app')

def _safe_case_folder(case_key):
    safe = str(case_key or '').strip().replace('..', '_')
    for ch in ['\\', '/', ':', '*', '?', '"', '<', '>', '|', '\n', '\r', '\t']:
        safe = safe.replace(ch, '_')
    return safe or 'uncategorized'


def _ensure_claims_layer_tables():
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.dfir_claims_v1 (
                    claim_id text PRIMARY KEY,
                    job_id text NOT NULL,
                    case_key text NOT NULL,
                    step_code text,
                    claim_type text NOT NULL,
                    claim_text text NOT NULL,
                    time_bound_start timestamptz,
                    time_bound_end timestamptz,
                    confidence text,
                    status text,
                    created_at timestamptz DEFAULT now(),
                    updated_at timestamptz DEFAULT now()
                )
            """)
            cur.execute("""CREATE INDEX IF NOT EXISTS idx_dfir_claims_v1_case_job ON public.dfir_claims_v1(case_key, job_id)""")
            cur.execute("""CREATE INDEX IF NOT EXISTS idx_dfir_claims_v1_type ON public.dfir_claims_v1(claim_type)""")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.dfir_claim_evidence_links_v1 (
                    link_id text PRIMARY KEY,
                    claim_id text NOT NULL,
                    job_id text NOT NULL,
                    case_key text NOT NULL,
                    source_table text,
                    source_row_ref text,
                    source_file text,
                    event_ts timestamptz,
                    evidence_role text,
                    snippet text,
                    weight numeric,
                    created_at timestamptz DEFAULT now()
                )
            """)
            cur.execute("""CREATE INDEX IF NOT EXISTS idx_dfir_claim_links_v1_claim ON public.dfir_claim_evidence_links_v1(claim_id)""")
            cur.execute("""CREATE INDEX IF NOT EXISTS idx_dfir_claim_links_v1_case_job ON public.dfir_claim_evidence_links_v1(case_key, job_id)""")


def _persist_claims_slice_v1(job_id, case_key, structured_input=None):
    import uuid
    import hashlib
    try:
        _ensure_claims_layer_tables()
    except Exception:
        return {'ok': False, 'written_claims': 0, 'written_links': 0, 'error': 'claims_layer_ensure_failed'}

    s = structured_input if isinstance(structured_input, dict) else _build_structured_input(job_id=job_id, case_key=case_key)
    claims = []
    links = []

    def _mk_claim(step_code, claim_type, claim_text, t0=None, t1=None, confidence='medium', status='active'):
        cid = str(uuid.uuid4())
        claims.append((cid, job_id, case_key, step_code, claim_type, str(claim_text or '')[:1200], t0, t1, confidence, status))
        return cid

    def _det_ref(source_table=None, source_file=None, event_ts=None, snippet=None, explicit=None):
        if explicit:
            return str(explicit)[:180]
        sf = str(source_file or '')
        sn = str(snippet or '')
        if sf and ('count=' in sf or 'row=' in sf or 'row_id=' in sf or 'uniq_' in sf or 'events=' in sf):
            return f"ref:file_token:{sf[:120]}"
        if source_table and event_ts:
            return f"ref:table_ts:{source_table}:{event_ts}"

        # deterministic snippet/file refs before generic fallback
        m_evt = re.search(r'(?i)event_id\s*=\s*(\d{3,5})', sn)
        if m_evt:
            hx = hashlib.sha1((sn[:160] + '|' + sf).encode('utf-8', 'ignore')).hexdigest()[:10]
            return f"ref:snippet_eventid:{m_evt.group(1)}:{hx}"

        m_tok = re.search(r'(?i)\b(count|events|uniq_ip|uniq_host|row|row_id)\s*=\s*([^\s,;|]+)', sn)
        if m_tok:
            return f"ref:snippet_token:{m_tok.group(1)}={m_tok.group(2)[:40]}"

        m_ip = re.search(r'((?:\d{1,3}\.){3}\d{1,3})', sn)
        if m_ip:
            return f"ref:snippet_ip:{m_ip.group(1)}"

        if sf:
            hx = hashlib.sha1(sn[:200].encode('utf-8', 'ignore')).hexdigest()[:10]
            return f"ref:file_sig:{sf[:90]}:{hx}"

        base = f"{source_table or '-'}|{source_file or '-'}|{event_ts or '-'}|{(sn[:120])}"
        h = hashlib.sha1(base.encode('utf-8','ignore')).hexdigest()[:16]
        return f"ref:fallback:{h}"

    def _mk_link(cid, source_table=None, source_row_ref=None, source_file=None, event_ts=None, role='support', snippet=None, weight=1.0):
        sref = _det_ref(source_table=source_table, source_file=source_file, event_ts=event_ts, snippet=snippet, explicit=source_row_ref)
        links.append((str(uuid.uuid4()), cid, job_id, case_key, source_table, sref, source_file, event_ts, role, (str(snippet or '')[:500] if snippet else None), float(weight or 1.0)))

    # timeline claims
    for ev in (s.get('attack_chronology_events') or [])[:40]:
        txt = ev.get('short_fact') or 'timeline event'
        cid = _mk_claim('incident_timeline', 'timeline', txt, ev.get('event_ts'), ev.get('event_ts'), ev.get('confidence') or 'medium', ev.get('status') or 'active')
        for e in (ev.get('evidence') or [])[:3]:
            _mk_link(cid,
                     source_table=e.get('source_table'),
                     source_row_ref=e.get('source_row_ref'),
                     source_file=e.get('source_file'),
                     event_ts=e.get('event_ts') or ev.get('event_ts'),
                     role='support',
                     snippet=e.get('evidence_text') or txt,
                     weight=1.0)

    # finding claims (support + counter)
    f = s.get('findings') or {}

    def _derive_finding_source(src, src_file, snippet):
        st = src if ('_' in str(src or '')) else None
        sf = src_file or None
        sn = str(snippet or '').lower()

        if not st and ('hayabusa|' in sn or 'rdp attempt' in sn or 'rdp conn attempt' in sn):
            st = 'tool_alerts_v2'
            sf = sf or 'hayabusa_events_offline.csv'
        if not st and ('keypath' in sn or 'root\\' in sn or 'currentversion\\run' in sn):
            st = 'raw_fallback_v2'
            sf = sf or 'registry_artifact_json'
        if not st and ('family=' in sn and 'source_ref=' in sn):
            st = 'event_logs_v2'
            sf = sf or 'corroboration_family_aggregate'
        if not st and ('verdict=' in sn or 'taxonomy=' in sn):
            st = 'corroboration_meta'
            sf = sf or 'dfir_run_steps_v2:corroboration'

        if not st:
            st = 'corroboration_meta'
            sf = sf or 'dfir_run_steps_v2:corroboration'
        return st, sf

    for bucket, cval, w in [('confirmed','high',1.0), ('corroborated','medium',0.8), ('needs_review','low',0.4), ('tool_only','low',0.3)]:
        for it in (f.get(bucket) or [])[:20]:
            ind = str((it.get('indicator') if isinstance(it, dict) else it) or 'finding')
            fs = (it.get('first_seen') if isinstance(it, dict) else None)
            ls = (it.get('last_seen') if isinstance(it, dict) else None)
            cid = _mk_claim('corroboration', 'finding', ind, fs, ls, cval, bucket)
            if isinstance(it, dict):
                src = it.get('source') or ''
                samples = it.get('evidence_samples') or []
                role = 'counter' if bucket in ('needs_review','tool_only') else 'support'
                sn = ' | '.join([str(x) for x in samples[:2]]) or ind
                st, sf = _derive_finding_source(src, it.get('source_file'), sn)
                _mk_link(cid,
                         source_table=st,
                         source_row_ref=it.get('source_ref') or it.get('row_ref'),
                         source_file=sf,
                         event_ts=fs or ls,
                         role=role,
                         snippet=sn,
                         weight=w)

    # IOC claims
    for it in (s.get('ioc_artifacts') or [])[:40]:
        if isinstance(it, dict):
            txt = str(it.get('artifact') or it.get('ioc') or it.get('value') or it.get('path') or 'ioc')
            st = it.get('source_table') or it.get('source')
            sf = it.get('source_file')
            et = it.get('event_ts')
            sn = it.get('reason') or txt
            sr = it.get('source_ref') or it.get('row_ref') or it.get('row_id')
        else:
            txt = str(it)
            st = sf = et = sr = None
            sn = txt
        cid = _mk_claim('ioc_artifacts', 'ioc', txt, et, et, 'medium', 'active')
        _mk_link(cid, source_table=st, source_row_ref=sr, source_file=sf, event_ts=et, role='support', snippet=sn, weight=0.7)

    # verdict claim (minimal + counter links from declared gaps)
    vtxt = 'Case verdict from structured input'
    status = 'inconclusive'
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""SELECT COALESCE(meta_json,'{}'::jsonb) FROM public.dfir_run_steps_v2 WHERE job_id=%s AND step_code='case_reasoning_v1' LIMIT 1""", (job_id,))
                rr = cur.fetchone()
                if rr and isinstance(rr[0], dict):
                    cr = (rr[0].get('case_reasoning_v1') or {})
                    if isinstance(cr, dict):
                        status = str(cr.get('summary_verdict') or status)
                        vtxt = f"summary_verdict={status}"
    except Exception:
        try: conn.rollback()
        except: pass
        pass
    verdict_cid = _mk_claim('case_reasoning_v1', 'verdict', vtxt, None, None, 'medium', status)

    # explicit counter evidence from gaps/manual checks
    gaps = (s.get('gaps') or {})
    for g in (gaps.get('missing_native_proof') or [])[:10]:
        _mk_link(verdict_cid,
                 source_table='dfir_gaps',
                 source_row_ref=f"gap:missing_native_proof:{str(g)[:80]}",
                 source_file='structured_input.gaps',
                 event_ts=None,
                 role='counter',
                 snippet=str(g),
                 weight=0.5)
    for g in (gaps.get('missing_sources') or [])[:10]:
        _mk_link(verdict_cid,
                 source_table='dfir_gaps',
                 source_row_ref=f"gap:missing_source:{str(g)[:80]}",
                 source_file='structured_input.gaps',
                 event_ts=None,
                 role='counter',
                 snippet=f"missing_source:{g}",
                 weight=0.4)

    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("DELETE FROM public.dfir_claim_evidence_links_v1 WHERE job_id=%s AND case_key=%s", (job_id, case_key))
                cur.execute("DELETE FROM public.dfir_claims_v1 WHERE job_id=%s AND case_key=%s", (job_id, case_key))
                cur.executemany("""
                    INSERT INTO public.dfir_claims_v1 (
                        claim_id, job_id, case_key, step_code, claim_type, claim_text,
                        time_bound_start, time_bound_end, confidence, status, created_at, updated_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now(),now())
                """, claims)
                cur.executemany("""
                    INSERT INTO public.dfir_claim_evidence_links_v1 (
                        link_id, claim_id, job_id, case_key, source_table, source_row_ref, source_file,
                        event_ts, evidence_role, snippet, weight, created_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())
                """, links)
                # Human verdicts must SURVIVE re-analysis. Claims are re-issued with a NEW
                # claim_id on every run (DELETE above), so the binding cannot be claim_id -
                # it is the NORMALIZED claim_text inside the same case. case_feedback is the
                # durable store (a re-run never deletes it). Identical normalization on both
                # sides, done entirely in SQL so Python/SQL cannot drift apart.
                try:
                    cur.execute("""
                        UPDATE public.dfir_claims_v1 c
                           SET status = CASE v.verdict WHEN 'correct' THEN 'human_confirmed'
                                                       ELSE 'human_rejected' END,
                               updated_at = now()
                          FROM (
                                SELECT DISTINCT ON (nk) nk, verdict FROM (
                                    SELECT left(lower(regexp_replace(btrim(claim_text), '[[:space:]]+', ' ', 'g')), 120) AS nk,
                                           verdict, ts
                                      FROM public.case_feedback
                                     WHERE case_key = %s AND verdict IN ('correct','incorrect')
                                ) z ORDER BY nk, ts DESC
                          ) v
                         WHERE c.job_id = %s AND c.case_key = %s
                           AND left(lower(regexp_replace(btrim(c.claim_text), '[[:space:]]+', ' ', 'g')), 120) = v.nk
                    """, (case_key, job_id, case_key))
                    _restamped = cur.rowcount or 0
                except Exception:
                    _restamped = 0
        return {
            'ok': True,
            'restamped_verdicts': _restamped,
            'written_claims': len(claims),
            'written_links': len(links),
            'written_support_links': sum(1 for x in links if x[8] == 'support'),
            'written_counter_links': sum(1 for x in links if x[8] == 'counter')
        }
    except Exception as e:
        return {'ok': False, 'written_claims': 0, 'written_links': 0, 'error': str(e)[:180]}


def _load_claims_slice_v1(job_id, case_key):
    out = {'timeline': [], 'finding': [], 'ioc': [], 'verdict': [], 'counts': {'claims':0,'links':0}}
    try:
        _ensure_claims_layer_tables()
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT claim_id, claim_type, step_code, claim_text, time_bound_start, time_bound_end, confidence, status
                    FROM public.dfir_claims_v1
                    WHERE job_id=%s AND case_key=%s
                    ORDER BY created_at ASC
                """, (job_id, case_key))
                rows = cur.fetchall() or []
                out['counts']['claims'] = len(rows)
                cids=[r[0] for r in rows]
                link_map={}
                if cids:
                    cur.execute("""
                        SELECT claim_id, source_table, source_row_ref, source_file, event_ts, evidence_role, snippet, weight
                        FROM public.dfir_claim_evidence_links_v1
                        WHERE job_id=%s AND case_key=%s
                        ORDER BY created_at ASC
                    """, (job_id, case_key))
                    for lr in cur.fetchall() or []:
                        link_map.setdefault(lr[0], []).append({
                            'source_table': lr[1], 'source_row_ref': lr[2], 'source_file': lr[3],
                            'event_ts': lr[4].isoformat() if lr[4] else None, 'evidence_role': lr[5],
                            'snippet': lr[6], 'weight': float(lr[7] or 0)
                        })
                out['counts']['links'] = sum(len(v) for v in link_map.values())
                for r in rows:
                    rec = {
                        'claim_id': r[0], 'claim_type': r[1], 'step_code': r[2], 'claim_text': r[3],
                        'time_bound_start': r[4].isoformat() if r[4] else None,
                        'time_bound_end': r[5].isoformat() if r[5] else None,
                        'confidence': r[6], 'status': r[7], 'evidence_links': link_map.get(r[0], [])
                    }
                    out.setdefault(r[1], []).append(rec)
    except Exception:
        try: conn.rollback()
        except: pass
        pass
    return out


