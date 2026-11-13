"""Trigger scan job helpers — catalog, staging, time windows."""
import json, logging, time, math
from datetime import datetime, timezone
import psycopg2
from core.config import PG_DSN
from core.db import table_exists
_log = logging.getLogger('app')

TRIGGER_JOBS: dict = {}

def _ensure_trigger_scan_jobs_table():
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.trigger_scan_jobs_v2 (
                  job_id text PRIMARY KEY,
                  case_key text NOT NULL,
                  status text NOT NULL DEFAULT 'queued',
                  stage text,
                  progress numeric NOT NULL DEFAULT 0,
                  error text,
                  run_id text,
                  ingest jsonb,
                  result jsonb,
                  started_at timestamptz,
                  finished_at timestamptz,
                  updated_at timestamptz NOT NULL DEFAULT now()
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_trigger_scan_jobs_case_started ON public.trigger_scan_jobs_v2(case_key, started_at DESC)")
            conn.commit()

def _persist_trigger_scan_job(job_id):
    st = TRIGGER_JOBS.get(job_id) or {}
    if not st:
        return
    try:
        _ensure_trigger_scan_jobs_table()
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO public.trigger_scan_jobs_v2(job_id, case_key, status, stage, progress, error, run_id, ingest, result, started_at, finished_at, updated_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s,%s,now())
                    ON CONFLICT (job_id) DO UPDATE
                    SET case_key=EXCLUDED.case_key,
                        status=EXCLUDED.status,
                        stage=EXCLUDED.stage,
                        progress=EXCLUDED.progress,
                        error=EXCLUDED.error,
                        run_id=EXCLUDED.run_id,
                        ingest=EXCLUDED.ingest,
                        result=EXCLUDED.result,
                        started_at=COALESCE(public.trigger_scan_jobs_v2.started_at, EXCLUDED.started_at),
                        finished_at=EXCLUDED.finished_at,
                        updated_at=now()
                """, (
                    job_id,
                    str(st.get('case_key','')),
                    str(st.get('status','queued')),
                    str(st.get('stage','queued')),
                    float(st.get('progress',0) or 0),
                    (str(st.get('error')) if st.get('error') is not None else None),
                    (str(st.get('run_id')) if st.get('run_id') is not None else None),
                    json.dumps(st.get('ingest')) if isinstance(st.get('ingest'), (dict,list)) else None,
                    json.dumps(st.get('result')) if isinstance(st.get('result'), (dict,list)) else None,
                    datetime.fromtimestamp(float(st.get('created_at', time.time())), tz=timezone.utc) if st.get('created_at') else datetime.now(timezone.utc),
                    datetime.now(timezone.utc) if str(st.get('status','')).lower() in ('done','failed') else None,
                ))
            conn.commit()
    except Exception:
        try: conn.rollback()
        except: pass
        pass

TABLES_ALL = [
    'event_logs_v2','program_exec_v2','filesystem_v2','srum_v2','raw_fallback_v2',
    'tool_alerts_v2','system_profile_v1',
    'tmp_case_trigger_hits','tmp_case_trigger_timeline','case_trigger_hits_v2',
    'ingest_files','ingest_jobs',
    'log_events','generic_log_rows','case_trigger_hits'
]

def _ensure_trigger_catalog_table():
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.trigger_catalog_v1 (
                  trigger_id bigserial PRIMARY KEY,
                  trigger_text text NOT NULL UNIQUE,
                  enabled boolean NOT NULL DEFAULT true,
                  priority int NOT NULL DEFAULT 100,
                  severity text,
                  source text NOT NULL DEFAULT 'manual',
                  version int NOT NULL DEFAULT 1,
                  created_at timestamptz NOT NULL DEFAULT now(),
                  updated_at timestamptz NOT NULL DEFAULT now(),
                  last_seen_at timestamptz
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_trigger_catalog_enabled_priority ON public.trigger_catalog_v1(enabled, priority, trigger_text)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_trigger_catalog_source ON public.trigger_catalog_v1(source)")
            conn.commit()


def _sync_trigger_catalog_from_cache():
    # backward-compatible bridge: keep old pg_triggers_cache usable while moving canonical reads to trigger_catalog_v1
    try:
        _ensure_trigger_catalog_table()
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                if table_exists('pg_triggers_cache'):
                    cur.execute("""
                        INSERT INTO public.trigger_catalog_v1(trigger_text, enabled, source, last_seen_at, updated_at)
                        SELECT trigger, COALESCE(enabled,true), 'pg_triggers_cache', now(), now()
                        FROM public.pg_triggers_cache
                        WHERE trigger IS NOT NULL AND btrim(trigger) <> ''
                        ON CONFLICT (trigger_text) DO UPDATE
                        SET enabled = EXCLUDED.enabled,
                            last_seen_at = now(),
                            updated_at = now()
                    """)
                conn.commit()
    except Exception:
        try: conn.rollback()
        except: pass
        pass



def _drop_vanilla_triggers(rows):
    """Remove triggers that name a stock Windows file.

    166 of the 180 catalogue entries are harvested automatically from past cases, and the
    harvest records what was PRESENT, not what was guilty. msvcr100.dll, msvcr120.dll and
    chrome.exe were in there. Four entries out of 180, but they match many files per case: on
    20_07_case_44_case_43 the triggers section came out 24 of 28 rows of Office libraries.

    Only an explicit True drops a trigger. known_good returns None when a reference database is
    missing, and None means "unknown" - reading it as "clean" would turn a missing file into a
    filter that quietly deletes real triggers.
    """
    try:
        from analysis import known_good as _kg
    except Exception:
        return rows                      # no reference data -> change nothing
    out, dropped = [], []
    for t in rows:
        raw = str(t or '').strip()
        name = raw.strip('\\/').split('\\')[-1].split('/')[-1].lower()
        keep = True
        # A trigger carrying a PATH is never filtered: a stock file name in a non-stock
        # directory is the classic masquerade, and the path IS the evidence. Matching the base
        # name alone dropped c:\\programdata\\reaitekhd\\taskhost.exe and
        # c:\\programdata\\windowstask\\audiodg.exe - malware wearing a system name.
        has_path = ('\\' in raw) or ('/' in raw)
        # Only system LIBRARIES are filtered, never executables. The measured harm was
        # msvcr*.dll matching dozens of Office files per case; an .exe that a clean image
        # happens to contain (7za.exe, psexesvc.exe) is staging or lateral movement when it
        # turns up in a case, and losing it costs more than the noise it saves.
        _lib = name.rsplit('.', 1)[-1] in ('dll', 'vdm', 'sys', 'mui', 'cat')
        if name and _lib and ' ' not in name and not has_path:
            try:
                if _kg.is_vanilla_name(name) is True:
                    keep = False
            except Exception:
                keep = True
        # And never drop what the attacker-tooling dictionary recognises. The vanilla reference
        # is built from clean images, so psexesvc.exe and 7za.exe can appear in one - in a case
        # they are lateral movement and staging, not furniture.
        if not keep:
            try:
                from analysis import attack_tools as _at
                _cls = getattr(_at, 'classify', None) or getattr(_at, 'categorize', None)
                if _cls and (_cls(name) or _cls(raw)):
                    keep = True
            except Exception:
                pass
        (out if keep else dropped).append(t)
    if dropped:
        try:
            _log.info('[triggers] відкинуто штатних файлів Windows: %d (%s)',
                      len(dropped), ', '.join(sorted(dropped)[:6]))
        except Exception:
            pass
    return out

def _load_effective_triggers():
    # Canonical path: trigger_catalog_v1. Fallback: pg_triggers_cache.
    _sync_trigger_catalog_from_cache()
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            if table_exists('trigger_catalog_v1'):
                cur.execute("""
                    SELECT trigger_text
                    FROM public.trigger_catalog_v1
                    WHERE enabled = true
                    ORDER BY priority ASC, trigger_text ASC
                """)
                rows = [r[0] for r in cur.fetchall() if r and r[0]]
                rows = _drop_vanilla_triggers(rows)
                if rows:
                    return rows
            if table_exists('pg_triggers_cache'):
                cur.execute("SELECT trigger FROM public.pg_triggers_cache WHERE enabled = true ORDER BY trigger")
                return [r[0] for r in cur.fetchall() if r and r[0]]
    return []


def _ensure_trigger_time_window_table():
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.trigger_time_windows_v1 (
                  run_id text PRIMARY KEY,
                  case_key text NOT NULL,
                  anchor_ts timestamptz,
                  month_start timestamptz,
                  month_end timestamptz,
                  window_start timestamptz,
                  window_end timestamptz,
                  first_relevant_ts timestamptz,
                  last_relevant_ts timestamptz,
                  hits_total int NOT NULL DEFAULT 0,
                  hits_with_ts int NOT NULL DEFAULT 0,
                  cluster_day_count int NOT NULL DEFAULT 0,
                  rationale text,
                  created_at timestamptz NOT NULL DEFAULT now(),
                  updated_at timestamptz NOT NULL DEFAULT now()
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_trigger_time_windows_case ON public.trigger_time_windows_v1(case_key, updated_at DESC)")
            conn.commit()


def _ensure_tmp_trigger_tables():
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.tmp_case_trigger_hits (
                  id bigserial PRIMARY KEY,
                  run_id text NOT NULL,
                  case_key text NOT NULL,
                  trigger text,
                  source_table text,
                  source_ref text,
                  event_ts timestamptz,
                  artifact_family text,
                  snippet text,
                  score numeric NOT NULL DEFAULT 0,
                  created_at timestamptz NOT NULL DEFAULT now()
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_tmp_trigger_hits_run ON public.tmp_case_trigger_hits(run_id, case_key)")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.tmp_case_trigger_timeline (
                  id bigserial PRIMARY KEY,
                  run_id text NOT NULL,
                  case_key text NOT NULL,
                  event_ts timestamptz,
                  trigger text,
                  source_table text,
                  source_ref text,
                  artifact_family text,
                  snippet text,
                  score numeric NOT NULL DEFAULT 0
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_tmp_trigger_timeline_run ON public.tmp_case_trigger_timeline(run_id, case_key)")
            conn.commit()


def _persist_trigger_staging_and_window(run_id, case_key):
    _ensure_trigger_time_window_table()
    _ensure_tmp_trigger_tables()
    out = {'ok': True, 'run_id': run_id, 'case_key': case_key}
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            # stage hits per run/case
            cur.execute("DELETE FROM public.tmp_case_trigger_hits WHERE run_id=%s", (run_id,))
            cur.execute("""
                INSERT INTO public.tmp_case_trigger_hits(run_id, case_key, trigger, source_table, source_ref, event_ts, artifact_family, snippet, score, created_at)
                SELECT run_id, case_key, trigger, source_table, source_ref, event_ts, artifact_family, snippet, score, created_at
                FROM public.case_trigger_hits_v2
                WHERE run_id=%s AND case_key=%s
            """, (run_id, case_key))

            cur.execute("DELETE FROM public.tmp_case_trigger_timeline WHERE run_id=%s", (run_id,))
            cur.execute("""
                INSERT INTO public.tmp_case_trigger_timeline(run_id, case_key, event_ts, trigger, source_table, source_ref, artifact_family, snippet, score)
                SELECT run_id, case_key, event_ts, trigger, source_table, source_ref, artifact_family, snippet, score
                FROM public.case_trigger_hits_v2
                WHERE run_id=%s AND case_key=%s
                ORDER BY event_ts NULLS LAST, score DESC
            """, (run_id, case_key))

            cur.execute("SELECT count(*), count(event_ts) FROM public.case_trigger_hits_v2 WHERE run_id=%s AND case_key=%s", (run_id, case_key))
            hits_total, hits_with_ts = cur.fetchone()
            hits_total = int(hits_total or 0)
            hits_with_ts = int(hits_with_ts or 0)

            anchor_ts = None
            cluster_day_count = 0
            primary_day_score = 0.0
            secondary_candidates = []
            cur.execute("SELECT max(event_ts) FROM public.case_trigger_hits_v2 WHERE run_id=%s AND case_key=%s AND event_ts IS NOT NULL", (run_id, case_key))
            max_ts = (cur.fetchone() or [None])[0]

            cur.execute("""
                SELECT
                  date_trunc('day', event_ts) AS day_ts,
                  count(*)::int AS day_count,
                  sum(COALESCE(score,1))::numeric AS day_score,
                  sum(CASE WHEN trigger LIKE '__family:%%' OR COALESCE(artifact_family,'') <> '' THEN 1 ELSE 0 END)::int AS family_hits,
                  sum(CASE
                        WHEN source_table='event_logs_v2' THEN 1.0
                        WHEN source_table='filesystem_v2' THEN 0.9
                        WHEN source_table='program_exec_v2' THEN 0.95
                        WHEN source_table='tool_alerts_v2' THEN 0.8
                        ELSE 0.6
                      END)::numeric AS source_weight
                FROM public.case_trigger_hits_v2
                WHERE run_id=%s AND case_key=%s AND event_ts IS NOT NULL
                GROUP BY 1
            """, (run_id, case_key))
            raw_days = cur.fetchall() or []
            ranked_days = []
            if max_ts:
                for d in raw_days:
                    day_ts, day_count, day_score, family_hits, source_weight = d
                    age_days = max(0.0, (max_ts - day_ts).total_seconds() / 86400.0)
                    recency_factor = max(0.05, 1.0 - min(age_days / 120.0, 0.95))
                    score_component = math.log1p(max(0.0, float(day_score or 0))) * (recency_factor ** 1.6)
                    density_bonus = min(2.5, float(day_count or 0) / 4.0)
                    family_bonus = min(3.0, float(family_hits or 0) * 0.50)
                    src_bonus = min(2.0, float(source_weight or 0) / 18.0)
                    rank_score = score_component + density_bonus + family_bonus + src_bonus
                    ranked_days.append({'day_ts':day_ts,'day_count':int(day_count or 0),'day_score':float(day_score or 0),'family_hits':int(family_hits or 0),'source_weight':float(source_weight or 0),'age_days':round(age_days,2),'recency_factor':round(recency_factor,3),'rank_score':round(rank_score,3)})
                ranked_days.sort(key=lambda x:(-x['rank_score'],-x['day_score'],-x['day_count'],x['day_ts']))

            if ranked_days:
                anchor_ts = ranked_days[0]['day_ts']
                cluster_day_count = ranked_days[0]['day_count']
                primary_day_score = float(ranked_days[0]['day_score'] or 0)
                for d in ranked_days[1:3]:
                    secondary_candidates.append({'day': d['day_ts'].isoformat() if d['day_ts'] else None, 'count': d['day_count'], 'score': d['day_score'], 'rank': d['rank_score'], 'age_days': d['age_days']})
            else:
                cur.execute("SELECT min(event_ts) FROM public.case_trigger_hits_v2 WHERE run_id=%s AND case_key=%s", (run_id, case_key))
                anchor_ts = (cur.fetchone() or [None])[0]

            if anchor_ts:
                cur.execute("SELECT date_trunc('month', %s::timestamptz), date_trunc('month', %s::timestamptz) + interval '1 month'", (anchor_ts, anchor_ts))
                month_start, month_end = cur.fetchone()
            else:
                month_start = None
                month_end = None

            cur.execute("SELECT min(event_ts), max(event_ts) FROM public.case_trigger_hits_v2 WHERE run_id=%s AND case_key=%s AND event_ts IS NOT NULL", (run_id, case_key))
            first_ts, last_ts = cur.fetchone()

            # outlier-guarded adaptive expansion: only sufficiently relevant rows can extend window
            rel_score_thr = max(2.0, primary_day_score * 0.35)
            rel_min_ts = None
            rel_max_ts = None
            if anchor_ts:
                cur.execute("""
                    SELECT min(event_ts), max(event_ts)
                    FROM public.case_trigger_hits_v2
                    WHERE run_id=%s AND case_key=%s AND event_ts IS NOT NULL
                      AND (
                        ((COALESCE(score,0) >= %s OR COALESCE(artifact_family,'') <> '' OR trigger LIKE '__family:%%')
                          AND event_ts BETWEEN (%s::timestamptz - interval '90 days') AND (%s::timestamptz + interval '90 days'))
                        OR event_ts BETWEEN (%s::timestamptz - interval '15 days') AND (%s::timestamptz + interval '15 days')
                      )
                """, (run_id, case_key, rel_score_thr, anchor_ts, anchor_ts, anchor_ts, anchor_ts))
                rel_min_ts, rel_max_ts = cur.fetchone()

            if month_start and month_end:
                # expand month only to relevant envelope, not global first/last
                if rel_min_ts is not None:
                    window_start = month_start if rel_min_ts >= month_start else rel_min_ts
                else:
                    window_start = month_start
                if rel_max_ts is not None:
                    window_end = month_end if rel_max_ts <= month_end else rel_max_ts
                else:
                    window_end = month_end
                rationale = f"month_window_primary_cluster_then_adaptive_expand_relevant_only(score_thr={rel_score_thr:.2f},secondary={json.dumps(secondary_candidates, ensure_ascii=False)})"
            else:
                window_start = rel_min_ts if rel_min_ts is not None else first_ts
                window_end = rel_max_ts if rel_max_ts is not None else last_ts
                rationale = f"no_anchor_ts_fallback_relevant_envelope(score_thr={rel_score_thr:.2f})"

            cur.execute("""
                INSERT INTO public.trigger_time_windows_v1(
                  run_id, case_key, anchor_ts, month_start, month_end, window_start, window_end,
                  first_relevant_ts, last_relevant_ts, hits_total, hits_with_ts, cluster_day_count, rationale, updated_at
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())
                ON CONFLICT (run_id) DO UPDATE
                SET case_key=EXCLUDED.case_key,
                    anchor_ts=EXCLUDED.anchor_ts,
                    month_start=EXCLUDED.month_start,
                    month_end=EXCLUDED.month_end,
                    window_start=EXCLUDED.window_start,
                    window_end=EXCLUDED.window_end,
                    first_relevant_ts=EXCLUDED.first_relevant_ts,
                    last_relevant_ts=EXCLUDED.last_relevant_ts,
                    hits_total=EXCLUDED.hits_total,
                    hits_with_ts=EXCLUDED.hits_with_ts,
                    cluster_day_count=EXCLUDED.cluster_day_count,
                    rationale=EXCLUDED.rationale,
                    updated_at=now()
            """, (run_id, case_key, anchor_ts, month_start, month_end, window_start, window_end, first_ts, last_ts, hits_total, hits_with_ts, cluster_day_count, rationale))
            conn.commit()

    out.update({
        'hits_total': hits_total,
        'hits_with_ts': hits_with_ts,
        'anchor_ts': anchor_ts.isoformat() if anchor_ts else None,
        'month_start': month_start.isoformat() if month_start else None,
        'month_end': month_end.isoformat() if month_end else None,
        'window_start': window_start.isoformat() if window_start else None,
        'window_end': window_end.isoformat() if window_end else None,
        'first_relevant_ts': first_ts.isoformat() if first_ts else None,
        'last_relevant_ts': last_ts.isoformat() if last_ts else None,
        'cluster_day_count': cluster_day_count,
        'rationale': rationale,
    })
    return out


# q(), table_exists(), _rowdict() now imported from core.db

# DFIR_STEP_CODES, STALE_HEARTBEAT_SECONDS imported from core.config

DFIR_RUNNERS = {}
AUTON_BATCH_RUNNERS = {}


# ── Assemblers (extracted to analysis/assemblers.py) ─────────────────────
from analysis.assemblers import (
    _ensure_event_identity_view, _table_has_case_data, _run_coverage,
    _extract_rdp_user_creation_linkage, _extract_script_host_execution_linkage,
    _ensure_browser_provenance_view, _extract_delivery_browser_provenance,
    _assemble_quality_findings, _assemble_incident_timeline,
    _assemble_detection_timeline, _assemble_ioc_artifacts,
    _get_trigger_family_snapshot, _assemble_case_llm_triage_v1,
    _assemble_case_drilldown_v1, _assemble_case_reasoning_v1,
    _normalize_core_step_meta, _build_general_triage_v1,
)


# _rowdict imported from core.db

_STEP_UA = {
    'ingest_check':           '📂 Перевірка файлів',
    'detection':              '🔍 Тригери з БД',
    'corroboration':          '🔗 Співставлення доказів',
    'incident_timeline':      '📅 Часова шкала',
    'case_llm_triage_v1':     '🤖 AI Триаж',
    'case_drilldown_v1':      '🔬 AI Drill-down',
    'case_reasoning_v1':      '🧠 AI Висновок',
    'detection_timeline':     '📊 Детекція timeline',
    'ioc_artifacts':          '🎯 IOC артефакти',
    'short_conclusion':       '📝 Короткий висновок',
    'txt_report':             '📄 Генерація звіту',
    'llm_report':             '🤖 AI звіт (LLM)',
    'agent_planner_v2':       '🗺 Планувальник агента',
}

