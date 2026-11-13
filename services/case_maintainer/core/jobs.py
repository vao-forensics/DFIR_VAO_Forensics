"""Job management — create, query, update DFIR run jobs and steps."""
import threading
import os, json, time, uuid, logging
import urllib.error
import psycopg2
from psycopg2.extras import Json
from core.config import (
    PG_DSN, CASE_LIB, TG_BOT_TOKEN, DFIR_STEP_CODES, STALE_HEARTBEAT_SECONDS,
)
from telegram.notify import _tg_send_or_edit, _build_progress_text
from core.triggers import DFIR_RUNNERS
from core.db import rowdict as _rowdict
from reports.claims import _safe_case_folder
from psycopg2.errors import UniqueViolation
from datetime import datetime, timezone, timedelta
_log = logging.getLogger('app')

def create_status_card(case_key, status='queued', current_step=0, total_steps=None, progress_pct=0.0,
                       chat_id=None, step_code=None):
    total_steps = int(total_steps or len(DFIR_STEP_CODES))
    tg_token = TG_BOT_TOKEN
    if not tg_token or not chat_id:
        return {'ok': True, 'message_id': None, 'chat_id': chat_id}
    text = _build_progress_text(case_key, status, current_step, total_steps, progress_pct, step_code)
    msg_id = _tg_send_or_edit(tg_token, chat_id, text)
    return {'ok': True, 'message_id': msg_id, 'chat_id': chat_id}


def edit_status_card(job):
    """Edit live progress message in Telegram after each step."""
    tg_token = TG_BOT_TOKEN
    chat_id = job.get('status_chat_id') or job.get('triggered_by_chat_id')
    msg_id = job.get('status_message_id')
    if not tg_token or not chat_id:
        return {'ok': True, 'edited': False}
    try:
        text = _build_progress_text(
            case_key=job.get('case_key', ''),
            status=job.get('status', 'running'),
            current_step=int(job.get('current_step') or 0),
            total_steps=int(job.get('total_steps') or len(DFIR_STEP_CODES)),
            progress_pct=float(job.get('progress_pct') or 0),
            step_code=job.get('latest_step_code'),
            error_short=job.get('error_short'),
            job_id=job.get('job_id'),
            started_at=job.get('created_at'),
            heartbeat_at=job.get('last_heartbeat_at') or job.get('updated_at'),
        )
        new_msg_id = _tg_send_or_edit(tg_token, chat_id, text, message_id=msg_id)
        if new_msg_id and not msg_id:
            # save message_id if first time
            try:
                with psycopg2.connect(PG_DSN) as conn:
                    conn.autocommit = True
                    with conn.cursor() as cur:
                        cur.execute("UPDATE dfir_run_jobs_v2 SET status_message_id=%s WHERE job_id=%s AND status_message_id IS NULL",
                                    (str(new_msg_id), job.get('job_id')))
                        conn.commit()
            except Exception:
                try: conn.rollback()
                except: pass
                pass
        return {'ok': True, 'edited': True}
    except Exception:
        return {'ok': True, 'edited': False}


def create_queued_job_race_safe(case_key, chat_id=None, user_id=None, retry_of_job_id=None, total_steps=None):
    total_steps = int(total_steps or len(DFIR_STEP_CODES))
    new_job_id = str(uuid.uuid4())
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO public.dfir_run_jobs_v2 (
                      job_id, case_key, status, run_mode,
                      current_step, total_steps, progress_pct,
                      status_chat_id,
                      triggered_by_user_id, triggered_by_chat_id,
                      retry_of_job_id,
                      created_at, updated_at
                    )
                    VALUES (%s,%s,'queued','full',0,%s,0.00,%s,%s,%s,%s,now(),now())
                    RETURNING job_id, case_key, status, created_at
                    """,
                    (new_job_id, case_key, int(total_steps), chat_id, user_id, chat_id, retry_of_job_id)
                )
                row = cur.fetchone()
                return {'created': True, 'job': {'job_id': row[0], 'case_key': row[1], 'status': row[2], 'created_at': row[3]}}
            except UniqueViolation:
                conn.rollback()
                # if conflict came from stale orphan row, reconcile and retry once
                try:
                    reconcile_stale_runs(case_key=case_key)
                except Exception:
                    try: conn.rollback()
                    except: pass
                    pass

                with psycopg2.connect(PG_DSN) as c_retry:
                    with c_retry.cursor() as cr:
                        try:
                            cr.execute(
                                """
                                INSERT INTO public.dfir_run_jobs_v2 (
                                  job_id, case_key, status, run_mode,
                                  current_step, total_steps, progress_pct,
                                  status_chat_id,
                                  triggered_by_user_id, triggered_by_chat_id,
                                  retry_of_job_id,
                                  created_at, updated_at
                                )
                                VALUES (%s,%s,'queued','full',0,%s,0.00,%s,%s,%s,%s,now(),now())
                                RETURNING job_id, case_key, status, created_at
                                """,
                                (new_job_id, case_key, int(total_steps), chat_id, user_id, chat_id, retry_of_job_id)
                            )
                            row = cr.fetchone()
                            return {'created': True, 'job': {'job_id': row[0], 'case_key': row[1], 'status': row[2], 'created_at': row[3]}}
                        except UniqueViolation:
                            c_retry.rollback()

                with psycopg2.connect(PG_DSN) as c2:
                    with c2.cursor() as c:
                        c.execute(
                            """
                            SELECT job_id, case_key, status, current_step, total_steps, progress_pct, latest_step_code, last_heartbeat_at
                            FROM public.dfir_run_jobs_v2
                            WHERE case_key=%s AND status IN ('queued','running')
                            ORDER BY created_at DESC
                            LIMIT 1
                            """,
                            (case_key,)
                        )
                        r = c.fetchone()
                        active = None
                        if r:
                            active = {
                                'job_id': r[0], 'case_key': r[1], 'status': r[2], 'current_step': r[3], 'total_steps': r[4],
                                'progress_pct': float(r[5] or 0), 'latest_step_code': r[6], 'last_heartbeat_at': r[7].isoformat() if r[7] else None
                            }
                        return {'created': False, 'active_job': active}


def get_latest_job(case_key):
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM public.dfir_run_jobs_v2
                WHERE case_key=%s
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (case_key,)
            )
            return _rowdict(cur)


def get_run_status(case_key):
    job = get_latest_job(case_key)
    if not job:
        return {'ok': True, 'case_key': case_key, 'has_job': False}
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT step_no, step_code, step_status, progress_pct, heartbeat_at, started_at, finished_at, message, error_code, error_short, meta_json, updated_at
                FROM public.dfir_run_steps_v2
                WHERE job_id=%s
                ORDER BY step_no ASC
                """,
                (job['job_id'],)
            )
            steps = []
            for r in cur.fetchall():
                steps.append({
                    'step_no': r[0], 'step_code': r[1], 'step_status': r[2], 'progress_pct': float(r[3]) if r[3] is not None else None,
                    'heartbeat_at': r[4].isoformat() if r[4] else None,
                    'started_at': r[5].isoformat() if r[5] else None,
                    'finished_at': r[6].isoformat() if r[6] else None,
                    'message': r[7], 'error_code': r[8], 'error_short': r[9], 'meta_json': r[10],
                    'updated_at': r[11].isoformat() if r[11] else None,
                })

    # execution health projection
    now_ts = time.time()
    hb = job.get('last_heartbeat_at')
    hb_age = None
    if hb:
        try:
            hb_age = max(0, int(now_ts - hb.timestamp()))
        except Exception:
            hb_age = None

    running_step = next((s for s in steps if s.get('step_status') == 'running'), None)
    step_runtime = None
    if running_step and running_step.get('started_at'):
        try:
            from datetime import datetime
            st = datetime.fromisoformat(running_step['started_at'])
            step_runtime = max(0, int(now_ts - st.timestamp()))
        except Exception:
            step_runtime = None

    runner = DFIR_RUNNERS.get(job.get('job_id'))
    worker_state = 'missing'
    if runner and runner.get('thread'):
        try:
            worker_state = 'alive' if runner['thread'].is_alive() else 'missing'
        except Exception:
            worker_state = 'missing'

    last_internal = None
    if steps:
        # most recent step update/message snapshot
        sx = sorted(steps, key=lambda x: x.get('updated_at') or '', reverse=True)[0]
        last_internal = {
            'step_no': sx.get('step_no'),
            'step_code': sx.get('step_code'),
            'step_status': sx.get('step_status'),
            'message': sx.get('message'),
            'updated_at': sx.get('updated_at'),
        }

    stale = bool(hb_age is not None and hb_age > STALE_HEARTBEAT_SECONDS)
    jstatus = str(job.get('status') or '')
    note = 'step active'
    if jstatus in ('failed', 'partial', 'completed', 'cancelled'):
        note = f'job terminal: {jstatus}'
    elif worker_state == 'missing' and stale and jstatus in ('running', 'queued'):
        note = 'job orphaned/stalled: worker missing + stale heartbeat'
    elif worker_state == 'alive' and stale:
        note = 'worker alive, waiting on long task (heartbeat stale)'
    elif worker_state == 'missing' and jstatus in ('running', 'queued'):
        note = 'worker missing, heartbeat not yet stale'

    return {
        'ok': True,
        'case_key': case_key,
        'has_job': True,
        'job': job,
        'steps': steps,
        'execution_health': {
            'worker_state': worker_state,
            'heartbeat_age_sec': hb_age,
            'step_runtime_sec': step_runtime,
            'last_internal_activity': last_internal,
            'stall_flag': stale,
            'note': note,
        }
    }


def _stale_cutoff_expr(seconds=STALE_HEARTBEAT_SECONDS):
    return f"(now() - interval '{int(seconds)} seconds')"


def reconcile_stale_runs(case_key=None, reason='stale_or_orphaned_runner', seconds=STALE_HEARTBEAT_SECONDS):
    """Mark truly stale queued/running jobs as failed.

    Liveness policy:
    - never reconcile by job row only;
    - require BOTH job heartbeat stale AND active step heartbeat stale;
    - do NOT reconcile when latest step is recently active/running OR recently finished success
      (job-row sync lag tolerance).
    """
    updated = []
    skipped = []
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            params = []
            where_case = ''
            if case_key:
                where_case = ' AND j.case_key=%s '
                params.append(case_key)

            # candidate jobs stale by job-row heartbeat
            cur.execute(
                f"""
                SELECT j.job_id, j.case_key,
                       j.status,
                       COALESCE(j.last_heartbeat_at, j.updated_at, j.created_at) AS job_hb,
                       ls.step_no,
                       ls.step_code,
                       ls.step_status,
                       ls.started_at,
                       ls.finished_at,
                       ls.heartbeat_at,
                       ls.updated_at
                FROM public.dfir_run_jobs_v2 j
                LEFT JOIN LATERAL (
                  SELECT s.step_no, s.step_code, s.step_status, s.started_at, s.finished_at, s.heartbeat_at, s.updated_at
                  FROM public.dfir_run_steps_v2 s
                  WHERE s.job_id = j.job_id
                  ORDER BY s.step_no DESC
                  LIMIT 1
                ) ls ON TRUE
                WHERE j.status IN ('queued','running')
                  {where_case}
                  AND COALESCE(j.last_heartbeat_at, j.updated_at, j.created_at) < {_stale_cutoff_expr(seconds)}
                ORDER BY j.created_at DESC
                """,
                tuple(params)
            )
            cand = cur.fetchall() or []

            to_reconcile = []
            for r in cand:
                job_id, ckey, jstatus, job_hb, step_no, step_code, step_status, started_at, finished_at, step_hb, step_updated = r
                step_touch = step_hb or step_updated or finished_at or started_at

                # If latest step has fresh activity, skip reconcile.
                fresh_step = bool(step_touch and step_touch >= (datetime.now(timezone.utc) - timedelta(seconds=int(seconds))))

                # If latest step finished success recently, allow job-row sync lag.
                recent_success_finish = bool(step_status == 'success' and finished_at and finished_at >= (datetime.now(timezone.utc) - timedelta(seconds=int(seconds))))

                if fresh_step or recent_success_finish:
                    skipped.append({
                        'job_id': job_id,
                        'case_key': ckey,
                        'job_hb': job_hb.isoformat() if job_hb else None,
                        'latest_step': {
                            'step_no': int(step_no) if step_no is not None else None,
                            'step_code': step_code,
                            'step_status': step_status,
                            'heartbeat_at': step_hb.isoformat() if step_hb else None,
                            'finished_at': finished_at.isoformat() if finished_at else None,
                            'updated_at': step_updated.isoformat() if step_updated else None,
                        },
                        'skip_reason': 'active_step_fresh_or_recent_success'
                    })
                    continue

                # no fresh step activity => truly stale
                to_reconcile.append(str(job_id))

            if to_reconcile:
                cur.execute(
                    """
                    UPDATE public.dfir_run_jobs_v2
                    SET status='failed',
                        error_code=COALESCE(error_code,'ORPHANED_STALE'),
                        error_short=COALESCE(error_short,%s),
                        latest_step_code=COALESCE(latest_step_code,'orphan_reconcile'),
                        finished_at=COALESCE(finished_at, now()),
                        updated_at=now()
                    WHERE job_id::text = ANY(%s)
                    RETURNING job_id, case_key, status, latest_step_code
                    """,
                    (reason, to_reconcile)
                )
                for rr in cur.fetchall() or []:
                    updated.append({'job_id': rr[0], 'case_key': rr[1], 'status': rr[2], 'latest_step_code': rr[3]})

                # align any running step rows for reconciled jobs
                cur.execute(
                    """
                    UPDATE public.dfir_run_steps_v2
                    SET step_status='failed',
                        error_code=COALESCE(error_code,'ORPHANED_STALE'),
                        error_short=COALESCE(error_short,%s),
                        finished_at=COALESCE(finished_at, now()),
                        updated_at=now()
                    WHERE job_id::text = ANY(%s)
                      AND step_status='running'
                    """,
                    (reason, to_reconcile)
                )
    return {'ok': True, 'updated': updated, 'count': len(updated), 'seconds': int(seconds), 'skipped': skipped}


def _get_latest_active_job(case_key):
    # reconcile stale orphaned rows before returning active guard row
    try:
        reconcile_stale_runs(case_key=case_key)
    except Exception:
        try: conn.rollback()
        except: pass
        pass
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM public.dfir_run_jobs_v2
                WHERE case_key=%s AND status IN ('queued','running')
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (case_key,)
            )
            return _rowdict(cur)


def _get_latest_usable_result_job(case_key):
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM public.dfir_run_jobs_v2
                WHERE case_key=%s
                  AND status IN ('completed','partial')
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (case_key,)
            )
            return _rowdict(cur)


def _rendered_cache_path(case_key, job_id):
    safe_case = _safe_case_folder(case_key)
    rep_dir = os.path.join(CASE_LIB, safe_case, 'reports')
    os.makedirs(rep_dir, exist_ok=True)
    return os.path.join(rep_dir, f'case_rendered_{job_id}.txt')


def _load_rendered_cache(case_key, job_id):
    try:
        p = _rendered_cache_path(case_key, job_id)
        if p and os.path.isfile(p):
            with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                t = f.read()
            low = (t or '').lower()
            bad_markers = (
                'дані відсутні', 'відсутні конкретні forensic-дані',
                'не можу вигадувати факти', 'чекаю на дані',
                'please provide forensic', 'no forensic data',
            )
            sep = '─' * 40
            if any(m in low for m in bad_markers):
                if sep in t:
                    tail = t.split(sep, 1)[1].strip()
                    if tail and not any(m in tail.lower() for m in bad_markers):
                        return {'ok': True, 'path': p, 'text': tail + '\n'}
                return {'ok': False, 'path': p, 'text': ''}
            if t and t.strip():
                return {'ok': True, 'path': p, 'text': t}
    except Exception:
        try: conn.rollback()
        except: pass
        pass
    return {'ok': False, 'path': None, 'text': ''}


# One background reshape per (case, job): see the comment inside _save_rendered_cache.
_RESHAPE_INFLIGHT = set()
_RESHAPE_LOCK = threading.Lock()


def _save_rendered_cache(case_key, job_id, text):
    """Reshape and persist the client report, without holding the caller for minutes.

    reshape_client_report rebuilds every deterministic section, and measurement put that at
    163.9 s on one case against a client that gives up at 60 - so a cache miss showed the user
    a failure while the work carried on. Waiting longer is not the fix: a silent button for
    three minutes reads as broken, and the person presses again, starting a second reshape.

    Under DFIR_RENDER_BUDGET_S (default 40, below the client's 60) this behaves exactly as it
    did. Past it the reshape finishes in a background thread and writes the file anyway, and
    the caller gets 'pending': True with the unreshaped text - so the NEXT press is a cache hit
    rather than another wait. Callers that do not look at 'pending' are unaffected.
    """
    try:
        _budget = float(os.environ.get('DFIR_RENDER_BUDGET_S') or 40)
        _slot = {}

        def _do_reshape():
            try:
                from reports.reshape import reshape_client_report
                _slot['text'] = reshape_client_report(case_key, text or '')
            except Exception:
                _slot['text'] = text or ''
            try:
                _p = _rendered_cache_path(case_key, job_id)
                with open(_p, 'w', encoding='utf-8') as _f:
                    _f.write(_slot.get('text') or '')
            except Exception:
                pass
            finally:
                with _RESHAPE_LOCK:
                    _RESHAPE_INFLIGHT.discard((str(case_key), str(job_id)))

        # One reshape per (case, job) at a time. Without this every press while the first is
        # still running starts ANOTHER one, and a person told to press again in a minute will
        # do exactly that - measured: a second call spawned a second thread for the same work.
        _key = (str(case_key), str(job_id))
        with _RESHAPE_LOCK:
            _running = _key in _RESHAPE_INFLIGHT
            if not _running:
                _RESHAPE_INFLIGHT.add(_key)
        if _running:
            return {'ok': False, 'path': None, 'text': '', 'pending': True}

        _th = threading.Thread(target=_do_reshape,
                               name='dfir-reshape-%s' % str(case_key)[:20])
        _th.daemon = True
        _th.start()
        _th.join(_budget)
        if _th.is_alive():
            return {'ok': False, 'path': None, 'text': '', 'pending': True}
        text = _slot.get('text', text)
        p = _rendered_cache_path(case_key, job_id)
        with open(p, 'w', encoding='utf-8') as f:
            f.write(text or '')
        # hand the reshaped text back: callers used to keep the pre-reshape string and
        # return that to the user, so the first reader of a fresh run got the raw
        # narrative and everybody after him got the client report.
        return {'ok': True, 'path': p, 'text': text or ''}
    except Exception:
        return {'ok': False, 'path': None, 'text': ''}


def _load_rendered_from_txt_snapshot(txt_path):
    try:
        if not txt_path or not os.path.isfile(txt_path):
            return {'ok': False, 'text': ''}
        with open(txt_path, 'r', encoding='utf-8', errors='ignore') as f:
            t = f.read()
        if not t:
            return {'ok': False, 'text': ''}
        # New format: forensic narrative starts with === or FORENSIC ЗВІТ or == РОЗДІЛ or ВЕРДИКТ:
        for marker in ('DFIR РЕЗУЛЬТАТ', '=' * 10, 'FORENSIC ЗВІТ', '== РОЗДІЛ', 'ВЕРДИКТ:'):
            if marker in t:
                part = t[t.index(marker):].strip()
                if len(part) > 200:
                    return {'ok': True, 'text': part + '\n'}
        # Legacy fallback: old marker
        old_marker = '=== User-facing Rendered Result ==='
        if old_marker in t:
            part = t.split(old_marker, 1)[1]
            stop_mark = '\n=== Raw '
            if stop_mark in part:
                part = part.split(stop_mark, 1)[0]
            part = part.strip()
            return {'ok': bool(part), 'text': part + '\n' if part else ''}
        return {'ok': False, 'text': ''}
    except Exception:
        return {'ok': False, 'text': ''}


def get_last_result_state(case_key):
    def _guard_last_result_text(text, kind='dfir_last_result'):
        try:
            from analysis.output_guardrails import guard_client_output
            guarded, issues = guard_client_output(case_key, text, kind=kind)
            return guarded, issues
        except Exception:
            return str(text or '').strip(), []

    usable = _get_latest_usable_result_job(case_key)
    active = _get_latest_active_job(case_key)
    latest = get_latest_job(case_key)

    # fast-path: return persisted rendered snapshot for latest usable run
    if usable:
        cache = _load_rendered_cache(case_key, usable.get('job_id'))
        if cache.get('ok'):
            guarded_text, guard_issues = _guard_last_result_text(cache.get('text') or '', kind='dfir_last_result_cache')
            if guard_issues and guarded_text != (cache.get('text') or ''):
                _save_rendered_cache(case_key, usable.get('job_id'), guarded_text)
            return {
                'ok': True,
                'case_key': case_key,
                'has_usable_result': True,
                'usable_result': usable,
                'has_active_run': bool(active),
                'active_run': active,
                'fallback_latest': latest,
                'rendered_report_text': guarded_text,
                'parity': None,
                'render_mode': 'cache_hit',
                'render_cache_path': cache.get('path'),
                'guard_issues': guard_issues,
            }

        # secondary fast-path: derive user-facing block from persisted TXT snapshot
        from_txt = _load_rendered_from_txt_snapshot(usable.get('txt_report_path'))
        if from_txt.get('ok'):
            guarded_text, guard_issues = _guard_last_result_text(from_txt.get('text') or '', kind='dfir_last_result_txt')
            saved = _save_rendered_cache(case_key, usable.get('job_id'), guarded_text)
            # The reshape ran past its budget and is finishing in the background. Serving the
            # raw snapshot here would hand the first reader a DIFFERENT document from everyone
            # after him - the exact defect 0378b36 fixed. Say what is happening instead.
            if saved.get('pending'):
                return {
                    'ok': True,
                    'case_key': case_key,
                    'has_usable_result': True,
                    'usable_result': usable,
                    'has_active_run': bool(active),
                    'active_run': active,
                    'fallback_latest': latest,
                    'rendered_report_text': (
                        '⏳ Звіт ще готується — велика справа, це кілька хвилин.\n'
                        'Натисніть «DFIR-аналіз» ще раз приблизно за хвилину: '
                        'тоді звіт віддасться одразу і повністю.'),
                    'parity': None,
                    'render_mode': 'reshape_in_progress',
                    'guard_issues': [],
                }
            # serve exactly what was cached, or the next call returns a different report
            if saved.get('text'):
                guarded_text, _g2 = _guard_last_result_text(saved['text'], kind='dfir_last_result_txt')
                if _g2:
                    guard_issues = list(guard_issues or []) + [g for g in _g2 if g not in (guard_issues or [])]
            return {
                'ok': True,
                'case_key': case_key,
                'has_usable_result': True,
                'usable_result': usable,
                'has_active_run': bool(active),
                'active_run': active,
                'fallback_latest': latest,
                'rendered_report_text': guarded_text,
                'parity': None,
                'render_mode': 'txt_snapshot_hit',
                'render_cache_path': saved.get('path') if saved.get('ok') else None,
                'guard_issues': guard_issues,
            }

    # fallback heavy render only when cache missing
    from reports.render import _render_user_facing_report as _ruf

    rendered = _ruf(case_key)

    rendered_text, guard_issues = _guard_last_result_text(rendered.get('text') or '', kind='dfir_last_result_render')

    # persist fallback render for future fast-path
    if usable and rendered_text:
        _saved_fb = _save_rendered_cache(case_key, usable.get('job_id'), rendered_text)
        if _saved_fb.get('pending'):
            # finishing in the background; do not serve a half-shaped report as if it were final
            rendered_text = ('⏳ Звіт ще готується — велика справа, це кілька хвилин.\n'
                             'Натисніть «DFIR-аналіз» ще раз приблизно за хвилину.')
            guard_issues = []
        elif _saved_fb.get('text'):
            rendered_text, _g3 = _guard_last_result_text(_saved_fb['text'], kind='dfir_last_result_render')
            if _g3:
                guard_issues = list(guard_issues or []) + [g for g in _g3 if g not in (guard_issues or [])]

    if usable:
        return {
            'ok': True,
            'case_key': case_key,
            'has_usable_result': True,
            'usable_result': usable,
            'has_active_run': bool(active),
            'active_run': active,
            'fallback_latest': latest,
            'rendered_report_text': rendered_text,
            'parity': rendered.get('parity'),
            'render_mode': 'fallback_render',
            'guard_issues': guard_issues,
        }

    if latest:
        return {
            'ok': True,
            'case_key': case_key,
            'has_usable_result': False,
            'usable_result': None,
            'has_active_run': bool(active),
            'active_run': active,
            'fallback_latest': latest,
            'rendered_report_text': rendered_text,
            'parity': rendered.get('parity'),
            'render_mode': 'fallback_render_no_usable',
            'guard_issues': guard_issues,
        }

    return {
        'ok': True,
        'case_key': case_key,
        'has_usable_result': False,
        'usable_result': None,
        'has_active_run': False,
        'active_run': None,
        'fallback_latest': None,
        'rendered_report_text': rendered_text,
        'parity': rendered.get('parity'),
        'render_mode': 'fallback_render_empty',
        'guard_issues': guard_issues,
    }


def get_download_txt_state(case_key):
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM public.dfir_run_jobs_v2
                WHERE case_key=%s
                  AND status IN ('completed','partial')
                  AND txt_report_ready = true
                  AND txt_report_path IS NOT NULL
                ORDER BY CASE WHEN status='completed' THEN 0 ELSE 1 END,
                         created_at DESC
                LIMIT 1
                """,
                (case_key,)
            )
            row = _rowdict(cur)

    if not row:
        return {
            'ok': True,
            'case_key': case_key,
            'ready': False,
            'reason': 'txt_not_ready',
            'job_id': None,
            'result_kind': None,
            'txt_report_path': None,
            'file_exists': False,
            'filename': None,
        }

    p = row.get('txt_report_path')
    exists = bool(p and os.path.isfile(p))
    return {
        'ok': True,
        'case_key': case_key,
        'ready': bool(row.get('txt_report_ready')) and exists,
        'reason': None if exists else 'file_missing',
        'job_id': row.get('job_id'),
        'result_kind': row.get('result_kind') or ('completed' if row.get('status') == 'completed' else 'partial'),
        'txt_report_path': p,
        'file_exists': exists,
        'filename': os.path.basename(p) if p else None,
    }


def get_download_txt_file(case_key):
    st = get_download_txt_state(case_key)
    if not st.get('ready'):
        return {
            'ok': True,
            'case_key': case_key,
            'ready': False,
            'reason': st.get('reason') or 'txt_not_ready',
            'job_id': st.get('job_id'),
            'result_kind': st.get('result_kind'),
            'filename': st.get('filename'),
            'content_base64': None,
        }

    p = st.get('txt_report_path')
    try:
        with open(p, 'rb') as f:
            raw = f.read()
        import base64
        b64 = base64.b64encode(raw).decode('ascii')
        return {
            'ok': True,
            'case_key': case_key,
            'ready': True,
            'reason': None,
            'job_id': st.get('job_id'),
            'result_kind': st.get('result_kind'),
            'filename': st.get('filename') or 'case_report.txt',
            'content_base64': b64,
            'size': len(raw),
            'mime_type': 'text/plain',
        }
    except Exception as e:
        return {
            'ok': True,
            'case_key': case_key,
            'ready': False,
            'reason': 'file_read_failed',
            'job_id': st.get('job_id'),
            'result_kind': st.get('result_kind'),
            'filename': st.get('filename'),
            'content_base64': None,
            'error': str(e)[:180],
        }



def step_running(job_id, step_no, step_code, step_progress_pct=0.0, msg=None):
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                WITH up_step AS (
                  INSERT INTO public.dfir_run_steps_v2 (
                    job_id, step_no, step_code, step_status,
                    progress_pct, heartbeat_at, started_at, message, updated_at
                  )
                  VALUES (%s,%s,%s,'running',%s,now(),now(),%s,now())
                  ON CONFLICT (job_id, step_no)
                  DO UPDATE SET
                    step_code    = EXCLUDED.step_code,
                    step_status  = 'running',
                    progress_pct = EXCLUDED.progress_pct,
                    heartbeat_at = now(),
                    message      = EXCLUDED.message,
                    updated_at   = now()
                  WHERE public.dfir_run_steps_v2.step_status NOT IN ('success','failed')
                  RETURNING job_id, step_no
                ),
                agg AS (
                  SELECT
                    j.job_id,
                    j.total_steps,
                    COUNT(*) FILTER (WHERE s.step_status = 'success')::numeric AS success_cnt,
                    COALESCE(MAX(s.progress_pct) FILTER (WHERE s.step_status = 'running'), 0)::numeric AS running_step_pct
                  FROM public.dfir_run_jobs_v2 j
                  LEFT JOIN public.dfir_run_steps_v2 s ON s.job_id = j.job_id
                  WHERE j.job_id = %s
                  GROUP BY j.job_id, j.total_steps
                )
                UPDATE public.dfir_run_jobs_v2 j
                SET
                  status = CASE WHEN j.status = 'queued' THEN 'running' ELSE j.status END,
                  started_at = COALESCE(j.started_at, now()),
                  current_step = GREATEST(j.current_step, %s),
                  latest_step_code = %s,
                  last_heartbeat_at = now(),
                  progress_pct = LEAST(99.90, ROUND(((agg.success_cnt + (agg.running_step_pct / 100.0)) / NULLIF(agg.total_steps,0)) * 100.0, 2)),
                  updated_at = now()
                FROM agg
                WHERE j.job_id = agg.job_id
                  AND EXISTS (SELECT 1 FROM up_step)
                """,
                (job_id, int(step_no), step_code, float(step_progress_pct or 0), msg, job_id, int(step_no), step_code)
            )


def step_success(job_id, step_no, step_code, meta_json=None, msg=None):
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                WITH up_step AS (
                  INSERT INTO public.dfir_run_steps_v2 (
                    job_id, step_no, step_code, step_status,
                    progress_pct, heartbeat_at, started_at, finished_at,
                    message, meta_json, updated_at
                  )
                  VALUES (%s,%s,%s,'success',100,now(),now(),now(),%s,COALESCE(%s::jsonb,'{}'::jsonb),now())
                  ON CONFLICT (job_id, step_no)
                  DO UPDATE SET
                    step_code    = EXCLUDED.step_code,
                    step_status  = 'success',
                    progress_pct = 100,
                    heartbeat_at = now(),
                    finished_at  = now(),
                    message      = EXCLUDED.message,
                    meta_json    = COALESCE(public.dfir_run_steps_v2.meta_json, '{}'::jsonb) || COALESCE(EXCLUDED.meta_json, '{}'::jsonb),
                    updated_at   = now()
                  WHERE public.dfir_run_steps_v2.step_status NOT IN ('failed')
                  RETURNING job_id, step_no
                ),
                agg AS (
                  SELECT
                    j.job_id,
                    j.total_steps,
                    COUNT(*) FILTER (WHERE s.step_status = 'success')::numeric AS success_cnt,
                    COALESCE(MAX(s.step_no) FILTER (WHERE s.step_status = 'success'), 0) AS last_success_step
                  FROM public.dfir_run_jobs_v2 j
                  LEFT JOIN public.dfir_run_steps_v2 s ON s.job_id = j.job_id
                  WHERE j.job_id = %s
                  GROUP BY j.job_id, j.total_steps
                )
                UPDATE public.dfir_run_jobs_v2 j
                SET
                  status = CASE WHEN j.status IN ('failed','partial','cancelled','completed') THEN j.status ELSE 'running' END,
                  current_step = CASE WHEN j.status IN ('failed','partial','cancelled','completed') THEN j.current_step ELSE GREATEST(j.current_step, %s) END,
                  latest_step_code = CASE WHEN j.status IN ('failed','partial','cancelled','completed') THEN j.latest_step_code ELSE %s END,
                  last_successful_step = GREATEST(j.last_successful_step, agg.last_success_step),
                  last_heartbeat_at = now(),
                  progress_pct = LEAST(99.90, ROUND((agg.success_cnt / NULLIF(agg.total_steps,0)) * 100.0, 2)),
                  updated_at = now()
                FROM agg
                WHERE j.job_id = agg.job_id
                  AND EXISTS (SELECT 1 FROM up_step)
                """,
                (job_id, int(step_no), step_code, msg, Json(meta_json or {}), job_id, int(step_no), step_code)
            )
            # Read updated job state for Telegram progress update
            cur.execute("""
                SELECT job_id, case_key, status, current_step, total_steps, progress_pct,
                       latest_step_code, status_chat_id, status_message_id,
                       triggered_by_chat_id, error_short
                FROM dfir_run_jobs_v2 WHERE job_id=%s
            """, (job_id,))
            jr = cur.fetchone()
        if jr:
            jd = {'job_id': str(jr[0]), 'case_key': jr[1], 'status': jr[2],
                  'current_step': jr[3], 'total_steps': jr[4], 'progress_pct': float(jr[5] or 0),
                  'latest_step_code': jr[6], 'status_chat_id': jr[7],
                  'status_message_id': jr[8], 'triggered_by_chat_id': jr[9], 'error_short': jr[10]}
            try:
                edit_status_card(jd)
            except Exception:
                try: conn.rollback()
                except: pass
                pass


def step_fail(job_id, step_no, step_code, error_code=None, error_short=None, is_critical=True, msg=None):
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                WITH up_step AS (
                  INSERT INTO public.dfir_run_steps_v2 (
                    job_id, step_no, step_code, step_status,
                    progress_pct, heartbeat_at, started_at, finished_at,
                    error_code, error_short, message, updated_at
                  )
                  VALUES (%s,%s,%s,'failed',NULL,now(),now(),now(),%s,%s,%s,now())
                  ON CONFLICT (job_id, step_no)
                  DO UPDATE SET
                    step_code    = EXCLUDED.step_code,
                    step_status  = 'failed',
                    heartbeat_at = now(),
                    finished_at  = now(),
                    error_code   = EXCLUDED.error_code,
                    error_short  = EXCLUDED.error_short,
                    message      = EXCLUDED.message,
                    updated_at   = now()
                  WHERE public.dfir_run_steps_v2.step_status NOT IN ('success')
                  RETURNING job_id, step_no
                )
                UPDATE public.dfir_run_jobs_v2 j
                SET
                  status = CASE WHEN %s THEN 'failed' ELSE 'partial' END,
                  current_step = GREATEST(j.current_step, %s),
                  latest_step_code = %s,
                  error_code = CASE WHEN %s THEN %s ELSE j.error_code END,
                  error_short = CASE WHEN %s THEN %s ELSE j.error_short END,
                  last_heartbeat_at = now(),
                  finished_at = CASE WHEN %s THEN now() ELSE j.finished_at END,
                  updated_at = now()
                WHERE j.job_id = %s
                  AND j.status IN ('queued','running')
                  AND EXISTS (SELECT 1 FROM up_step)
                """,
                (job_id, int(step_no), step_code, error_code, error_short, msg,
                 bool(is_critical), int(step_no), step_code,
                 bool(is_critical), error_code, bool(is_critical), error_short,
                 bool(is_critical), job_id)
            )


def finalize_completed_outputs(job_id, result_ref=None, txt_path=None, txt_ready=False, latest_step_code='txt_report'):
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE public.dfir_run_jobs_v2
                SET
                  status = 'completed',
                  progress_pct = 100.00,
                  result_kind = 'completed',
                  result_ref = %s,
                  result_generated_at = now(),
                  txt_report_path = %s,
                  txt_report_ready = COALESCE(%s, false),
                  latest_step_code = COALESCE(%s, latest_step_code),
                  finished_at = COALESCE(finished_at, now()),
                  updated_at = now()
                WHERE job_id = %s
                  AND status = 'running'
                """,
                (result_ref, txt_path, bool(txt_ready), latest_step_code, job_id)
            )
    # Theme A (step 5): on a completed (re-)ingest/analysis run, demote any verified
    # cache rows for this case back to verified=false (evidence may have changed).
    # Provenance hint is kept; this only forces a re-confirm (👍) before auto-serve.
    # Fully guarded so a failure never affects job finalization.
    try:
        _ck = None
        with psycopg2.connect(PG_DSN) as _c2:
            with _c2.cursor() as _cur2:
                _cur2.execute("SELECT case_key FROM public.dfir_run_jobs_v2 WHERE job_id=%s", (job_id,))
                _r2 = _cur2.fetchone()
                _ck = _r2[0] if _r2 else None
        if _ck:
            from analysis.qa_cache import _qa_cache_invalidate_case
            _qa_cache_invalidate_case(_ck)
    except Exception:
        pass

    # feedback loop (S3): offer per-claim verification to TRUSTED analysts only.
    # Fully guarded: never affects job finalization.
    try:
        _chat = None
        with psycopg2.connect(PG_DSN) as _c4:
            with _c4.cursor() as _cur4:
                _cur4.execute("SELECT COALESCE(status_chat_id, triggered_by_chat_id) "
                              "FROM public.dfir_run_jobs_v2 WHERE job_id=%s", (job_id,))
                _r4 = _cur4.fetchone()
                _chat = _r4[0] if _r4 else None
        if False:  # button moved to _run_dfir_job after report+QA delivery
            from analysis.report_feedback import _is_trusted
            if _is_trusted(_chat):
                from core.config import TG_BOT_TOKEN
                import urllib.request as _u, json as _j
                _kb = {'inline_keyboard': [
                        [{'text': '\U0001F50E Перевірити висновки звіту',
                          'callback_data': 'tool:fbstart:%s' % job_id}],
                        [{'text': '\U0001F4CE Додати звіт у памʼять кейсу',
                          'callback_data': 'tool:addrep:%s' % job_id}]]}
                _body = _j.dumps({'chat_id': str(_chat),
                        'text': '\U0001F4CB Звіт готовий. Перевірте ключові висновки \u2014 '
                                '\u0446\u0435 навчає бота бути точнішим (\u2705/\u274C/\u2753).',
                        'reply_markup': _kb}, ensure_ascii=False).encode()
                _u.urlopen(_u.Request('https://api.telegram.org/bot%s/sendMessage' % TG_BOT_TOKEN,
                        data=_body, headers={'Content-Type': 'application/json'}), timeout=15)
    except Exception:
        pass

def finalize_partial_outputs(job_id, case_key):
    # finalize partial markers first so builder reads finalized snapshot
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE public.dfir_run_jobs_v2
                SET result_kind='partial',
                    result_generated_at=COALESCE(result_generated_at, now()),
                    latest_step_code='txt_report',
                    updated_at=now()
                WHERE job_id=%s
                """,
                (job_id,)
            )

    txt_path = None
    txt_ready = False
    try:
        txt_path = _build_minimal_txt_report(job_id=job_id, case_key=case_key)
        txt_ready = bool(txt_path and os.path.isfile(txt_path))
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE public.dfir_run_jobs_v2
                    SET txt_report_path=%s,
                        txt_report_ready=COALESCE(%s,false),
                        latest_step_code='txt_report',
                        updated_at=now()
                    WHERE job_id=%s
                    """,
                    (txt_path, bool(txt_ready), job_id)
                )
    except Exception:
        _mark_txt_generation_failed(job_id)


def mark_job_failed_status_card(job_id):
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE public.dfir_run_jobs_v2
                SET status='failed',
                    error_code='STATUS_CARD_ERR',
                    error_short='status_card_create_failed',
                    latest_step_code='status_card_create',
                    finished_at=now(),
                    updated_at=now()
                WHERE job_id=%s AND status='queued'
                """,
                (job_id,)
            )


def mark_job_failed_enqueue(job_id):
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE public.dfir_run_jobs_v2
                SET status='failed',
                    error_code='ENQUEUE_ERR',
                    error_short='runner_enqueue_failed',
                    latest_step_code='enqueue_runner',
                    finished_at=now(),
                    updated_at=now()
                WHERE job_id=%s AND status='queued'
                """,
                (job_id,)
            )


def _set_job_running_from_queued(job_id):
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE public.dfir_run_jobs_v2
                SET status='running', started_at=COALESCE(started_at,now()), updated_at=now()
                WHERE job_id=%s AND status='queued'
                RETURNING job_id
                """,
                (job_id,)
            )
            return cur.fetchone() is not None


def try_mark_run_running(job_id):
    return _set_job_running_from_queued(job_id)


def mark_run_failed(job_id, error_code='RUNNER_ERR', error_short='runner_failed', latest_step_code='runner'):
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE public.dfir_run_jobs_v2
                SET status='failed',
                    error_code=%s,
                    error_short=%s,
                    latest_step_code=%s,
                    finished_at=COALESCE(finished_at, now()),
                    updated_at=now()
                WHERE job_id=%s
                  AND status IN ('queued','running')
                """,
                (error_code, error_short, latest_step_code, job_id)
            )


def _is_retryable_error(exc):
    txt = str(exc).lower()
    if isinstance(exc, (TimeoutError, urllib.error.URLError, ConnectionError, psycopg2.OperationalError, psycopg2.InterfaceError)):
        return True
    return any(k in txt for k in ['timeout', 'timed out', 'connection reset', 'could not connect', 'temporarily unavailable', 'deadlock'])


def run_step_with_retry(job_id, step_no, step_code, fn, max_attempts=3, base_backoff=0.8):
    step_running(job_id, step_no, step_code, 0, f"running:{step_code}:attempt=1/{max_attempts}")
    for attempt in range(1, max_attempts + 1):
        try:
            out = fn()
            step_success(job_id, step_no, step_code, out.get('meta') if isinstance(out, dict) else None, f"success:{step_code}:attempt={attempt}")
            return True, out
        except Exception as e:
            retryable = _is_retryable_error(e)
            if retryable and attempt < max_attempts:
                step_running(job_id, step_no, step_code, 0, f"retry:{step_code}:attempt={attempt+1}/{max_attempts}:{str(e)[:120]}")
                time.sleep(base_backoff * attempt)
                continue
            step_fail(job_id, step_no, step_code, 'STEP_ERR', str(e)[:300], True, f"failed:{step_code}:attempt={attempt}")
            return False, None





def _ensure_active_run_unique_index():
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS ux_dfir_active_case
                    ON public.dfir_run_jobs_v2(case_key)
                    WHERE status IN ('queued','running')
                """)
                conn.commit()
    except Exception:
        try: conn.rollback()
        except: pass
        pass


def _local_retry(op, attempts=2, backoff_sec=0.25):
    last = None
    for i in range(max(1, int(attempts))):
        try:
            return op()
        except Exception as e:
            last = e
            if i < (int(attempts) - 1):
                time.sleep(float(backoff_sec) * (i + 1))
                continue
            raise last





# ── Txt report helpers ─────────────────────────────────────────
def _build_minimal_txt_report(job_id, case_key):
    from datetime import datetime
    from zoneinfo import ZoneInfo

    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
                SELECT job_id, case_key, status, result_kind, result_ref, progress_pct, current_step, total_steps,
                       latest_step_code, last_heartbeat_at, updated_at, error_short
                FROM public.dfir_run_jobs_v2
                WHERE job_id=%s
                LIMIT 1
            """, (job_id,))
            jr = cur.fetchone()
            if not jr:
                raise RuntimeError('job_not_found')

            cur.execute("""
                SELECT step_no, step_code, step_status, message, error_short, meta_json, heartbeat_at
                FROM public.dfir_run_steps_v2
                WHERE job_id=%s
                ORDER BY step_no
            """, (job_id,))
            steps = cur.fetchall()

    j = {
        'job_id': jr[0], 'case_key': jr[1], 'status': jr[2], 'result_kind': jr[3], 'result_ref': jr[4],
        'progress_pct': float(jr[5] or 0), 'current_step': jr[6], 'total_steps': jr[7], 'latest_step_code': jr[8],
        'last_heartbeat_at': jr[9], 'updated_at': jr[10], 'error_short': jr[11]
    }

    # derive minimal buckets/timelines/artifacts from finalized step meta_json
    buckets = {'confirmed': [], 'likely': [], 'tool_only': [], 'needs_review': []}
    incident = []
    detection = []
    iocs = []

    for s in steps:
        meta = s[5] if isinstance(s[5], dict) else {}
        if not isinstance(meta, dict):
            continue
        for k in ['confirmed', 'confirmed_findings']:
            if isinstance(meta.get(k), list):
                buckets['confirmed'].extend([str(x) for x in meta.get(k)[:20]])
        for k in ['likely', 'corroborated', 'likely_findings']:
            if isinstance(meta.get(k), list):
                buckets['likely'].extend([str(x) for x in meta.get(k)[:20]])
        for k in ['tool_only', 'tool_only_findings']:
            if isinstance(meta.get(k), list):
                buckets['tool_only'].extend([str(x) for x in meta.get(k)[:20]])
        for k in ['needs_review', 'needs_review_findings']:
            if isinstance(meta.get(k), list):
                buckets['needs_review'].extend([str(x) for x in meta.get(k)[:20]])
        if isinstance(meta.get('incident_timeline'), list):
            incident.extend([str(x) for x in meta.get('incident_timeline')[:40]])
        if isinstance(meta.get('detection_timeline'), list):
            detection.extend([str(x) for x in meta.get('detection_timeline')[:40]])
        if isinstance(meta.get('ioc_artifacts'), list):
            iocs.extend([str(x) for x in meta.get('ioc_artifacts')[:80]])

    safe_case = _safe_case_folder(case_key)
    rep_dir = os.path.join(CASE_LIB, safe_case, 'reports')
    os.makedirs(rep_dir, exist_ok=True)
    out_path = os.path.join(rep_dir, f'case_report_{job_id}.txt')

    def _fmt_ts(v):
        try:
            return v.isoformat() if v else '—'
        except Exception:
            return str(v) if v else '—'

    lines = []

    # TXT = evidence-based rendered report first. LLM narrative is only a fallback
    # and refusals like "дані відсутні" must not override real PostgreSQL evidence.
    forensic_report = ''
    try:
        rr = j.get('result_ref')
        if rr and os.path.isfile(rr):
            with open(rr, 'r', encoding='utf-8') as rf:
                robj = json.load(rf)
            rendered_text = str(((robj.get('rendered_result') or {}).get('text') or '')).strip()
            narrative_text = str(robj.get('llm_narrative') or robj.get('ollama_narrative') or '').strip()
            bad_markers = [
                'дані відсутні', 'відсутні конкретні forensic-дані',
                'не можу вигадувати факти', 'чекаю на дані',
                'please provide forensic', 'no forensic data',
            ]
            def _is_bad_llm_text(txt):
                low = (txt or '').lower()
                return any(m in low for m in bad_markers)
            # If an old result has bad LLM text prepended before the separator,
            # strip that preface and keep the deterministic evidence section.
            sep = '─' * 40
            if rendered_text and _is_bad_llm_text(rendered_text) and sep in rendered_text:
                tail = rendered_text.split(sep, 1)[1].strip()
                if tail:
                    rendered_text = tail
            good_narrative = bool(narrative_text and not _is_bad_llm_text(narrative_text) and len(narrative_text) >= 1200 and any(m in narrative_text for m in ['FORENSIC ЗВІТ', 'ЗАГАЛЬНИЙ ВИСНОВОК', 'ХРОНОЛОГІЯ', 'ІНДИКАТОРИ КОМПРОМЕТАЦІЇ']))
            rendered_already_has_ai = rendered_text.lstrip().startswith('# FORENSIC ЗВІТ') or rendered_text.lstrip().startswith('FORENSIC ЗВІТ') or rendered_text.lstrip().startswith('## ЗАГАЛЬНИЙ ВИСНОВОК')
            if rendered_text:
                # TXT snapshots must reflect the already-guarded rendered_result.
                # Do not re-prepend ollama_narrative here; narrative may contain a
                # polished but cross-case/hallucinated report even when the rendered
                # deterministic report is available.
                forensic_report = rendered_text.strip()
            elif good_narrative:
                forensic_report = narrative_text
            elif narrative_text and not _is_bad_llm_text(narrative_text):
                forensic_report = narrative_text
            if forensic_report:
                try:
                    from analysis.output_guardrails import guard_client_output
                    forensic_report, _ = guard_client_output(case_key, forensic_report, kind='txt_report')
                except Exception:
                    pass
                try:
                    from reports.reshape import reshape_client_report
                    forensic_report = reshape_client_report(case_key, forensic_report)
                except Exception:
                    pass
    except Exception:
        try: conn.rollback()
        except: pass
        pass
    # Markdown header + legend so the delivered .md renders cleanly and the analyst
    # can tell AI-written analysis from script-extracted data.
    try:
        _gen_ts = datetime.now(ZoneInfo('Europe/Kyiv')).strftime('%d.%m.%Y %H:%M')
    except Exception:
        _gen_ts = ''
    header = [
        f"# 🛡️ DFIR-звіт — {case_key.replace('_', ' ')}",
        f"*Згенеровано: {_gen_ts} · Кейс: `{case_key}`*",
        "",
        "> 🤖 **ШІ-аналіз** — висновки, оцінки та інтерпретація сформовані LLM-моделлю.",
        "> 📊 **Дані з логів** — таблиці, події та артефакти отримані автоматично з PostgreSQL/KAPE (скрипт, без ШІ).",
        "",
        "---",
        "",
    ]

    # Per-section AI/script markers: tag each markdown heading so the analyst sees
    # which sections are model interpretation (🤖) vs data pulled from logs (📊).
    def _mark_sections(text):
        _ai_kw = ('висновок', 'аналіз', 'гіпотез', 'оцінк', 'рекоменд', 'verdict',
                  'summary', 'резюме', 'інтерпрет', 'що сталося', 'що сталось',
                  'загальний', 'narrative', 'наратив')
        _data_kw = ('хронолог', 'timeline', 'індикатор', 'ioc', 'артефакт', 'таблиц',
                    'докази', 'детекц', 'події', 'подія', 'процеси', 'логон', 'мережев',
                    'persistence', 'персистент', 'файли', 'хеш')
        out = []
        for ln in text.split('\n'):
            s = ln.lstrip()
            if s.startswith('#'):
                low = s.lstrip('#').strip().lower()
                if '🤖' not in s and '📊' not in s:
                    hashes = s[:len(s) - len(s.lstrip('#'))]
                    title = s.lstrip('#').strip()
                    if any(k in low for k in _ai_kw):
                        ln = f"{hashes} 🤖 {title}"
                    elif any(k in low for k in _data_kw):
                        ln = f"{hashes} 📊 {title}"
            out.append(ln)
        return '\n'.join(out)
    try:
        forensic_report = _mark_sections(forensic_report)
    except Exception:
        pass

    if forensic_report:
        lines.extend(header)
        lines.append(forensic_report)
        lines.append('')
    else:
        lines.extend(header)
        lines.append('⚠️ Forensic звіт ще не згенеровано або недоступний.')
        lines.append('')

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines).strip() + '\n')

    return out_path

def _mark_txt_generation_failed(job_id):
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE public.dfir_run_jobs_v2
                SET txt_report_ready=false,
                    latest_step_code='txt_report',
                    error_short=COALESCE(error_short,'txt_report_generation_failed'),
                    updated_at=now()
                WHERE job_id=%s
                """,
                (job_id,)
            )


def _reconcile_completed_txt_state(job_id, case_key):
    """Ensure completed runs expose consistent txt_report_path/txt_report_ready state."""
    safe_case = _safe_case_folder(case_key)
    rep_dir = os.path.join(CASE_LIB, safe_case, 'reports')
    os.makedirs(rep_dir, exist_ok=True)

    p1 = os.path.join(rep_dir, f'case_report_{job_id}.txt')
    p2 = os.path.join(rep_dir, f'case_rendered_{job_id}.txt')
    chosen = p1 if os.path.isfile(p1) else (p2 if os.path.isfile(p2) else None)

    # if neither exists but rendered cache text is available, persist a txt snapshot
    if not chosen:
        try:
            rr = _render_user_facing_report(case_key)
            txt = str(rr.get('text') or '').strip()
            if txt:
                with open(p1, 'w', encoding='utf-8') as f:
                    f.write(txt + '\n')
                chosen = p1
        except Exception:
            try: conn.rollback()
            except: pass
            pass

    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE public.dfir_run_jobs_v2
                SET txt_report_path=%s,
                    txt_report_ready=COALESCE(%s,false),
                    latest_step_code='txt_report',
                    updated_at=now()
                WHERE job_id=%s AND status='completed'
                """,
                (chosen, bool(chosen and os.path.isfile(chosen)), job_id)
            )


