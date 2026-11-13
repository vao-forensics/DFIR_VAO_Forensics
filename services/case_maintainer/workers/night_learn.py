"""Night DEEP self-learning + self-TEST orchestrator.

Runs ONCE per night (night+idle gated — same window as the light qa-cache worker;
kill-switch DFIR_NIGHT_DEEP=off) the heavier pipeline the cache worker does not:

  C)   books            -> skill cards     (skills_scaffold.build_skill_cards)
  B)   analyst REPORT   -> lessons/finds   (report_extractor.extract_case_report;
                                            HUMAN-GATED, reads kb_reports = the
                                            analyst's report, NOT uploaded evidence)
  --   reconcile/dedup lessons             (lesson_reconcile.reconcile_lessons)
  TEST) bot report vs golden facts -> /5   (benchmark._benchmark_run_case)

Then DMs the admin a morning summary. Every step yields the instant a user becomes
active and never runs in daytime. All imports are lazy and wrapped so any failure
is contained and never touches the bot or sibling workers.
"""
import os
import time
import logging
import datetime

from workers.state import _idle_worker_stop, _bg_llm_lock, _state
from workers.idle_learning import _is_night

_log = logging.getLogger('app')

_COLD_START = int(os.environ.get('DFIR_NIGHT_DEEP_COLDSTART', '600'))
_IDLE_MIN = int(os.environ.get('DFIR_NIGHT_DEEP_IDLE_MIN', '900'))


def _active_run():
    try:
        from workers.benchmark import _has_active_production_run
        return _has_active_production_run()
    except Exception:
        return False


def _go():
    """True only while it is still night, the user is idle, and no production run."""
    return (not _idle_worker_stop.is_set()
            and _is_night()
            and (time.time() - _state['last_user_request_ts']) >= _IDLE_MIN
            and not _active_run())


def _locked(fn, *a, **k):
    """Run fn holding the shared bg-LLM lock so night workers never collide on the
    single GPU slot. (benchmark self-locks internally → call it WITHOUT this.)"""
    if not _bg_llm_lock.acquire(timeout=900):
        raise RuntimeError('bg_llm_lock timeout')
    try:
        return fn(*a, **k)
    finally:
        _bg_llm_lock.release()


def _bench_avg_recent():
    """Avg benchmark score from runs finished in the last 8h (tonight)."""
    try:
        import psycopg2
        from core.config import PG_DSN
        with psycopg2.connect(PG_DSN) as c:
            with c.cursor() as cur:
                cur.execute("""SELECT count(*), avg(quality_score)
                    FROM dfir_benchmark_runs_v1
                    WHERE status='done' AND quality_score IS NOT NULL
                      AND finished_at > NOW() - interval '8 hours'""")
                n, avg = cur.fetchone()
        return int(n or 0), (float(avg) if avg is not None else None)
    except Exception:
        return 0, None


def _report_case_keys():
    """Case keys that actually have an analyst REPORT (doc_type='report') in
    kb_reports — NOT event-log keys (mismatch on '__' vs '_') and NOT 'docs'
    (uploaded EVIDENCE, which we must never learn from — privacy)."""
    try:
        import json
        import urllib.request
        from core.config import QDRANT_URL
        keys, off = set(), None
        for _ in range(40):
            body = {"limit": 256, "with_payload": True, "with_vector": False,
                    "filter": {"must": [{"key": "doc_type", "match": {"value": "report"}}]}}
            if off is not None:
                body["offset"] = off
            req = urllib.request.Request(
                QDRANT_URL.rstrip('/') + "/collections/kb_reports/points/scroll",
                data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
            r = json.loads(urllib.request.urlopen(req, timeout=15).read())
            for p in r.get("result", {}).get("points", []):
                ck = (p.get("payload") or {}).get("case_key")
                if ck:
                    keys.add(ck)
            off = r.get("result", {}).get("next_page_offset")
            if not off:
                break
        return sorted(keys)
    except Exception as e:
        _log.error('[night_deep] _report_case_keys error: %s' % e)
        return []


def _ensure_done_table():
    import psycopg2
    from core.config import PG_DSN
    with psycopg2.connect(PG_DSN) as c:
        c.autocommit = True
        with c.cursor() as cur:
            cur.execute("CREATE TABLE IF NOT EXISTS dfir_night_report_done "
                        "(report_case_key text PRIMARY KEY, done_at timestamptz DEFAULT now())")


def _report_done(rck):
    try:
        import psycopg2
        from core.config import PG_DSN
        with psycopg2.connect(PG_DSN) as c:
            with c.cursor() as cur:
                cur.execute("SELECT 1 FROM dfir_night_report_done WHERE report_case_key=%s", (rck,))
                return cur.fetchone() is not None
    except Exception:
        return False


def _mark_report_done(rck):
    try:
        import psycopg2
        from core.config import PG_DSN
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            with c.cursor() as cur:
                cur.execute("INSERT INTO dfir_night_report_done(report_case_key) VALUES (%s) "
                            "ON CONFLICT (report_case_key) DO NOTHING", (rck,))
    except Exception as e:
        _log.error('[night_deep] _mark_report_done error: %s' % e)


def _run_pipeline():
    lines = ['🌙 <b>Нічне навчання + тест моделі</b>']

    # C) books -> skill cards
    try:
        from workers.skills_scaffold import build_skill_cards
        r = _locked(build_skill_cards, dry_run=False)
        lines.append(f'• Скіли з книг (Theme C): {str(r)[:120]}')
    except Exception as e:
        lines.append(f'• Скіли з книг: ⚠️ {str(e)[:90]}')

    # B) analyst REPORT -> lessons/findings (human-gated). Iterate ONLY case_keys
    #    that truly have a doc_type='report' chunk; skip reports already extracted
    #    so we never re-spam duplicate pending findings night after night.
    if _go():
        try:
            from workers.report_extractor import extract_case_report
            _ensure_done_table()
            rcks = _report_case_keys()
            nf = nl = ncases = 0
            for rck in rcks:
                if not _go():
                    break
                if _report_done(rck):
                    continue
                s = _locked(extract_case_report, rck, dry_run=False) or {}
                if s.get('errors') and 'no report chunks' in str(s.get('errors')):
                    continue
                nf += int(s.get('findings_written') or 0)
                nl += int(s.get('lessons_written') or 0)
                ncases += 1
                _mark_report_done(rck)
                _idle_worker_stop.wait(5)
            lines.append(f'• Уроки зі звітів (Theme B): {ncases} нових звітів → {nf} знахідок (на підтвердження), {nl} уроків')
        except Exception as e:
            lines.append(f'• Уроки зі звітів: ⚠️ {str(e)[:90]}')

    # reconcile / dedup lessons
    if _go():
        try:
            from workers.lesson_reconcile import reconcile_lessons
            r = _locked(reconcile_lessons, dry_run=False)
            lines.append(f'• Дедуп уроків: {str(r)[:120]}')
        except Exception as e:
            lines.append(f'• Дедуп уроків: ⚠️ {str(e)[:90]}')

    # TEST) benchmark: bot report vs golden facts -> score/5
    if _go():
        try:
            from workers.benchmark import (_ensure_benchmark_tables,
                                           _benchmark_get_cases, _benchmark_run_case)
            _ensure_benchmark_tables()
            cks = _benchmark_get_cases() or []
            ran = 0
            for ck in cks:
                if not _go():
                    break
                _benchmark_run_case(ck)   # self-locks + sends its own per-case admin msg
                ran += 1
                _idle_worker_stop.wait(5)
            n, avg = _bench_avg_recent()
            if avg is not None:
                lines.append(f'• 🔬 ТЕСТ моделі (benchmark): {n} справ, середній бал <b>{avg:.1f}/5</b>')
            else:
                lines.append(f'• 🔬 ТЕСТ моделі: прогнано {ran} справ (golden-факти ще збираються)')
        except Exception as e:
            lines.append(f'• ТЕСТ моделі: ⚠️ {str(e)[:90]}')

    return '\n'.join(lines)


def _night_done_today():
    """Persistent once-per-night guard: the in-memory last_day marker is wiped by
    every container restart (daytime code deploys), which re-ran the whole heavy
    pipeline the SAME night (2026-07-08: two full benchmark clusters, 03:03 + 07:09)."""
    try:
        import psycopg2
        from core.config import PG_DSN
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            with c.cursor() as cur:
                cur.execute("CREATE TABLE IF NOT EXISTS dfir_night_deep_done_v1 (day date PRIMARY KEY)")
                cur.execute("SELECT 1 FROM dfir_night_deep_done_v1 WHERE day = current_date")
                return cur.fetchone() is not None
    except Exception:
        return False


def _mark_night_done():
    try:
        import psycopg2
        from core.config import PG_DSN
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            with c.cursor() as cur:
                cur.execute("CREATE TABLE IF NOT EXISTS dfir_night_deep_done_v1 (day date PRIMARY KEY)")
                cur.execute("INSERT INTO dfir_night_deep_done_v1(day) VALUES (current_date) ON CONFLICT DO NOTHING")
    except Exception:
        pass


def _night_deep_worker():
    _log.info('[night_deep] started (night+idle gated; off via DFIR_NIGHT_DEEP=off)')
    _idle_worker_stop.wait(_COLD_START)
    last_day = None
    while not _idle_worker_stop.is_set():
        try:
            if not _go():
                _idle_worker_stop.wait(180)
                continue
            today = datetime.date.today().isoformat()
            if last_day == today:
                _idle_worker_stop.wait(600)
                continue
            if _night_done_today():
                last_day = today
                continue
            _log.info('[night_deep] starting nightly deep learning + self-test pipeline')
            summary = _run_pipeline()
            last_day = today
            _mark_night_done()
            try:
                from telegram.notify import _tg_send_admin
                # only ping admin if the pipeline finished while it is STILL night — a long
                # (multi-hour) run that spills into the morning must not interrupt active use.
                if _is_night():
                    _tg_send_admin(summary)
                else:
                    _log.info('[night_deep] finished after night window -> summary logged, not sent: %s' % summary[:200])
            except Exception:
                pass
            _log.info('[night_deep] pipeline complete')
        except Exception as e:
            _log.error(f'[night_deep] loop error: {e}')
            _idle_worker_stop.wait(300)
