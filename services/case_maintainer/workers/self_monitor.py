"""Self-monitor worker — detect stuck runs, send daily stats via Telegram."""
import json, logging, time
import psycopg2
from datetime import datetime, timezone
from core.config import PG_DSN
from telegram.notify import _tg_send_admin
from workers.state import _idle_worker_stop
_log = logging.getLogger('app')

def _self_monitor_worker():
    """Hourly health check: fixes stuck runs, tracks failure rate, sends 24h summary to admin."""
    _log.info("[monitor] worker started")
    _last_daily_report = [0.0]

    while not _idle_worker_stop.is_set():
        try:
            _idle_worker_stop.wait(3600)  # раз на годину
            if _idle_worker_stop.is_set():
                break

            now = time.time()

            # 1. Фікс stuck 'running' старше 2 годин
            stuck_fixed = 0
            try:
                with psycopg2.connect(PG_DSN) as _conn:
                    with _conn.cursor() as _cur:
                        _cur.execute("""
                            UPDATE dfir_self_eval_runs_v1
                            SET status='error', notes='auto_fixed_stuck_running', finished_at=NOW()
                            WHERE status='running'
                            AND started_at < NOW() - INTERVAL '2 hours'
                        """)
                        stuck_fixed = _cur.rowcount
                        _conn.commit()
            except Exception as _e:
                _log.error(f"[monitor] stuck-fix error: {_e}")

            if stuck_fixed:
                _log.info(f"[monitor] fixed {stuck_fixed} stuck runs")

            # 2. Статистика за останні 24h
            stats = {}
            try:
                with psycopg2.connect(PG_DSN) as _conn:
                    with _conn.cursor() as _cur:
                        _cur.execute("""
                            SELECT status, COUNT(*) FROM dfir_self_eval_runs_v1
                            WHERE started_at >= NOW() - INTERVAL '24 hours'
                            AND (notes IS NULL OR notes NOT LIKE '%stuck_running_cleanup%')
                            GROUP BY status
                        """)
                        stats['eval'] = {r[0]: r[1] for r in _cur.fetchall()}

                        _cur.execute("""
                            SELECT lesson_type, COUNT(*) FROM dfir_lessons_learned_v1
                            WHERE created_at >= NOW() - INTERVAL '24 hours'
                            GROUP BY lesson_type
                        """)
                        stats['lessons'] = {r[0]: r[1] for r in _cur.fetchall()}

                        _cur.execute("""
                            SELECT gap_type, COUNT(*) FROM dfir_self_eval_gaps_v1
                            WHERE created_at >= NOW() - INTERVAL '24 hours'
                            GROUP BY gap_type ORDER BY COUNT(*) DESC LIMIT 3
                        """)
                        stats['top_gaps'] = _cur.fetchall()

                        _cur.execute("""
                            SELECT COUNT(*) FROM dfir_self_eval_runs_v1
                            WHERE status='running' AND started_at < NOW() - INTERVAL '30 minutes'
                        """)
                        stats['still_stuck'] = _cur.fetchone()[0]
            except Exception as _e:
                _log.error(f"[monitor] stats error: {_e}")

            # 3. Щоденний звіт адміну (раз на 24h)
            if now - _last_daily_report[0] >= 86400:
                _last_daily_report[0] = now
                try:
                    eval_s = stats.get('eval', {})
                    lessons_s = stats.get('lessons', {})
                    top_gaps = stats.get('top_gaps', [])
                    still_stuck = stats.get('still_stuck', 0)

                    total_eval = sum(eval_s.values())
                    done_count = eval_s.get('done', 0)
                    err_count = eval_s.get('error', 0)
                    paused_count = eval_s.get('paused', 0)

                    total_lessons = sum(lessons_s.values())
                    pass_l = lessons_s.get('qa_pass', 0)
                    fail_l = lessons_s.get('qa_failure', 0)
                    fail_rate = int(fail_l / total_lessons * 100) if total_lessons else 0

                    gaps_txt = ''
                    for g in top_gaps:
                        gaps_txt += f"\n  • {g[0]}: {g[1]}"

                    stuck_warn = f'\n⚠️ Ще застрягло: {still_stuck} runs' if still_stuck else ''

                    msg = (
                        f"🤖 <b>DFIR Self-Monitor — добовий звіт</b>\n\n"
                        f"📊 <b>Self-eval за 24h:</b>\n"
                        f"  done: {done_count} | error: {err_count} | paused: {paused_count} | всього: {total_eval}\n\n"
                        f"📚 <b>Уроки за 24h:</b> {total_lessons}\n"
                        f"  pass: {pass_l} | failure: {fail_l} ({fail_rate}% невдач)\n\n"
                        f"🔍 <b>Топ gaps:</b>{gaps_txt if gaps_txt else ' немає даних'}\n"
                        f"{stuck_warn}\n"
                        f"{'⚠️ УВАГА: failure rate > 80%! Перевір LLM.' if fail_rate > 80 else '✅ Система працює нормально.'}"
                    )
                    _tg_send_admin(msg)
                    _log.info(f"[monitor] daily report sent: eval={total_eval} lessons={total_lessons}")
                except Exception as _e:
                    _log.error(f"[monitor] daily report error: {_e}")

            # 4. Алерт якщо stuck runs є прямо зараз
            if stats.get('still_stuck', 0) > 10:
                try:
                    _tg_send_admin(
                        f"⚠️ <b>DFIR Monitor</b>: {stats['still_stuck']} self-eval runs застрягли у 'running' > 30хв.\n"
                        f"Автофікс запуститься наступної години."
                    )
                except Exception:
                    pass

        except Exception as _e:
            _log.error(f"[monitor] worker error: {_e}")

    _log.error("[monitor] worker stopped")


# ─────────────────────────────────────────────────────────────────────────────
# IDLE BENCHMARK LEARNING — golden-reference self-improvement
# ─────────────────────────────────────────────────────────────────────────────

