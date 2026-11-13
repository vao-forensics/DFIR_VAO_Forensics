# -*- coding: utf-8 -*-
"""The machine's biography: the frame an investigator establishes before anything else.

When was the OS installed, who was created on it and when, when did each account first
and last sign in, when was it rebooted, and what period does each evidence source
actually cover. This is what a human analyst writes down on the first page before
looking at a single indicator - and the pipeline never had it.

Why it matters concretely: on 2026-09-16 the incident window was computed as
2025-08-24..2025-08-25 for a machine whose OS was installed on 2025-11-11. Nothing on
that machine could have happened in August. The install date is a hard floor, and having
it in front of the model makes that class of error visible instead of silent.

Read-only, exception-safe, and cheap: a handful of grouped queries.
"""
import logging

import psycopg2

from core.config import PG_DSN

_log = logging.getLogger('app')

# An event ID means nothing without its provider. Measured on a real case: event_id 41
# returned 1135 hits, of which 879 were WindowsUpdateClient and 230 TerminalServices -
# only 4 were the Kernel-Power "shut down unexpectedly" event. Reporting 1135 crashes to
# the model would plant exactly the kind of false anchor this module exists to prevent.
_REBOOT_SOURCES = (
    (6005, 'EventLog'),                          # event log service started -> boot
    (6006, 'EventLog'),                          # event log service stopped -> clean shutdown
    (6008, 'EventLog'),                          # previous shutdown was unexpected
    (1074, 'User32'),                            # initiated by a user or process
    (41,   'Microsoft-Windows-Kernel-Power'),    # rebooted without shutting down cleanly
)


def _rows(cur, sql, params):
    try:
        cur.execute(sql, params)
        return cur.fetchall()
    except Exception as e:
        _log.error('[biography] query failed: %s' % e)
        try:
            cur.connection.rollback()
        except Exception:
            pass
        return []


def machine_biography(case_key, max_users=8):
    """Compact Ukrainian text block, or '' when nothing is known."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                return _build(cur, case_key, max_users)
    except Exception as e:
        _log.error('[biography] failed: %s' % e)
        return ''


def _build(cur, case_key, max_users):
    out = []
    install = None

    prof = _rows(cur, "SELECT computer_name, os_name, install_date_utc, timezone "
                      "FROM public.system_profile_v1 WHERE case_key=%s LIMIT 1", (case_key,))
    if prof:
        name, os_name, install, tz = prof[0]
        out.append('Компʼютер: %s | %s' % (name or '?', os_name or '?'))
        if install:
            out.append('ОС встановлена: %s  <- РАНІШЕ ЦІЄЇ ДАТИ НА ЦІЙ МАШИНІ НІЧОГО НЕ БУЛО' % install)
        if tz:
            out.append('Часовий пояс: %s' % tz)

    cov = _rows(cur, "SELECT min(event_ts)::date, max(event_ts)::date, count(*) "
                     "FROM public.event_logs_v2 WHERE case_key=%s AND event_ts IS NOT NULL", (case_key,))
    if cov and cov[0][0]:
        out.append('Журнали подій покривають: %s .. %s (%s подій)' % (cov[0][0], cov[0][1], cov[0][2]))

    created = _rows(cur, "SELECT event_ts::date, coalesce(target_user,'?'), count(*) "
                         "FROM public.event_logs_v2 WHERE case_key=%s AND event_id=4720 "
                         "GROUP BY 1,2 ORDER BY 1 LIMIT %s", (case_key, max_users))
    if created:
        out.append('Створені облікові записи (4720):')
        for d, u, _n in created:
            out.append('   %s  %s' % (d, u))

    logons = _rows(cur, "SELECT coalesce(target_user,'?'), min(event_ts)::date, max(event_ts)::date, count(*) "
                        "FROM public.event_logs_v2 WHERE case_key=%s AND event_id=4624 "
                        "AND coalesce(target_user,'') NOT IN ('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','') "
                        "GROUP BY 1 ORDER BY 4 DESC LIMIT %s", (case_key, max_users))
    if logons:
        out.append('Входи в систему (4624), перший .. останній:')
        for u, a, b, n in logons:
            out.append('   %-22s %s .. %s  (%s)' % (str(u)[:22], a, b, n))

    eids = [e for e, _p in _REBOOT_SOURCES]
    provs = [p for _e, p in _REBOOT_SOURCES]
    reboots = _rows(cur, "SELECT count(*), min(event_ts)::date, max(event_ts)::date "
                         "FROM public.event_logs_v2 WHERE case_key=%s "
                         "AND (event_id, coalesce(provider,'')) IN "
                         "(SELECT unnest(%s::int[]), unnest(%s::text[]))",
                    (case_key, eids, provs))
    if reboots and reboots[0][0]:
        n, a, b = reboots[0]
        out.append('Перезавантаження/вимкнення: %s подій, %s .. %s' % (n, a, b))
        hard = _rows(cur, "SELECT count(*) FROM public.event_logs_v2 WHERE case_key=%s "
                          "AND event_id=41 AND coalesce(provider,'')='Microsoft-Windows-Kernel-Power'",
                     (case_key,))
        if hard and hard[0][0]:
            out.append('   з них аварійних (Kernel-Power 41): %s' % hard[0][0])

    srcs = _rows(cur, "SELECT 'filesystem_v2', min(event_ts)::date, max(event_ts)::date FROM public.filesystem_v2 WHERE case_key=%s AND event_ts IS NOT NULL "
                      "UNION ALL SELECT 'program_exec_v2', min(event_ts)::date, max(event_ts)::date FROM public.program_exec_v2 WHERE case_key=%s AND event_ts IS NOT NULL",
                  (case_key, case_key))
    cover = [r for r in srcs if r[1]]
    if cover:
        out.append('Покриття інших джерел:')
        for t, a, b in cover:
            out.append('   %-18s %s .. %s' % (t, a, b))

    if not out:
        return ''
    return 'БІОГРАФІЯ МАШИНИ (рамка розслідування):\n' + '\n'.join(out)
