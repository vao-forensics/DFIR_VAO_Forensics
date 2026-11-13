"""Deliver finished DFIR reports that never reached Telegram.

Why (23.10.2026): a job is marked `completed` long before its report is sent. Between the two
the runner still fills gaps, builds the system profile, runs the deep Q&A and attribution -
minutes of work held only in a daemon thread. A restart or a power cut in that window left a
completed job whose report nobody ever received (the "delivery_done" mark lived only in the
process's memory). Now delivery is recorded in `dfir_run_jobs_v2.delivered_at`, and on startup
the reports of the last 24 h that were never delivered are sent again.

Hard rule: the bot sends files ONLY to the owner's chat. A report another user asked for is
sent to the owner with a note naming the requester; the owner decides what to forward.
"""
import json
import logging
import os
import urllib.request
import uuid

import psycopg2

from core.config import PG_DSN

OWNER_CHAT = 'CHANGE_ME_OWNER_CHAT_ID'
_log = logging.getLogger('delivery_reconcile')


def ensure_column():
    """Add delivered_at once. On the very first run every existing completed job counts as
    delivered, so the reconciler can never replay the whole history."""
    with psycopg2.connect(PG_DSN) as c:
        c.autocommit = True
        cur = c.cursor()
        cur.execute("""SELECT 1 FROM information_schema.columns
                       WHERE table_schema='public' AND table_name='dfir_run_jobs_v2' AND column_name='delivered_at'""")
        if cur.fetchone():
            return False
        cur.execute("ALTER TABLE public.dfir_run_jobs_v2 ADD COLUMN IF NOT EXISTS delivered_at timestamptz")
        cur.execute("UPDATE public.dfir_run_jobs_v2 SET delivered_at=COALESCE(finished_at, updated_at, now()) "
                    "WHERE delivered_at IS NULL")
        return True


def mark_delivered(job_id):
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            c.cursor().execute("UPDATE public.dfir_run_jobs_v2 SET delivered_at=now() WHERE job_id=%s", (str(job_id),))
    except Exception as e:
        _log.warning('mark_delivered %s: %r', str(job_id)[:8], e)


def pending(hours=24, before=None):
    with psycopg2.connect(PG_DSN) as c:
        cur = c.cursor()
        cur.execute("""SELECT job_id::text, case_key, triggered_by_chat_id, txt_report_path
                       FROM public.dfir_run_jobs_v2
                       WHERE status='completed' AND delivered_at IS NULL AND triggered_by_chat_id IS NOT NULL
                         AND txt_report_ready AND COALESCE(finished_at, updated_at) > now() - %s * interval '1 hour'
                         AND COALESCE(finished_at, updated_at) < COALESCE(to_timestamp(%s), now())
                       ORDER BY COALESCE(finished_at, updated_at)""", (hours, before))
        return cur.fetchall()


def _report_bytes(job_id, case_key, txt_path):
    """The same text the normal delivery sends: the stored full report, else the reshaped TXT."""
    try:
        with psycopg2.connect(PG_DSN) as c:
            cur = c.cursor()
            cur.execute("SELECT report_md FROM dfir_case_reports_v1 WHERE case_key=%s AND job_id=%s", (case_key, job_id))
            r = cur.fetchone()
            if r and r[0] and len(r[0]) > 200:
                return r[0].encode('utf-8')
    except Exception:
        pass
    if not (txt_path and os.path.isfile(txt_path)):
        return None
    data = open(txt_path, 'rb').read()
    try:
        from reports.reshape import reshape_client_report
        t = reshape_client_report(case_key, data.decode('utf-8', 'replace'))
        if t and len(t) > 200:
            return t.encode('utf-8')
    except Exception:
        pass
    return data


def _send_document(token, chat_id, caption, fname, data):
    b = uuid.uuid4().hex

    def part(name, value, filename=None, ctype='text/plain'):
        disp = 'form-data; name="%s"' % name + ('; filename="%s"' % filename if filename else '')
        head = '--%s\r\nContent-Disposition: %s\r\n' % (b, disp) + ('Content-Type: %s\r\n' % ctype if filename else '') + '\r\n'
        return head.encode('utf-8') + (value if isinstance(value, bytes) else value.encode('utf-8')) + b'\r\n'
    body = (part('chat_id', str(chat_id)) + part('caption', caption)
            + part('document', data, filename=fname, ctype='text/markdown')
            + part('reply_markup', json.dumps({'inline_keyboard': [[{'text': '🌳 Дерево тек (TXT)', 'callback_data': 'tool:fstree'}],
                                                               [{'text': '⬅️ До кейсу', 'callback_data': 'case_menu'}]]},
                                              ensure_ascii=False))
            + ('--%s--\r\n' % b).encode('utf-8'))
    req = urllib.request.Request('https://api.telegram.org/bot%s/sendDocument' % token, data=body,
                                 headers={'Content-Type': 'multipart/form-data; boundary=%s' % b})
    urllib.request.urlopen(req, timeout=60).read()


def run(token, hours=24, before=None):
    """Send every undelivered report of the last `hours` that completed before `before` (epoch;
    the process start: a job completed after it still has its own runner and delivers itself).
    Returns the number sent."""
    if not token:
        return 0
    ensure_column()
    sent = 0
    for job_id, case_key, chat, txt_path in pending(hours, before):
        data = _report_bytes(job_id, case_key, txt_path)
        if not data:
            _log.warning('undelivered %s %s: no report file', job_id[:8], case_key)
            continue
        caption = ('♻️ Звіт, який не дійшов через перезапуск сервера\n📁 Кейс: %s' % case_key.replace('_', ' '))
        if str(chat) != OWNER_CHAT:
            caption += '\n👤 Запитував користувач %s (звіт надіслано лише власнику)' % chat
        try:
            _send_document(token, OWNER_CHAT, caption[:1000], 'dfir_report_%s_%s.md' % (case_key[:40], job_id[:8]), data)
            mark_delivered(job_id)
            sent += 1
            _log.error('[delivery] re-sent undelivered report job=%s case=%s requester=%s', job_id[:8], case_key, chat)
        except Exception as e:
            _log.error('[delivery] re-send failed job=%s: %r', job_id[:8], e)
    return sent
