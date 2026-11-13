# -*- coding: utf-8 -*-
"""S8 (feedback loop): nightly self-reflection on HUMAN ❌ verdicts.
Reads unreflected verdict='incorrect' rows from case_feedback and:
  1. writes a negative lesson (dfir_lessons_learned_v1, lesson_type='human_rejected'),
  2. embeds a 'wrong_approach' fact (kb_case_knowledge) so retrieval down-weights it,
  3. detects RECURRING mistakes (same claim marked wrong across ≥N cases) and alerts
     the owner to review the detector.
Idempotent via case_feedback.reflected_at. Default = dry-run; pass --apply to write.
Run (cron): docker exec case-maintainer python3 /app/workers/feedback_reflect.py --apply
See docs/FEEDBACK_LOOP_PLAN.md."""
import sys, json, urllib.request
sys.path.insert(0, '/app')
import psycopg2
from core.config import PG_DSN, TG_BOT_TOKEN, ADMIN_CHAT_ID
from analysis.learnings import _save_lesson, _save_case_knowledge

_OWNER = str(ADMIN_CHAT_ID or 'CHANGE_ME_OWNER_CHAT_ID')
_RECUR_THRESHOLD = 3   # same wrong claim across ≥3 cases = systemic false positive


def _tg(text):
    try:
        b = json.dumps({'chat_id': _OWNER, 'text': text[:3500]}, ensure_ascii=False).encode()
        urllib.request.urlopen(urllib.request.Request(
            'https://api.telegram.org/bot%s/sendMessage' % TG_BOT_TOKEN,
            data=b, headers={'Content-Type': 'application/json'}), timeout=15)
    except Exception:
        pass


def reflect_on_feedback(dry_run=False):
    processed = lessons = 0
    with psycopg2.connect(PG_DSN) as c:
        c.autocommit = True
        with c.cursor() as cur:
            cur.execute("ALTER TABLE case_feedback ADD COLUMN IF NOT EXISTS reflected_at timestamptz")
            cur.execute("""
                SELECT id, case_key, claim_id, claim_type, claim_text
                FROM case_feedback
                WHERE verdict='incorrect' AND reflected_at IS NULL
                ORDER BY ts LIMIT 500
            """)
            rows = cur.fetchall()

    for _id, ck, cid, ctype, ctext in rows:
        lesson = ("Аналітик позначив ХИБНИМ висновок у кейсі %s: «%s» (тип: %s). "
                  "Не подавати цей висновок як підтверджений без додаткових незалежних "
                  "доказів — раніше він давав хибне спрацювання." % (ck, ctext, ctype))
        if not dry_run:
            try:
                _save_lesson(ck, 'report_feedback', 'human_rejected', lesson, [], [], {})
                _save_case_knowledge(
                    ck, 'wrong_approach',
                    "ВІДХИЛЕНО аналітиком у кейсі %s: %s. Не вважати це підтвердженим фактом." % (ck, ctext),
                    'report_feedback', '')
                lessons += 1
            except Exception:
                pass
            with psycopg2.connect(PG_DSN) as c:
                c.autocommit = True
                with c.cursor() as cur:
                    cur.execute("UPDATE case_feedback SET reflected_at=now() WHERE id=%s", (_id,))
        processed += 1

    # recurring systemic mistakes across ALL incorrect feedback
    with psycopg2.connect(PG_DSN) as c:
        c.autocommit = True
        with c.cursor() as cur:
            cur.execute("""
                SELECT claim_type, lower(claim_text) AS t, count(DISTINCT case_key) AS n
                FROM case_feedback WHERE verdict='incorrect'
                GROUP BY 1, 2 HAVING count(DISTINCT case_key) >= %s
                ORDER BY n DESC LIMIT 10
            """, (_RECUR_THRESHOLD,))
            recurring = cur.fetchall()

    if recurring and not dry_run:
        _tg("🧠 Саморефлексія бота: систематичні ХИБНІ висновки (❌ у кількох кейсах) — "
            "варто переглянути детектор:\n" +
            "\n".join("• [%s] «%s» — у %d кейсах" % (r[0], r[1][:70], r[2]) for r in recurring))

    return {'processed': processed, 'lessons_written': lessons,
            'recurring_patterns': len(recurring), 'dry_run': dry_run}


if __name__ == '__main__':
    dry = '--apply' not in sys.argv
    print(json.dumps(reflect_on_feedback(dry_run=dry), ensure_ascii=False))
