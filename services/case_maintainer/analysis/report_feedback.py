# -*- coding: utf-8 -*-
"""S3/S4 (feedback loop): interactive per-claim verification of a DFIR report.
A trusted analyst steps through the curated key claims with ✅/❌/❓ buttons.
Verdicts land in case_feedback; ✅ -> case_verified_facts + dfir_claims_v1 status
='human_confirmed' (trusted case memory, retrieved later by S6). ACL-gated so
public users cannot degrade the bot (owner + bot_free_chat_acl only).
Callback grammar (piggybacks the tool: namespace n8n already routes):
  tool:fbstart:<job_id>   -> start review
  tool:fbv:<verdict>      -> record current claim + advance (correct|incorrect|unknown|stop)
See docs/FEEDBACK_LOOP_PLAN.md."""
import psycopg2

_TYPE_UA = {'verdict': 'Вердикт', 'finding': 'Знахідка',
            'ioc': 'Індикатор (IOC)', 'timeline': 'Подія'}

# readable labels for terse deterministic finding codes
_CODE_UA = {
    'rdp_user_creation_linkage': 'Створення користувача повʼязане з RDP-доступом',
    'script_host_execution_linkage': 'Виконання через скрипт-хост (WScript/CScript)',
    'defender_tampering': 'Втручання у Windows Defender (послаблення захисту)',
    'delivery_browser_provenance': 'Шкідливий файл доставлено через браузер',
    'ngrok_7za_chain': 'Ланцюг ngrok + 7za (тунель + розпакування)',
    'ngrok_rdp_chain': 'Ланцюг ngrok + RDP (тунельований віддалений доступ)',
    'weak_text_hit': 'Слабке текстове співпадіння (потребує перевірки)',
    'generic_tool_alert': 'Виявлено підозрілий інструмент подвійного призначення',
    'log_tampering': 'Втручання у журнали подій (антифорензика)',
    'rdp_external_burst': 'Сплеск зовнішніх RDP-підключень',
}


def _dsn():
    from core.config import PG_DSN
    return PG_DSN


def _uid_int(uid):
    try:
        return int(str(uid).strip())
    except Exception:
        return None


def _is_trusted(uid):
    """Abuse defense: only owner + ACL-listed analysts may vote."""
    try:
        from core.config import ADMIN_CHAT_ID
        if str(uid) == str(ADMIN_CHAT_ID):
            return True
    except Exception:
        pass
    try:
        from analysis.free_chat import is_allowed
        return bool(is_allowed(uid))
    except Exception:
        return False


def _label(claim):
    t = _TYPE_UA.get(claim.get('claim_type', ''), 'Твердження')
    txt = claim.get('claim_text', '')
    if claim.get('claim_type') == 'finding':
        txt = _CODE_UA.get(txt.strip(), txt)
    return t, txt


def _kb():
    return {'inline_keyboard': [
        [{'text': '✅ Вірно', 'callback_data': 'tool:fbv:correct'},
         {'text': '❌ Невірно', 'callback_data': 'tool:fbv:incorrect'},
         {'text': '❓ Не знаю', 'callback_data': 'tool:fbv:unknown'}],
        [{'text': '⏹ Завершити', 'callback_data': 'tool:fbv:stop'}],
    ]}


def _send(chat_id, text, kb=None):
    from case_maintainer_addtools import _send_plain
    if kb is not None:
        _send_plain(chat_id, text, reply_markup=kb)
    else:
        _send_plain(chat_id, text)


def _prompt(st):
    i = st['idx']
    claims = st['claims']
    typ, txt = _label(claims[i])
    return ('🔎 <b>Перевірка висновків</b>  (%d/%d)\n\n<b>%s:</b> %s\n\nЦе твердження правильне?'
            % (i + 1, len(claims), typ, txt[:350]))


def start_review(chat_id, user_id, job_id):
    from case_maintainer_addtools import _set_pending
    if not _is_trusted(user_id):
        _send(chat_id, '🔒 Перевірка висновків доступна лише авторизованим аналітикам.')
        return
    case_key = None
    try:
        with psycopg2.connect(_dsn()) as c:
            c.autocommit = True
            with c.cursor() as cur:
                cur.execute("SELECT case_key FROM dfir_run_jobs_v2 WHERE job_id=%s", (str(job_id),))
                r = cur.fetchone()
                case_key = r[0] if r else None
    except Exception:
        case_key = None
    if not case_key:
        _send(chat_id, '⌛ Не знайдено кейс для цього звіту.')
        return
    try:
        from analysis.claim_extract import select_review_claims
        claims = select_review_claims(case_key, job_id, _dsn())
    except Exception:
        claims = []
    if not claims:
        _send(chat_id, 'ℹ️ Немає ключових тверджень для перевірки в цьому звіті.')
        return
    _set_pending(chat_id, user_id, 'reportfb', 'review',
                 claims=claims, idx=0, job_id=str(job_id), case_key=case_key,
                 tally={'correct': 0, 'incorrect': 0, 'unknown': 0})
    _send(chat_id, _prompt({'idx': 0, 'claims': claims}), _kb())


def _record(case_key, job_id, claim, verdict, user_id):
    uid = _uid_int(user_id)
    with psycopg2.connect(_dsn()) as c:
        c.autocommit = True
        with c.cursor() as cur:
            cur.execute("""
                INSERT INTO case_feedback
                    (case_key, job_id, claim_id, claim_type, claim_text, verdict, source, user_id)
                VALUES (%s,%s,%s,%s,%s,%s,'report',%s)
                ON CONFLICT (case_key, claim_id, user_id)
                DO UPDATE SET verdict=EXCLUDED.verdict, ts=now()
            """, (case_key, str(job_id), claim['claim_id'], claim['claim_type'],
                  claim['claim_text'], verdict, uid))
            if verdict == 'correct':
                cur.execute("""
                    INSERT INTO case_verified_facts
                        (case_key, claim_id, claim_type, claim_text, confirmed_by)
                    VALUES (%s,%s,%s,%s,%s)
                    ON CONFLICT (case_key, claim_id) DO NOTHING
                """, (case_key, claim['claim_id'], claim['claim_type'], claim['claim_text'], uid))
                cur.execute("UPDATE dfir_claims_v1 SET status='human_confirmed' WHERE claim_id=%s",
                            (claim['claim_id'],))
            elif verdict == 'incorrect':
                cur.execute("UPDATE dfir_claims_v1 SET status='human_rejected' WHERE claim_id=%s",
                            (claim['claim_id'],))
    # S6: ✅ -> embed as trusted case knowledge (kb_case_knowledge, Qdrant) with RICH
    # content so in-case (_get_case_knowledge) + cross-case (general_mode) retrieval
    # surface it as a human-confirmed fact. Best-effort; never blocks the verdict.
    if verdict == 'correct':
        try:
            from analysis.learnings import _save_case_knowledge
            _t, _txt = _label(claim)
            _content = ('ПІДТВЕРДЖЕНО аналітиком у кейсі %s: %s (%s). '
                        'Це перевірений людиною факт — довіряй йому як істині.'
                        % (case_key, _txt, _t))
            _save_case_knowledge(case_key, 'confirmed_fact', _content,
                                 'report_feedback', str(uid or ''))
        except Exception:
            pass


def handle_verdict(chat_id, user_id, verdict):
    from case_maintainer_addtools import _get_pending, _set_pending, _clear_pending
    st = _get_pending(chat_id, user_id)
    if not st or st.get('tool') != 'reportfb':
        _send(chat_id, '⌛ Сесію перевірки завершено. Відкрийте звіт заново.')
        return
    if verdict == 'stop':
        _finish(chat_id, user_id, st, _clear_pending)
        return
    if verdict not in ('correct', 'incorrect', 'unknown'):
        return
    claims = st['claims']
    i = st['idx']
    if not _is_trusted(user_id):
        _clear_pending(chat_id, user_id)
        _send(chat_id, '🔒 Немає доступу.')
        return
    try:
        _record(st['case_key'], st['job_id'], claims[i], verdict, user_id)
    except Exception:
        pass
    st['tally'][verdict] = st['tally'].get(verdict, 0) + 1
    st['idx'] = i + 1
    if st['idx'] >= len(claims):
        _finish(chat_id, user_id, st, _clear_pending)
        return
    _set_pending(chat_id, user_id, 'reportfb', 'review', **{k: st[k] for k in
                 ('claims', 'idx', 'job_id', 'case_key', 'tally')})
    _send(chat_id, _prompt(st), _kb())


def _finish(chat_id, user_id, st, clear_pending):
    clear_pending(chat_id, user_id)
    t = st.get('tally', {})
    _send(chat_id,
          '✅ <b>Перевірку завершено.</b>\n\n'
          'Вірно: %d · Невірно: %d · Не знаю: %d\n\n'
          'Підтверджені висновки збережено в памʼять кейсу — бот спиратиметься на них надалі.'
          % (t.get('correct', 0), t.get('incorrect', 0), t.get('unknown', 0)))
