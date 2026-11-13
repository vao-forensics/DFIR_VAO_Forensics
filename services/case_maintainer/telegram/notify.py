"""Telegram notification helpers."""
import json, logging, urllib.request, urllib.error, html
from core.config import TG_BOT_TOKEN, ADMIN_CHAT_ID, DFIR_STEP_CODES, PG_DSN

_log = logging.getLogger('app')


# ── Live progress card (ADDITIVE) ────────────────────────────────────────────
#  build_live_card() renders a clean Ukrainian one-block progress string with a
#  FIXED grammar. It is pure/string-only, never raises, and NEVER reveals an LLM
#  model name. Used by the Additional-Tools progress heartbeat.
#
#  Grammar (lines, in order; optional lines omitted when their arg is None):
#     {icon} {title}
#     📁 {case}                         (if case)
#     {progress line}                   (bar ▰▱ + pct  OR  "сторінка done/total")
#     ⏱ {elapsed} · ⏳ ETA {eta}        (if elapsed and/or eta)
#     🎮 GPU {gpu}%                      (if gpu is not None)
#     ⏳ у черзі: {queue_pos}            (if queue_pos)
#     {detail}                          (if detail)
#
#  Special: status="swap" (model loading / swapping) replaces the whole body
#  with a reassuring line and NEVER names a model.

# Swap / model-loading line — generic, never reveals a model name.
LIVE_SWAP_TEXT = ("🔄 Готую модель під твою задачу, зачекай… "
                  "(модель для іншого завдання звільняє місце)")

_LIVE_OP_ICONS = {
    'pdf_translate': '📄', 'translate': '🌐', 'ocr': '🔎', 'pdf_unlock': '🔓',
    'pdf_watermark': '💧', 'meta': '🧬', 'llm': '🤖', 'analysis': '🧠',
    'ask': '🤖', 'report': '📝',
}

_LIVE_STATUS_ICON = {
    'running': '⚙️', 'queued': '⏳', 'swap': '🔄',
    'done': '✅', 'completed': '✅', 'failed': '❌', 'error': '❌',
}


def _live_fmt_secs(v) -> str:
    """Humanize seconds -> '8с' / '2хв 5с' / '1г 3хв'. Accepts int/float/str."""
    try:
        s = int(round(float(v)))
    except Exception:
        return str(v)
    if s < 0:
        s = 0
    if s < 60:
        return f"{s}с"
    if s < 3600:
        m, ss = divmod(s, 60)
        return f"{m}хв" + (f" {ss}с" if ss else "")
    h, rem = divmod(s, 3600)
    m = rem // 60
    return f"{h}г" + (f" {m}хв" if m else "")


def _live_bar(pct, width: int = 10) -> str:
    try:
        p = max(0, min(100, int(round(float(pct)))))
    except Exception:
        p = 0
    filled = int(round(width * p / 100.0))
    filled = max(0, min(width, filled))
    return '▰' * filled + '▱' * (width - filled)


# -- ADDITIVE: strip a leading emoji cluster from a title so build_live_card
#  never prepends a second icon and yields a doubled icon (e.g. '🔎 🔎 OCR').
#  Pure/string-only; never raises. Char-by-char over known emoji/symbol code
#  point ranges plus variation selectors / ZWJ / skin-tone modifiers.
def _live_is_emoji_char(ch):
    o = ord(ch)
    return (
        0x1F000 <= o <= 0x1FAFF      # misc symbols & pictographs, emoticons, etc.
        or 0x2600 <= o <= 0x27BF     # misc symbols + dingbats
        or 0x2190 <= o <= 0x21FF     # arrows
        or 0x2B00 <= o <= 0x2BFF     # misc symbols and arrows
        or 0x1F1E6 <= o <= 0x1F1FF   # regional indicators
        or 0x1F3FB <= o <= 0x1F3FF   # skin tone modifiers
        or o == 0xFE0F or o == 0xFE0E  # variation selectors
        or o == 0x200D               # zero-width joiner
        or o == 0x20E3               # combining enclosing keycap
        or 0x2300 <= o <= 0x23FF     # misc technical (incl. hourglass, watch)
        or 0x2B05 <= o <= 0x2B07     # arrows
    )


def _live_strip_lead_icon(title):
    """Remove ONE leading emoji cluster + following whitespace from title.

    If the title is ONLY an emoji (stripping leaves nothing) return it
    unchanged so the rendered line is never empty.
    """
    try:
        s = str(title)
        i = 0
        n = len(s)
        # skip leading whitespace
        while i < n and s[i].isspace():
            i += 1
        start = i
        # consume a run of emoji-ish chars (the cluster)
        while i < n and _live_is_emoji_char(s[i]):
            i += 1
        if i == start:
            return s  # no leading emoji -> unchanged
        rest = s[i:].lstrip()
        return rest if rest else s
    except Exception:
        return title



def build_live_card(op, title, *, case=None, pct=None, done=None, total=None,
                    step=None, step_label=None, elapsed=None, eta=None,
                    gpu=None, queue_pos=None, phase=None, status="running",
                    detail=None):
    """Render a Ukrainian live-progress card. Pure string; never raises.

    Args (all optional except op/title):
      op          str  – operation key (selects icon), e.g. 'pdf_translate'
      title       str  – human title line, e.g. 'Переклад PDF'
      case        str  – case label -> '📁 {case}'
      pct         num  – 0..100 -> progress bar ▰▱ + percent
      done,total  num  – page/item progress -> 'сторінка {done}/{total}' (+bar)
      step,step_label  – optional sub-step display ('крок 2/5: …')
      elapsed     num/str – seconds elapsed -> ⏱
      eta         num/str – seconds remaining -> ⏳ ETA
      gpu         num  – GPU busiest util % -> 🎮 GPU {gpu}%
      queue_pos   num  – position/size in LLM queue -> ⏳ у черзі: {queue_pos}
      phase       str  – free phase label (shown as detail if no detail given)
      status      str  – running|queued|swap|done|failed (selects status icon)
      detail      str  – extra free line at the end
    """
    try:
        st = (status or "running").lower()
        title = _live_strip_lead_icon(title)

        # SWAP: model loading/swapping — single reassuring block, no model name.
        if st == "swap" or (phase or "").lower() == "swap":
            head_icon = '🔄'
            lines = [f"{head_icon} {title}".rstrip()]
            if case:
                lines.append(f"📁 {case}")
            lines.append(LIVE_SWAP_TEXT)
            if elapsed is not None:
                lines.append(f"⏱ {_live_fmt_secs(elapsed)}")
            return "\n".join(lines)[:3900]

        icon = _LIVE_OP_ICONS.get(str(op or '').lower())
        if not icon:
            icon = _LIVE_STATUS_ICON.get(st, '⚙️')

        lines = [f"{icon} {title}".rstrip()]

        if case:
            lines.append(f"📁 {case}")

        if step is not None:
            try:
                sl = f"крок {int(step)}"
            except Exception:
                sl = f"крок {step}"
            if step_label:
                sl += f": {step_label}"
            lines.append(sl)

        # Progress line: prefer explicit pages (done/total), else pct bar.
        if done is not None and total is not None:
            try:
                d = int(done); t = int(total)
            except Exception:
                d, t = done, total
            p = None
            try:
                if float(total) > 0:
                    p = int(round(100.0 * float(done) / float(total)))
            except Exception:
                p = None
            page_line = f"сторінка {d}/{t}"
            if p is not None:
                lines.append(f"{_live_bar(p)} {page_line}")
            else:
                lines.append(page_line)
        elif pct is not None:
            try:
                p = max(0, min(100, int(round(float(pct)))))
            except Exception:
                p = 0
            lines.append(f"{_live_bar(p)} {p}%")

        # Timing line.
        timing = []
        if elapsed is not None:
            timing.append(f"⏱ {_live_fmt_secs(elapsed)}")
        if eta is not None:
            timing.append(f"⏳ ETA {_live_fmt_secs(eta)}")
        if timing:
            lines.append(" · ".join(timing))

        if gpu is not None:
            try:
                lines.append(f"🎮 GPU {int(round(float(gpu)))}%")
            except Exception:
                pass

        if queue_pos:
            lines.append(f"⏳ у черзі: {queue_pos}")

        tail = detail if detail else (phase if phase else None)
        if tail:
            lines.append(str(tail))

        # Terminal status flourish.
        if st in ("done", "completed"):
            lines.append("✅ Готово")
        elif st in ("failed", "error"):
            lines.append("❌ Помилка")

        return "\n".join(lines)[:3900]
    except Exception:
        # Absolute fail-safe: never break the caller's heartbeat.
        try:
            return f"{title}"[:3900]
        except Exception:
            return "Обробка…"


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
    'llm_report':             '🤖 AI звіт',
    'agent_planner_v2':       '🗺 Планувальник агента',
    # The agent phase is a single pipeline step that runs for tens of minutes. Without
    # its own labels the card showed a bare code, or nothing, for that whole time.
    'agent_collect':          '🧰 Збір доказів',
    'agent_investigate':      '🧠 Модель розслідує',
    'agent_coverage':         '✅ Перевірка покриття фаз',
    'ingest_bootstrap':       '💾 Імпорт логів у БД',
}

def _tg_send_or_edit(tg_token, chat_id, text, message_id=None):
    """Send new or edit existing Telegram message. Returns message_id."""
    if not tg_token or not chat_id:
        return None
    try:
        if message_id:
            url = f"https://api.telegram.org/bot{tg_token}/editMessageText"
            body = json.dumps({'chat_id': str(chat_id), 'message_id': int(message_id),
                               'text': text, 'parse_mode': 'HTML'}).encode('utf-8')
        else:
            url = f"https://api.telegram.org/bot{tg_token}/sendMessage"
            body = json.dumps({'chat_id': str(chat_id), 'text': text,
                               'parse_mode': 'HTML'}).encode('utf-8')
        req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
        resp = json.loads(urllib.request.urlopen(req, timeout=10).read())
        return (resp.get('result') or {}).get('message_id')
    except Exception:
        return message_id


def _tg_scan_progress_edit(tg_token, chat_id, msg_id, stage, progress, case_key):
    if not tg_token or not chat_id or not msg_id:
        return msg_id
    bars = int(progress / 5)
    bar = '█' * bars + '░' * (20 - bars)
    stage_labels = {
        'loading_triggers': '📂 Завантаження тригерів',
        'ingest_bootstrap': '💾 Завантаження логів у БД',
        'scanning': '🔍 Сканування артефактів',
        'done': '✅ Готово',
        'failed': '❌ Помилка',
    }
    label = stage_labels.get(stage, stage)
    case_d = case_key.replace('_', ' ')[:50]
    text = (f'📊 Обробка кейсу\n📁 {case_d}\n\n'
            f'<code>{bar}</code> {progress}%\n{label}')
    return _tg_send_or_edit(tg_token, chat_id, text, message_id=msg_id)





def _liveness_line(started_at=None, heartbeat_at=None):
    """"How long it has been working" and "when it last proved it". A percentage that
    does not move is ambiguous; a timestamp that does not move is not."""
    from datetime import datetime, timezone

    def _age(ts):
        if not ts:
            return None
        try:
            if isinstance(ts, str):
                return None
            now = datetime.now(timezone.utc)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return max(0, int((now - ts).total_seconds()))
        except Exception:
            return None

    def _human(sec):
        if sec is None:
            return None
        if sec < 60:
            return '%d с' % sec
        if sec < 3600:
            return '%d хв' % (sec // 60)
        return '%d год %d хв' % (sec // 3600, (sec % 3600) // 60)

    run = _human(_age(started_at))
    beat = _age(heartbeat_at)
    parts = []
    if run:
        parts.append('\u23f1 %s у роботі' % run)
    if beat is not None:
        if beat > 300:
            parts.append('\u26a0\ufe0f сигналу немає %s' % _human(beat))
        else:
            parts.append('сигнал %s тому' % _human(beat))
    return ' \u00b7 '.join(parts) if parts else ''


def _build_progress_text(case_key, status, current_step, total_steps, progress_pct, step_code=None, error_short=None, job_id=None, started_at=None, heartbeat_at=None):
    """Build visual progress card for Telegram."""
    case_display = case_key.replace('_', ' ')[:60]
    pct = int(float(progress_pct or 0))

    bar_len = 16
    filled = round(bar_len * pct / 100)
    bar = '▓' * filled + '░' * (bar_len - filled)

    step_name = _STEP_UA.get(step_code or '', step_code or '—')

    if status == 'queued':
        icon = '⏳'
        status_ua = 'В черзі'
    elif status == 'running':
        icon = '⚙️'
        status_ua = 'Виконується'
    elif status == 'completed':
        icon = '✅'
        status_ua = 'Завершено'
    elif status == 'failed':
        icon = '❌'
        status_ua = f'Помилка: {error_short or "невідома"}'
    else:
        icon = '❓'
        status_ua = status

    def _step_action(code):
        return {
            'ingest_check': 'Перевіряю, чи логи вже розібрані в базу, і рахую доступні таблиці доказів.',
            'detection': 'Шукаю high-signal події: Defender, нові акаунти, RDP, services/tasks, LOLBins, підозрілі процеси.',
            'corroboration': 'Зіставляю незалежні джерела між собою, щоб не видати одиночний старий артефакт за атаку.',
            'incident_timeline': 'Будую часовий ланцюг: delivery → execution → persistence/remote access → tampering/impact.',
            'case_llm_triage_v1': 'ШІ читає зібрані докази й формує первинні гіпотези без вигадування фактів.',
            'case_drilldown_v1': 'ШІ перевіряє слабкі місця: чи є пропущені IOC, часові розриви, remote-access та persistence.',
            'case_reasoning_v1': 'ШІ зводить докази в аналітичний verdict і відділяє confirmed / likely / gaps.',
            'detection_timeline': 'Групую детекції в зрозумілу хронологію, прибираючи низькоцінний шум.',
            'ioc_artifacts': 'Збираю IOC: файли, шляхи, хеші, акаунти, IP/URL/домени, remote tools.',
            'short_conclusion': 'Формую модуль “Загальний висновок” для Telegram.',
            'txt_report': 'Матеріалізую фінальний Markdown/TXT звіт і перевіряю, що він не порожній.',
            'llm_report': 'ШІ пише повний клієнтський Markdown-звіт у стилі аналітика.',
            'agent_planner_v2': 'Планую, які джерела й артефакти треба перевірити першими.',
        }.get(code or '', 'Виконую поточний етап аналізу та оновлюю артефакти кейсу.')

    def _next_step(code):
        try:
            idx = DFIR_STEP_CODES.index(code)
            if idx + 1 < len(DFIR_STEP_CODES):
                return _STEP_UA.get(DFIR_STEP_CODES[idx + 1], DFIR_STEP_CODES[idx + 1])
        except Exception:
            pass
        return None

    def _short_findings(jid):
        if not jid:
            return []
        out = []
        try:
            with psycopg2.connect(PG_DSN) as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT step_code, step_status, COALESCE(message,''), COALESCE(meta_json,'{}'::jsonb)
                        FROM public.dfir_run_steps_v2
                        WHERE job_id=%s
                        ORDER BY step_no ASC
                    """, (jid,))
                    rows = cur.fetchall() or []
        except Exception:
            return []
        for code, st, msg, meta in rows:
            if st != 'success' or not isinstance(meta, dict):
                continue
            try:
                if code == 'ingest_check':
                    counts = meta.get('counts') or meta.get('table_counts') or {}
                    if isinstance(counts, dict) and counts:
                        bits = []
                        for k in ['event_logs_v2','program_exec_v2','filesystem_v2','tool_alerts_v2','case_iocs']:
                            if counts.get(k): bits.append(f"{k.replace('_v2','')}={counts.get(k)}")
                        if bits: out.append('📦 Дані: ' + ', '.join(bits[:4]))
                elif code == 'detection':
                    families = meta.get('families') or meta.get('trigger_families') or []
                    if families:
                        vals = [str(x.get('family') if isinstance(x, dict) else x) for x in families[:4]]
                        out.append('🚩 Тригери: ' + ', '.join([v for v in vals if v]))
                elif code == 'corroboration':
                    confirmed = meta.get('confirmed') or []
                    likely = meta.get('likely') or []
                    out.append(f'🔗 Кореляція: confirmed={len(confirmed)}, likely={len(likely)}')
                elif code == 'incident_timeline':
                    tl = meta.get('incident_timeline') or meta.get('timeline') or []
                    if tl: out.append(f'📅 Хронологія: {len(tl)} ключових подій')
                elif code == 'ioc_artifacts':
                    iocs = meta.get('ioc_artifacts') or meta.get('iocs') or []
                    if iocs: out.append(f'🎯 IOC: {len(iocs)} кандидатів')
                elif code == 'case_reasoning_v1':
                    rr = meta.get('case_reasoning_v1') or meta
                    verdict = rr.get('summary_verdict') if isinstance(rr, dict) else None
                    conf = rr.get('confidence') if isinstance(rr, dict) else None
                    if verdict: out.append(f'🧠 Вердикт: {verdict}' + (f' / {conf}' if conf else ''))
            except Exception:
                continue
            if len(out) >= 4:
                break
        return out

    safe_case = html.escape(case_display)
    safe_step = html.escape(step_name)
    safe_status = html.escape(status_ua)
    action = html.escape(_step_action(step_code))
    next_s = _next_step(step_code)

    lines = [
        f"{icon} <b>DFIR Аналіз</b>",
        f"📁 <code>{safe_case}</code>",
        f"",
        f"<code>[{bar}] {pct}%</code>",
        f"<b>Крок {current_step}/{total_steps}:</b> {safe_step}",
        f"<b>Статус:</b> {safe_status}",
    ]
    # Elapsed time plus the age of the last signal. A percentage frozen for thirty minutes
    # looks identical whether the model is thinking or the process is dead; a timestamp
    # that stops moving does not.
    _live = _liveness_line(started_at, heartbeat_at)
    if _live:
        lines.append(_live)
    lines.append("")
    lines.append(f"🔎 <b>Зараз роблю:</b> {action}")
    if step_code in ('case_llm_triage_v1','case_drilldown_v1','case_reasoning_v1','short_conclusion','txt_report','llm_report'):
        lines.append('🤖 <b>ШІ зараз:</b> читає зібрані докази, перевіряє гіпотези та готує текст без вигаданих фактів.')
    findings = _short_findings(job_id)
    if findings:
        lines.append('')
        lines.append('✅ <b>Вже знайдено / готово:</b>')
        for f in findings[:4]:
            lines.append('• ' + html.escape(str(f)[:150]))
    if next_s and status not in ('completed','failed'):
        lines.append('')
        lines.append('➡️ <b>Далі:</b> ' + html.escape(next_s))
    if status == 'completed':
        lines.append('')
        lines.append("🔔 Повний звіт надіслано вище ↑")
    return '\n'.join(lines)[:3900]



def _tg_send_admin(text, reply_markup=None):
    """Send message to admin only (DFIR_ADMIN_CHAT_ID). reply_markup: optional inline keyboard."""
    tg_token = TG_BOT_TOKEN
    admin_chat = ADMIN_CHAT_ID
    if not tg_token or not admin_chat:
        return
    try:
        payload = {
            'chat_id': admin_chat,
            'text': text[:4096],
            'parse_mode': 'HTML',
        }
        if reply_markup:
            payload['reply_markup'] = reply_markup
        body = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            f'https://api.telegram.org/bot{tg_token}/sendMessage',
            data=body, headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception as _e:
        _log.error(f"[monitor] _tg_send_admin error: {_e}")




# ── Complex telegram notification functions ──────────────────────────────────
import threading as _thr
import psycopg2
from core.config import PG_DSN, TG_BOT_TOKEN
from analysis.ioc_extract import _extract_and_store_case_iocs_from_sql

def _check_critical_events(case_key):
    """Return list of critical event strings (EID 4720, 1116, 4648) found in case."""
    alerts = []
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT event_id, event_ts, target_user, process_name, source_file
                    FROM event_logs_v2
                    WHERE case_key=%s AND event_id IN (4720,4726,1116,1117,4648,4732)
                    ORDER BY event_ts ASC LIMIT 10
                """, (case_key,))
                eid_labels = {4720:'🚨 Новий акаунт', 4726:'❌ Акаунт видалено', 1116:'🦠 Defender: malware',
                              1117:'🛡️ Defender: quarantine', 4648:'🔑 Explicit creds', 4732:'👥 Група: Admins'}
                for eid, ts, user, proc, src in cur.fetchall():
                    label = eid_labels.get(eid, f'EID {eid}')
                    ts_s = ts.strftime('%Y-%m-%d %H:%M') if ts else 'n/a'
                    alerts.append(f'{label}: {user or proc or "?"} @ {ts_s}')
    except Exception:
        pass
    return alerts


def _hayabusa_severity_alert(case_key, chat_id, tg_token):
    """Check Hayabusa tool_alerts_v2 for critical/high severity and send Telegram alert."""
    if not tg_token or not chat_id:
        return
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT severity, rule, COALESCE(user_name,'') as usr,
                           COALESCE(details,'') as det,
                           to_char(event_ts AT TIME ZONE 'Europe/Kyiv','YYYY-MM-DD HH24:MI') as ts
                    FROM tool_alerts_v2
                    WHERE case_key=%s
                      AND lower(severity) IN ('critical','crit','high')
                    ORDER BY
                        CASE lower(severity) WHEN 'critical' THEN 0 WHEN 'crit' THEN 0 ELSE 1 END,
                        event_ts DESC
                    LIMIT 10
                """, (case_key,))
                rows = cur.fetchall()
        if not rows:
            return
        sev_icons = {'critical': '🔴', 'crit': '🔴', 'high': '🟠'}
        lines = []
        for sev, rule, usr, det, ts in rows:
            icon = sev_icons.get((sev or '').lower(), '🟡')
            rule_short = (rule or '?')[:50]
            detail_short = (det or '')[:60]
            ts_s = ts or 'n/a'
            lines.append(f'{icon} [{sev}] <code>{rule_short}</code> {ts_s}')
            if detail_short:
                lines.append(f'  ↳ {detail_short}')
        msg = (f'🚨 Hayabusa High/Critical Alerts\n'
               f'📁 {case_key[:50]}\n\n' + '\n'.join(lines))
        _tg_send_or_edit(tg_token, chat_id, msg)
    except Exception as e:
        _log.warning(f'[hayabusa_alert] {e}')


def _auto_first_analysis(case_key, chat_id, tg_token):
    """Send auto timeline + triggers summary after new case scan completes."""
    import time as _t
    _t.sleep(8)  # wait for scan notification to land first
    try:
        # Extract IOCs from SQL and update ioc_overlap table
        try:
            _extract_and_store_case_iocs_from_sql(case_key)
            # Auto YARA-scan collected binaries (fires once KAPE FileCollection provides them)
            try:
                import urllib.request as _u, json as _j, threading as _t
                def _yc():
                    try:
                        _u.urlopen(_u.Request('http://localhost:8787/yara-case',
                            data=_j.dumps({'case_key': case_key}).encode(),
                            headers={'Content-Type': 'application/json'}), timeout=300).read()
                    except Exception:
                        pass
                _t.Thread(target=_yc, daemon=True).start()
            except Exception:
                pass
            _log.error(f'[auto_analysis] IOC extraction done for {case_key}')
        except Exception as _ioc_e:
            _log.error(f'[auto_analysis] IOC extraction failed: {_ioc_e}')

        tg_url = f'https://api.telegram.org/bot{tg_token}/sendMessage'

        def _send(text):
            try:
                _b = json.dumps({'chat_id': str(chat_id), 'text': text[:4000],
                                 'parse_mode': 'HTML'}, ensure_ascii=False).encode()
                urllib.request.urlopen(urllib.request.Request(
                    tg_url, data=_b, headers={'Content-Type': 'application/json'}), timeout=15)
            except Exception:
                pass

        # Critical events alert
        crits = _check_critical_events(case_key)
        if crits:
            _send('⚠️ <b>КРИТИЧНІ ПОДІЇ у кейсі ' + case_key[:50] + ':</b>\n' +
                  '\n'.join(f'  • {c}' for c in crits[:8]))

        # Top triggers summary
        try:
            triggers_txt = _agent_tool_get_case_triggers(case_key)
            if triggers_txt and 'ERROR' not in triggers_txt:
                _send('🎯 <b>Топ тригерів:</b>\n<code>' + triggers_txt[:1800] + '</code>')
        except Exception:
            pass

        # Full timeline summary
        try:
            timeline_txt = _agent_tool_get_full_timeline(case_key)
            if timeline_txt and 'ERROR' not in timeline_txt:
                _send('📅 <b>Хронологія кейсу:</b>\n<code>' + timeline_txt[:2500] + '</code>')
        except Exception:
            pass
    except Exception:
        pass


def _tg_scan_done_notify(tg_token, chat_id, case_key, triggers_matched, triggers_total, threat_top=None, auto_iocs=None):
    if not tg_token or not chat_id:
        return
    case_d = case_key.replace('_', ' ')[:50]

    # Top threats block
    threat_lines = ''
    if threat_top:
        sev_icons = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
        lines = []
        for t in (threat_top or [])[:5]:
            icon = sev_icons.get(t.get('severity',''), '⚪')
            lines.append(f"  {icon} <code>{t['trigger']}</code> [{t['severity']}] score={t['score']}")
        threat_lines = '\n🏆 Топ загроз:\n' + '\n'.join(lines)

    # Auto IOC block
    ioc_lines = ''
    if auto_iocs:
        ioc_list = [f"<code>{i['value'][:60]}</code> [{i['type']}]" for i in (auto_iocs or [])[:5]]
        ioc_lines = '\n\n🔎 Авто-IOC:\n' + '\n'.join(f"  • {x}" for x in ioc_list)

    _stats = ''
    try:
        import psycopg2 as _pg, os as _os
        with _pg.connect(_os.getenv('PG_DSN')) as _c:
            with _c.cursor() as _cu:
                def _cnt(tbl):
                    try:
                        _cu.execute('SELECT count(*) FROM ' + tbl + ' WHERE case_key=%s', (case_key,)); return _cu.fetchone()[0]
                    except Exception:
                        return 0
                _ev, _fs, _pe, _rf, _al, _io = (_cnt('event_logs_v2'), _cnt('filesystem_v2'), _cnt('program_exec_v2'), _cnt('raw_fallback_v2'), _cnt('tool_alerts_v2'), _cnt('case_iocs'))
        def _f(x):
            return format(x, ',').replace(',', ' ')
        _stats = ('\n\n📊 Оброблено:\n'
                  '  • Подій журналів: <b>%s</b>\n'
                  '  • Файлів (MFT): <b>%s</b>\n'
                  '  • Запусків програм: <b>%s</b>\n'
                  '  • Реєстр/артефакти: <b>%s</b>\n'
                  '  • Детекцій: <b>%s</b> · IOC: <b>%s</b>') % (_f(_ev), _f(_fs), _f(_pe), _f(_rf), _f(_al), _f(_io))
    except Exception:
        pass
    text = (f'✅ Логи успішно оброблено — кейс готовий\n'
            f'📁 Кейс: {case_d}\n\n'
            f'🎯 Тригерів: <b>{triggers_matched}</b> / {triggers_total}'
            f'{_stats}'
            f'{threat_lines}{ioc_lines}\n\n'
            f'👉 Відкрий кейс — там: DFIR-аналіз · хронологія · висновок · питання (Q&A).')
    body = json.dumps({
        'chat_id': str(chat_id), 'text': text, 'parse_mode': 'HTML',
        'reply_markup': {'inline_keyboard': [
            [{'text': '🔍 Розпочати DFIR аналіз', 'callback_data': 'dfir.start_full_run'}],
            [{'text': '📂 Відкрити кейс', 'callback_data': 'case_menu'}]
        ]}
    }, ensure_ascii=False).encode('utf-8')
    try:
        tg_url = f'https://api.telegram.org/bot{tg_token}/sendMessage'
        urllib.request.urlopen(
            urllib.request.Request(tg_url, data=body, headers={'Content-Type': 'application/json'}),
            timeout=10)
    except Exception:
        try: conn.rollback()
        except: pass
        pass
    # Cross-case IOC correlation — alert if this case shares IOCs with previous cases
    def _cross_case_alert():
        try:
            with psycopg2.connect(PG_DSN) as _conn:
                _conn.autocommit = True
                with _conn.cursor() as _cur:
                    _cur.execute("""
                        SELECT i.ioc_value, i.ioc_type, array_agg(DISTINCT o.case_key) as other_cases
                        FROM case_iocs i
                        JOIN case_iocs o ON o.ioc_norm = i.ioc_norm
                            AND o.case_key <> i.case_key
                            AND o.ioc_type NOT IN ('path','user')
                        WHERE i.case_key = %s
                        GROUP BY i.ioc_value, i.ioc_type
                        HAVING count(DISTINCT o.case_key) >= 1
                        ORDER BY count(DISTINCT o.case_key) DESC
                        LIMIT 5
                    """, (case_key,))
                    shared = _cur.fetchall()
            if shared:
                lines = [f"  🔗 <code>{r[0][:50]}</code> [{r[1]}] → {', '.join(r[2][:2])}" for r in shared]
                msg = f"⚠️ Cross-case IOC кореляція\n📁 {case_key[:50]}\n\n" + '\n'.join(lines)
                _tg_send_or_edit(tg_token, chat_id, msg)
        except Exception:
            pass
    import threading as _thr
    _thr.Thread(target=_cross_case_alert, daemon=True).start()
    # Hayabusa critical/high severity alert
    if tg_token and chat_id:
        _thr.Thread(target=_hayabusa_severity_alert, args=(case_key, chat_id, tg_token), daemon=True).start()
    # Auto-analysis: launch background thread to send timeline + critical events
    if tg_token and chat_id:
        _thr.Thread(target=_auto_first_analysis, args=(case_key, chat_id, tg_token), daemon=True).start()


