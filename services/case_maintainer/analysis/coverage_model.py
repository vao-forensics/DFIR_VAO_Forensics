# -*- coding: utf-8 -*-
"""Evidence-coverage model: which evidence sources a case actually has, and therefore which
detector categories are BLIND for it.

Why: 13 real cases came from four collector generations. Registry/autoruns exist in 6 of 13,
browser artefacts in 6, Prefetch in 6, SRUM in 4, scanner alerts in 6, Sysmon in 0. A signature
that needs a missing source returns nothing, and the report read that silence as «calm». This
module turns silence into a named blind spot: the report prints it, the calm verdict is
scoped to what was collected, and the truth suite explains misses with it.

Public API (all pure SQL counts, no LLM):
  evidence_sources(case_key, conn) -> {source_key: row_count}
  blind_spots(sources)             -> [ {key, title, affects, why} ] for sources with 0 rows
  report_lines(case_key, conn)     -> list of markdown lines for «ПОВНОТА ДАНИХ»
  calm_caveat(case_key, conn)      -> one sentence (or '') to append to a calm conclusion
"""
import psycopg2

# source_key -> (SQL count expression, title_ua, categories that go blind without it)
# Sysmon is deliberately absent: it is not deployed on the machines we see, and a spot that
# fires on every case tells the investigator nothing.
SOURCES = [
    ('security_logons', "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id IN (4624,4625,4648,4672)",
     'журнал Security (входи 4624/4625/4648)', ['Доступ (RDP)', 'Крадіжка облікових даних', 'бекдор-акаунти']),
    ('terminal_services', "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND source_file ILIKE '%%TerminalServices%%'",
     'журнали TerminalServices (RDP-сесії)', ['Доступ (RDP)']),
    ('defender', "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND source_file ILIKE '%%Defender%%'",
     'журнал Windows Defender', ['Захист вимикали', 'Захист обходили', 'детекції антивіруса']),
    ('powershell', "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND source_file ILIKE '%%PowerShell%%'",
     'журнали PowerShell', ['Виконання (обфускований PowerShell)']),
    ('task_scheduler', "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND (source_file ILIKE '%%TaskScheduler%%' OR event_id IN (4698,106,140))",
     'журнал планувальника завдань', ['Закріплення (заплановані завдання)']),
    ('exec_amcache', "SELECT count(*) FROM program_exec_v2 WHERE case_key=%s AND source_file ILIKE '%%Amcache%%'",
     'Amcache', ['Виконання', 'Інструменти атакувальника']),
    ('exec_shimcache', "SELECT count(*) FROM program_exec_v2 WHERE case_key=%s AND source_file ILIKE '%%AppCompat%%'",
     'ShimCache', ['Виконання (присутність файлів)']),
    ('exec_prefetch', "SELECT count(*) FROM program_exec_v2 WHERE case_key=%s AND source_file ILIKE '%%PECmd%%'",
     'Prefetch', ['Виконання (час і кількість запусків)']),
    ('registry', "SELECT count(*) FROM raw_fallback_v2 WHERE case_key=%s AND parser_family IN ('registry','regripper_software','regripper_ntuser','regripper_system','autoruns')",
     'реєстр (гілки Run/IFEO/служби, Autoruns)', ['Закріплення (реєстр)', 'Закріплення/привілеї']),
    ('browser', "SELECT count(*) FROM raw_fallback_v2 WHERE case_key=%s AND parser_family LIKE 'browser%%'",
     'історія та завантаження браузерів', ['Доставка (фішинг-завантаження)']),
    ('lnk_jumplists', "SELECT count(*) FROM raw_fallback_v2 WHERE case_key=%s AND parser_family IN ('lnk','jumplists')",
     'LNK / JumpLists (відкриті файли)', ['Доставка (відкриті вкладення)']),
    ('srum', "SELECT count(*) FROM srum_v2 WHERE case_key=%s",
     'SRUM (мережева активність процесів)', ['Тунель / прихований канал (обсяги трафіку)']),
    ('mft', "SELECT count(*) FROM filesystem_v2 WHERE case_key=%s",
     '$MFT (файлова система)', ['Ransomware', 'Знищення', 'теки розпакування архівів']),
    ('scanner_alerts', "SELECT count(*) FROM tool_alerts_v2 WHERE case_key=%s",
     'сигнатурні сканери (Hayabusa/DeepBlueCLI/Sigma)', ['Сигма/DeepBlue детекції']),
]

_ORDER = {k: i for i, (k, _, _, _) in enumerate(SOURCES)}


def evidence_sources(case_key, conn=None):
    """{source_key: row_count} for the case. Never raises: a failed count is reported as 0."""
    own = conn is None
    if own:
        from core.config import PG_DSN
        conn = psycopg2.connect(PG_DSN)
        conn.autocommit = True
    out = {}
    try:
        cur = conn.cursor()
        try:
            cur.execute("SET statement_timeout='20000'")
        except Exception:
            pass
        for key, sql, _t, _c in SOURCES:
            try:
                cur.execute(sql, (case_key,))
                out[key] = int((cur.fetchone() or [0])[0] or 0)
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                out[key] = 0
    finally:
        if own:
            conn.close()
    return out


def blind_spots(sources):
    """Sources with zero rows, in a stable order, each with the categories it blinds."""
    spots = []
    for key, _sql, title, affects in SOURCES:
        if not sources.get(key):
            spots.append({'key': key, 'title': title, 'affects': list(affects),
                          'why': 'джерела немає в архіві або парсер його не прочитав'})
    return spots


def report_lines(case_key, conn=None):
    """Markdown lines for the «📦 ПОВНОТА ДАНИХ» block. Empty list when nothing is blind."""
    spots = blind_spots(evidence_sources(case_key, conn))
    if not spots:
        return ['- 🔦 Сліпих зон детектора немає: усі очікувані джерела доказів присутні.']
    lines = ['- 🔦 **Сліпі зони детектора** — джерел нижче в архіві немає, тому відповідні '
             'ознаки НЕ перевірялись (мовчання тут ≠ «чисто»):']
    for s in spots:
        lines.append('  - %s → не перевірено: %s' % (s['title'], ', '.join(s['affects'])))
    return lines


def calm_caveat(case_key, conn=None, max_names=4):
    """One sentence scoping a calm verdict to the collected sources. '' when nothing is blind."""
    spots = blind_spots(evidence_sources(case_key, conn))
    if not spots:
        return ''
    names = [s['title'] for s in spots[:max_names]]
    more = len(spots) - len(names)
    return ('Висновок стосується лише зібраних джерел: не перевірено %s%s — див. «Повнота даних».'
            % ('; '.join(names), (' та ще %d' % more) if more > 0 else ''))
