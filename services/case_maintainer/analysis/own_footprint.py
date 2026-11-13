# -*- coding: utf-8 -*-
"""What the pipeline itself left on the target — so the report stops accusing us.

Twice on one case (3-4-19-1N, 2026-09-04) the bot described its own work as the attack:
the offline NTLM recovery became "the attacker ran secretsdump", and the collector's
KAPE.EXE / 7za.exe / dfp_*.ps1 in Temp\\DFIRTriage_* at 12:51 became "data collection
before destruction". Every detector, IOC extractor, chronology and Q&A context must ask
this module before calling something evidence.

Three sources of truth, from the strongest down:
  1. the collector's own declaration (_collector_self.txt -> analysis.collector_self):
     the exact paths it added to Defender exclusions;
  2. the collector's start time on this case: the first execution of vao_collector*
     (program_exec_v2). Anything under its staging folder at or after that moment is ours;
  3. name patterns nobody else uses: DFIRTriage_<hex> staging folder, dfp_<hex>.ps1 probes,
     vao_collector*.exe, DFIR_Triage work root, _collector_self.txt.

Deliberately narrow, like collector_self: KAPE.EXE or 7za.exe on their own are NOT ours -
an attacker may use them too. They are ours only under the staging folder or after the
collector started. Keep it that way; a broad filter once swallowed a user's-desktop
svchost.exe, i.e. real evidence.
"""
import os
import re
from datetime import datetime, timedelta

try:
    import psycopg2
except Exception:  # pragma: no cover
    psycopg2 = None

PG_DSN = os.environ.get('PG_DSN', '')

# strings that only our tooling produces (matched case-insensitively as substrings)
OWN_MARKERS = (
    'dfirtriage_',          # staging folder Temp\DFIRTriage_<hex>
    'dfir_triage',          # work root C:\DFIR_Triage
    'vao_collector',        # the collector executable
    'vao_triage',           # its C# launcher
    'vao_collect_all',      # the combined PowerShell it drives
    'vao_dfir_collector_marker',   # banner every collector script carries (lands in EID 4104)
    '!dfirbot',             # Modules\!DFIRbot\*.ps1
    'kape_triage',          # RAM capture work dir
    'magnetramcapture',     # the RAM capture driver/service it installs
    'for_dump_event',       # the examiner's event-log dump dir
    '_collector_self.txt',
    # the v3 / manual-KAPE generation of the same collector (case_66, case_45): the examiner's
    # KAPE target/module files (mimikatz_NTLMHashes.mkape became "8 credential-dump artefacts"),
    # the shared triage folder, the v3 executable, the RAM-capture tools
    '.mkape', '.tkape', 'kape_triage_shared', 'dfir_collector_v3', 'winpmem', 'dumpit',
    'dfp_',                 # PowerShell probes dfp_<hex>.ps1 (checked with the .ps1 suffix below)
)
_DFP_RX = re.compile(r'dfp_[0-9a-f]{6,}\.ps1', re.I)
# rule files of the Sigma/Hayabusa sets the collector unpacks (case_50: win_alert_mimikatz_keywords.yml
# and posh_ps_susp_keylogger_activity.yml became «mimikatz» and «keylogger» indicators, 02.10.2026)
_RULE_FILE_RX = re.compile(r'(^|[\\/\s])(proc_creation|proc_access|posh_ps|posh_pm|posh_pc|win_alert|win_security|win_system'
                           r'|file_event|file_access|file_delete|registry_(set|add|event|delete)|net_connection|image_load|pipe_created'
                           r'|dns_query|create_remote_thread|process_access|driver_load|ps_script|sysmon)_[\w.-]*\.(yml|yaml|yms)\b', re.I)

# tools we run on the target, ours only in our staging folder or after we started
OWN_TOOLS = ('kape.exe', '7za.exe', '7z.exe', 'mftecmd.exe', 'evtxecmd.exe', 'recmd.exe',
             'amcacheparser.exe', 'pecmd.exe', 'lecmd.exe', 'jlecmd.exe', 'rbcmd.exe',
             'sbecmd.exe', 'srumecmd.exe', 'hayabusa.exe', 'thor.exe', 'thor64.exe', 'loki.exe',
             'autorunsc.exe', 'autorunsc64.exe', 'autoruns64.exe', 'autoruns.exe', 'hindsight.exe', 'winpmem', 'dumpit.exe',
             'reg_hunter', 'deepbluecli')

# a tool name as a whole token: bare when it follows a path separator (…\7za), otherwise
# only with its .exe - a bare "hayabusa" or "thor" in an alert line names the detector
# that produced the alert, not a process that ran
_TOOL_STEMS = '|'.join(re.escape(t[:-4] if t.endswith('.exe') else t) for t in OWN_TOOLS)
_TOOLS_RX = re.compile(r'(^|[\\/])(' + _TOOL_STEMS + r')(\.exe)?(?=[\s"\'|\\/,;)\]]|$)'
                       r'|(^|[\s"\'|=(])(' + _TOOL_STEMS + r')\.exe(?=[\s"\'|\\/,;)\]]|$)', re.I)

# SQL: rows that carry a marker string are ours regardless of time (no backslashes needed)
SQL_OWN_MARKERS = "(%s ILIKE '%%%%DFIRTriage_%%%%' OR %s ILIKE '%%%%DFIR_Triage%%%%' OR %s ILIKE '%%%%vao_collector%%%%' OR %s ILIKE '%%%%vao_triage%%%%' OR %s ILIKE '%%%%dfp_%%%%.ps1%%%%')"


def sql_not_own(col):
    """WHERE-fragment: `col` does not carry one of our marker strings. Use as
    `AND analysis.own_footprint.sql_not_own("coalesce(command_line,'')")`."""
    return 'NOT ' + SQL_OWN_MARKERS % ((col,) * 5)


_started_cache = {}


def own_started_at(case_key, conn=None):
    """When our collector first ran on this machine (first vao_collector* execution), or None.
    Cached per process; a case without a collector run (RAM-only, old archive) yields None."""
    if case_key in _started_cache:
        return _started_cache[case_key]
    ts = None
    # v4.5+ states it outright. This exists because a machine with Prefetch switched off
    # leaves no vao_collector execution artefact for the hunt below to find.
    try:
        from analysis.collector_self import declared_started_at
        ts = declared_started_at(case_key, conn)
    except Exception:
        ts = None
    if ts is not None:
        _started_cache[case_key] = ts
        return ts
    if psycopg2 is not None and case_key:
        own = conn is None
        try:
            c = conn or psycopg2.connect(PG_DSN)
            try:
                cur = c.cursor()
                cur.execute("""SELECT min(event_ts) FROM program_exec_v2 WHERE case_key=%s
                               AND (lower(coalesce(executable_name,'')) LIKE '%%vao_collector%%'
                                    OR lower(coalesce(full_path,'')) LIKE '%%vao_collector%%')""", (case_key,))
                r = cur.fetchone()
                ts = r[0] if r else None
                if ts is None:
                    cur.execute("""SELECT min(event_ts) FROM event_logs_v2 WHERE case_key=%s
                                   AND lower(coalesce(process_name,'') || ' ' || coalesce(command_line,'')) LIKE '%%vao_collector%%'""", (case_key,))
                    r = cur.fetchone()
                    ts = r[0] if r else None
            finally:
                if own:
                    c.close()
        except Exception:
            ts = None
    _started_cache[case_key] = ts
    return ts


# The earlier collector generations and the examiner's imaging tools (manual KAPE, v3,
# DumpIt, MagnetRAMCapture, FTK Imager / AccessData driver). Their first run marks the
# start of the response on the box; nothing after it is the attacker (FIX_QUEUE №10).
_COLLECT_TOOL_RX = ('vao_collector|dfir_collector|dumpit|magnetram|winpmem|ftk imager|ftk_imager|'
                    'accessdata|kape_triage|kape[.]exe|gkape')
_collect_cache = {}


def collect_started_at(case_key, conn=None):
    """When the collection/response started on this machine: own_started_at() when our
    collector ran, else the first run of an imaging/triage tool (dfir_collector, DumpIt,
    MagnetRAM, WinPmem, FTK Imager, KAPE) or the 7045 install of the AccessData/MagnetRAM
    driver - but only inside the last 3 days of the case's newest event, so an FTK Imager
    that ran years earlier does not cut a case in half. None when nothing marks it."""
    if case_key in _collect_cache:
        return _collect_cache[case_key]
    ts = own_started_at(case_key, conn)
    if ts is None and psycopg2 is not None and case_key:
        own = conn is None
        try:
            c = conn or psycopg2.connect(PG_DSN)
            try:
                cur = c.cursor()
                cur.execute("""SELECT least(
                    (SELECT min(event_ts) FROM program_exec_v2 p WHERE p.case_key=%s
                       AND lower(coalesce(p.executable_name,'')||' '||coalesce(p.full_path,'')) ~ %s
                       AND p.event_ts >= (SELECT max(event_ts) - interval '3 days' FROM event_logs_v2 WHERE case_key=%s)),
                    (SELECT min(event_ts) FROM event_logs_v2 e WHERE e.case_key=%s AND e.event_id=7045
                       AND e.payload::text ~* 'accessdata driver|magnetramcapture|winpmem|dumpit'
                       AND e.event_ts >= (SELECT max(event_ts) - interval '3 days' FROM event_logs_v2 WHERE case_key=%s)))""",
                            (case_key, _COLLECT_TOOL_RX, case_key, case_key, case_key))
                r = cur.fetchone()
                ts = r[0] if r else None
            finally:
                if own:
                    c.close()
        except Exception:
            try:
                (conn or c).rollback()
            except Exception:
                pass
            ts = None
    _collect_cache[case_key] = ts
    return ts


_finished_cache = {}
_OWN_END_RX = r'dfirtriage_|vao_collector|vao_triage|vao_collect_all|_collector_self[.]txt|dfir_triage'
OWN_WINDOW_DELTA = timedelta(minutes=2)
# a full path to a common tool (drive letter or a system/user root before the tool name)
_EXT_PATH_RX = re.compile(r'([a-z]:\\|\\device\\harddiskvolume\d+\\|\\users\\|\\windows\\|'
                          r'\\program files|\\programdata\\|\\temp\\|\\appdata\\)[^"|]*?(' + _TOOL_STEMS + r')(\.exe)?\b', re.I)


def own_finished_at(case_key, conn=None):
    """t1 - when our collector last left a record on this machine: the newest row carrying one of
    our marker strings (staging folder, collector executable, declaration file); without such rows,
    the moment the event logs were exported (the newest event of the case), after which the
    collector could not leave anything that ended up in the archive. None if unknown."""
    if case_key in _finished_cache:
        return _finished_cache[case_key]
    res = None
    own = conn is None
    try:
        if own:
            if psycopg2 is None or not PG_DSN:
                return None
            conn = psycopg2.connect(PG_DSN)
        with conn.cursor() as cur:
            cur.execute("""SELECT greatest(
                             (SELECT max(event_ts) FROM program_exec_v2 WHERE case_key=%s
                                AND lower(coalesce(full_path, executable_name, '')) ~ %s),
                             (SELECT max(event_ts) FROM filesystem_v2 WHERE case_key=%s
                                AND lower(coalesce(parent_path, '') || '/' || coalesce(file_name, '')) ~ %s))""",
                        (case_key, _OWN_END_RX, case_key, _OWN_END_RX))
            r = cur.fetchone()
            res = r[0] if r else None
            if res is None:
                cur.execute("SELECT max(event_ts) FROM event_logs_v2 WHERE case_key=%s", (case_key,))
                r = cur.fetchone()
                res = r[0] if r else None
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        res = None
    finally:
        if own and conn is not None:
            try:
                conn.close()
            except Exception:
                pass
    _finished_cache[case_key] = res
    return res


def is_own(text, ts=None, case_key=None, conn=None, declared=None):
    """True when `text` (a path, file name, command line, task name...) is the pipeline's
    own footprint. `ts` (event time) and `case_key` enable the time rule for OWN_TOOLS;
    `declared` is the set from collector_self.declared_self_paths when the caller has it."""
    s = (text or '')
    if not s:
        return False
    low = s.replace('/', chr(92)).lower()
    if _RULE_FILE_RX.search(low):
        return True
    for m in OWN_MARKERS:
        if m == 'dfp_':
            if _DFP_RX.search(low):
                return True
            continue
        if m in low:
            return True
    if declared:
        for d in declared:
            if d and d in low:
                return True
    if _TOOLS_RX.search(low):
        # Pext(x): a full path to the tool outside our staging folder (that folder is a marker and
        # was accepted above) - an attacker's or a vendor's copy, i.e. evidence
        if _EXT_PATH_RX.search(low):
            return False
        if ts is not None and case_key:
            start = own_started_at(case_key, conn)
            if start is not None:
                try:
                    t = ts if isinstance(ts, datetime) else datetime.fromisoformat(str(ts)[:19])
                    if t.tzinfo is None and start.tzinfo is not None:
                        t = t.replace(tzinfo=start.tzinfo)
                    end = own_finished_at(case_key, conn) or start
                    if end < start:
                        end = start
                    if end.tzinfo is None and start.tzinfo is not None:
                        end = end.replace(tzinfo=start.tzinfo)
                    # I(x) ∧ t0 - Δ <= t(x) <= t1 + Δ
                    if start - OWN_WINDOW_DELTA <= t <= end + OWN_WINDOW_DELTA:
                        return True
                except Exception:
                    pass
    return False


def strip_own_lines(text, case_key=None, conn=None):
    """Drop the lines of a tool's text output that describe our own footprint.

    The agent tools return plain text to the model; one choke point in the dispatcher is
    cheaper and safer than touching sixty query functions. Header lines (=== ... ===) and
    lines without a marker pass through untouched. A line carrying an ISO-ish timestamp is
    judged with that time, so KAPE.EXE after the collector started is ours and KAPE.EXE a
    week earlier is not."""
    if not text or not isinstance(text, str):
        return text
    out = []
    dropped = 0
    for line in text.split('\n'):
        ts = None
        m = _TS_RX.search(line)
        if m:
            ts = m.group(0).replace('T', ' ')
        if is_own(line, ts=ts, case_key=case_key, conn=conn):
            dropped += 1
            continue
        out.append(line)
    if dropped:
        out.append('(вилучено %d рядк(ів) власного сліду збирача — vao_collector/DFIRTriage/dfp_ — це не активність атакувальника)' % dropped)
    return '\n'.join(out)


_TS_RX = re.compile(r'20\d\d-\d\d-\d\d[ T]\d\d:\d\d(:\d\d)?')


def filter_rows(rows, text_at, ts_at=None, case_key=None, conn=None):
    """Drop our own rows from a result set. `text_at` / `ts_at` are indices or callables."""
    out = []
    for r in rows or []:
        txt = text_at(r) if callable(text_at) else (r[text_at] if r is not None else '')
        ts = None
        if ts_at is not None:
            ts = ts_at(r) if callable(ts_at) else r[ts_at]
        if not is_own(txt, ts=ts, case_key=case_key, conn=conn):
            out.append(r)
    return out
