"""Case assembler functions — SQL-driven evidence gathering and report assembly.
Extracted from app.py. Do not call app.py functions from here (circular import).
"""
import json, math, os, re, time, hashlib, urllib.request, urllib.error, logging
import psycopg2
from datetime import datetime, timezone, timedelta
from core.config import PG_DSN, LLM_URL, LLM_MODEL, LLM_FAST_MODEL, TRIAGE_SLICE_CHARS, LLM_JSON_TEMPERATURE
from core.db import q, table_exists, _parse_ts
from core.model_router import build_chat_payload

_log = logging.getLogger('app')

def _ensure_event_identity_view():
    sql = """
    DROP VIEW IF EXISTS public.event_identity_v1;
    CREATE VIEW public.event_identity_v1 AS
    SELECT
      e.row_id,
      e.case_key,
      e.event_id,
      e.event_ts,
      COALESCE(
        e.event_ts,
        NULLIF((regexp_match(e.payload::text, '(?i)"timestamp"\\s*:\\s*"([0-9T:\\.-]+(?:Z|[+\\-][0-9:]+))"'))[1],'')::timestamptz
      ) AS event_ts_norm,
      e.channel,
      e.provider,
      e.computer,
      e.source_file,
      e.remote_host,
      e.target_user,
      e.logon_type,
      e.process_name,
      e.command_line,
      e.payload,
      COALESCE(
        NULLIF((regexp_match(e.payload::text, '(?i)"@Name":"TargetUserName"[^#]{0,80}"#text":"([^"]+)"'))[1],''),
        NULLIF((regexp_match(e.payload::text, '(?i)TargetUserName[^A-Za-z0-9]{0,40}([A-Za-z0-9_\\.-]+)'))[1],''),
        NULLIF((regexp_match(e.payload::text, '(?i)"User"\\s*:\\s*"([^"]+)"'))[1],''),
        NULLIF(e.target_user,'')
      ) AS target_user_name,
      COALESCE(
        NULLIF((regexp_match(e.payload::text, '(?i)"@Name":"SubjectUserName"[^#]{0,80}"#text":"([^"]+)"'))[1],''),
        NULLIF((regexp_match(e.payload::text, '(?i)SubjectUserName[^A-Za-z0-9]{0,40}([A-Za-z0-9_\\.-]+)'))[1],'')
      ) AS subject_user_name,
      COALESCE(
        NULLIF((regexp_match(e.payload::text, '(?i)"@Name":"MemberName"[^#]{0,80}"#text":"([^"]+)"'))[1],''),
        NULLIF((regexp_match(e.payload::text, '(?i)MemberName[^A-Za-z0-9]{0,40}([A-Za-z0-9_\\.-]+)'))[1],'')
      ) AS member_name,
      COALESCE(
        NULLIF((regexp_match(e.payload::text, '(?i)"@Name":"TargetUserName"[^#]{0,80}"#text":"([^"]+)"'))[1],''),
        NULLIF((regexp_match(e.payload::text, '(?i)"User"\\s*:\\s*"([^"]+)"'))[1],''),
        NULLIF(e.remote_host,'')
      ) AS group_name,
      COALESCE(
        NULLIF((regexp_match(e.payload::text, '((?:\\d{1,3}\\.){3}\\d{1,3})'))[1],''),
        NULLIF((regexp_match(e.remote_host, '((?:\\d{1,3}\\.){3}\\d{1,3})'))[1],'')
      ) AS ip_address,
      COALESCE(
        NULLIF((regexp_match(e.payload::text, '(?i)"@Name":"WorkstationName"[^#]{0,80}"#text":"([^"]+)"'))[1],''),
        NULLIF((regexp_match(e.payload::text, '(?i)WorkstationName[^A-Za-z0-9]{0,40}([A-Za-z0-9_\\.-]+)'))[1],'')
      ) AS workstation_name,
      COALESCE(
        NULLIF((regexp_match(e.payload::text, '(?i)SessionGuid[^A-Za-z0-9]{0,20}([A-Za-z0-9\\{}-]+)'))[1],''),
        NULLIF((regexp_match(e.payload::text, '(?i)LogonGuid[^A-Za-z0-9]{0,20}([A-Za-z0-9\\{}-]+)'))[1],'')
      ) AS session_hint,
      COALESCE(
        NULLIF((regexp_match(e.payload::text, '(?i)"@Name":"TargetSid"[^#]{0,80}"#text":"(S-[0-9-]+)"'))[1],''),
        NULLIF((regexp_match(e.payload::text, '(?i)"User SID"\\s*:\\s*"(S-[0-9-]+)"'))[1],''),
        NULLIF((regexp_match(e.target_user, '(S-[0-9-]+)'))[1],'')
      ) AS target_sid,
      COALESCE(
        NULLIF((regexp_match(e.payload::text, '(?i)"@Name":"MemberSid"[^#]{0,80}"#text":"(S-[0-9-]+)"'))[1],''),
        NULLIF((regexp_match(e.payload::text, '(?i)"Member SID"\\s*:\\s*"(S-[0-9-]+)"'))[1],'')
      ) AS member_sid,
      COALESCE(
        NULLIF((regexp_match(e.payload::text, '(?i)"@Name":"SubjectUserSid"[^#]{0,80}"#text":"(S-[0-9-]+)"'))[1],''),
        NULLIF((regexp_match(e.payload::text, '(?i)SubjectUserSid[^A-Za-z0-9]{0,40}(S-[0-9-]+)'))[1],'')
      ) AS subject_sid
    FROM public.event_logs_v2 e;
    """
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(sql)
def _table_has_case_data(table_name, case_key):
    if not table_exists(table_name):
        return False
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(f"SELECT EXISTS(SELECT 1 FROM {table_name} WHERE case_key=%s LIMIT 1)", (case_key,))
                return bool(cur.fetchone()[0])
    except Exception:
        return False


def _run_coverage(case_key):
    required = ['event_logs_v2', 'program_exec_v2', 'filesystem_v2', 'tool_alerts_v2', 'raw_fallback_v2']
    available = []
    missing = []
    for t in required:
        if _table_has_case_data(t, case_key):
            available.append(t)
        else:
            missing.append(t)
    return {
        'available_tables': available,
        'missing_tables': missing,
        'coverage_ratio': round(len(available) / max(1, len(required)), 3),
    }


def _extract_rdp_user_creation_linkage(case_key):
    _ensure_event_identity_view()
    rows = []
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
                SELECT event_id, event_ts_norm, source_file, channel, provider, computer,
                       coalesce(target_user_name,''), coalesce(subject_user_name,''), coalesce(member_name,''),
                       coalesce(group_name,''), coalesce(ip_address,''), coalesce(workstation_name,''),
                       coalesce(remote_host,''), coalesce(logon_type::text,''), coalesce(process_name,''),
                       coalesce(command_line,''), left(coalesce(payload::text,''), 400),
                       coalesce(target_sid,''), coalesce(member_sid,''), coalesce(subject_sid,'')
                FROM public.event_identity_v1
                WHERE case_key=%s
                  AND (
                    event_id IN (4720,4728,4732,4756,4672,4624,4625,1149)
                    OR coalesce(remote_host,'') NOT IN ('', '-', '::1', '127.0.0.1', '0.0.0.0')
                    OR coalesce(ip_address,'') NOT IN ('', '-', '::1', '127.0.0.1', '0.0.0.0', '-:-')
                    OR payload::text ILIKE '%%rdpwrap%%'
                    OR payload::text ILIKE '%%rdpwinst%%'
                    OR source_file ILIKE '%%account_tampering%%'
                    OR source_file ILIKE '%%lateral_movement%%'
                    OR source_file ILIKE '%%sigma%%'
                    OR (
                      lower(coalesce(channel,'')) LIKE '%%terminalservices%%'
                      OR lower(coalesce(provider,'')) LIKE '%%terminalservices%%'
                      OR lower(coalesce(provider,'')) LIKE '%%localsessionmanager%%'
                      OR lower(coalesce(provider,'')) LIKE '%%remoteconnectionmanager%%'
                    )
                  )
                ORDER BY
                  CASE WHEN event_id IN (4720,4728,4732,4756,4672,4624,4625,1149) THEN 0 ELSE 1 END,
                  event_ts_norm NULLS LAST
                LIMIT 12000
            """, (case_key,))
            rows = cur.fetchall()

    GROUP_OR_PRIV_IDS = (4728, 4732, 4756, 4672)
    LOGON_IDS = (4624, 4625, 1149)
    # Windows built-in and parser-placeholder principals: keying the chain on one of
    # these names would tie it to every workstation instead of to this case.
    GENERIC_ACCOUNT_NAMES = {
        'user', 'users', 'admin', 'admins', 'administrator', 'administrators',
        'guest', 'guests', 'system', 'none', 'null', 'defaultaccount',
        'wdagutilityaccount', 'remote', 'subjectusername', 'payloaddata1',
    }

    def _txt(r):
        return ' '.join([str(x or '') for x in [r[6], r[7], r[8], r[9], r[10], r[11], r[12], r[16], r[17], r[18], r[19]]]).lower()

    # The pivot of this chain is whatever account was created inside THIS case:
    # both the SID and the login name are read from the 4720 events themselves.
    created_sids = set()
    created_names = set()
    sid_to_user = {}
    for r in rows:
        if int(r[0] or 0) != 4720:
            continue
        sid = str(r[17] or '').strip().upper()
        uname = str(r[6] or '').strip()
        if sid:
            created_sids.add(sid)
            if uname:
                sid_to_user[sid] = uname
        low = uname.lower()
        if len(low) >= 3 and low not in GENERIC_ACCOUNT_NAMES:
            created_names.add(low)

    def sid_matches_created(r):
        for sid in (str(r[17] or '').upper(), str(r[18] or '').upper(), str(r[19] or '').upper()):
            if sid and sid in created_sids:
                return True
        return False

    def name_matches_created(r):
        if not created_names:
            return False
        txt = _txt(r)
        return any(n in txt for n in created_names)

    def linked_to_created(r):
        return sid_matches_created(r) or name_matches_created(r)

    def has_remote_target(r):
        rhost = str(r[12] or '').strip()
        if rhost and rhost not in ('-', '', '::1', '127.0.0.1', '0.0.0.0'):
            return True
        ip_addr = str(r[10] or '').strip()
        return bool(ip_addr and ip_addr not in ('-', '', '::1', '127.0.0.1', '0.0.0.0', '-:-'))

    def is_security_auth_event(r):
        eid = int(r[0] or 0)
        ch = str(r[3] or '').lower()
        pr = str(r[4] or '').lower()
        sf = str(r[2] or '').lower()
        if eid == 1149:
            return True
        if eid in (4624, 4625, 4672, 4720, 4728, 4732, 4756):
            return ('security' in ch) or ('security-auditing' in pr) or ('lateral_movement' in sf) or ('account_tampering' in sf)
        return False

    def has_rdp_signal(r):
        ch = str(r[3] or '').lower()
        pr = str(r[4] or '').lower()
        sf = str(r[2] or '').lower()
        payload = str(r[16] or '').lower()
        return ('terminalservices' in ch) or ('terminalservices' in pr) or ('localsessionmanager' in pr) or ('remoteconnectionmanager' in pr) or ('lateral_movement' in sf) or ('rdp' in payload)

    user_creation = [r for r in rows if int(r[0] or 0) == 4720]

    privilege = [
        r for r in rows
        if int(r[0] or 0) in GROUP_OR_PRIV_IDS and linked_to_created(r)
    ]

    logons = [
        r for r in rows
        if int(r[0] or 0) in LOGON_IDS
        and is_security_auth_event(r)
        and (linked_to_created(r) or has_remote_target(r))
    ]
    access_ctx = [r for r in rows if has_rdp_signal(r) or has_remote_target(r)]

    # subchains
    identity_subchain = bool(user_creation) and bool(privilege)
    access_subchain = bool(logons) and (any(has_remote_target(r) for r in (logons + access_ctx)) or any(linked_to_created(r) for r in logons))

    # temporal coherence: privilege/logon within 72h from creation
    temporal_coherence = False
    if user_creation:
        cts = [r[1] for r in user_creation if r[1] is not None]
        others = [r[1] for r in (privilege + logons + access_ctx) if r[1] is not None]
        if cts and others:
            cmin = min(cts)
            cmax = max(cts)
            for t in others:
                if abs((t - cmin).total_seconds()) <= 72 * 3600 or abs((t - cmax).total_seconds()) <= 72 * 3600:
                    temporal_coherence = True
                    break

    if identity_subchain and access_subchain and temporal_coherence:
        verdict = 'covered'
        confidence = 'high'
    elif identity_subchain and (bool(logons) or bool(access_ctx)):
        verdict = 'partial'
        confidence = 'medium'
    elif bool(user_creation) or bool(privilege) or bool(logons) or bool(access_ctx):
        verdict = 'partial'
        confidence = 'low'
    else:
        verdict = 'missing'
        confidence = 'low'

    missing_joins = []
    if not bool(user_creation):
        missing_joins.append('4720 account creation evidence')
    if not bool(privilege):
        missing_joins.append('4728/4732/4756/4672 group or privilege linkage for the created account')
    if not bool(logons):
        missing_joins.append('4624/4625/1149 security-auth logon linkage')
    if not any(has_remote_target(r) for r in (logons + access_ctx)):
        missing_joins.append('remote host/ip linkage')
    if not temporal_coherence:
        missing_joins.append('temporal coherence between identity and access subchains')

    def to_ev(r, label):
        return {
            'label': label,
            'event_id': int(r[0]) if r[0] is not None else None,
            'event_ts': r[1].isoformat() if r[1] else None,
            'source_table': 'event_logs_v2',
            'source_file': r[2],
            'target_sid': r[17],
            'member_sid': r[18],
            'subject_sid': r[19],
            'evidence_text': f"channel={r[3]} provider={r[4]} computer={r[5]} target_user={r[6]} subject_user={r[7]} member={r[8]} group={r[9]} ip={r[10]} workstation={r[11]} remote_host={r[12]} sid_target={r[17]} sid_member={r[18]} sid_subject={r[19]}"[:360]
        }

    # Which single row represents each stage in the report: when the case has a
    # creation event, the row closest to it tells the chain, while the earliest row
    # in the table may sit weeks away from it and only look like context.
    _anchor_list = [r[1] for r in user_creation if r[1] is not None]
    _anchor = min(_anchor_list) if _anchor_list else None

    def pick(cands, group_first=False):
        if not cands:
            return None
        if _anchor is None:
            return cands[0]

        def key(r):
            rank = 0 if (group_first and int(r[0] or 0) in (4728, 4732, 4756)) else 1
            link = 0 if linked_to_created(r) else 1
            gap = abs((r[1] - _anchor).total_seconds()) if r[1] is not None else 10 ** 9
            return (rank, link, gap)

        return sorted(cands, key=key)[0]

    strongest = []
    if user_creation:
        strongest.append(to_ev(user_creation[0], 'user_creation_event'))
    if privilege:
        strongest.append(to_ev(pick(privilege, group_first=True), 'privilege_assignment_event'))
    if logons:
        strongest.append(to_ev(pick(logons), 'remote_logon_event'))
    if access_ctx:
        strongest.append(to_ev(pick(access_ctx), 'rdp_context_event'))

    return {
        'indicator': 'rdp_user_creation_linkage',
        'verdict': verdict,
        'confidence': confidence,
        'identity_subchain': identity_subchain,
        'access_subchain': access_subchain,
        'temporal_coherence': temporal_coherence,
        'sid_to_user_map_size': len(sid_to_user),
        'missing_joins': missing_joins,
        'strongest_evidence': strongest[:8],
        'counts': {
            'user_creation_rows': len(user_creation),
            'privilege_rows': len(privilege),
            'logon_rows': len(logons),
            'rdp_context_rows': len(access_ctx)
        }
    }





# Script-type artefacts are the point of the script-host finding, and every case has its
# own. Until 2026-08-20 the list below was four filenames from a single 2026 case: on the
# other eleven the finding could only ever return "missing", and its missing_proof line
# printed those foreign filenames into the report of a case that had never seen them.
# Measured before the change: of twelve production cases, three hold a script-type
# artefact at all, and no two of them hold the same one.
_SCRIPT_EXT_RE = re.compile('[.](vbs|vbe|js|jse|wsf|wsh|bat|cmd|ps1|psm1|hta)$', re.I)


def _script_host_targets(case_key, limit=12):
    """Artefacts of THIS case worth testing for script-host execution.

    Three sources, all case-scoped: what actually ran (program_exec_v2), what a tool
    flagged (tool_alerts_v2), and the case's own indicators (case_iocs). An indicator is
    only a candidate - the tier system below still decides whether anything executed it.
    """
    names = {}

    def _add(raw):
        n = (raw or '').strip().strip('"').strip("'").lower()
        n = n.split(chr(92))[-1].split(chr(47))[-1].strip()
        if not n or len(n) > 64 or '.' not in n:
            return
        if n.startswith('.') or ' ' in n[:1]:
            return
        names[n] = names.get(n, 0) + 1

    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                if table_exists('program_exec_v2'):
                    cur.execute("SELECT DISTINCT lower(executable_name) FROM program_exec_v2 "
                                "WHERE case_key=%s AND executable_name ~* %s LIMIT 40",
                                (case_key, _SCRIPT_EXT_RE.pattern))
                    for (n,) in cur.fetchall():
                        _add(n)
                if table_exists('tool_alerts_v2'):
                    cur.execute("SELECT DISTINCT lower(ioc_value) FROM tool_alerts_v2 "
                                "WHERE case_key=%s AND ioc_value ~* %s LIMIT 40",
                                (case_key, _SCRIPT_EXT_RE.pattern))
                    for (n,) in cur.fetchall():
                        _add(n)
                if table_exists('case_iocs'):
                    cur.execute("SELECT DISTINCT lower(ioc_value) FROM case_iocs "
                                "WHERE case_key=%s AND ioc_type ILIKE %s LIMIT 40",
                                (case_key, '%file%'))
                    for (n,) in cur.fetchall():
                        _add(n)
    except Exception as _e:
        # NAMED on purpose: an empty target list makes the whole finding say "nothing to
        # test", which is indistinguishable from a clean case. If the discovery itself
        # broke, the log has to say so.
        _log.error("[script_host] target discovery failed for %s: %s"
                   % (case_key, repr(_e)[:160]))
        return []

    # A script-type artefact is what this finding is about; anything else is a payload
    # candidate and rides along only if there is room.
    scripts = sorted(n for n in names if _SCRIPT_EXT_RE.search(n))
    others = sorted((n for n in names if n not in scripts), key=lambda n: (-names[n], n))
    return (scripts + others)[:limit]


def _extract_script_host_execution_linkage(case_key):
    targets = _script_host_targets(case_key)
    if not targets:
        # Nothing script-shaped in this case. Say that, instead of reporting a failure
        # to prove execution of files the case never contained.
        return {
            'indicator': 'script_host_execution_linkage',
            'verdict': 'missing', 'confidence': 'low',
            'artifact_tiers': {}, 'artifacts': {}, 'strongest_evidence': [],
            'missing_proof': ['No script-type artifact (vbs/js/bat/cmd/ps1/hta) was found '
                              'in this case, so script-host execution has nothing to test'],
        }
    host_terms = ['wscript.exe', 'cscript.exe', 'cmd.exe', 'powershell.exe', 'pwsh.exe', 'rundll32.exe', 'explorer.exe']

    result = {k: {'artifact': k, 'tier': 'missing', 'direct_rows': [], 'near_rows': [], 'file_rows': [], 'tool_rows': []} for k in targets}

    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            for art in targets:
                patt = f'%{art.lower()}%'

                if table_exists('event_logs_v2'):
                    cur.execute("""
                        SELECT event_ts, source_file, coalesce(process_name,''), coalesce(command_line,''), left(coalesce(payload::text,''), 240)
                        FROM event_logs_v2
                        WHERE case_key=%s AND (
                          lower(coalesce(command_line,'')) LIKE %s OR
                          lower(coalesce(process_name,'')) LIKE %s OR
                          lower(coalesce(payload::text,'')) LIKE %s
                        )
                        ORDER BY event_ts DESC NULLS LAST
                        LIMIT 80
                    """, (case_key, patt, patt, patt))
                    for ts, sf, pn, cl, pl in cur.fetchall():
                        evtxt = f'pn={pn} cl={cl} payload={pl}'
                        result[art]['direct_rows'].append({
                            'event_ts': ts.isoformat() if ts else None,
                            'source_table': 'event_logs_v2',
                            'source_file': sf,
                            'evidence_text': evtxt[:320]
                        })

                if table_exists('program_exec_v2'):
                    cur.execute("""
                        SELECT event_ts, source_file, coalesce(executable_name,''), coalesce(full_path,''), left(coalesce(payload::text,''), 200)
                        FROM program_exec_v2
                        WHERE case_key=%s AND (
                          lower(coalesce(executable_name,'')) LIKE %s OR
                          lower(coalesce(full_path,'')) LIKE %s OR
                          lower(coalesce(payload::text,'')) LIKE %s
                        )
                        ORDER BY event_ts DESC NULLS LAST
                        LIMIT 40
                    """, (case_key, patt, patt, patt))
                    for ts, sf, exe, fp, pl in cur.fetchall():
                        result[art]['direct_rows'].append({
                            'event_ts': ts.isoformat() if ts else None,
                            'source_table': 'program_exec_v2',
                            'source_file': sf,
                            'evidence_text': f'exe={exe} full_path={fp} payload={pl}'[:320]
                        })

                if table_exists('filesystem_v2'):
                    cur.execute("""
                        SELECT event_ts, source_file, coalesce(file_name,''), coalesce(parent_path,'')
                        FROM filesystem_v2
                        WHERE case_key=%s AND lower(coalesce(file_name,''))=%s
                        ORDER BY event_ts DESC NULLS LAST
                        LIMIT 40
                    """, (case_key, art.lower()))
                    for ts, sf, fn, pp in cur.fetchall():
                        result[art]['file_rows'].append({
                            'event_ts': ts.isoformat() if ts else None,
                            'source_table': 'filesystem_v2',
                            'source_file': sf,
                            'evidence_text': f'file={fn} path={pp}'[:260]
                        })

                if table_exists('tool_alerts_v2'):
                    cur.execute("""
                        SELECT event_ts, source_file, coalesce(tool,''), coalesce(rule,''), coalesce(ioc_value,''), left(coalesce(details,''),180)
                        FROM tool_alerts_v2
                        WHERE case_key=%s AND (
                          lower(coalesce(rule,'')) LIKE %s OR
                          lower(coalesce(ioc_value,'')) LIKE %s OR
                          lower(coalesce(details,'')) LIKE %s
                        )
                        ORDER BY event_ts DESC NULLS LAST
                        LIMIT 60
                    """, (case_key, patt, patt, patt))
                    for ts, sf, tool, rule, ioc, det in cur.fetchall():
                        result[art]['tool_rows'].append({
                            'event_ts': ts.isoformat() if ts else None,
                            'source_table': 'tool_alerts_v2',
                            'source_file': sf,
                            'evidence_text': f'tool={tool} rule={rule} ioc={ioc} details={det}'[:320]
                        })

            # near-time staged execution context from host-processes + suspicious chain terms
            host_like = '%' + '%|%'.join(host_terms) + '%'
            cur.execute("""
                SELECT event_ts, source_file, coalesce(process_name,''), coalesce(command_line,''), left(coalesce(payload::text,''),220)
                FROM event_logs_v2
                WHERE case_key=%s AND (
                  lower(coalesce(process_name,'')) ~ '(wscript|cscript|cmd|powershell|pwsh|rundll32|explorer)' OR
                  lower(coalesce(command_line,'')) ~ '(wscript|cscript|cmd|powershell|pwsh|rundll32|explorer)'
                )
                ORDER BY event_ts DESC NULLS LAST
                LIMIT 600
            """, (case_key,))
            host_rows = cur.fetchall()

    for art in targets:
        art_l = art.lower()
        # Near-time corroboration means ANOTHER artefact of this case turning up beside
        # a script host. The old list named a different case, so on this one it added
        # nothing and on that one it corroborated by coincidence.
        suspicious_terms = ([art_l, 'appdata' + chr(92) + 'roaming']
                            + [t for t in targets if t != art])
        for ts, sf, pn, cl, pl in host_rows:
            blob = ' '.join([str(pn or ''), str(cl or ''), str(pl or '')]).lower()
            if art_l in blob:
                continue
            if any(t in blob for t in suspicious_terms):
                result[art]['near_rows'].append({
                    'event_ts': ts.isoformat() if ts else None,
                    'source_table': 'event_logs_v2',
                    'source_file': sf,
                    'evidence_text': f'pn={pn} cl={cl} payload={pl}'[:320]
                })

        direct = len(result[art]['direct_rows']) > 0
        near = len(result[art]['near_rows']) > 0 and (len(result[art]['tool_rows']) > 0 or len(result[art]['file_rows']) > 0)
        weak = len(result[art]['file_rows']) > 0 or len(result[art]['tool_rows']) > 0
        if direct:
            tier = 'direct_execution_proof'
        elif near:
            tier = 'near_time_corroboration'
        elif weak:
            tier = 'file_presence_only'
        else:
            tier = 'missing'
        result[art]['tier'] = tier

        # noise control ranking
        def _score(ev):
            txt = (ev.get('evidence_text') or '').lower()
            score = 0
            if art_l in txt:
                score += 10
            if any(h in txt for h in host_terms):
                score += 3
            if 'appdata' in txt or 'roaming' in txt:
                score += 2
            if any(t in txt for t in targets if t != art):
                score += 2
            if ev.get('event_ts'):
                score += 1
            return score
        for k in ['direct_rows', 'near_rows', 'file_rows', 'tool_rows']:
            uniq = []
            seen = set()
            for e in result[art][k]:
                key = (e.get('event_ts'), e.get('source_file'), e.get('evidence_text'))
                if key in seen:
                    continue
                seen.add(key)
                uniq.append(e)
            uniq.sort(key=_score, reverse=True)
            result[art][k] = uniq[:8]

    # final verdict policy
    # 'covered' means a SCRIPT was proven to run - a payload executable alone is a
    # weaker claim, and which script it is depends on the case, not on this file.
    _script_targets = [a for a in targets if _SCRIPT_EXT_RE.search(a)]
    key_direct = any(result[a]['tier'] == 'direct_execution_proof' for a in _script_targets)
    # The verdict is about SCRIPTS. A payload executable with execution proof belongs to
    # the execution findings; counting it here reported script-host activity on cases that
    # held no script at all - measured 2026-08-20: four of fourteen cases said 'partial'
    # purely on a remote-admin binary. Payload artefacts stay in the result as context.
    any_direct = any(result[a]['tier'] == 'direct_execution_proof' for a in _script_targets)
    any_near = any(result[a]['tier'] == 'near_time_corroboration' for a in _script_targets)

    if key_direct:
        verdict = 'covered'
        confidence = 'high'
    elif any_direct or any_near:
        verdict = 'partial'
        confidence = 'medium' if any_direct else 'low'
    else:
        verdict = 'missing'
        confidence = 'low'

    missing_proof = []
    if not key_direct:
        missing_proof.append(
            'No direct native execution proof for the script-type artifacts of this case'
            + (' (' + ', '.join(_script_targets[:4]) + ')' if _script_targets
               else ' - none were found'))

    strongest = []
    for art in targets:
        tier = result[art]['tier']
        if tier == 'direct_execution_proof' and result[art]['direct_rows']:
            strongest.append({'artifact': art, 'tier': tier, **result[art]['direct_rows'][0]})
        elif tier == 'near_time_corroboration' and result[art]['near_rows']:
            strongest.append({'artifact': art, 'tier': tier, **result[art]['near_rows'][0]})
        elif tier == 'file_presence_only' and result[art]['file_rows']:
            strongest.append({'artifact': art, 'tier': tier, **result[art]['file_rows'][0]})

    return {
        'indicator': 'script_host_execution_linkage',
        'verdict': verdict,
        'confidence': confidence,
        'artifact_tiers': {k: {'tier': v['tier'], 'direct_count': len(v['direct_rows']), 'near_count': len(v['near_rows']), 'file_count': len(v['file_rows']), 'tool_count': len(v['tool_rows'])} for k, v in result.items()},
        'artifacts': result,
        'strongest_evidence': strongest[:8],
        'missing_proof': missing_proof,
    }



def _ensure_browser_provenance_view():
    sql = """
    DROP VIEW IF EXISTS public.browser_provenance_v1;
    CREATE VIEW public.browser_provenance_v1 AS
    WITH fs AS (
      SELECT
        f.case_key,
        f.event_ts,
        CASE
          WHEN lower(coalesce(f.parent_path,'')) LIKE '%edge%' THEN 'edge'
          WHEN lower(coalesce(f.parent_path,'')) LIKE '%chrome%' THEN 'chrome'
          WHEN lower(coalesce(f.parent_path,'')) LIKE '%internet explorer%' THEN 'ie'
          ELSE NULL
        END AS browser,
        NULL::text AS profile_name,
        NULL::text AS user_name,
        CASE
          WHEN lower(coalesce(f.parent_path,'')) LIKE 'internet explorer (homepage)/http%' THEN split_part(f.parent_path, 'Internet Explorer (Homepage)/', 2)
          ELSE NULL
        END AS url,
        NULL::text AS domain,
        NULL::text AS remote_ip,
        NULL::text AS referrer_url,
        CASE WHEN lower(coalesce(f.parent_path,'')) LIKE '%downloads%' THEN f.parent_path ELSE NULL END AS download_path,
        CASE WHEN coalesce(f.parent_path,'')<>'' THEN (f.parent_path || '/' || coalesce(f.file_name,'')) ELSE coalesce(f.file_name,'') END AS local_path,
        (regexp_match(f.payload->>'zone_id', 'HostUrl=([^\r\n]+)'))[1]::text AS zone_identifier_host_url,
        (regexp_match(f.payload->>'zone_id', 'ReferrerUrl=([^\r\n]+)'))[1]::text AS zone_identifier_referrer_url,
        f.source_file,
        'filesystem_lnk_or_path'::text AS source_type,
        'filesystem_v2'::text AS source_table,
        NULL::text AS container_path,
        NULL::text AS archive_origin,
        'native'::text AS evidence_kind
      FROM public.filesystem_v2 f
      -- ILIKE on the bare column (not lower(coalesce(...))) so the trigram GIN
      -- indexes idx_fs2_ppath_trgm / idx_fs2_payload_trgm can actually be used.
      -- Same rows: coalesce only mapped NULL to '', which matches nothing anyway.
      WHERE f.parent_path ILIKE '%downloads%'
         OR f.parent_path ILIKE 'internet explorer (homepage)/%'
         OR f.parent_path ILIKE '%edge%'
         OR f.parent_path ILIKE '%chrome%'
         OR (f.payload::text ILIKE '%HostUrl%' AND (f.payload->>'zone_id') ILIKE '%HostUrl%')
    ), ev AS (
      SELECT
        e.case_key,
        e.event_ts,
        CASE
          WHEN lower(coalesce(e.payload::text,'')) LIKE '%edge%' THEN 'edge'
          WHEN lower(coalesce(e.payload::text,'')) LIKE '%chrome%' THEN 'chrome'
          ELSE NULL
        END AS browser,
        NULL::text AS profile_name,
        NULL::text AS user_name,
        (regexp_match(coalesce(e.payload::text,''), '(https?://[^"\\\\s]+)'))[1]::text AS url,
        NULL::text AS domain,
        (regexp_match(coalesce(e.payload::text,''), '((?:\\d{1,3}\\.){3}\\d{1,3})'))[1]::text AS remote_ip,
        NULL::text AS referrer_url,
        NULL::text AS download_path,
        NULL::text AS local_path,
        NULL::text AS zone_identifier_host_url,
        NULL::text AS zone_identifier_referrer_url,
        e.source_file,
        'event_payload_text'::text AS source_type,
        'event_logs_v2'::text AS source_table,
        NULL::text AS container_path,
        NULL::text AS archive_origin,
        'text_fallback'::text AS evidence_kind
      FROM public.event_logs_v2 e
      -- the same alternation spelled as ILIKEs, which the trigram index can serve
      -- (payload is NOT NULL, so the coalesce was a no-op)
      WHERE e.payload::text ILIKE '%http://%'
         OR e.payload::text ILIKE '%https://%'
         OR e.payload::text ILIKE '%download%'
         OR e.payload::text ILIKE '%browser%'
         OR e.payload::text ILIKE '%edge%'
         OR e.payload::text ILIKE '%chrome%'
    )
    SELECT * FROM fs
    UNION ALL
    SELECT * FROM ev;
    """
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(sql)


def _extract_delivery_browser_provenance(case_key):
    _ensure_browser_provenance_view()
    out_rows = []
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
                SELECT case_key, event_ts, coalesce(browser,''), coalesce(profile_name,''), coalesce(user_name,''),
                       coalesce(url,''), coalesce(domain,''), coalesce(remote_ip,''), coalesce(referrer_url,''),
                       coalesce(download_path,''), coalesce(local_path,''),
                       coalesce(zone_identifier_host_url,''), coalesce(zone_identifier_referrer_url,''),
                       coalesce(source_file,''), coalesce(source_type,''), coalesce(source_table,''),
                       coalesce(container_path,''), coalesce(archive_origin,''), coalesce(evidence_kind,'')
                FROM public.browser_provenance_v1
                WHERE case_key=%s
                ORDER BY event_ts DESC NULLS LAST
                LIMIT 5000
            """, (case_key,))
            out_rows = cur.fetchall()

    def row_to_ev(r):
        return {
            'event_ts': r[1].isoformat() if r[1] else None,
            'browser': r[2], 'profile_name': r[3], 'user_name': r[4], 'url': r[5], 'domain': r[6], 'remote_ip': r[7],
            'referrer_url': r[8], 'download_path': r[9], 'local_path': r[10],
            'zone_identifier_host_url': r[11], 'zone_identifier_referrer_url': r[12],
            'source_file': r[13], 'source_type': r[14], 'source_table': r[15],
            'container_path': r[16], 'archive_origin': r[17], 'evidence_kind': r[18],
        }

    rows = [row_to_ev(r) for r in out_rows]

    native_rows = [r for r in rows if r.get('evidence_kind') == 'native']
    fallback_rows = [r for r in rows if r.get('evidence_kind') != 'native']

    # source status details
    source_files_present = len(rows) > 0
    native_useful_rows = [r for r in native_rows if (r.get('url') or r.get('download_path') or r.get('local_path') or r.get('zone_identifier_host_url'))]
    parser_lifted_fields = any(r.get('url') or r.get('download_path') or r.get('local_path') or r.get('zone_identifier_host_url') for r in rows)

    # strict chain requirements
    suspicious_hit = []
    for r in rows:
        blob = ' '.join([str(r.get('url') or ''), str(r.get('domain') or ''), str(r.get('remote_ip') or ''), str(r.get('download_path') or ''), str(r.get('local_path') or ''), str(r.get('zone_identifier_host_url') or ''), str(r.get('zone_identifier_referrer_url') or ''), str(r.get('source_file') or '')]).lower()
        if ('swisstransfer' in blob) or ('185.125.25.84' in blob):
            suspicious_hit.append(r)

    has_native_provenance = any((r.get('url') or r.get('zone_identifier_host_url') or r.get('download_path')) for r in native_rows)

    # linkage to suspicious artifact chain (VBS/EXE execution) OR direct archive/exe download with Zone.Identifier
    artifact_chain = any(any(k in (str(r.get('local_path') or '') + ' ' + str(r.get('download_path') or '')).lower() for k in ['start.vbs','ng.bat','try.exe','msedgex.exe','ngrok','7za']) for r in rows)
    # Zone.Identifier with HostUrl on a suspicious archive IS proof of initial delivery
    zone_delivery = any(r.get('zone_identifier_host_url') and any(ext in str(r.get('local_path') or '').lower() for ext in ['.zip','.rar','.7z','.exe','.msi','.js','.vbs']) for r in suspicious_hit)

    strict_covered = bool(suspicious_hit) and has_native_provenance and (artifact_chain or zone_delivery)

    # taxonomy states
    if not source_files_present:
        taxonomy = 'source_missing'
    elif source_files_present and not parser_lifted_fields:
        taxonomy = 'source_present_but_not_normalized'
    elif parser_lifted_fields and not strict_covered and not suspicious_hit:
        taxonomy = 'normalized_but_no_strict_hit'
    elif strict_covered:
        taxonomy = 'covered'
    else:
        taxonomy = 'partial'

    verdict = 'covered' if taxonomy == 'covered' else ('partial' if taxonomy in ('partial', 'normalized_but_no_strict_hit', 'source_present_but_not_normalized') else 'missing')

    # ranking: native browser > zone/motw > archive/container > text mentions
    def score(ev):
        s = 0
        if ev.get('evidence_kind') == 'native':
            s += 100
        if ev.get('zone_identifier_host_url') or ev.get('zone_identifier_referrer_url'):
            s += 60
        if ev.get('url'):
            s += 40
        if ev.get('archive_origin') or ev.get('container_path'):
            s += 20
        blob = ' '.join([str(ev.get('url') or ''), str(ev.get('download_path') or ''), str(ev.get('local_path') or ''), str(ev.get('source_file') or '')]).lower()
        if 'swisstransfer' in blob or '185.125.25.84' in blob:
            s += 15
        if ev.get('event_ts'):
            s += 5
        return s

    dedup = []
    seen = set()
    for ev in sorted(rows, key=score, reverse=True):
        key = (ev.get('url'), ev.get('domain'), ev.get('remote_ip'), ev.get('download_path'), ev.get('local_path'), ev.get('source_file'), ev.get('evidence_kind'))
        if key in seen:
            continue
        seen.add(key)
        dedup.append(ev)

    strongest = dedup[:8]

    missing = []
    if not has_native_provenance:
        missing.append('native browser provenance found: no')
    else:
        missing.append('native browser provenance found: yes')
    if not any(r.get('zone_identifier_host_url') or r.get('zone_identifier_referrer_url') for r in native_rows):
        missing.append('Zone.Identifier/MotW found: no')
    else:
        missing.append('Zone.Identifier/MotW found: yes')
    if not suspicious_hit:
        missing.append('suspicious url/domain/ip mention found: no')
    else:
        missing.append('suspicious url/domain/ip mention found: yes')
    if not artifact_chain:
        missing.append('download-history linkage to suspicious artifact chain found: no')
    else:
        missing.append('download-history linkage to suspicious artifact chain found: yes')

    # empty-source handling detail
    source_state = {
        'source_file_absent': not source_files_present,
        'source_file_present_but_no_useful_rows': source_files_present and not native_useful_rows and not fallback_rows,
        'source_file_present_but_not_lifted': source_files_present and not parser_lifted_fields,
    }

    return {
        'indicator': 'delivery_browser_provenance',
        'taxonomy_state': taxonomy,
        'verdict': verdict,
        'native_browser_provenance_found': has_native_provenance,
        'zone_identifier_found': any(r.get('zone_identifier_host_url') or r.get('zone_identifier_referrer_url') for r in native_rows),
        'download_history_linkage_found': artifact_chain,
        'suspicious_mention_found': bool(suspicious_hit),
        'strict_covered': strict_covered,
        'source_state': source_state,
        'counts': {
            'total_rows': len(rows),
            'native_rows': len(native_rows),
            'fallback_rows': len(fallback_rows),
            'suspicious_rows': len(suspicious_hit),
        },
        'strongest_evidence': strongest,
        'missing_reason': missing,
        'native_sources_sample': native_rows[:5],
    }

# ── our own collector's payload must never be read as the attacker's toolkit ──
# An indicator search over filesystem_v2 matches three kinds of row that belong to the
# EXAMINER, not to the intruder. On case_23 the
# `mimikatz` search returned 370 rows of which only 22 were real, and `last_seen` in the
# report became 2026-08-13 13:12 — the minute OUR collector ran — instead of the actual
# 2026-08-12 10:31. A 27-hour error in a timestamp that goes into a legal report.
#   1) rule/signature files shipped with hayabusa / chainsaw / sigma / thor / KAPE:
#      a file literally named `*mimikatz*.yml` is a DETECTION RULE, never the tool;
#   2) anything unpacked under the collector's staging folder `DFIRTriage_<hex>`;
#   3) $J journal echoes of (1) and (2): those rows carry NO parent_path at all
#      (290 of the 370 above), so a path filter cannot see them. They are recognised
#      by the same file name also appearing under a DFIRTriage_ parent in the SAME case.
# The staging folder is matched by NON-ALPHANUMERIC boundary, not by a path-separator
# character class: a backslash inside a Postgres bracket expression is an escape, and
# every layer between an editor and the server halves the backslashes on the way in.
# Deliberately NARROW. It never excludes on a path alone — a filter borrowed wholesale
# from another module once hid real malicious drivers in System32. Only signature-shaped
# names and our own staging directory are dropped; a real tool that happens to sit in a
# normal folder is untouched.
_EXAMINER_FS_SQL = """
                      AND lower(coalesce(file_name,'')) !~ '[.](yml|yaml|yms|mkape|tkape)$'
                      AND coalesce(parent_path,'') !~* '(^|[^a-z0-9])dfirtriage_[0-9a-f]{6,}([^a-z0-9]|$)'
                      AND NOT (coalesce(parent_path,'') = '' AND EXISTS (
                            SELECT 1 FROM filesystem_v2 _ex
                            WHERE _ex.case_key = filesystem_v2.case_key
                              AND _ex.file_name = filesystem_v2.file_name
                              AND _ex.parent_path !~ '^$'
                              AND _ex.parent_path ~* '(^|[^a-z0-9])dfirtriage_[0-9a-f]{6,}([^a-z0-9]|$)'))
"""


def _assemble_quality_findings(case_key):
    coverage = _run_coverage(case_key)
    confirmed = {}
    likely = {}
    tool_only = {}
    needs_review = {}

    def _bucket_add(b, indicator, source_table, source_file, event_ts=None, ev=None, native=False, artifact=False, tool=False):
        x = b.setdefault(indicator, {
            'indicator': indicator,
            'sources': set(),
            'source_tables': set(),
            'source_files': set(),
            'event_ts': [],
            'evidence_samples': [],
            'native_time_present': False,
            'artifact_evidence_present': False,
            'tool_evidence_present': False,
            'evidence_count': 0,
        })
        x['sources'].add(source_table)
        x['source_tables'].add(source_table)
        if source_file:
            x['source_files'].add(source_file)
        if event_ts:
            x['event_ts'].append(event_ts)
        if ev:
            x['evidence_samples'].append(str(ev)[:220])
        x['native_time_present'] = x['native_time_present'] or (native and event_ts is not None)
        x['artifact_evidence_present'] = x['artifact_evidence_present'] or artifact
        x['tool_evidence_present'] = x['tool_evidence_present'] or tool
        x['evidence_count'] += 1

    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            # confirmed candidate: ngrok execution footprint
            if table_exists('program_exec_v2'):
                cur.execute("""
                    SELECT event_ts, source_file, coalesce(executable_name,''), coalesce(full_path,'')
                    FROM program_exec_v2
                    WHERE case_key=%s
                      AND (lower(coalesce(executable_name,'')) LIKE %s OR lower(coalesce(full_path,'')) LIKE %s)
                    LIMIT 300
                """, (case_key, '%ngrok%', '%ngrok.exe%'))
                for ts, sf, exe, fp in cur.fetchall():
                    _bucket_add(confirmed, 'ngrok.exe', 'program_exec_v2', sf, ts, f'exe={exe} path={fp}', native=True)

            if table_exists('filesystem_v2'):
                cur.execute("""
                    SELECT event_ts, source_file, coalesce(file_name,''), coalesce(parent_path,'')
                    FROM filesystem_v2
                    WHERE case_key=%s AND lower(coalesce(file_name,''))=%s
                """ + _EXAMINER_FS_SQL + """
                    ORDER BY row_id
                    LIMIT 300
                """, (case_key, 'ngrok.exe'))
                for ts, sf, fn, pp in cur.fetchall():
                    _bucket_add(confirmed, 'ngrok.exe', 'filesystem_v2', sf, ts, f'file={fn} path={pp}', native=True, artifact=True)

            if table_exists('tool_alerts_v2'):
                cur.execute("""
                    SELECT event_ts, source_file, coalesce(tool,''), coalesce(rule,''), coalesce(ioc_value,''), coalesce(details,'')
                    FROM tool_alerts_v2
                    WHERE case_key=%s AND (
                      lower(coalesce(ioc_value,'')) LIKE %s OR
                      lower(coalesce(rule,'')) LIKE %s OR
                      lower(coalesce(details,'')) LIKE %s
                    )
                    LIMIT 300
                """, (case_key, '%ngrok%', '%ngrok%', '%ngrok%'))
                for ts, sf, tool, rule, ioc, det in cur.fetchall():
                    _bucket_add(confirmed, 'ngrok.exe', 'tool_alerts_v2', sf, ts, f'tool={tool} rule={rule} ioc={ioc} details={det}', tool=True)

            # likely indicators
            for ind in ['mimikatz', 'ng.bat', 'start.vbs']:
                patt = f'%{ind}%'
                if table_exists('filesystem_v2'):
                    if ind == 'mimikatz':
                        cur.execute("""
                            SELECT event_ts, source_file, coalesce(file_name,''), coalesce(parent_path,'')
                            FROM filesystem_v2
                            WHERE case_key=%s AND (lower(coalesce(file_name,'')) LIKE %s OR lower(coalesce(parent_path,'')) LIKE %s)
                        """ + _EXAMINER_FS_SQL + """
                            ORDER BY row_id
                            LIMIT 300
                        """, (case_key, '%mimikatz%', '%mimikatz%'))
                    else:
                        cur.execute("""
                            SELECT event_ts, source_file, coalesce(file_name,''), coalesce(parent_path,'')
                            FROM filesystem_v2
                            WHERE case_key=%s AND lower(coalesce(file_name,''))=%s
                        """ + _EXAMINER_FS_SQL + """
                            ORDER BY row_id
                            LIMIT 300
                        """, (case_key, ind))
                    for ts, sf, fn, pp in cur.fetchall():
                        _bucket_add(likely, ind, 'filesystem_v2', sf, ts, f'file={fn} path={pp}', native=True, artifact=True)

                if table_exists('tool_alerts_v2'):
                    cur.execute("""
                        SELECT event_ts, source_file, coalesce(tool,''), coalesce(rule,''), coalesce(ioc_value,''), coalesce(details,'')
                        FROM tool_alerts_v2
                        WHERE case_key=%s AND (
                          lower(coalesce(rule,'')) LIKE %s OR
                          lower(coalesce(ioc_value,'')) LIKE %s OR
                          lower(coalesce(details,'')) LIKE %s
                        )
                        LIMIT 300
                    """, (case_key, patt, patt, patt))
                    for ts, sf, tool, rule, ioc, det in cur.fetchall():
                        _bucket_add(likely, ind, 'tool_alerts_v2', sf, ts, f'tool={tool} rule={rule} ioc={ioc} details={det}', tool=True)

            # simple tool-only / needs-review fallbacks
            if table_exists('tool_alerts_v2'):
                cur.execute("""
                    SELECT source_file, coalesce(tool,''), coalesce(rule,''), coalesce(ioc_value,''), coalesce(details,'')
                    FROM tool_alerts_v2
                    WHERE case_key=%s
                    -- ORDER BY, бо без нього LIMIT віддає довільні рядки і звіт
                    -- відрізняється між прогонами на тих самих даних
                    ORDER BY row_id
                    LIMIT 120
                """, (case_key,))
                for sf, tool, rule, ioc, det in cur.fetchall():
                    txt = ' '.join([tool, rule, ioc, det]).lower()
                    if any(k in txt for k in ['ngrok', 'mimikatz', 'start.vbs', 'ng.bat']):
                        continue
                    _bucket_add(tool_only, 'generic_tool_alert', 'tool_alerts_v2', sf, None, f'{tool}|{rule}|{ioc}')

            if table_exists('raw_fallback_v2'):
                cur.execute("""
                    SELECT source_file, left(payload::text, 200)
                    FROM raw_fallback_v2
                    WHERE case_key=%s
                      AND (payload::text ILIKE %s OR payload::text ILIKE %s OR payload::text ILIKE %s)
                    LIMIT 60
                """, (case_key, '%mimikatz%', '%ng.bat%', '%start.vbs%'))
                for sf, sn in cur.fetchall():
                    _bucket_add(needs_review, 'weak_text_hit', 'raw_fallback_v2', sf, None, sn)

    def _finalize(bucket, status_name):
        arr = []
        for x in bucket.values():
            ts = sorted(x['event_ts'])
            native = bool(x['native_time_present'])
            confidence_note = None
            if status_name == 'confirmed' and not native:
                confidence_note = 'confirmed_by_artifact_or_tool_without_native_time'
            arr.append({
                'indicator': x['indicator'],
                'status': status_name,
                'status_hint': confidence_note,
                'native_time_present': native,
                'artifact_evidence_present': bool(x['artifact_evidence_present']),
                'tool_evidence_present': bool(x['tool_evidence_present']),
                'evidence_count': int(x['evidence_count']),
                'first_seen': ts[0].isoformat() if ts else None,
                'last_seen': ts[-1].isoformat() if ts else None,
                'sources': sorted(x['sources']),
                'source_tables': sorted(x['source_tables']),
                'source_files': sorted(x['source_files'])[:8],
                'evidence_samples': list(dict.fromkeys(x['evidence_samples']))[:4],
                'scope': 'case_scoped_fallback',
            })
        arr.sort(key=lambda i: (-i['evidence_count'], i['indicator']))
        return arr

    out = {
        'confirmed': _finalize(confirmed, 'confirmed'),
        'likely': _finalize(likely, 'corroborated'),
        'tool_only': _finalize(tool_only, 'tool-only'),
        'needs_review': _finalize(needs_review, 'needs review'),
        'coverage': coverage,
    }

    # integrate deterministic RDP/user linkage finding
    try:
        rdp = _extract_rdp_user_creation_linkage(case_key)
        rdp_item = {
            'indicator': 'rdp_user_creation_linkage',
            'status': 'confirmed' if rdp['verdict'] == 'covered' else ('corroborated' if rdp['verdict'] == 'partial' else 'needs review'),
            'status_hint': 'strict_chain' if rdp['verdict'] == 'covered' else ('stronger_partial' if rdp['verdict'] == 'partial' else 'missing_chain'),
            'native_time_present': any(bool((e.get('event_ts') or '').strip()) for e in rdp.get('strongest_evidence', [])),
            'artifact_evidence_present': False,
            'tool_evidence_present': False,
            'evidence_count': int(sum(rdp.get('counts', {}).values())),
            'first_seen': next((e.get('event_ts') for e in rdp.get('strongest_evidence', []) if e.get('event_ts')), None),
            'last_seen': next((e.get('event_ts') for e in reversed(rdp.get('strongest_evidence', [])) if e.get('event_ts')), None),
            'sources': ['event_logs_v2'],
            'source_tables': ['event_logs_v2'],
            'source_files': list(dict.fromkeys([e.get('source_file') for e in rdp.get('strongest_evidence', []) if e.get('source_file')]))[:8],
            'evidence_samples': [
                f"verdict={rdp.get('verdict')} confidence={rdp.get('confidence')}",
                *[e.get('evidence_text', '')[:180] for e in rdp.get('strongest_evidence', [])[:3]],
                *( [f"missing_join: {m}" for m in rdp.get('missing_joins', [])[:2]] )
            ],
            'scope': 'case_scoped_fallback',
            'rdp_linkage': rdp,
        }
        if rdp['verdict'] == 'covered':
            out['confirmed'].append(rdp_item)
        elif rdp['verdict'] == 'partial':
            out['likely'].append(rdp_item)
        else:
            out['needs_review'].append(rdp_item)
    except Exception:
        try: conn.rollback()
        except: pass
        pass

    # integrate deterministic script-host execution linkage finding (Patch 2)
    try:
        sh = _extract_script_host_execution_linkage(case_key)
        sh_item = {
            'indicator': 'script_host_execution_linkage',
            'status': 'confirmed' if sh['verdict'] == 'covered' else ('corroborated' if sh['verdict'] == 'partial' else 'needs review'),
            'status_hint': sh.get('verdict'),
            'native_time_present': any(bool((e.get('event_ts') or '').strip()) for e in sh.get('strongest_evidence', [])),
            'artifact_evidence_present': any(v.get('file_count', 0) > 0 for v in (sh.get('artifact_tiers') or {}).values()),
            'tool_evidence_present': any(v.get('tool_count', 0) > 0 for v in (sh.get('artifact_tiers') or {}).values()),
            'evidence_count': int(sum((v.get('direct_count', 0) + v.get('near_count', 0) + v.get('file_count', 0) + v.get('tool_count', 0)) for v in (sh.get('artifact_tiers') or {}).values())),
            'first_seen': next((e.get('event_ts') for e in sh.get('strongest_evidence', []) if e.get('event_ts')), None),
            'last_seen': next((e.get('event_ts') for e in reversed(sh.get('strongest_evidence', [])) if e.get('event_ts')), None),
            'sources': sorted(list({e.get('source_table') for e in sh.get('strongest_evidence', []) if e.get('source_table')})),
            'source_tables': sorted(list({e.get('source_table') for e in sh.get('strongest_evidence', []) if e.get('source_table')})),
            'source_files': list(dict.fromkeys([e.get('source_file') for e in sh.get('strongest_evidence', []) if e.get('source_file')]))[:8],
            'evidence_samples': [
                f"verdict={sh.get('verdict')} confidence={sh.get('confidence')}",
                *[f"{a}: {d.get('tier')}" for a, d in (sh.get('artifact_tiers') or {}).items()],
                *[e.get('evidence_text', '')[:180] for e in sh.get('strongest_evidence', [])[:2]],
                *[f"missing_proof: {m}" for m in sh.get('missing_proof', [])[:2]],
            ][:8],
            'scope': 'case_scoped_fallback',
            'script_host_linkage': sh,
        }
        if sh['verdict'] == 'covered':
            out['confirmed'].append(sh_item)
        elif sh['verdict'] == 'partial':
            out['likely'].append(sh_item)
        else:
            out['needs_review'].append(sh_item)
    except Exception:
        try: conn.rollback()
        except: pass
        pass

    # integrate delivery/browser provenance taxonomy (Patch 3)
    try:
        dp = _extract_delivery_browser_provenance(case_key)
        dp_item = {
            'indicator': 'delivery_browser_provenance',
            'status': 'confirmed' if dp['verdict'] == 'covered' else ('corroborated' if dp['verdict'] == 'partial' else 'needs review'),
            'status_hint': dp.get('taxonomy_state'),
            'native_time_present': any(bool((e.get('event_ts') or '').strip()) for e in dp.get('strongest_evidence', [])),
            'artifact_evidence_present': bool(dp.get('download_history_linkage_found')),
            'tool_evidence_present': bool(dp.get('suspicious_mention_found') and not dp.get('native_browser_provenance_found')),
            'evidence_count': int(dp.get('counts', {}).get('total_rows', 0)),
            'first_seen': next((e.get('event_ts') for e in dp.get('strongest_evidence', []) if e.get('event_ts')), None),
            'last_seen': next((e.get('event_ts') for e in reversed(dp.get('strongest_evidence', [])) if e.get('event_ts')), None),
            'sources': sorted(list({e.get('source_table') for e in dp.get('strongest_evidence', []) if e.get('source_table')})),
            'source_tables': sorted(list({e.get('source_table') for e in dp.get('strongest_evidence', []) if e.get('source_table')})),
            'source_files': list(dict.fromkeys([e.get('source_file') for e in dp.get('strongest_evidence', []) if e.get('source_file')]))[:8],
            'evidence_samples': [
                f"taxonomy={dp.get('taxonomy_state')} verdict={dp.get('verdict')}",
                f"native browser provenance found: {'yes' if dp.get('native_browser_provenance_found') else 'no'}",
                f"Zone.Identifier found: {'yes' if dp.get('zone_identifier_found') else 'no'}",
                f"download-history linkage found: {'yes' if dp.get('download_history_linkage_found') else 'no'}",
                f"suspicious url/domain/ip mention found: {'yes' if dp.get('suspicious_mention_found') else 'no'}",
                *[m for m in dp.get('missing_reason', [])[:3]],
            ][:8],
            'scope': 'case_scoped_fallback',
            'delivery_browser_provenance': dp,
        }
        if dp['verdict'] == 'covered':
            out['confirmed'].append(dp_item)
        elif dp['verdict'] == 'partial':
            out['likely'].append(dp_item)
        else:
            out['needs_review'].append(dp_item)
    except Exception:
        try: conn.rollback()
        except: pass
        pass

    return out


def _assemble_incident_timeline(case_key):
    if not table_exists('event_logs_v2'):
        return {'incident_timeline': [], 'scope': 'case_scoped_fallback'}
    keys = ['ngrok', 'mimikatz', 'sekurlsa', 'lsadump', 'ng.bat', 'start.vbs', 'try.exe', '7za', 'rdpwrap', 'rdpwinst', 'rdpconf', 'rdpcheck', 'add-mppreference', 'exclusionpath', 'tamper', 'defender']

    # incident window
    cond = ' OR '.join(["lower(coalesce(command_line,'')) LIKE %s OR lower(coalesce(process_name,'')) LIKE %s" for _ in keys])
    params = [case_key]
    for k in keys:
        params.extend([f'%{k}%', f'%{k}%'])

    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT min(event_ts), max(event_ts)
                FROM event_logs_v2
                WHERE case_key=%s AND event_ts IS NOT NULL AND ({cond})
            """, tuple(params))
            win = cur.fetchone()
            win_start, win_end = win[0], win[1]

            p2 = [case_key]
            win_sql = ''
            if win_start and win_end:
                win_sql = " AND event_ts BETWEEN %s - interval '6 hours' AND %s + interval '6 hours' "
                p2 += [win_start, win_end]
            cond2 = ' OR '.join(["lower(coalesce(command_line,'')) LIKE %s OR lower(coalesce(process_name,'')) LIKE %s" for _ in keys])
            for k in keys:
                p2.extend([f'%{k}%', f'%{k}%'])
            cur.execute(f"""
                SELECT event_ts, source_file,
                       trim(coalesce(process_name,'') || ' | ' || coalesce(command_line,'')) AS summary
                FROM event_logs_v2
                WHERE case_key=%s AND event_ts IS NOT NULL {win_sql}
                  AND (({cond2}) OR event_id IN (4688,4720,4732,4672,4624,4625))
                ORDER BY event_ts
                LIMIT 500
            """, tuple(p2))
            rows = cur.fetchall()

    out = []
    seen = set()
    indicator_terms = ['ngrok', 'mimikatz', 'sekurlsa', 'lsadump', 'ng.bat', 'start.vbs', 'try.exe', '7za', 'rdpwrap', 'rdpwinst', 'rdpconf', 'rdpcheck']
    attack_terms = ['add-mppreference', 'exclusionpath', 'tamper', 'net user', 'net localgroup administrators']
    for ts, sf, sm in rows:
        sm = (sm or '').strip()
        if sm in ('', '|') or len(sm) < 12:
            continue
        lo = sm.lower()
        has_indicator = any(t in lo for t in indicator_terms)
        has_attack = any(t in lo for t in attack_terms)
        if not (has_indicator or has_attack):
            continue
        # drop generic scriptblock noise; keep only concrete indicator/attack scriptblocks
        if 'scriptblock:' in lo and not any(t in lo for t in ['ngrok', 'mimikatz', 'ng.bat', 'start.vbs', 'try.exe', '7za', 'rdpwrap', 'rdpwinst', 'rdpconf', 'rdpcheck', 'add-mppreference', 'exclusionpath']):
            continue
        if 'potentially malicious pwsh' in lo and not has_indicator:
            continue
        key = (ts.isoformat(), sm)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            'event_ts': ts.isoformat(),
            'source_table': 'event_logs_v2',
            'source_file': sf,
            'summary': sm[:260],
            'time_source': 'native',
            'scope': 'case_scoped_fallback',
        })
        if len(out) >= 120:
            break

    # Product-quality fallback: enrich the chronology with execution/filesystem artifacts
    # when EVTX-only timeline is too short for a client report. These are still real
    # evidence rows (Prefetch/Amcache/MFT), not invented LLM events.
    if len(out) < 35:
        try:
            with psycopg2.connect(PG_DSN) as conn:
                conn.autocommit = True
                with conn.cursor() as cur:
                    if table_exists('program_exec_v2'):
                        cur.execute("""
                            SELECT event_ts, source_file,
                                   trim(coalesce(executable_name,'') || ' @ ' || coalesce(full_path,'')) AS summary
                            FROM program_exec_v2
                            WHERE case_key=%s AND event_ts IS NOT NULL
                              AND (%s::timestamptz IS NULL OR event_ts >= %s::timestamptz - interval '420 days')
                              AND (%s::timestamptz IS NULL OR event_ts <= %s::timestamptz + interval '120 days')
                              AND lower(coalesce(executable_name,'') || ' ' || coalesce(full_path,''))
                                  ~ '(ngrok|try[.]exe|7za|anydesk|teamviewer|wscript|cscript|powershell|regsvr32|rdp|до відома)'
                            ORDER BY event_ts ASC NULLS LAST
                            LIMIT 80
                        """, (case_key, win_start, win_start, win_end, win_end))
                        for ts, sf, sm in cur.fetchall():
                            sm = (sm or '').strip()
                            if not sm or len(sm) < 8:
                                continue
                            key = (ts.isoformat() if hasattr(ts, 'isoformat') else str(ts), 'program_exec_v2', sm)
                            if key in seen:
                                continue
                            seen.add(key)
                            out.append({
                                'event_ts': ts.isoformat() if hasattr(ts, 'isoformat') else str(ts),
                                'source_table': 'program_exec_v2',
                                'source_file': sf,
                                'summary': ('Execution artifact: ' + sm)[:260],
                                'time_source': 'artifact',
                                'scope': 'case_scoped_fallback',
                            })
                            if len(out) >= 35:
                                break
                    if len(out) < 35 and table_exists('filesystem_v2'):
                        cur.execute("""
                            SELECT event_ts, source_file,
                                   trim(coalesce(file_name,'') || ' @ ' || coalesce(parent_path,'')) AS summary
                            FROM filesystem_v2
                            WHERE case_key=%s AND event_ts IS NOT NULL
                              AND (%s::timestamptz IS NULL OR event_ts >= %s::timestamptz - interval '420 days')
                              AND (%s::timestamptz IS NULL OR event_ts <= %s::timestamptz + interval '120 days')
                              AND lower(coalesce(file_name,'') || ' ' || coalesce(parent_path,''))
                                  ~ '(ngrok|try[.]exe|7za|anydesk|teamviewer|start[.]vbs|ng[.]bat|до відома|readme)'
                            ORDER BY event_ts ASC NULLS LAST
                            LIMIT 120
                        """, (case_key, win_start, win_start, win_end, win_end))
                        for ts, sf, sm in cur.fetchall():
                            sm = (sm or '').strip()
                            if not sm or len(sm) < 8:
                                continue
                            key = (ts.isoformat() if hasattr(ts, 'isoformat') else str(ts), 'filesystem_v2', sm)
                            if key in seen:
                                continue
                            seen.add(key)
                            out.append({
                                'event_ts': ts.isoformat() if hasattr(ts, 'isoformat') else str(ts),
                                'source_table': 'filesystem_v2',
                                'source_file': sf,
                                'summary': ('Filesystem artifact: ' + sm)[:260],
                                'time_source': 'artifact',
                                'scope': 'case_scoped_fallback',
                            })
                            if len(out) >= 35:
                                break
        except Exception as e:
            _log.error(f"[incident_timeline] enrichment failed for {case_key}: {e}")
            try: conn.rollback()
            except Exception: pass

    out.sort(key=lambda x: str(x.get('event_ts') or ''))
    return {'incident_timeline': out[:120], 'scope': 'case_scoped_fallback'}


def _assemble_detection_timeline(case_key):
    if not table_exists('tool_alerts_v2'):
        return {'detection_timeline': [], 'scope': 'case_scoped_fallback'}

    include_keys = ['ngrok', 'mimikatz', 'ng.bat', 'start.vbs', 'try.exe', '7za', 'rdpwrap', 'rdpwinst', 'rdpconf', 'rdpcheck']
    noise = ['device conn', 'device connection', 'potentially malicious pwsh', 'powershell suspicious win32_pnpentity']

    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
                SELECT event_ts, source_file, coalesce(tool,''), coalesce(rule,''), coalesce(ioc_value,''), coalesce(details,''), coalesce(severity,'')
                FROM tool_alerts_v2
                WHERE case_key=%s
                ORDER BY event_ts NULLS LAST
                LIMIT 4000
            """, (case_key,))
            rows = cur.fetchall()

    out = []
    seen = set()
    for ts, sf, tool, rule, ioc, det, sev in rows:
        text = ' '.join([tool, rule, ioc, det]).lower()
        if any(n in rule.lower() for n in noise) and not any(k in text for k in include_keys):
            continue
        if not any(k in text for k in include_keys):
            continue
        summary = f"{tool} | {rule} | {ioc or det}".strip()
        key = (ts.isoformat() if ts else None, summary)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            'event_ts': ts.isoformat() if ts else None,
            'source_table': 'tool_alerts_v2',
            'source_file': sf,
            'summary': summary[:300],
            'time_source': 'derived',
            'severity': sev,
            'scope': 'case_scoped_fallback',
        })
        if len(out) >= 120:
            break

    # strict-indicator fallback (keeps timeline non-empty when generic filtering is too aggressive)
    if not out:
        for ts, sf, tool, rule, ioc, det, sev in rows:
            text = ' '.join([tool, rule, ioc, det]).lower()
            if not any(k in text for k in ['ngrok', 'mimikatz', 'ng.bat', 'start.vbs', 'try.exe', '7za', 'rdpwrap', 'rdpwinst', 'rdpconf', 'rdpcheck']):
                continue
            summary = f"{tool} | {rule} | {ioc or det}".strip()
            key = (ts.isoformat() if ts else None, summary)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                'event_ts': ts.isoformat() if ts else None,
                'source_table': 'tool_alerts_v2',
                'source_file': sf,
                'summary': summary[:300],
                'time_source': 'derived',
                'severity': sev,
                'scope': 'case_scoped_fallback',
            })
            if len(out) >= 60:
                break

    return {'detection_timeline': out, 'scope': 'case_scoped_fallback'}


def _assemble_ioc_artifacts(case_key):
    out = []
    seen = set()

    def _score(txt):
        t = str(txt or '').lower()
        s = 0
        if any(k in t for k in ['ransom_extension_mass', 'ransom_note_pattern']): s += 100
        if any(k in t for k in ['event_id=1102', 'event_id=104', 'log_tampering']): s += 60
        if any(k in t for k in ['rdp_external_burst', 'teamviewer', 'anydesk', 'ngrok', '7za']): s += 40
        if any(k in t for k in ['mimikatz', 'start.vbs', 'ng.bat', 'try.exe']): s += 20
        return s

    def _add(src_table, src_file, ioc):
        if not ioc:
            return
        key = (src_table, str(ioc)[:280])
        if key in seen:
            return
        seen.add(key)
        out.append({
            'source_table': src_table,
            'source_file': src_file,
            'ioc': str(ioc)[:320],
            'rank': _score(ioc),
            'scope': 'case_scoped_fallback'
        })

    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            # families as first-class IOC signals
            try:
                trig = _get_trigger_family_snapshot(case_key)
                for f in (trig.get('families') or []):
                    _add(f.get('source_table') or 'case_trigger_hits_v2', f.get('source_ref') or '', f"family={f.get('family')} src={f.get('source_ref')} score={f.get('score')}")
            except Exception:
                try: conn.rollback()
                except: pass
                pass

            if table_exists('filesystem_v2'):
                cur.execute("""
                    SELECT source_file, trim(coalesce(file_name,'') || ' @ ' || coalesce(parent_path,''))
                    FROM filesystem_v2
                    WHERE case_key=%s AND (
                      lower(coalesce(file_name,'')) IN ('ngrok.exe','start.vbs','ng.bat','mimikatz.exe','try.exe','7za.exe')
                      OR lower(coalesce(extension,''))='ngsxtmo7s'
                      OR lower(coalesce(file_name,'')) LIKE '%%readme%%.txt%%'
                      OR lower(coalesce(parent_path,'')) LIKE '%%teamviewer%%'
                    )
                    LIMIT 800
                """, (case_key,))
                for sf, ioc in cur.fetchall():
                    _add('filesystem_v2', sf, ioc)

            if table_exists('program_exec_v2'):
                cur.execute("""
                    SELECT source_file, trim(coalesce(executable_name,'') || ' @ ' || coalesce(full_path,''))
                    FROM program_exec_v2
                    WHERE case_key=%s AND (
                      lower(coalesce(full_path,'')) ~ '(ngrok|mimikatz|teamviewer|anydesk|7za|wscript|cscript|powershell)'
                      OR lower(coalesce(executable_name,'')) ~ '(ngrok|mimikatz|teamviewer|anydesk|7za|wscript|cscript|powershell)'
                    )
                    LIMIT 800
                """, (case_key,))
                for sf, ioc in cur.fetchall():
                    _add('program_exec_v2', sf, ioc)

            if table_exists('tool_alerts_v2'):
                cur.execute("""
                    SELECT source_file, coalesce(ioc_value, rule, details)
                    FROM tool_alerts_v2
                    WHERE case_key=%s AND (
                      lower(coalesce(ioc_value,'')) ~ '(ngrok|mimikatz|teamviewer|anydesk|7za|tamper|defender|1102|event log|rdp)'
                      OR lower(coalesce(rule,'')) ~ '(ngrok|mimikatz|teamviewer|anydesk|7za|tamper|defender|event log|rdp)'
                      OR lower(coalesce(details,'')) ~ '(ngrok|mimikatz|teamviewer|anydesk|7za|tamper|defender|1102|eventlog|rdp)'
                    )
                    -- ORDER BY, бо без нього LIMIT віддає довільні рядки і звіт
                    -- відрізняється між прогонами на тих самих даних
                    ORDER BY row_id
                    LIMIT 800
                """, (case_key,))
                for sf, ioc in cur.fetchall():
                    _add('tool_alerts_v2', sf, ioc)

            # network IOC hints from remote hosts
            if table_exists('event_logs_v2'):
                cur.execute("""
                    -- GROUP BY, not LIMIT: the caller wants the SET of remote IPs, and
                    -- a bare LIMIT 300 over 713 qualifying rows returned a DIFFERENT
                    -- subset on every execution plan (28 / 29 / 30 of the 36 IPs on
                    -- case_23, 8 never reachable at all).
                    -- That is what made the same case produce a different report twice.
                    -- Aggregating returns all 36, deterministically, and reads less data.
                    SELECT min(source_file) AS source_file,
                           split_part(coalesce(remote_host,''),':',1) AS ip
                    FROM event_logs_v2
                    WHERE case_key=%s AND coalesce(remote_host,'') ~ '^[0-9]{1,3}([.][0-9]{1,3}){3}(:[0-9]+)?$'
                    GROUP BY 2
                    ORDER BY 2
                    LIMIT 300
                """, (case_key,))
                for sf, ip in cur.fetchall():
                    if ip:
                        _add('event_logs_v2', sf, f'remote_ip={ip}')

    out.sort(key=lambda x: (-int(x.get('rank') or 0), str(x.get('source_table') or ''), str(x.get('ioc') or '')))
    return {'ioc_artifacts': out[:120], 'scope': 'case_scoped_fallback'}


def _get_trigger_family_snapshot(case_key, trigger_jobs=None):
    _trigger_jobs = trigger_jobs if trigger_jobs is not None else {}
    out = {
        'ready': False,
        'pending': False,
        'families': [],
        'families_map': {},
        'source_mode': 'inline_sql'
    }

    # keep pending status for visibility only (no gating)
    try:
        pend = []
        for jid, st in _trigger_jobs.items():
            if str(st.get('case_key','')) == str(case_key) and st.get('status') in ('queued','running'):
                pend.append((st.get('created_at', 0), jid, st))
        if pend:
            pend.sort(key=lambda x: x[0], reverse=True)
            _, jid, st = pend[0]
            out['pending'] = True
            out['pending_job_id'] = jid
            out['pending_stage'] = st.get('stage')
            out['pending_progress'] = st.get('progress')
    except Exception:
        try: conn.rollback()
        except: pass
        pass

    fam = []
    fmap = {}
    detector_status = {}
    detector_counts = {}
    detector_errors = []

    def _push(key, source_table, source_ref, event_ts, score):
        item = {
            'family': key,
            'trigger': f'__family:{key}',
            'source_table': source_table,
            'source_ref': source_ref,
            'event_ts': event_ts.isoformat() if hasattr(event_ts, 'isoformat') and event_ts else (str(event_ts) if event_ts else None),
            'score': float(score or 0),
            'run_id': None,
        }
        fam.append(item)
        fmap[key] = item

    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            def _guard(name, fn):
                try:
                    fn()
                    detector_status[name] = 'ok'
                except Exception as e:
                    detector_status[name] = 'error'
                    detector_errors.append({'detector': name, 'error': str(e)[:240]})

            def _det_ransom_extension_mass():
                cur.execute("""
                    SELECT count(*)::int, min(event_ts)
                    FROM filesystem_v2
                    WHERE case_key=%s AND lower(coalesce(extension,''))='ngsxtmo7s'
                """, (case_key,))
                c_ext, t_ext = cur.fetchone()
                detector_counts['ransom_extension_mass'] = int(c_ext or 0)
                if (c_ext or 0) >= 100:
                    _push('ransom_extension_mass', 'filesystem_v2', f'ext=ngsxtmo7s,count={c_ext}', t_ext, min(100000, c_ext))

            def _det_ransom_note_pattern():
                cur.execute("""
                    SELECT count(*)::int, min(event_ts)
                    FROM filesystem_v2
                    WHERE case_key=%s AND lower(coalesce(file_name,'')) LIKE '%%readme%%' AND lower(coalesce(file_name,'')) LIKE '%%.txt%%'
                      AND coalesce(parent_path,'') <> ''
                      AND lower(parent_path) NOT LIKE '%%program files%%'
                      AND lower(parent_path) NOT LIKE '%%appdata%%'
                      AND lower(parent_path) NOT LIKE '%%\\\\share\\\\%%'
                """, (case_key,))
                c_note, t_note = cur.fetchone()
                detector_counts['ransom_note_pattern'] = int(c_note or 0)
                if (c_note or 0) >= 20:
                    _push('ransom_note_pattern', 'filesystem_v2', f'readme_txt,count={c_note}', t_note, min(100000, c_note*2))

            def _det_rdp_external_burst():
                cur.execute("""
                    SELECT
                      count(*)::int,
                      count(DISTINCT split_part((regexp_match(coalesce(remote_host,''), '((?:[0-9]{1,3}\\.){3}[0-9]{1,3})'))[1],':',1))::int,
                      min(event_ts)
                    FROM event_logs_v2
                    WHERE case_key=%s
                      AND (
                        lower(coalesce(channel,'')) like '%%rdpcorets%%'
                        OR lower(coalesce(channel,'')) like '%%terminalservices-gateway%%'
                        OR event_id in (1149)
                      )
                """, (case_key,))
                c_rdp, uniq_ip, t_rdp = cur.fetchone()
                detector_counts['rdp_external_burst'] = {'events': int(c_rdp or 0), 'uniq_ip': int(uniq_ip or 0)}
                if (c_rdp or 0) >= 3:
                    _push('rdp_external_burst', 'event_logs_v2', f'events={c_rdp},uniq_ip={uniq_ip or 0}', t_rdp, min(100000, (c_rdp or 0) + (uniq_ip or 0)*10))

            def _det_log_tampering():
                cur.execute("""
                    SELECT count(*)::int, min(event_ts)
                    FROM event_logs_v2
                    WHERE case_key=%s AND ((event_id=1102 AND channel ILIKE '%%Security%%') OR (event_id=104 AND (channel ILIKE '%%System%%' OR channel ILIKE '%%Eventlog%%')))
                """, (case_key,))
                c_tamp_ev, t_tamp = cur.fetchone()
                cur.execute("""
                    SELECT count(*)::int
                    FROM tool_alerts_v2
                    WHERE case_key=%s
                      AND (
                        lower(coalesce(source_file,'')) like '%%sigma%%'
                        OR lower(coalesce(source_file,'')) like '%%log_tampering%%'
                        OR lower(coalesce(rule,'')) like '%%log tamper%%'
                        OR lower(coalesce(rule,'')) like '%%event log cleared%%'
                        OR lower(coalesce(details,'')) like '%%1102%%'
                        OR lower(coalesce(details,'')) like '%%eventlog%%'
                      )
                """, (case_key,))
                c_tamp_tool = (cur.fetchone() or [0])[0] or 0
                detector_counts['log_tampering'] = {'event_hits': int(c_tamp_ev or 0), 'tool_hits': int(c_tamp_tool or 0)}
                if (c_tamp_ev or 0) + c_tamp_tool >= 1:
                    _push('log_tampering', 'tool_alerts_v2', f'event_hits={c_tamp_ev},tool_hits={c_tamp_tool}', t_tamp, min(100000, (c_tamp_ev or 0)*10 + c_tamp_tool*3))

            def _det_remote_tooling_context():
                cur.execute("""
                    SELECT count(*)::int, min(event_ts)
                    FROM program_exec_v2
                    WHERE case_key=%s
                      AND lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) ~ '(teamviewer|anydesk|ngrok|7za)'
                """, (case_key,))
                c_rt_prog, t_rt = cur.fetchone()
                cur.execute("""
                    SELECT count(*)::int
                    FROM tool_alerts_v2
                    WHERE case_key=%s
                      AND (
                        lower(coalesce(ioc_value,'')) ~ '(teamviewer|anydesk|ngrok|7za)'
                        OR lower(coalesce(rule,'')) ~ '(teamviewer|anydesk|ngrok|7za|remote tooling)'
                        OR lower(coalesce(details,'')) ~ '(teamviewer|anydesk|ngrok|7za)'
                      )
                """, (case_key,))
                c_rt_tool = (cur.fetchone() or [0])[0] or 0
                c_rt = (c_rt_prog or 0) + (c_rt_tool or 0)
                detector_counts['remote_tooling_context'] = {'program_hits': int(c_rt_prog or 0), 'tool_hits': int(c_rt_tool or 0), 'total_hits': int(c_rt)}
                if c_rt >= 1:
                    _push('remote_tooling_context', 'program_exec_v2', f'program_hits={c_rt_prog},tool_hits={c_rt_tool}', t_rt, min(100000, c_rt*5))

            _guard('ransom_extension_mass', _det_ransom_extension_mass)
            _guard('ransom_note_pattern', _det_ransom_note_pattern)
            _guard('rdp_external_burst', _det_rdp_external_burst)
            _guard('log_tampering', _det_log_tampering)
            _guard('remote_tooling_context', _det_remote_tooling_context)

    # fallback to latest persisted family hits only if inline had nothing
    if not fam:
        try:
            with psycopg2.connect(PG_DSN) as conn:
                conn.autocommit = True
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT run_id, count(*) c
                        FROM case_trigger_hits_v2
                        WHERE case_key=%s
                        GROUP BY run_id
                        ORDER BY c DESC
                        LIMIT 1
                    """, (case_key,))
                    rr = cur.fetchone()
                    if rr:
                        run_id = rr[0]
                        cur.execute("""
                            SELECT trigger, source_table, source_ref, event_ts, score
                            FROM case_trigger_hits_v2
                            WHERE case_key=%s AND run_id=%s AND trigger LIKE '__family:%%'
                            ORDER BY score DESC NULLS LAST
                        """, (case_key, run_id))
                        for trig, src_tbl, src_ref, ev_ts, score in cur.fetchall():
                            key = str(trig).replace('__family:', '')
                            _push(key, src_tbl, src_ref, ev_ts, score)
                        out['run_id'] = run_id
                        out['source_mode'] = 'persisted_fallback'
        except Exception:
            try: conn.rollback()
            except: pass
            pass

    out['ready'] = len(fam) > 0
    out['families'] = fam
    out['families_map'] = fmap
    out['detector_status'] = detector_status
    out['detector_counts'] = detector_counts
    out['errors'] = detector_errors
    return out


def _assemble_case_llm_triage_v1(case_key, cor, inc):
    """Phase-by-phase SQL triage (Windows IR cheat sheet order):
    Defender → Logon/RDP → Process/PS → Persistence → Lateral → Tampering → Artifacts → AD/DC
    Cross-phase correlation + deterministic probe ranking. Small LLM call (max_tokens=80) only for ranking.
    """
    VALID_CHAINS = {'initial_access', 'execution', 'persistence_remote', 'defense_evasion_tampering', 'impact'}
    ALLOWED_PROBES = ('probe_initial_access_native_linkage', 'probe_execution_native_linkage',
                      'probe_rdp_deep', 'probe_remote_tooling_deep', 'probe_tamper_deep', 'probe_impact_deep')

    families = [str(f.get('family') or '') for f in (((cor.get('trigger_correlation') or {}).get('families') or []))]
    win_start = cor.get('incident_window_start')
    win_end = cor.get('incident_window_end')
    win_sql = 'AND event_ts BETWEEN %s AND %s' if (win_start and win_end) else ''
    win_args = (win_start, win_end) if (win_start and win_end) else ()

    findings = []
    slice_counts = {}

    def _q(conn, sql, params=()):
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return cur.fetchall()
        except Exception as ex:
            try: conn.rollback()
            except: pass
            _log.info(f'[triage_sql] {ex}')
            return []

    def _f(chain, conf, why, ts=None, artifact='', process='', path='', user='', src='event_logs_v2', probe='none', missing=''):
        return {
            'chain': chain, 'finding_type': 'signal',
            'confidence': round(min(1.0, max(0.0, float(conf))), 2),
            'why_relevant': str(why)[:300],
            'time_anchor': str(ts) if ts else None,
            'artifact': str(artifact)[:180], 'process': str(process)[:180],
            'path': str(path)[:220], 'user': str(user)[:120], 'host': '',
            'source_rows': [str(src)],
            'suggested_next_probe': probe if probe in ALLOWED_PROBES else 'none',
            'missing_evidence': str(missing)[:300],
        }

    def _ts_epoch(ts):
        if ts is None: return None
        try:
            if hasattr(ts, 'timestamp'): return ts.timestamp()
            s = str(ts)
            for fmt in ('%Y-%m-%d %H:%M:%S.%f+%f', '%Y-%m-%d %H:%M:%S.%f'):
                try: return datetime.strptime(s[:26].rstrip('Z'), fmt[:len(s)]).timestamp()
                except: pass
            return None
        except: return None

    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True

        # ── PHASE 1: DEFENDER ─────────────────────────────────────────────
        rows = _q(conn, f"""
            SELECT event_ts, event_id, left(coalesce(payload::text,''),400), source_file
            FROM event_logs_v2 WHERE case_key=%s
            AND event_id IN (1116,1118,1119,1120,5000,5001,5007,5010,5012,5013)
            {win_sql} ORDER BY event_ts ASC NULLS LAST LIMIT 40
        """, (case_key, *win_args))
        slice_counts['defender'] = len(rows)
        defender_disable_ts = None

        for ts, eid, payload, src in rows:
            p = str(payload or '').lower()
            if eid == 1116:
                threat = next((l.strip()[:80] for l in str(payload or '').split('\n') if 'threat' in l.lower()), '')
                findings.append(_f('defense_evasion_tampering', 0.95,
                    f'Defender EID 1116: malware detected — {threat}',
                    ts, artifact=f'EID 1116 {threat}', src=f'event_logs_v2:{src}', probe='probe_tamper_deep'))
            elif eid == 1120:
                findings.append(_f('defense_evasion_tampering', 0.88,
                    'Defender EID 1120: remediation FAILED — file may still be active',
                    ts, artifact='EID 1120 remediation_failed', src=f'event_logs_v2:{src}',
                    probe='probe_tamper_deep', missing='verify file still present on disk'))
            elif eid == 5001:
                defender_disable_ts = ts
                findings.append(_f('defense_evasion_tampering', 0.90,
                    'Defender EID 5001: real-time protection DISABLED',
                    ts, artifact='EID 5001 defender_disabled', src=f'event_logs_v2:{src}', probe='probe_tamper_deep'))
            elif eid == 5007:
                conf = 0.90 if ('exclusion' in p or 'exclu' in p) else 0.72
                why = 'Defender EID 5007: exclusion added — evasion' if conf > 0.85 else 'Defender EID 5007: config changed'
                findings.append(_f('defense_evasion_tampering', conf, why,
                    ts, artifact='EID 5007', src=f'event_logs_v2:{src}', probe='probe_tamper_deep'))

        # ── PHASE 2: LOGON / RDP ──────────────────────────────────────────
        rows = _q(conn, f"""
            SELECT event_ts, event_id, left(coalesce(payload::text,''),400), source_file
            FROM event_logs_v2 WHERE case_key=%s
            AND event_id IN (1149,4624,4625,4634,4647,4648,4672,4778,4779,21,22,24,25,40)
            {win_sql} ORDER BY event_ts ASC NULLS LAST LIMIT 100
        """, (case_key, *win_args))
        slice_counts['logon'] = len(rows)
        failed_logons, rdp_logon_ts = [], []

        for ts, eid, payload, src in rows:
            p = str(payload or '').lower()
            pt = str(payload or '')
            if eid == 4625:
                failed_logons.append(ts)
            elif eid == 1149:
                ip = next((l.strip()[:60] for l in pt.split('\n') if 'source network' in l.lower() or 'ipaddress' in l.lower()), '')
                rdp_logon_ts.append(ts)
                findings.append(_f('initial_access', 0.82,
                    f'EID 1149: RDP auth succeeded — {ip}',
                    ts, artifact='EID 1149 RDP_auth', src=f'event_logs_v2:{src}',
                    probe='probe_rdp_deep', missing='correlate with 4624 type=10 and session activity'))
            elif eid == 4648:
                target = next((l.strip()[:60] for l in pt.split('\n') if 'targetserver' in l.lower() or 'target server' in l.lower()), '')
                findings.append(_f('persistence_remote', 0.80,
                    f'EID 4648: explicit credentials (runas/PSRemoting/lateral) — {target}',
                    ts, artifact='EID 4648 explicit_creds', src=f'event_logs_v2:{src}', probe='probe_rdp_deep'))
            elif eid == 4672:
                if any(x in p for x in ['sedebug', 'seimpersonate', '0x3e7']):
                    findings.append(_f('initial_access', 0.85,
                        'EID 4672: SeDebugPrivilege/SeImpersonatePrivilege — admin/SYSTEM logon',
                        ts, artifact='EID 4672 special_privs', src=f'event_logs_v2:{src}', probe='probe_rdp_deep'))
            elif eid == 4624:
                lt = next((l.strip() for l in pt.split('\n') if 'logontype' in l.lower() or 'logon type' in l.lower()), '')
                if re.search(r'[:\s]10\b', lt):
                    findings.append(_f('initial_access', 0.78,
                        'EID 4624 LogonType=10: RDP interactive logon',
                        ts, artifact='EID 4624 type=10', src=f'event_logs_v2:{src}', probe='probe_rdp_deep'))
                elif re.search(r'[:\s]3\b', lt) and any(x in p for x in ['workstation', 'source', 'ipaddr']):
                    findings.append(_f('persistence_remote', 0.65,
                        'EID 4624 LogonType=3: network logon (SMB/lateral candidate)',
                        ts, artifact='EID 4624 type=3', src=f'event_logs_v2:{src}', probe='probe_rdp_deep'))

        if len(failed_logons) >= 5:
            findings.append(_f('initial_access', 0.85,
                f'Brute force: {len(failed_logons)} EID 4625 failed logons in incident window',
                failed_logons[0], artifact=f'EID 4625 x{len(failed_logons)}',
                src='event_logs_v2', probe='probe_rdp_deep'))

        # ── PHASE 3: PROCESS / POWERSHELL ─────────────────────────────────
        # Suspicious 4688: LOLBIN or suspicious args
        rows_lolbin = _q(conn, f"""
            SELECT event_ts, left(coalesce(payload::text,''),500), source_file
            FROM event_logs_v2 WHERE case_key=%s AND event_id=4688
            AND (
                lower(coalesce(payload::text,'')) ~ '(powershell|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec|cmstp|odbcconf)'
                OR lower(coalesce(payload::text,'')) ~ '(-enc|-encodedcommand|-nop|-noprofile|iex |invoke-expression|downloadstring|frombase64|webclient|-windowstyle h|bypass)'
            )
            {win_sql} ORDER BY event_ts ASC NULLS LAST LIMIT 60
        """, (case_key, *win_args))

        # PS ScriptBlock 4104
        rows_ps = _q(conn, f"""
            SELECT event_ts, left(coalesce(payload::text,''),500), source_file
            FROM event_logs_v2 WHERE case_key=%s AND event_id=4104
            AND lower(coalesce(payload::text,'')) ~ '(iex|invoke-expression|downloadstring|frombase64string|webclient|hidden|bypass|add-mppreference|set-mppreference|scheduledtask|new-object)'
            {win_sql} ORDER BY event_ts ASC NULLS LAST LIMIT 40
        """, (case_key, *win_args))

        slice_counts['process'] = len(rows_lolbin) + len(rows_ps)

        for ts, payload, src in rows_lolbin:
            p = str(payload or '').lower()
            proc = next((l.strip()[:100] for l in str(payload or '').split('\n') if 'newprocessname' in l.lower() or 'new process name' in l.lower()), '')
            has_sus_args = bool(re.search(r'(-enc|-encodedcommand|-nop|iex |invoke-expression|downloadstring|frombase64|-windowstyle h|bypass)', p))
            from_sus_path = any(x in p for x in ['\\temp\\', '\\appdata\\', '\\programdata\\', '\\public\\', '\\downloads\\'])
            is_office_spawn = any(x in p for x in ['winword', 'excel', 'powerpnt', 'outlook']) and bool(re.search(r'(powershell|wscript|mshta|rundll32|regsvr32)', p))

            if is_office_spawn:
                findings.append(_f('initial_access', 0.92,
                    f'EID 4688: Office spawned LOLBIN — macro execution. {proc}',
                    ts, process=proc, artifact='EID 4688 office_macro_spawn',
                    src=f'event_logs_v2:{src}', probe='probe_initial_access_native_linkage',
                    missing='source document, VBA content'))
            elif has_sus_args:
                findings.append(_f('execution', 0.92,
                    f'EID 4688: suspicious cmdline (encoded/download/bypass). {proc}',
                    ts, process=proc, artifact='EID 4688 sus_cmdline',
                    src=f'event_logs_v2:{src}', probe='probe_execution_native_linkage'))
            elif from_sus_path:
                findings.append(_f('execution', 0.85,
                    f'EID 4688: LOLBIN from suspicious path. {proc}',
                    ts, process=proc, artifact='EID 4688 lolbin_sus_path',
                    src=f'event_logs_v2:{src}', probe='probe_execution_native_linkage'))
            else:
                findings.append(_f('execution', 0.68,
                    f'EID 4688: LOLBIN execution. {proc}',
                    ts, process=proc, artifact='EID 4688 lolbin',
                    src=f'event_logs_v2:{src}', probe='probe_execution_native_linkage'))

        for ts, payload, src in rows_ps:
            p = str(payload or '').lower()
            hits = [x for x in ['iex', 'invoke-expression', 'downloadstring', 'frombase64string', 'webclient', 'hidden', 'bypass', 'add-mppreference', 'scheduledtask'] if x in p]
            findings.append(_f('execution', 0.93,
                f'EID 4104 PS ScriptBlock: {", ".join(hits[:5])}',
                ts, artifact='EID 4104 scriptblock', src=f'event_logs_v2:{src}',
                probe='probe_execution_native_linkage', missing='full decoded payload'))

        # program_exec_v2 (Prefetch/AppCompat/Amcache)
        rows_exec = _q(conn, """
            SELECT event_ts, executable_name, full_path, min(source_file) AS source_file
            FROM program_exec_v2 WHERE case_key=%s
            AND (
                lower(coalesce(executable_name,'')||' '||coalesce(full_path,''))
                    ~ '(mimikatz|wce|fgdump|procdump|psexec|rclone|ngrok|teamviewer|anydesk|7za|cobalt|meterpreter|netscan|advanced.port)'
                OR lower(coalesce(full_path,'')) ~ '(\\\\temp\\\\|\\\\appdata\\\\|\\\\programdata\\\\|\\\\public\\\\|\\\\downloads\\\\|\\\\desktop\\\\)'
            )
            GROUP BY 1, 2, 3
            ORDER BY event_ts ASC NULLS LAST, min(row_id) ASC LIMIT 40
        """, (case_key,))
        slice_counts['program_exec'] = len(rows_exec)

        # Deterministic legit-tool denylist: banking software (the TARGET, not malware),
        # analyst/forensic tools, and vendor updaters must NOT be flagged as attacker
        # tools just because they sit in a user/download path (false-positive noise).
        _LEGIT_NOISE = ('barscryptor', 'websigner', 'dbo soft', 'dbo_soft', 'ibank', 'iit_avtor',
                        'iit avtor', 'x-ways', 'xways', 'routerscan', 'fiddler', 'wireshark',
                        'networkminer', 'passware', 'dwebp', 'punto', 'greenfish', 'foxitreader',
                        'foxit', 'x-ways forensics', 'ftk imager', 'accessdata')
        for ts, exe, path, src in rows_exec:
            _pl = (str(exe or '') + ' ' + str(path or '')).lower()
            if any(_n in _pl for _n in _LEGIT_NOISE):
                continue  # known-legit banking/analyst/vendor tool — not attacker tooling
            exe_l = str(exe or '').lower()
            is_hacktool = bool(re.search(r'(mimikatz|wce|fgdump|procdump|psexec|rclone|ngrok|cobalt|meterpreter)', exe_l))
            conf = 0.95 if is_hacktool else 0.80
            findings.append(_f('execution', conf,
                f'program_exec: {"hacking tool" if is_hacktool else "executable from suspicious path"}: {exe}',
                ts, process=str(exe), path=str(path or ''),
                src=f'program_exec_v2:{src}', probe='probe_execution_native_linkage'))

        # ── PHASE 4: PERSISTENCE ──────────────────────────────────────────
        rows = _q(conn, f"""
            SELECT event_ts, event_id, left(coalesce(payload::text,''),400), source_file
            FROM event_logs_v2 WHERE case_key=%s
            AND event_id IN (4697,4698,4699,4700,4701,4702,106,7045,7040,7035,7036)
            {win_sql} ORDER BY event_ts ASC NULLS LAST LIMIT 40
        """, (case_key, *win_args))
        slice_counts['persistence'] = len(rows)

        for ts, eid, payload, src in rows:
            p = str(payload or '').lower()
            sus_path = any(x in p for x in ['\\temp\\', '\\appdata\\', '\\programdata\\', '\\public\\', '%temp%', '%appdata%', 'unc\\\\'])
            svc = next((l.strip()[:60] for l in str(payload or '').split('\n') if 'service name' in l.lower()), '')
            if eid == 4698:
                findings.append(_f('persistence_remote', 0.90 if sus_path else 0.72,
                    f'EID 4698: scheduled task CREATED{"  from suspicious path" if sus_path else ""}',
                    ts, artifact='EID 4698 task_created', src=f'event_logs_v2:{src}',
                    probe='probe_remote_tooling_deep', missing='task name, action path, trigger, user'))
            elif eid == 4702:
                findings.append(_f('persistence_remote', 0.75,
                    'EID 4702: scheduled task UPDATED — modified persistence',
                    ts, artifact='EID 4702 task_updated', src=f'event_logs_v2:{src}',
                    probe='probe_remote_tooling_deep'))
            elif eid in (7045, 4697):
                _svc_benign = any(x in p for x in ['driverstore', 'definition updates',
                    'inf_amd64', 'inf_x86', 'windows defender', 'system32\\drivers'])
                if _svc_benign and not sus_path:
                    continue  # legit Windows driver / Defender service install
                findings.append(_f('persistence_remote', 0.92 if sus_path else 0.80,
                    f'EID {eid}: service INSTALLED{"  from suspicious path" if sus_path else ""}. {svc}',
                    ts, artifact=f'EID {eid} service_installed', src=f'event_logs_v2:{src}',
                    probe='probe_remote_tooling_deep', missing='ImagePath, StartType, account'))

        # ── PHASE 5: LATERAL MOVEMENT ─────────────────────────────────────
        rows = _q(conn, f"""
            SELECT event_ts, event_id, left(coalesce(payload::text,''),300), source_file
            FROM event_logs_v2 WHERE case_key=%s
            AND event_id IN (4768,4769,4771,4776,5140,5142,5145)
            {win_sql} ORDER BY event_ts ASC NULLS LAST LIMIT 60
        """, (case_key, *win_args))
        slice_counts['lateral'] = len(rows)
        kerb_fails = 0

        for ts, eid, payload, src in rows:
            pt = str(payload or '')
            if eid == 4771:
                kerb_fails += 1
            elif eid == 5140:
                share = next((l.strip()[:60] for l in pt.split('\n') if 'share name' in l.lower() or 'objectname' in l.lower()), '')
                findings.append(_f('persistence_remote', 0.68,
                    f'EID 5140: network share accessed — {share}',
                    ts, artifact=f'EID 5140 share:{share}', src=f'event_logs_v2:{src}',
                    probe='probe_remote_tooling_deep'))
            elif eid == 4769:
                spn = next((l.strip()[:80] for l in pt.split('\n') if 'servicename' in l.lower() or 'service name' in l.lower()), '')
                if spn:
                    findings.append(_f('persistence_remote', 0.65,
                        f'EID 4769: Kerberos TGS — {spn}',
                        ts, artifact='EID 4769 kerberos_tgs', src=f'event_logs_v2:{src}', probe='probe_rdp_deep'))
            elif eid == 4776:
                findings.append(_f('persistence_remote', 0.60,
                    'EID 4776: NTLM auth — check for legacy/relay attack',
                    ts, artifact='EID 4776 NTLM', src=f'event_logs_v2:{src}', probe='probe_rdp_deep'))

        if kerb_fails >= 5:
            findings.append(_f('initial_access', 0.85,
                f'Kerberos spray/brute: {kerb_fails} EID 4771 preauth failures',
                None, artifact=f'EID 4771 x{kerb_fails}', src='event_logs_v2', probe='probe_rdp_deep'))

        # ── PHASE 6: TAMPERING / DEFENSE EVASION ─────────────────────────
        rows = _q(conn, f"""
            SELECT event_ts, event_id, left(coalesce(payload::text,''),200), source_file
            FROM event_logs_v2 WHERE case_key=%s
            AND ((event_id IN (1100,1102,4719,4907,4616) AND channel ILIKE '%%Security%%') OR (event_id IN (104,1074) AND (channel ILIKE '%%System%%' OR channel ILIKE '%%Eventlog%%')))
            {win_sql} ORDER BY event_ts ASC NULLS LAST LIMIT 40
        """, (case_key, *win_args))
        slice_counts['tampering'] = len(rows)
        log_clear_ts = []

        for ts, eid, payload, src in rows:
            if eid == 1102:
                log_clear_ts.append(ts)
                findings.append(_f('defense_evasion_tampering', 0.95,
                    'EID 1102: Security log CLEARED — strong cleanup indicator',
                    ts, artifact='EID 1102 security_log_cleared', src=f'event_logs_v2:{src}', probe='probe_tamper_deep'))
            elif eid == 104:
                log_clear_ts.append(ts)
                findings.append(_f('defense_evasion_tampering', 0.90,
                    'EID 104: event log channel CLEARED',
                    ts, artifact='EID 104 log_cleared', src=f'event_logs_v2:{src}', probe='probe_tamper_deep'))
            elif eid == 4719:
                findings.append(_f('defense_evasion_tampering', 0.85,
                    'EID 4719: audit policy CHANGED — may have disabled logging',
                    ts, artifact='EID 4719 audit_policy', src=f'event_logs_v2:{src}', probe='probe_tamper_deep'))
            elif eid == 4616:
                findings.append(_f('defense_evasion_tampering', 0.80,
                    'EID 4616: system time CHANGED — anti-forensics / timeline manipulation',
                    ts, artifact='EID 4616 time_changed', src=f'event_logs_v2:{src}', probe='probe_tamper_deep'))
            elif eid == 1074:
                findings.append(_f('defense_evasion_tampering', 0.70,
                    'EID 1074: shutdown/restart initiated by process',
                    ts, artifact='EID 1074 shutdown', src=f'event_logs_v2:{src}', probe='probe_tamper_deep'))

        # ── PHASE 7: ARTIFACTS ────────────────────────────────────────────
        rows_fs = _q(conn, """
            SELECT event_ts, file_name, parent_path, extension, source_file
            FROM filesystem_v2 WHERE case_key=%s AND (
                lower(coalesce(parent_path,'')) ~ '(\\\\temp\\\\|\\\\appdata\\\\|\\\\programdata\\\\|\\\\public\\\\|\\\\downloads\\\\|\\\\desktop\\\\)'
                OR lower(coalesce(file_name,'')) ~ '(readme|ransom|encrypt|locker|crypt|\\.locked|\\.encrypted)'
                OR lower(coalesce(extension,'')) IN ('.exe','.dll','.vbs','.bat','.ps1','.cmd','.hta','.js','.scr')
            )
            ORDER BY event_ts ASC NULLS LAST LIMIT 40
        """, (case_key,))
        slice_counts['filesystem'] = len(rows_fs)

        for ts, fname, fpath, ext, src in rows_fs:
            fn_l = str(fname or '').lower()
            if any(x in fn_l for x in ['readme', 'ransom', 'encrypt', 'locker', 'crypt', '.locked', '.encrypted']):
                findings.append(_f('impact', 0.95,
                    f'MFT: ransom note/encrypted file — {fname}',
                    ts, artifact=str(fname), path=str(fpath or ''),
                    src=f'filesystem_v2:{src}', probe='probe_impact_deep'))
            else:
                fp_l = str(fpath or '').lower()
                conf = 0.85 if str(ext or '').lower() in ('.exe', '.dll', '.hta', '.scr') else 0.70
                findings.append(_f('execution', conf,
                    f'MFT: {"binary" if conf > 0.80 else "script"} dropped in suspicious path — {fname}',
                    ts, artifact=str(fname), path=str(fpath or ''),
                    src=f'filesystem_v2:{src}', probe='probe_execution_native_linkage'))

        rows_alerts = _q(conn, """
            SELECT event_ts, rule, left(coalesce(details,''),300), source_file
            FROM tool_alerts_v2 WHERE case_key=%s
            ORDER BY event_ts ASC NULLS LAST LIMIT 40
        """, (case_key,))
        slice_counts['tool_alerts'] = len(rows_alerts)

        for ts, rule, details, src in rows_alerts:
            rule_l = str(rule or '').lower()
            chain = 'impact' if any(x in rule_l for x in ['ransom', 'crypt', 'encrypt', 'locker']) \
                else 'defense_evasion_tampering' if any(x in rule_l for x in ['tamper', 'defender', 'av_kill', 'log_clear']) \
                else 'execution'
            findings.append(_f(chain, 0.90,
                f'THOR/LOKI: {rule} — {str(details or "")[:120]}',
                ts, artifact=f'tool_alert:{rule}', src=f'tool_alerts_v2:{src}',
                probe='probe_execution_native_linkage'))

        rows_browser = _q(conn, """
            SELECT event_ts, url, referrer_url, source_file
            FROM browser_provenance_v1 WHERE case_key=%s
            ORDER BY event_ts ASC NULLS LAST LIMIT 20
        """, (case_key,))
        slice_counts['browser'] = len(rows_browser)
        for ts, url, ref, src in rows_browser:
            findings.append(_f('initial_access', 0.75,
                f'Browser download: {str(url or "")[:120]}',
                ts, artifact=f'browser:{str(url or "")[:80]}',
                src=f'browser_provenance_v1:{src}', probe='probe_initial_access_native_linkage',
                missing='correlate URL with dropped file in filesystem_v2'))

        # ── PHASE 8: AD / DC ──────────────────────────────────────────────
        rows = _q(conn, f"""
            SELECT event_ts, event_id, left(coalesce(payload::text,''),300), source_file
            FROM event_logs_v2 WHERE case_key=%s
            AND event_id IN (4720,4722,4723,4724,4725,4726,4728,4729,4732,4733,4735,4737,4738,4740,4756,4757,4767,4794,5136,5137,5139,5141)
            {win_sql} ORDER BY event_ts ASC NULLS LAST LIMIT 40
        """, (case_key, *win_args))
        slice_counts['ad'] = len(rows)
        user_created_ts = []

        for ts, eid, payload, src in rows:
            if eid == 4720:
                user_created_ts.append(ts)
                findings.append(_f('persistence_remote', 0.92,
                    'EID 4720: user account CREATED — possible backdoor account',
                    ts, artifact='EID 4720 user_created', src=f'event_logs_v2:{src}',
                    probe='probe_remote_tooling_deep', missing='check 4728/4732 for immediate group add'))
            elif eid in (4728, 4732, 4756):
                grp = {4728: 'global', 4732: 'local', 4756: 'universal'}.get(eid, '')
                findings.append(_f('persistence_remote', 0.85,
                    f'EID {eid}: member added to {grp} group — privilege escalation',
                    ts, artifact=f'EID {eid} group_add_{grp}', src=f'event_logs_v2:{src}',
                    probe='probe_remote_tooling_deep'))
            elif eid == 4738:
                findings.append(_f('persistence_remote', 0.75,
                    'EID 4738: user account CHANGED — check UAC flags, SPN, pwd settings',
                    ts, artifact='EID 4738 account_changed', src=f'event_logs_v2:{src}',
                    probe='probe_remote_tooling_deep'))
            elif eid == 5136:
                findings.append(_f('persistence_remote', 0.80,
                    'EID 5136: AD object modified — check GPO/ACL/sensitive object',
                    ts, artifact='EID 5136 ad_object_modified', src=f'event_logs_v2:{src}',
                    probe='probe_remote_tooling_deep'))
            elif eid == 4726:
                findings.append(_f('defense_evasion_tampering', 0.80,
                    'EID 4726: user DELETED — cleanup of backdoor account',
                    ts, artifact='EID 4726 user_deleted', src=f'event_logs_v2:{src}',
                    probe='probe_tamper_deep'))

    # ── CROSS-PHASE CORRELATION ───────────────────────────────────────────
    exec_findings = [f for f in findings if f.get('chain') == 'execution']

    # Chain: Defender disabled → execution within 10 min
    if defender_disable_ts:
        dt = _ts_epoch(defender_disable_ts)
        for ef in exec_findings:
            et = _ts_epoch(ef.get('time_anchor'))
            if dt and et and 0 <= (et - dt) <= 600:
                findings.append(_f('defense_evasion_tampering', 0.95,
                    'CHAIN: Defender disabled (EID 5001) then execution within 10 min — defense evasion confirmed',
                    defender_disable_ts, artifact='chain:5001→execution',
                    src='cross_phase_correlation', probe='probe_tamper_deep'))
                break

    # Chain: user created → added to group within 30 min
    group_add_findings = [f for f in findings if re.search(r'EID (4728|4732|4756)', str(f.get('artifact', '')))]
    for uts in user_created_ts:
        ut = _ts_epoch(uts)
        if not ut: continue
        for gf in group_add_findings:
            gt = _ts_epoch(gf.get('time_anchor'))
            if gt and 0 <= (gt - ut) <= 1800:
                findings.append(_f('persistence_remote', 0.95,
                    'CHAIN: User created (4720) then added to group within 30 min — backdoor account confirmed',
                    uts, artifact='chain:4720→4728/4732',
                    src='cross_phase_correlation', probe='probe_remote_tooling_deep'))
                break

    # Chain: log cleared near execution
    for lts in log_clear_ts:
        lt = _ts_epoch(lts)
        if not lt: continue
        for ef in exec_findings:
            et = _ts_epoch(ef.get('time_anchor'))
            if et and abs(lt - et) <= 3600:
                findings.append(_f('defense_evasion_tampering', 0.95,
                    'CHAIN: log cleared near execution — attack cleanup confirmed',
                    lts, artifact='chain:execution→log_clear',
                    src='cross_phase_correlation', probe='probe_tamper_deep'))
                break

    # ── FAMILY FALLBACK (no SQL hits) ────────────────────────────────────
    if not findings:
        fmap = [
            (['ransom_extension_mass', 'ransom_note_pattern'], 'impact', 0.80, 'ransom family trigger', 'probe_impact_deep'),
            (['rdp_external_burst'], 'persistence_remote', 0.70, 'RDP burst family', 'probe_rdp_deep'),
            (['remote_tooling_context'], 'persistence_remote', 0.70, 'remote tooling family', 'probe_remote_tooling_deep'),
            (['log_tampering'], 'defense_evasion_tampering', 0.75, 'log tampering family', 'probe_tamper_deep'),
        ]
        for fams, chain, conf, why, probe in fmap:
            if any(x in families for x in fams):
                findings.append(_f(chain, conf, why, artifact='trigger_correlation.families', src='corroboration', probe=probe))

    # ── SANITIZE + DEDUPLICATE ────────────────────────────────────────────
    clean, seen = [], set()
    for f in sorted(findings, key=lambda x: -float(x.get('confidence') or 0)):
        chain = str(f.get('chain') or '')
        if chain not in VALID_CHAINS: continue
        key = str(f.get('artifact', ''))[:60]
        if key in seen and 'cross_phase' not in str(f.get('source_rows', '')):
            continue
        seen.add(key)
        clean.append(f)
        if len(clean) >= 20: break

    # ── DETERMINISTIC PROBE RANKING ───────────────────────────────────────
    probe_score = {}
    for f in clean:
        p = f.get('suggested_next_probe', 'none')
        if p in ALLOWED_PROBES:
            probe_score[p] = probe_score.get(p, 0) + float(f.get('confidence', 0))
    ranked = sorted(probe_score, key=probe_score.get, reverse=True)[:6]
    if not ranked:
        for fams, probe in [(['rdp_external_burst'], 'probe_rdp_deep'), (['remote_tooling_context'], 'probe_remote_tooling_deep'),
                             (['log_tampering'], 'probe_tamper_deep'), (['ransom_extension_mass', 'ransom_note_pattern'], 'probe_impact_deep')]:
            if any(x in families for x in fams): ranked.append(probe)
        if not ranked: ranked = ['probe_execution_native_linkage']
    block = [p for p in ALLOWED_PROBES if p not in ranked][:3]

    cc = {}
    for f in clean:
        ch = f.get('chain')
        if ch and float(f.get('confidence', 0)) > cc.get(ch, {}).get('confidence', 0):
            cc[ch] = {'chain': ch, 'confidence': float(f['confidence']),
                      'rationale': f'SQL: {sum(1 for x in clean if x.get("chain")==ch)} findings'}
    cc_list = list(cc.values())

    # ── OPTIONAL SMALL LLM RANKING CALL (max 120s, non-blocking fallback) ─
    llm_attempts, llm_error, llm_latency_ms = 0, '', None
    if clean:
        try:
            llm_url = LLM_URL
            llm_model = LLM_MODEL
            summary = '\n'.join(
                f'[{f["chain"].upper()}] conf={f["confidence"]} {f["why_relevant"][:100]}'
                for f in clean[:10]
            )
            llm_prompt = (
                'DFIR analyst. From these findings, return ONLY JSON: '
                '{"ranked_probe_plan":["probe_name",...]} using probes from: '
                '[probe_initial_access_native_linkage, probe_execution_native_linkage, '
                'probe_rdp_deep, probe_remote_tooling_deep, probe_tamper_deep, probe_impact_deep].\n\n'
                f'FINDINGS:\n{summary}'
            )
            t0 = time.time()
            llm_attempts = 1
            req_body = json.dumps(build_chat_payload(
                model=llm_model,
                messages=[{'role': 'user', 'content': llm_prompt}],
                role='json',
                max_tokens=int(os.environ.get('DFIR_PROBE_PLAN_MAX_TOKENS', '300')),
                temperature=LLM_JSON_TEMPERATURE,
                stream=False,
                reasoning_effort=os.environ.get('DFIR_JSON_REASONING_EFFORT', 'low'),
            )).encode()
            req = urllib.request.Request(f"{llm_url.rstrip('/')}/v1/chat/completions",
                data=req_body, headers={'Content-Type': 'application/json'})
            resp = urllib.request.urlopen(req, timeout=120)
            llm_latency_ms = int((time.time() - t0) * 1000)
            rjson = json.loads(resp.read().decode())
            content = (rjson.get('choices') or [{}])[0].get('message', {}).get('content', '') or ''
            s, e = content.find('{'), content.rfind('}')
            if s >= 0 and e > s:
                robj = json.loads(content[s:e+1])
                llm_ranked = [str(x) for x in (robj.get('ranked_probe_plan') or []) if str(x) in ALLOWED_PROBES]
                if llm_ranked:
                    ranked = llm_ranked[:6]
        except Exception as ex:
            llm_error = str(ex)[:120]

    return {
        'scope_mode': 'case_llm_triage_v1',
        'model': 'sql_rules_v2',
        'source_mode': 'sql+llm' if (llm_attempts and not llm_error) else 'sql_rules',
        'ollama_call_attempts': llm_attempts,
        'ollama_last_error': llm_error,
        'ollama_latency_ms': llm_latency_ms,
        'schema_repair_retry': False,
        'first_reply_top_keys': [],
        'slice_counts': slice_counts,
        'decision': {
            'ranked_probe_plan': ranked,
            'probe_blocklist': block,
            'chain_confidence_updates': cc_list,
            'why_probe_ranked': {p: f'score={probe_score.get(p,0):.2f}' for p in ranked if p in probe_score},
            'why_probe_blocked': {p: 'lower_score' for p in block},
        },
        'findings': clean,
    }


def _assemble_case_drilldown_v1(case_key, cor, inc, llm_triage=None):
    """Bounded mini-loop: max 2 iterations / max 3 targeted probes.
    Triggered when initial_access/execution/persistence are weak/inconclusive indicators.
    """
    families = {str(f.get('family') or ''): f for f in (((cor.get('trigger_correlation') or {}).get('families') or []))}
    likely = cor.get('likely') or []
    likely_blob = ' '.join([str(x.get('indicator') or '') + ' ' + ' '.join([str(y) for y in (x.get('evidence_samples') or [])]) for x in likely]).lower()

    need_execution = 'script_host_execution_linkage' in likely_blob or 'verdict=partial confidence=medium' in likely_blob
    need_initial = 'delivery_browser_provenance' in likely_blob or 'normalized_but_no_strict_hit' in likely_blob
    need_persist = ('rdp_user_creation_linkage' in likely_blob) or ('rdp_external_burst' in families) or ('remote_tooling_context' in families)

    det_planned = []
    if need_initial:
        det_planned.append('probe_initial_access_native_linkage')
    if need_execution:
        det_planned.append('probe_execution_native_linkage')
    if 'rdp_external_burst' in families or need_persist:
        det_planned.append('probe_rdp_deep')
    if 'remote_tooling_context' in families:
        det_planned.append('probe_remote_tooling_deep')
    if 'ransom_extension_mass' in families or 'ransom_note_pattern' in families:
        det_planned.append('probe_impact_deep')
    if 'log_tampering' in families:
        det_planned.append('probe_tamper_deep')

    allowed = ('probe_initial_access_native_linkage','probe_execution_native_linkage','probe_rdp_deep','probe_remote_tooling_deep','probe_tamper_deep','probe_impact_deep')
    llm_decision = ((llm_triage or {}).get('decision') if isinstance((llm_triage or {}).get('decision'), dict) else {})
    llm_ranked = [str(x) for x in (llm_decision.get('ranked_probe_plan') or []) if str(x) in allowed]
    llm_block = set([str(x) for x in (llm_decision.get('probe_blocklist') or []) if str(x) in allowed])

    # fallback compatibility: if no ranked plan provided, derive from findings
    if not llm_ranked:
        for f in ((llm_triage or {}).get('findings') or []):
            sp = str((f or {}).get('suggested_next_probe') or '').strip()
            if sp in allowed:
                llm_ranked.append(sp)

    # planner gate v1: LLM ranked plan has primary ordering/gating; deterministic probes are safety fallback
    planned = []
    for p in llm_ranked:
        if p not in llm_block:
            planned.append(p)
    for p in det_planned:
        if p not in llm_block:
            planned.append(p)

    # de-dup keep order, bounded top-3
    uniq=[]
    for p in planned:
        if p not in uniq:
            uniq.append(p)
    planned=uniq[:3]

    results = []
    errors = []
    probes_run = []

    def _push_probe(name, chain, sql_note, rows, meta=None):
        probes_run.append(name)
        item = {
            'probe': name,
            'chain': chain,
            'sql_note': sql_note,
            'rows': rows,
            'row_count': len(rows or [])
        }
        if isinstance(meta, dict):
            item.update(meta)
        results.append(item)

    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            for _iter in range(2):
                remaining = [p for p in planned if p not in probes_run]
                if not remaining:
                    break
                for p in list(remaining):
                    if len(probes_run) >= 3:
                        break
                    try:
                        if p == 'probe_rdp_deep':
                            cur.execute("""
                                SELECT event_ts, event_id, channel, coalesce(remote_host,''), coalesce(target_user,''), source_file
                                FROM event_logs_v2
                                WHERE case_key=%s AND (
                                  lower(coalesce(channel,'')) like '%%rdpcorets%%'
                                  OR lower(coalesce(channel,'')) like '%%terminalservices-gateway%%'
                                  OR event_id IN (1149,4624,4625)
                                )
                                ORDER BY event_ts NULLS LAST
                                LIMIT 30
                            """, (case_key,))
                            rows = [{'event_ts': str(r[0]) if r[0] else None, 'event_id': r[1], 'channel': r[2], 'remote_host': r[3], 'target_user': r[4], 'source_file': r[5]} for r in cur.fetchall()]
                            _push_probe(p, 'persistence_remote', 'event_logs_v2 RDP/session deep sample', rows)

                        elif p == 'probe_remote_tooling_deep':
                            cur.execute("""
                                SELECT event_ts, coalesce(executable_name,''), coalesce(full_path,''), source_file
                                FROM program_exec_v2
                                WHERE case_key=%s AND lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) ~ '(teamviewer|anydesk|ngrok|7za)'
                                ORDER BY event_ts NULLS LAST
                                LIMIT 30
                            """, (case_key,))
                            rows = [{'event_ts': str(r[0]) if r[0] else None, 'exe': r[1], 'path': r[2], 'source_file': r[3]} for r in cur.fetchall()]
                            _push_probe(p, 'persistence_remote', 'program_exec_v2 remote-tooling sample', rows)

                        elif p == 'probe_impact_deep':
                            cur.execute("""
                                SELECT event_ts, file_name, parent_path, source_file
                                FROM filesystem_v2
                                WHERE case_key=%s AND (
                                  lower(coalesce(extension,''))='ngsxtmo7s'
                                  OR lower(coalesce(file_name,'')) LIKE '%%readme%%.txt%%'
                                )
                                ORDER BY event_ts NULLS LAST
                                LIMIT 40
                            """, (case_key,))
                            rows = [{'event_ts': str(r[0]) if r[0] else None, 'file_name': r[1], 'parent_path': r[2], 'source_file': r[3]} for r in cur.fetchall()]
                            _push_probe(p, 'impact', 'filesystem_v2 ransom impact sample', rows)

                        elif p == 'probe_tamper_deep':
                            cur.execute("""
                                SELECT event_ts, event_id, channel, source_file
                                FROM event_logs_v2
                                WHERE case_key=%s AND ((event_id=1102 AND channel ILIKE '%%Security%%') OR (event_id=104 AND (channel ILIKE '%%System%%' OR channel ILIKE '%%Eventlog%%')))
                                ORDER BY event_ts NULLS LAST
                                LIMIT 30
                            """, (case_key,))
                            rows = [{'event_ts': str(r[0]) if r[0] else None, 'event_id': r[1], 'channel': r[2], 'source_file': r[3]} for r in cur.fetchall()]
                            _push_probe(p, 'defense_evasion_tampering', 'event_logs_v2 log-clear sample', rows)

                        elif p == 'probe_initial_access_native_linkage':
                            # delivery_native_linker_v2: origin/url/referrer -> download/archive -> payload -> nearest execution
                            cur.execute("""
                                SELECT event_ts, url, referrer_url, source_file
                                FROM browser_provenance_v1
                                WHERE case_key=%s
                                ORDER BY event_ts NULLS LAST
                                LIMIT 120
                            """, (case_key,))
                            b_rows = [{'event_ts': str(r[0]) if r[0] else None, 'url': r[1], 'host_url': None, 'referrer_url': r[2], 'source_file': r[3]} for r in cur.fetchall()]

                            cur.execute("""
                                SELECT event_ts, lower(coalesce(executable_name,'')) as exe, lower(coalesce(full_path,'')) as path, source_file
                                FROM program_exec_v2
                                WHERE case_key=%s
                                  AND lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) ~ '(start\\.vbs|ng\\.bat|try\\.exe|msedgex\\.exe|ngrok\\.exe|7za\\.exe|teamviewer|anydesk)'
                                ORDER BY event_ts NULLS LAST
                                LIMIT 120
                            """, (case_key,))
                            a_prog = [{'event_ts': str(r[0]) if r[0] else None, 'artifact': (r[1] or r[2] or ''), 'path': r[2], 'source_file': r[3]} for r in cur.fetchall()]

                            cur.execute("""
                                SELECT event_ts, lower(coalesce(file_name,'')) as fn, lower(coalesce(parent_path,'')) as pp, source_file
                                FROM filesystem_v2
                                WHERE case_key=%s
                                  AND lower(coalesce(file_name,'')||' '||coalesce(parent_path,'')) ~ '(start\\.vbs|ng\\.bat|try\\.exe|msedgex\\.exe|ngrok\\.exe|7za\\.exe|\\.zip|\\.rar|\\.7z)'
                                ORDER BY event_ts NULLS LAST
                                LIMIT 120
                            """, (case_key,))
                            a_fs = [{'event_ts': str(r[0]) if r[0] else None, 'artifact': (r[1] or ''), 'path': r[2], 'source_file': r[3]} for r in cur.fetchall()]

                            raw_rows = []
                            if table_exists('raw_fallback_v2'):
                                cur.execute("""
                                    SELECT source_file, left(to_jsonb(raw_fallback_v2)::text, 420)
                                    FROM raw_fallback_v2
                                    WHERE case_key=%s AND lower(to_jsonb(raw_fallback_v2)::text) ~ '(zone.identifier|motw|hosturl|referrer|download|url|\\.zip|\\.rar|\\.7z|http://|https://)'
                                    -- ORDER BY, бо без нього LIMIT віддає довільні рядки і звіт
                                    -- відрізняється між прогонами на тих самих даних
                                    ORDER BY row_id
                                    LIMIT 120
                                """, (case_key,))
                                raw_rows = [{'source_file': r[0], 'raw_hint': r[1]} for r in cur.fetchall()]

                            def _pts(v):
                                return _parse_ts(v) if v else None

                            sus_kw = ['swisstransfer', 'dropbox', 'mega.nz', 'drive.google', 'docs.google', 'we.tl', 'transfer', 'file.io', 'ngrok', 'pastebin', 'telegram', 't.me']
                            suspicious_url = None
                            native_hit = None
                            for br in b_rows:
                                blob = ' '.join([str(br.get('url') or ''), str(br.get('referrer_url') or '')]).lower()
                                benign = any(k in blob for k in ['microsoft.com','bing.com','msn.com','g.live.com/odclientsettings','w3.org'])
                                suspicious = any(k in blob for k in sus_kw)
                                if (not benign) and suspicious and ('http://' in blob or 'https://' in blob):
                                    suspicious_url = br.get('url') or br.get('referrer_url')
                                    native_hit = br
                                    break

                            motw_hit = None
                            matched_download = None
                            for rr in raw_rows:
                                rb = str(rr.get('raw_hint') or '').lower()
                                if ('zone.identifier' in rb or 'motw' in rb) and motw_hit is None:
                                    motw_hit = rr
                                if matched_download is None and any(k in rb for k in ['.zip', '.rar', '.7z', 'download']):
                                    matched_download = rr.get('raw_hint')

                            payload_candidates = a_prog + a_fs
                            suspicious_art = ['start.vbs','ng.bat','try.exe','msedgex.exe','ngrok.exe','7za.exe','teamviewer','anydesk']
                            payload = None
                            for a in payload_candidates:
                                aa = (str(a.get('artifact') or '') + ' ' + str(a.get('path') or '')).lower()
                                if any(k in aa for k in suspicious_art):
                                    payload = a
                                    break

                            # archive/container lineage heuristic
                            archive_lineage_match = False
                            if payload and matched_download:
                                dl = str(matched_download).lower()
                                pp = str(payload.get('path') or '').lower()
                                if any(x in dl for x in ['.zip', '.rar', '.7z']) and any(x in pp for x in ['downloads', 'temp', 'appdata', 'desktop']):
                                    archive_lineage_match = True

                            # path lineage match heuristic
                            path_lineage_match = False
                            if payload and native_hit:
                                nh = (str(native_hit.get('url') or '') + ' ' + str(native_hit.get('referrer_url') or '')).lower()
                                pp = str(payload.get('path') or '').lower()
                                if any(k in nh for k in ['swisstransfer','dropbox','mega','drive.google','we.tl']) and any(k in pp for k in ['downloads','desktop','appdata','temp']):
                                    path_lineage_match = True

                            # nearest execution context
                            matched_execution_context = None
                            time_delta = None
                            if payload:
                                t_payload = _pts(payload.get('event_ts'))
                                if t_payload:
                                    deltas = []
                                    for a in a_prog:
                                        t = _pts(a.get('event_ts'))
                                        if t:
                                            deltas.append((abs((t - t_payload).total_seconds()), a))
                                    if deltas:
                                        deltas.sort(key=lambda x: x[0])
                                        time_delta, matched_execution_context = deltas[0]

                            source_type = 'none'
                            if native_hit:
                                source_type = 'native_browser'
                            elif motw_hit:
                                source_type = 'motw_zone'
                            elif archive_lineage_match:
                                source_type = 'archive_lineage'
                            elif raw_rows:
                                source_type = 'fallback_text'
                            elif payload:
                                source_type = 'artifact_temporal'

                            matched_url = suspicious_url
                            matched_payload = (payload.get('artifact') if payload else None)
                            matched_first_execution = (matched_execution_context.get('artifact') if isinstance(matched_execution_context, dict) else None)

                            # universal scores
                            path_lineage_score = 1.0 if path_lineage_match else 0.0
                            artifact_continuity_score = 1.0 if (matched_payload and matched_first_execution) else (0.6 if matched_payload else 0.0)
                            if time_delta is None:
                                time_adjacency_score = 0.0
                            elif time_delta <= 3600:
                                time_adjacency_score = 1.0
                            elif time_delta <= 86400:
                                time_adjacency_score = 0.6
                            else:
                                time_adjacency_score = 0.2
                            source_reliability_score = {
                                'native_browser': 1.0,
                                'motw_zone': 0.85,
                                'archive_lineage': 0.7,
                                'fallback_text': 0.45,
                                'artifact_temporal': 0.35,
                                'none': 0.0,
                            }.get(source_type, 0.0)

                            corr = (path_lineage_score*0.30 + artifact_continuity_score*0.30 + time_adjacency_score*0.20 + source_reliability_score*0.20)

                            link_strength = 'none'
                            gaps = []
                            has_partial_lineage = bool(
                                (path_lineage_score > 0.0)
                                or (artifact_continuity_score > 0.0)
                                or (time_adjacency_score > 0.0)
                                or matched_download
                                or (source_type == 'fallback_text' and len(raw_rows or []) > 0)
                            )
                            if source_type in ('native_browser','motw_zone') and matched_url and matched_payload and matched_first_execution and corr >= 0.78:
                                link_strength = 'direct'
                            elif matched_payload and (matched_url or matched_download or archive_lineage_match or path_lineage_match) and corr >= 0.50:
                                link_strength = 'corroborating'
                            elif corr >= 0.28 or has_partial_lineage:
                                link_strength = 'weak'
                            else:
                                gaps.append('no_strict_origin_to_payload_lineage')

                            sample_rows = []
                            if native_hit:
                                sample_rows.append({'native': native_hit})
                            if motw_hit:
                                sample_rows.append({'motw': motw_hit})
                            if matched_download:
                                sample_rows.append({'download': matched_download})
                            if payload:
                                sample_rows.append({'payload': payload})
                            if matched_execution_context:
                                sample_rows.append({'execution_context': matched_execution_context})
                            sample_rows.extend([{'raw': x} for x in raw_rows[:2]])

                            _push_probe(
                                p,
                                'initial_access',
                                'delivery_native_linker_v2 origin/download/archive -> payload -> execution context',
                                sample_rows,
                                meta={
                                    'link_strength': link_strength,
                                    'source_type': source_type,
                                    'matched_url_or_origin': matched_url,
                                    'matched_download': matched_download,
                                    'matched_payload': matched_payload,
                                    'matched_execution_context': (matched_execution_context.get('artifact') if isinstance(matched_execution_context, dict) else None),
                                    'matched_first_execution': matched_first_execution,
                                    'path_lineage_match': bool(path_lineage_match),
                                    'archive_lineage_match': bool(archive_lineage_match),
                                    'path_lineage_score': path_lineage_score,
                                    'artifact_continuity_score': artifact_continuity_score,
                                    'time_adjacency_score': time_adjacency_score,
                                    'source_reliability_score': source_reliability_score,
                                    'time_delta': time_delta,
                                    'supporting_rows': len(sample_rows),
                                    'gaps': gaps,
                                }
                            )

                        elif p == 'probe_execution_native_linkage':
                            cur.execute("""
                                SELECT event_ts, event_id, coalesce(channel,''), left(coalesce(payload::text,''),260), source_file
                                FROM event_logs_v2
                                WHERE case_key=%s
                                  AND lower(coalesce(payload::text,'')) ~ '(powershell\\.exe|wscript\\.exe|cscript\\.exe|cmd\\.exe|mshta\\.exe|rundll32\\.exe|try\\.exe|start\\.vbs|ng\\.bat|msedgex\\.exe|ngrok\\.exe|7za\\.exe|teamviewer|anydesk)'
                                ORDER BY event_ts NULLS LAST
                                LIMIT 80
                            """, (case_key,))
                            ev_rows = [{'event_ts': str(r[0]) if r[0] else None, 'event_id': r[1], 'channel': r[2], 'payload': r[3], 'source_file': r[4]} for r in cur.fetchall()]

                            cur.execute("""
                                SELECT event_ts, lower(coalesce(executable_name,'')), lower(coalesce(full_path,'')), source_file
                                FROM program_exec_v2
                                WHERE case_key=%s
                                  AND lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) ~ '(powershell\\.exe|wscript\\.exe|cscript\\.exe|cmd\\.exe|mshta\\.exe|rundll32\\.exe|try\\.exe|start\\.vbs|ng\\.bat|msedgex\\.exe|ngrok\\.exe|7za\\.exe|teamviewer|anydesk)'
                                ORDER BY event_ts NULLS LAST
                                LIMIT 80
                            """, (case_key,))
                            prog_rows = [{'event_ts': str(r[0]) if r[0] else None, 'exe': r[1], 'path': r[2], 'source_file': r[3]} for r in cur.fetchall()]

                            cur.execute("""
                                SELECT event_ts, lower(coalesce(file_name,'')), lower(coalesce(parent_path,'')), source_file
                                FROM filesystem_v2
                                WHERE case_key=%s
                                  AND lower(coalesce(file_name,'')||' '||coalesce(parent_path,'')) ~ '(try\\.exe|start\\.vbs|ng\\.bat|msedgex\\.exe|ngrok\\.exe|7za\\.exe|teamviewer|anydesk)'
                                ORDER BY event_ts NULLS LAST
                                LIMIT 80
                            """, (case_key,))
                            fs_rows = [{'event_ts': str(r[0]) if r[0] else None, 'artifact': r[1], 'path': r[2], 'source_file': r[3]} for r in cur.fetchall()]

                            cur.execute("""
                                SELECT event_ts, coalesce(rule,''), left(coalesce(details,''),220), source_file
                                FROM tool_alerts_v2
                                WHERE case_key=%s
                                  AND lower(coalesce(rule,'')||' '||coalesce(details,'')) ~ '(powershell|wscript|cscript|cmd\\.exe|mshta|rundll32|try\\.exe|start\\.vbs|ng\\.bat|msedgex\\.exe|ngrok\\.exe|7za\\.exe|teamviewer|anydesk|script host)'
                                -- ORDER BY, бо без нього LIMIT віддає довільні рядки і звіт
                                -- відрізняється між прогонами на тих самих даних
                                ORDER BY row_id
                                LIMIT 80
                            """, (case_key,))
                            ta_rows = [{'event_ts': str(r[0]) if r[0] else None, 'rule': r[1], 'details': r[2], 'source_file': r[3]} for r in cur.fetchall()]

                            all_art = prog_rows + fs_rows

                            def _pts(v):
                                return _parse_ts(v) if v else None

                            # execution_correlation_enricher_v1
                            # try to correlate process<->artifact<->path<->time + tool/appcompat context
                            corr_best = None
                            for ev in ev_rows[:30]:
                                ptxt = str(ev.get('payload') or '').lower()
                                # parse weak user/host/parent hints from payload text
                                m_user = None; m_host = None; m_parent = None
                                for tok in ['user','target_user','subject_user','account']:
                                    i = ptxt.find(tok)
                                    if i >= 0:
                                        m_user = ptxt[i:i+120]
                                        break
                                for tok in ['computer','host','workstation','remote_host']:
                                    i = ptxt.find(tok)
                                    if i >= 0:
                                        m_host = ptxt[i:i+120]
                                        break
                                for tok in ['parentimage','parentprocessname','parent','commandline']:
                                    i = ptxt.find(tok)
                                    if i >= 0:
                                        m_parent = ptxt[i:i+160]
                                        break

                                for a in all_art[:80]:
                                    art = (str(a.get('exe') or '') + ' ' + str(a.get('artifact') or '')).lower()
                                    apath = str(a.get('path') or '').lower()
                                    # matching dimensions
                                    artifact_match = any(k in (ptxt + ' ' + art) for k in ['try.exe','start.vbs','ng.bat','msedgex.exe','ngrok.exe','7za.exe','powershell.exe','wscript.exe','cscript.exe','mshta.exe','rundll32.exe','teamviewer','anydesk'])
                                    path_match = False
                                    if apath:
                                        for seg in ['\\users\\public\\documents','\\users\\user\\appdata\\local','\\desktop\\','teamviewer','anydesk','ngrok','7za']:
                                            if seg in apath and seg in ptxt:
                                                path_match = True
                                                break
                                    t0 = _pts(ev.get('event_ts')); t1 = _pts(a.get('event_ts'))
                                    td = abs((t1 - t0).total_seconds()) if (t0 and t1) else None
                                    time_match = (td is not None and td <= 7200)

                                    # tool/appcompat corroboration
                                    tool_support = 0
                                    key_blob = (art + ' ' + apath)
                                    for tr in ta_rows[:80]:
                                        tb = (str(tr.get('rule') or '') + ' ' + str(tr.get('details') or '')).lower()
                                        if any(k in tb for k in ['powershell','wscript','cscript','cmd.exe','mshta','rundll32','try.exe','start.vbs','ng.bat','msedgex.exe','ngrok.exe','7za.exe','teamviewer','anydesk']):
                                            if any(k in tb for k in ['try.exe','start.vbs','ng.bat','msedgex.exe','ngrok.exe','7za.exe','teamviewer','anydesk']) or any(k in key_blob for k in ['try.exe','start.vbs','ng.bat','msedgex.exe','ngrok.exe','7za.exe','teamviewer','anydesk']):
                                                tool_support = 1
                                                break

                                    # score
                                    score = 0
                                    if artifact_match: score += 40
                                    if path_match: score += 25
                                    if time_match: score += 20
                                    if tool_support: score += 15
                                    if m_parent: score += 5

                                    cand = {
                                        'event': ev, 'artifact': a,
                                        'matched_user': m_user,
                                        'matched_host': m_host,
                                        'matched_parent': m_parent,
                                        'artifact_match': bool(artifact_match),
                                        'path_match': bool(path_match),
                                        'time_match': bool(time_match),
                                        'time_delta': td,
                                        'correlation_score': score,
                                    }
                                    if (corr_best is None) or (cand['correlation_score'] > corr_best['correlation_score']):
                                        corr_best = cand

                            native_exec = ev_rows[0] if ev_rows else None
                            matched = (corr_best or {}).get('artifact') if corr_best else (all_art[0] if all_art else None)
                            td = (corr_best or {}).get('time_delta') if corr_best else None

                            source_type = 'none'
                            if native_exec:
                                source_type = 'native_execution'
                            elif prog_rows:
                                source_type = 'appcompat_amcache'
                            elif ta_rows:
                                source_type = 'tool_alert_context'
                            elif fs_rows:
                                source_type = 'artifact_temporal'

                            link_strength = 'none'
                            gaps = []
                            matched_process = (native_exec.get('payload') if native_exec else (matched.get('exe') if matched else None))
                            matched_artifact = (matched.get('artifact') if matched else (matched.get('exe') if matched else None))
                            matched_path = (matched.get('path') if matched else None)
                            corr_score = int((corr_best or {}).get('correlation_score') or 0)

                            if source_type == 'native_execution' and corr_score >= 70 and (corr_best or {}).get('artifact_match') and ((corr_best or {}).get('time_match') or (corr_best or {}).get('path_match')):
                                link_strength = 'direct'
                            elif corr_score >= 45 and source_type in ('native_execution','appcompat_amcache','tool_alert_context'):
                                link_strength = 'corroborating'
                            elif corr_score >= 20 or source_type in ('artifact_temporal','tool_alert_context'):
                                link_strength = 'weak'
                            else:
                                gaps.append('no_usable_execution_linkage')

                            sample_rows = []
                            sample_rows.extend([{'native': x} for x in ev_rows[:3]])
                            sample_rows.extend([{'program': x} for x in prog_rows[:3]])
                            sample_rows.extend([{'filesystem': x} for x in fs_rows[:3]])
                            sample_rows.extend([{'tool': x} for x in ta_rows[:3]])

                            _push_probe(
                                p,
                                'execution',
                                'native execution linkage (event/program/files/tool)',
                                sample_rows,
                                meta={
                                    'link_strength': link_strength,
                                    'source_type': source_type,
                                    'matched_process': matched_process,
                                    'matched_artifact': matched_artifact,
                                    'matched_path': matched_path,
                                    'matched_user': (corr_best or {}).get('matched_user') if corr_best else None,
                                    'matched_host': (corr_best or {}).get('matched_host') if corr_best else None,
                                    'matched_parent': (corr_best or {}).get('matched_parent') if corr_best else None,
                                    'path_match': (corr_best or {}).get('path_match') if corr_best else False,
                                    'artifact_match': (corr_best or {}).get('artifact_match') if corr_best else False,
                                    'time_match': (corr_best or {}).get('time_match') if corr_best else False,
                                    'correlation_score': corr_score,
                                    'time_delta': td,
                                    'supporting_rows': len(sample_rows),
                                    'gaps': gaps,
                                }
                            )

                    except Exception as e:
                        try:
                            conn.rollback()
                        except Exception:
                            try: conn.rollback()
                            except: pass
                            pass
                        errors.append({'probe': p, 'error': str(e)[:220]})

                # bounded loop: second iteration only if we still have no useful rows
                useful = sum(int(x.get('row_count') or 0) for x in results)
                if useful > 0:
                    break

    return {
        'scope_mode': 'case_drilldown_v1',
        'max_iterations': 2,
        'max_probes': 3,
        'planned_probes': planned,
        'planner_gate': {
            'llm_ranked_probe_plan': llm_ranked[:6],
            'llm_probe_blocklist': sorted(list(llm_block))[:6],
            'deterministic_fallback_plan': det_planned[:6],
            'llm_source_mode': str((llm_triage or {}).get('source_mode') or 'unknown')
        },
        'probes_run': probes_run,
        'results': results,
        'errors': errors,
        'summary': {
            'total_rows': sum(int(x.get('row_count') or 0) for x in results),
            'chains_touched': sorted(list({x.get('chain') for x in results if x.get('chain')}))
        }
    }


def _assemble_case_reasoning_v1(case_key, cor, inc, coverage, drill=None, llm_triage=None):
    def _txt(it):
        return (str(it.get('indicator') or '') + ' ' + ' '.join([str(x) for x in (it.get('evidence_samples') or [])])).lower()

    # strict class rules:
    # - direct only for strict/native/high-confidence evidence
    # - partial/likely/normalized_but_no_strict_hit/text_fallback can never be direct
    def _rank_item(item, bucket):
        t = _txt(item)
        hint = str(item.get('status_hint') or '').lower()
        ind = str(item.get('indicator') or '').lower()

        # benign/noise first
        if any(x in t for x in ['onedrive', 'g.live.com/odclientsettings', 'microsoft.com', 'edgewelcome', 'bing.com', 'msn.com']):
            return 'benign_noise'

        # weak conditions (cannot be direct)
        weak_markers = ['missing_proof', 'missing_join', 'text_fallback', 'normalized_but_no_strict_hit', 'verdict=partial', 'confidence=low']
        if any(x in t for x in weak_markers) or bucket in ('needs_review', 'tool_only'):
            return 'weak'

        # direct only from strong strict proof patterns
        direct_tokens = ['event_id=1102', 'event_id=104', 'strict_hit', 'direct_execution_proof', 'zone_identifier', 'motw']
        if bucket == 'confirmed' and (any(x in t for x in direct_tokens) or any(x in hint for x in ['strict', 'direct_execution_proof', 'covered'])):
            return 'direct'

        # ransomware family evidence is strong corroborating for impact (not direct by default)
        if any(x in t for x in ['ransom_extension_mass', 'ransom_note_pattern']) or ind == 'impact_chain':
            return 'corroborating'

        if any(x in t for x in ['rdp_external_burst', 'log_tampering', 'remote_tooling_context', 'add-mppreference', 'exclusionpath', 'wscript', 'powershell', 'ngrok', '7za']):
            return 'corroborating'

        return 'weak'

    def _map_chain(item):
        t = _txt(item)
        ind = str(item.get('indicator') or '').lower()
        if any(x in t for x in ['ransom_extension_mass', 'ransom_note_pattern']) or ind in ('impact_chain','file_drop_chain'):
            return 'impact'
        if any(x in t for x in ['delivery_browser_provenance', 'delivery', 'browser', 'motw', 'swisstransfer']):
            return 'initial_access'
        if any(x in t for x in ['script_host_execution_linkage', 'script_or_batch_execution_event', 'wscript', 'powershell', 'cmd.exe']):
            return 'execution'
        if any(x in t for x in ['rdp_user_creation_linkage', 'rdp_external_burst', 'ngrok', 'remote_tooling_context']):
            return 'persistence_remote'
        if any(x in t for x in ['defender_tampering', 'log_tampering', 'mppreference', 'exclusionpath']):
            return 'defense_evasion_tampering'
        return None

    evidence_catalog = []
    seq = 1
    for bucket in ['confirmed', 'likely', 'needs_review', 'tool_only']:
        for it in (cor.get(bucket) or []):
            if not isinstance(it, dict):
                continue
            cls = _rank_item(it, bucket)
            chain = _map_chain(it)
            ev = {
                'id': f"E{seq:03d}",
                'class': cls,
                'bucket': bucket,
                'indicator': it.get('indicator'),
                'chain': chain,
                'fact': (it.get('evidence_samples') or [''])[0],
                'source': ','.join([str(x) for x in (it.get('source_tables') or [])[:3]])
            }
            evidence_catalog.append(ev)
            seq += 1

    # execution enrichment from incident timeline (case-scoped, evidence-only)
    for ev in (inc or []):
        s = str((ev or {}).get('summary') or '').lower()
        if any(k in s for k in ['script_or_batch_execution_event', 'staged_execution_context_event', 'wscript', 'cscript', 'powershell', 'cmd.exe', 'try.exe']):
            evidence_catalog.append({
                'id': f"E{seq:03d}",
                'class': 'corroborating' if 'script_or_batch_execution_event' in s else 'weak',
                'bucket': 'timeline',
                'indicator': 'execution_chain',
                'chain': 'execution',
                'fact': str((ev or {}).get('summary') or '')[:220],
                'source': str((ev or {}).get('source_table') or '')
            })
            seq += 1

    # add drilldown evidence (bounded probes) as additional corroborating/weak inputs
    for pr in ((drill or {}).get('results') or []):
        chain = pr.get('chain')
        rows = pr.get('rows') or []
        rc = int(pr.get('row_count') or 0)
        if not chain:
            continue

        # strict handling for initial access native linkage probe
        if str(pr.get('probe') or '') == 'probe_initial_access_native_linkage':
            ls = str(pr.get('link_strength') or 'none').lower()
            st = str(pr.get('source_type') or 'none').lower()
            org = pr.get('matched_url_or_origin')
            dl = pr.get('matched_download')
            payload = pr.get('matched_payload')
            fx = pr.get('matched_first_execution') or pr.get('matched_execution_context')
            plm = bool(pr.get('path_lineage_match'))
            alm = bool(pr.get('archive_lineage_match'))
            pls = float(pr.get('path_lineage_score') or 0)
            acs = float(pr.get('artifact_continuity_score') or 0)
            tas = float(pr.get('time_adjacency_score') or 0)
            srs = float(pr.get('source_reliability_score') or 0)
            td = pr.get('time_delta')
            corr = (pls*0.30 + acs*0.30 + tas*0.20 + srs*0.20)
            if ls == 'direct' and st in ('native_browser', 'motw_zone') and org and payload and fx and corr >= 0.78:
                cls = 'direct'
            elif ls == 'corroborating' and payload and (org or dl or plm or alm) and corr >= 0.50:
                cls = 'corroborating'
            elif ls == 'weak':
                cls = 'weak'
            else:
                cls = None
            if cls:
                evidence_catalog.append({
                    'id': f"E{seq:03d}",
                    'class': cls,
                    'bucket': 'drilldown',
                    'indicator': 'initial_access_native_linkage_v1',
                    'chain': 'initial_access',
                    'fact': f"source_type={st} link_strength={ls} origin={org or '-'} download={str(dl or '-')[:120]} payload={payload or '-'} first_exec={fx or '-'} pls={pls:.2f} acs={acs:.2f} tas={tas:.2f} srs={srs:.2f} time_delta={td if td is not None else '-'}",
                    'source': 'case_drilldown_v1'
                })
                seq += 1
            continue

        # strict handling for execution native linkage probe
        if str(pr.get('probe') or '') == 'probe_execution_native_linkage':
            ls = str(pr.get('link_strength') or 'none').lower()
            st = str(pr.get('source_type') or 'none').lower()
            mp = pr.get('matched_process')
            ma = pr.get('matched_artifact')
            mpth = pr.get('matched_path')
            td = pr.get('time_delta')
            score = int(pr.get('correlation_score') or 0)
            artm = bool(pr.get('artifact_match'))
            pathm = bool(pr.get('path_match'))
            timem = bool(pr.get('time_match'))
            if ls == 'direct' and st == 'native_execution' and score >= 70 and artm and (pathm or timem):
                cls = 'direct'
            elif ls == 'corroborating' and score >= 45 and st in ('native_execution','appcompat_amcache','tool_alert_context') and (mp or ma):
                cls = 'corroborating'
            elif ls == 'weak':
                cls = 'weak'
            else:
                cls = None
            if cls:
                evidence_catalog.append({
                    'id': f"E{seq:03d}",
                    'class': cls,
                    'bucket': 'drilldown',
                    'indicator': 'execution_native_linkage_v1',
                    'chain': 'execution',
                    'fact': f"source_type={st} link_strength={ls} score={score} artifact_match={artm} path_match={pathm} time_match={timem} process={mp or '-'} artifact={ma or '-'} path={mpth or '-'} time_delta={td if td is not None else '-'}",
                    'source': 'case_drilldown_v1'
                })
                seq += 1
            continue

        if rc <= 0:
            continue
        evidence_catalog.append({
            'id': f"E{seq:03d}",
            'class': 'corroborating' if rc >= 2 else 'weak',
            'bucket': 'drilldown',
            'indicator': f"{pr.get('probe')}_evidence",
            'chain': chain,
            'fact': f"probe={pr.get('probe')} rows={rc}",
            'source': 'case_drilldown_v1'
        })
        seq += 1

    # add LLM triage structured findings as bounded hints
    for f in ((llm_triage or {}).get('findings') or []):
        if not isinstance(f, dict):
            continue
        ch = str(f.get('chain') or '')
        if ch not in ('initial_access','execution','persistence_remote','defense_evasion_tampering','impact'):
            continue
        conf = float(f.get('confidence') or 0)
        cls = 'corroborating' if conf >= 0.65 else ('weak' if conf >= 0.35 else None)
        if not cls:
            continue
        evidence_catalog.append({
            'id': f"E{seq:03d}",
            'class': cls,
            'bucket': 'llm_triage',
            'indicator': 'llm_triage_finding',
            'chain': ch,
            'fact': f"type={str(f.get('finding_type') or '-')[:24]} conf={conf:.2f} why={str(f.get('why_relevant') or '')[:140]} probe={str(f.get('suggested_next_probe') or '-')[:48]}",
            'source': 'case_llm_triage_v1'
        })
        seq += 1

    # bounded planner-gate influence: keep as weak/corroborating hints only (no direct promotion)
    for u in (((llm_triage or {}).get('decision') or {}).get('chain_confidence_updates') or []):
        if not isinstance(u, dict):
            continue
        ch = str(u.get('chain') or '')
        if ch not in ('initial_access','execution','persistence_remote','defense_evasion_tampering','impact'):
            continue
        conf = max(0.0, min(1.0, float(u.get('confidence') or 0.0)))
        cls = 'corroborating' if conf >= 0.7 else ('weak' if conf >= 0.45 else None)
        if not cls:
            continue
        evidence_catalog.append({
            'id': f"E{seq:03d}",
            'class': cls,
            'bucket': 'llm_planner_gate',
            'indicator': 'llm_chain_confidence_update',
            'chain': ch,
            'fact': f"chain_conf={conf:.2f} rationale={str(u.get('rationale') or '')[:140]}",
            'source': 'case_llm_triage_v1'
        })
        seq += 1

    # add family evidence with stronger chain influence (impact / persistence / tampering)
    fam = {str(f.get('family') or ''): f for f in (((cor.get('trigger_correlation') or {}).get('families') or []))}

    def _add_family(fam_key, chain, indicator, cls='corroborating'):
        nonlocal seq
        x = fam.get(fam_key)
        if not x:
            return
        evidence_catalog.append({
            'id': f"E{seq:03d}",
            'class': cls,
            'bucket': 'family',
            'indicator': indicator,
            'chain': chain,
            'fact': f"family={fam_key} source_ref={x.get('source_ref')} score={x.get('score')}",
            'source': str(x.get('source_table') or 'case_trigger_hits_v2')
        })
        seq += 1

    _add_family('ransom_extension_mass', 'impact', 'impact_chain', 'corroborating')
    _add_family('ransom_note_pattern', 'impact', 'impact_chain', 'corroborating')
    _add_family('rdp_external_burst', 'persistence_remote', 'persistence_remote_chain', 'corroborating')
    # log tampering may be direct when explicit event-log-clear semantics are present
    lt = fam.get('log_tampering')
    if lt and any(k in str(lt.get('source_ref') or '').lower() for k in ['event_id=104', 'event_id=1102', 'logclear', 'clear-eventlog']):
        _add_family('log_tampering', 'defense_evasion_tampering', 'defense_evasion_chain', 'direct')
    else:
        _add_family('log_tampering', 'defense_evasion_tampering', 'defense_evasion_chain', 'corroborating')
    _add_family('remote_tooling_context', 'persistence_remote', 'persistence_remote_chain', 'corroborating')

    # stable order: class first, then chain priority so strong family signals stay on top
    cls_rank = {'direct': 0, 'corroborating': 1, 'weak': 2, 'benign_noise': 3}
    chain_rank = {'impact': 0, 'persistence_remote': 1, 'defense_evasion_tampering': 2, 'execution': 3, 'initial_access': 4, None: 9}
    evidence_catalog = sorted(
        evidence_catalog,
        key=lambda e: (
            cls_rank.get(e.get('class'), 9),
            chain_rank.get(e.get('chain'), 9),
            0 if e.get('bucket') == 'family' else 1,
            str(e.get('indicator') or '')
        )
    )[:80]

    # compaction: dedup equivalent rows, keep strongest
    compact = {}
    for e in evidence_catalog:
        sig = (
            str(e.get('class') or ''),
            str(e.get('chain') or ''),
            str(e.get('indicator') or ''),
            str(e.get('fact') or '')[:120].lower()
        )
        prev = compact.get(sig)
        if prev is None:
            compact[sig] = e
            continue
        # prefer family/drilldown over generic weak duplicates
        p_cur = 1 if e.get('bucket') in ('family', 'drilldown') else 0
        p_prev = 1 if prev.get('bucket') in ('family', 'drilldown') else 0
        if p_cur > p_prev:
            compact[sig] = e
    evidence_catalog = list(compact.values())

    def _pick(chain, classes=('direct', 'corroborating')):
        return [e['id'] for e in evidence_catalog if e.get('chain') == chain and e.get('class') in classes][:6]

    def _pick_counter(chain):
        return [e['id'] for e in evidence_catalog if e.get('chain') == chain and e.get('class') in ('weak', 'benign_noise')][:6]

    def _chain_status(chain):
        d = len(_pick(chain, classes=('direct',)))
        c = len(_pick(chain, classes=('corroborating',)))
        if d >= 2:
            return 'confirmed'
        if d >= 1 or c >= 2:
            return 'corroborated'
        if c >= 1:
            return 'partial'
        return 'inconclusive'

    chains = {}
    for ch in ['initial_access', 'execution', 'persistence_remote', 'defense_evasion_tampering', 'impact']:
        chains[ch] = {
            'status': _chain_status(ch),
            'evidence_ids': _pick(ch),
            'counter_evidence_ids': _pick_counter(ch)
        }

    # honest downgrade for initial access when only weak delivery signals exist
    if chains['initial_access']['status'] in ('corroborated', 'partial'):
        has_direct_or_corr = any(e.get('chain') == 'initial_access' and e.get('class') in ('direct', 'corroborating') for e in evidence_catalog)
        if not has_direct_or_corr:
            chains['initial_access']['status'] = 'inconclusive'

    # initial_access_aggregation_v1: allow bounded promotion from multiple independent weak signals
    # + initial_access_evidence_mapping_cleanup_v1: keep positive weak IA signals out of counter set
    ia_weak_all = [e for e in evidence_catalog if e.get('chain') == 'initial_access' and e.get('class') == 'weak']

    def _ia_is_positive_weak(e):
        ind = str(e.get('indicator') or '').lower()
        fact = str(e.get('fact') or '').lower()
        # explicit blockers/gaps must stay counter-only
        if ('no_strict' in fact) or ('gap' in fact) or ('contradict' in fact) or ('blocker' in fact):
            return False
        return ind in ('initial_access_native_linkage_v1', 'delivery_browser_provenance')

    ia_positive_weak = [e for e in ia_weak_all if _ia_is_positive_weak(e)]
    ia_positive_ids = [e.get('id') for e in ia_positive_weak if e.get('id')]
    ia_counter_ids = [e.get('id') for e in ia_weak_all if e.get('id') and e.get('id') not in set(ia_positive_ids)]

    if chains['initial_access']['status'] == 'inconclusive':
        source_div = sorted(list({str(e.get('source') or '') for e in ia_positive_weak if str(e.get('source') or '')}))

        # read consistency from drilldown probe meta (if present)
        ia_probe = None
        for pr in ((drill or {}).get('results') or []):
            if str(pr.get('probe') or '') == 'probe_initial_access_native_linkage':
                ia_probe = pr
                break

        pls = float((ia_probe or {}).get('path_lineage_score') or 0.0)
        acs = float((ia_probe or {}).get('artifact_continuity_score') or 0.0)
        tas = float((ia_probe or {}).get('time_adjacency_score') or 0.0)
        srs = float((ia_probe or {}).get('source_reliability_score') or 0.0)
        link_strength = str((ia_probe or {}).get('link_strength') or 'none').lower()
        support_rows = int((ia_probe or {}).get('supporting_rows') or 0)
        coherence = (pls*0.30 + acs*0.30 + tas*0.20 + srs*0.20)

        has_continuity = bool((pls > 0.0) or (acs > 0.0) or (tas > 0.0) or (support_rows >= 2) or (link_strength in ('weak', 'corroborating')))

        # bounded, no fake direct promotion
        if len(ia_positive_weak) >= 2 and len(source_div) >= 2 and has_continuity:
            chains['initial_access']['status'] = 'partial'
            chains['initial_access']['evidence_ids'] = ia_positive_ids[:4]
        if len(ia_positive_weak) >= 3 and len(source_div) >= 3 and coherence >= 0.55 and link_strength in ('weak', 'corroborating'):
            chains['initial_access']['status'] = 'corroborated'
            chains['initial_access']['evidence_ids'] = ia_positive_ids[:4]

    # mapping cleanup: never mirror positive weak IA IDs into counter set
    if chains['initial_access']['status'] in ('partial', 'corroborated'):
        if not (chains['initial_access'].get('evidence_ids') or []):
            chains['initial_access']['evidence_ids'] = ia_positive_ids[:4]
        chains['initial_access']['counter_evidence_ids'] = [x for x in ia_counter_ids[:6] if x not in set(chains['initial_access']['evidence_ids'] or [])]

    # impact fallback for strong non-ransomware chains (file-drop/tooling/staging coherence)
    if chains['impact']['status'] == 'inconclusive':
        has_filedrop_like = any(str(e.get('indicator') or '').lower() in ('file_drop_chain','ngrok_7za_chain','probe_impact_deep_evidence') and e.get('class') in ('direct','corroborating') for e in evidence_catalog)
        has_tooling = any(str(e.get('indicator') or '').lower() in ('persistence_remote_chain','probe_remote_tooling_deep_evidence','ngrok_7za_chain') and e.get('class') in ('direct','corroborating') for e in evidence_catalog)
        exec_ok = chains['execution']['status'] in ('confirmed','corroborated','partial')
        persist_ok = chains['persistence_remote']['status'] in ('confirmed','corroborated','partial')
        defense_ok = chains['defense_evasion_tampering']['status'] in ('confirmed','corroborated','partial')
        if (has_filedrop_like or has_tooling) and exec_ok and (persist_ok or defense_ok):
            chains['impact']['status'] = 'corroborated'
        elif (has_filedrop_like or has_tooling) and exec_ok:
            chains['impact']['status'] = 'partial'

    # ensure impact has surfaced evidence ids when promoted via coherence fallback
    if chains['impact']['status'] in ('partial','corroborated','confirmed') and not (chains['impact'].get('evidence_ids') or []):
        promote = [
            e['id'] for e in evidence_catalog
            if e.get('class') in ('direct','corroborating') and (
                e.get('chain') == 'impact' or
                str(e.get('indicator') or '').lower() in ('file_drop_chain','ngrok_7za_chain','probe_impact_deep_evidence','probe_remote_tooling_deep_evidence')
            )
        ]
        chains['impact']['evidence_ids'] = promote[:4]

    strong = sum(1 for v in chains.values() if v['status'] in ('confirmed', 'corroborated'))
    partial = sum(1 for v in chains.values() if v['status'] == 'partial')

    if strong >= 3:
        verdict, conf = 'compromised', 'high'
    elif chains['impact']['status'] in ('confirmed', 'corroborated') and (chains['execution']['status'] in ('confirmed', 'corroborated', 'partial') or chains['persistence_remote']['status'] in ('confirmed', 'corroborated', 'partial')):
        verdict, conf = 'likely_compromised', ('medium' if strong >= 2 else 'low')
    elif strong >= 1 or partial >= 2:
        verdict, conf = 'likely_compromised', 'low'
    else:
        verdict, conf = 'inconclusive', 'low'

    milestones = []
    if fam.get('ransom_extension_mass') and fam.get('ransom_note_pattern'):
        ts = fam.get('ransom_extension_mass', {}).get('event_ts') or fam.get('ransom_note_pattern', {}).get('event_ts')
        milestones.append({
            'stage': 'impact',
            'event_ts': ts,
            'title': 'Mass encryption impact + ransom note pattern confirmed',
            'why': 'Combined ransomware-family signal from normalized evidence.'
        })

    return {
        'summary_verdict': verdict,
        'confidence': conf,
        'chains': chains,
        'key_uncertainties': [
            'initial_access_unproven' if chains['initial_access']['status'] in ('partial', 'inconclusive') else None,
            'delivery_strict_linkage_gap' if chains['initial_access']['status'] != 'confirmed' else None,
        ],
        'competing_hypotheses': [
            {
                'name': 'ransomware_like_operational_chain',
                'support_evidence_ids': chains['impact']['evidence_ids'][:3] + chains['execution']['evidence_ids'][:2],
                'gaps': ['strict_initial_access_native_proof'] if chains['initial_access']['status'] != 'confirmed' else []
            }
        ],
        'evidence_catalog': evidence_catalog[:40],
        'narrative_milestones': milestones,
        'coverage': coverage,
        'scope_mode': 'case_reasoning_v1'
    }


def _normalize_core_step_meta(step_code, meta):
    meta = meta if isinstance(meta, dict) else {}

    def _arr(v):
        return v if isinstance(v, list) else ([] if v is None else ([v] if not isinstance(v, dict) else []))

    def _obj(v):
        return v if isinstance(v, dict) else {}

    def _contract_status(obj, req_keys):
        missing = [k for k in req_keys if k not in obj]
        if missing:
            return 'invalid'
        return 'ok'

    if step_code == 'corroboration':
        out = {
            'schema_version': 'm2.1-corroboration-v1',
            'contract_status': 'ok',
            'confirmed': _arr(meta.get('confirmed')),
            'likely': _arr(meta.get('likely')),
            'tool_only': _arr(meta.get('tool_only')),
            'needs_review': _arr(meta.get('needs_review')),
            'coverage': _obj(meta.get('coverage')),
            'trigger_correlation': _obj(meta.get('trigger_correlation')),
            'assembler': _obj(meta.get('assembler')),
        }
        out['contract_status'] = _contract_status(out, ['schema_version','contract_status','confirmed','likely','tool_only','needs_review','coverage','trigger_correlation','assembler'])
        return out

    if step_code == 'incident_timeline':
        rows = _arr(meta.get('incident_timeline'))
        norm_rows = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            rr = dict(r)
            rr['source_table'] = str(rr.get('source_table') or '')
            rr['source_ref'] = str(rr.get('source_ref') or rr.get('source_file') or '')
            rr['source_file'] = str(rr.get('source_file') or '')
            rr['time_source'] = str(rr.get('time_source') or ('missing' if rr.get('event_ts') in (None, '') else 'native'))
            if rr.get('event_ts') in ('',):
                rr['event_ts'] = None
            norm_rows.append(rr)
        out = {
            'schema_version': 'm2.1-incident_timeline-v1',
            'contract_status': 'ok',
            'incident_timeline': norm_rows,
            'coverage': _obj(meta.get('coverage')),
            'assembler': _obj(meta.get('assembler')),
        }
        out['contract_status'] = _contract_status(out, ['schema_version','contract_status','incident_timeline','coverage','assembler'])
        return out

    if step_code == 'case_reasoning_v1':
        rr = _obj(meta.get('case_reasoning_v1'))
        verdict = str(rr.get('summary_verdict') or 'unknown').strip().lower() or 'unknown'
        allowed = {'compromised','not_compromised','inconclusive','unknown'}
        if verdict not in allowed:
            verdict = 'unknown'
        out_reason = {
            **rr,
            'summary_verdict': verdict,
            'chains': _obj(rr.get('chains')),
            'confidence_overall': str(rr.get('confidence_overall') or 'low'),
            'gaps': _arr(rr.get('gaps')),
        }
        out = {
            'schema_version': 'm2.1-case_reasoning-v1',
            'contract_status': 'ok',
            'case_reasoning_v1': out_reason,
            'coverage': _obj(meta.get('coverage')),
            'assembler': _obj(meta.get('assembler')),
        }
        out['contract_status'] = _contract_status(out, ['schema_version','contract_status','case_reasoning_v1','coverage','assembler'])
        return out

    if step_code == 'ioc_artifacts':
        rows = _arr(meta.get('ioc_artifacts'))
        norm_rows = []
        for r in rows:
            if isinstance(r, dict):
                rr = dict(r)
                rr['source_table'] = str(rr.get('source_table') or '')
                rr['source_ref'] = str(rr.get('source_ref') or rr.get('source_file') or rr.get('ioc') or rr.get('artifact') or '')
                rr['source_file'] = str(rr.get('source_file') or '')
                rr['time_source'] = str(rr.get('time_source') or ('missing' if rr.get('event_ts') in (None, '') else 'native'))
                if rr.get('event_ts') in ('',):
                    rr['event_ts'] = None
                norm_rows.append(rr)
            else:
                norm_rows.append({'value': str(r), 'source_table':'', 'source_ref': str(r), 'source_file':'', 'event_ts': None, 'time_source':'missing'})
        out = {
            'schema_version': 'm2.1-ioc_artifacts-v1',
            'contract_status': 'ok',
            'ioc_artifacts': norm_rows,
            'coverage': _obj(meta.get('coverage')),
            'assembler': _obj(meta.get('assembler')),
        }
        out['contract_status'] = _contract_status(out, ['schema_version','contract_status','ioc_artifacts','coverage','assembler'])
        return out

    return meta




def _build_general_triage_v1(case_key, run_id, tri_raw=None):
    tri_raw = tri_raw if isinstance(tri_raw, dict) else {}
    out = {
        'schema_version': 'm2.2-triage-v1',
        'triage_status': 'ok',
        'likely_initial_access_candidates': [],
        'likely_execution_paths': [],
        'likely_persistence_paths': [],
        'likely_tampering_paths': [],
        'prioritized_next_steps': [],
        'confidence_overall': 'medium',
        'manual_checks': [],
        'notes': [],
    }

    # Try to load staging + narrowed window only
    rows = []
    tw = {}
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                eff_run_id = run_id
                cur.execute("SELECT count(*) FROM public.tmp_case_trigger_timeline WHERE run_id=%s AND case_key=%s", (run_id, case_key))
                c = int((cur.fetchone() or [0])[0] or 0)
                if c == 0:
                    cur.execute("SELECT run_id FROM public.tmp_case_trigger_timeline WHERE case_key=%s ORDER BY event_ts DESC NULLS LAST LIMIT 1", (case_key,))
                    rrid = cur.fetchone()
                    if rrid and rrid[0]:
                        eff_run_id = rrid[0]

                cur.execute("""
                    SELECT event_ts, trigger, source_table, source_ref, artifact_family, snippet, score
                    FROM public.tmp_case_trigger_timeline
                    WHERE run_id=%s AND case_key=%s
                    ORDER BY event_ts NULLS LAST, score DESC
                    LIMIT 300
                """, (eff_run_id, case_key))
                for r in cur.fetchall():
                    rows.append({
                        'event_ts': r[0].isoformat() if r[0] else None,
                        'trigger': r[1] or '',
                        'source_table': r[2] or '',
                        'source_ref': r[3] or '',
                        'artifact_family': r[4] or '',
                        'snippet': (r[5] or '')[:300],
                        'score': float(r[6] or 0),
                    })
                cur.execute("""
                    SELECT anchor_ts, month_start, month_end, window_start, window_end, rationale
                    FROM public.trigger_time_windows_v1
                    WHERE run_id=%s
                    LIMIT 1
                """, (eff_run_id,))
                rr = cur.fetchone()
                if rr:
                    tw = {
                        'anchor_ts': rr[0].isoformat() if rr[0] else None,
                        'month_start': rr[1].isoformat() if rr[1] else None,
                        'month_end': rr[2].isoformat() if rr[2] else None,
                        'window_start': rr[3].isoformat() if rr[3] else None,
                        'window_end': rr[4].isoformat() if rr[4] else None,
                        'rationale': rr[5] or '',
                    }

                # upstream native-source enrichment for initial access recovery
                try:
                    cur.execute("""
                        SELECT event_ts, coalesce(url,''), coalesce(referrer_url,''),
                               coalesce(download_path,''), coalesce(local_path,''),
                               coalesce(zone_identifier_host_url,''), coalesce(zone_identifier_referrer_url,''),
                               coalesce(evidence_kind,''), coalesce(source_file,''), coalesce(browser,''), coalesce(source_type,'')
                        FROM public.browser_provenance_v1
                        WHERE case_key=%s
                          AND event_ts IS NOT NULL
                          AND (%s::timestamptz IS NULL OR event_ts >= %s::timestamptz)
                          AND (%s::timestamptz IS NULL OR event_ts <= %s::timestamptz)
                        ORDER BY
                          (
                            CASE WHEN coalesce(download_path,'')<>'' OR coalesce(local_path,'')<>'' THEN 4 ELSE 0 END +
                            CASE WHEN lower(coalesce(url,'')) ~ '(\\.exe|\\.bat|\\.cmd|\\.js|\\.vbs|\\.zip|\\.rar|\\.7z)' THEN 3 ELSE 0 END +
                            CASE WHEN coalesce(zone_identifier_host_url,'')<>'' OR coalesce(zone_identifier_referrer_url,'')<>'' THEN 2 ELSE 0 END +
                            CASE WHEN EXISTS (
                              SELECT 1
                              FROM public.tmp_case_trigger_timeline t2
                              WHERE t2.run_id=%s
                                AND t2.case_key=%s
                                AND t2.event_ts IS NOT NULL
                                AND abs(extract(epoch from (event_ts - t2.event_ts))) <= 43200
                                AND lower(coalesce(t2.trigger,'')||' '||coalesce(t2.artifact_family,'')||' '||coalesce(t2.snippet,'')) ~ '(payload|dropper|archive|attachment|script|\\.zip|\\.rar|\\.7z|\\.exe|\\.bat|\\.vbs|\\.js)'
                            ) THEN 2 ELSE 0 END
                          ) DESC,
                          event_ts DESC
                        LIMIT 240
                    """, (case_key, tw.get('window_start'), tw.get('window_start'), tw.get('window_end'), tw.get('window_end'), eff_run_id, case_key))
                    for br in (cur.fetchall() or []):
                        evt_ts = br[0].isoformat() if br[0] else None
                        url = br[1] or ''
                        ref = br[2] or ''
                        dlp = br[3] or ''
                        lcp = br[4] or ''
                        zih = br[5] or ''
                        zir = br[6] or ''
                        evk = (br[7] or '').lower()
                        sf = br[8] or 'browser_provenance_v1'
                        browser_name = br[9] or ''
                        src_type = br[10] or ''

                        blob = ' '.join([url, ref, dlp, lcp, zih, zir, browser_name, src_type]).lower()
                        # keep only delivery-relevant browser rows (not generic browsing telemetry)
                        if not (dlp or lcp or zih or zir or any(k in blob for k in ['.exe','.bat','.cmd','.js','.vbs','.zip','.rar','.7z','download'])):
                            continue

                        score = 55.0 if evk == 'native' else 42.0
                        if zih or zir:
                            score += 20.0
                        if any(k in blob for k in ['.exe','.bat','.cmd','.js','.vbs','.zip','.rar','.7z']):
                            score += 10.0
                        if any(k in blob for k in ['download', 'attachment']):
                            score += 6.0

                        sn = f"browser={browser_name}; url={url[:120]}; ref={ref[:100]}; dl={dlp[:80]}; local={lcp[:80]}; zone={zih[:80] or zir[:80]}; kind={evk or 'n/a'}"
                        rows.append({
                            'event_ts': evt_ts,
                            'trigger': 'browser_provenance_event',
                            'source_table': 'browser_provenance_v1',
                            'source_ref': f"ref=bpv:{__import__('hashlib').sha1((str(evt_ts)+'|'+sf+'|'+url[:120]).encode('utf-8','ignore')).hexdigest()[:16]}",
                            'artifact_family': 'browser_provenance',
                            'snippet': sn[:300],
                            'score': float(score),
                        })
                except Exception:
                    try: conn.rollback()
                    except: pass
                    pass
    except Exception as e:
        out['triage_status'] = 'partial'
        out['notes'].append(f'staging_read_failed:{str(e)[:120]}')

    # Deterministic candidate extraction with source-priority ranking and quality guard (general, no case-specific hardcode)
    source_priority = {
        'browser': 1,
        'registry': 2,
        'event_logs': 3,
        'prefetch': 4,
        'amcache': 5,
        'jump_lists': 6,
        'mft_usn_logfile': 7,
        'lnk': 8,
        'defender': 9,
        'other': 10,
    }

    def classify_source_bucket(x):
        s = ((x.get('trigger') or '') + ' ' + (x.get('artifact_family') or '') + ' ' + (x.get('snippet') or '')).lower()
        st = (x.get('source_table') or '').lower()
        if st == 'browser_provenance_v1':
            return 'browser'
        if any(k in s for k in ['browser','url','download','zone.identifier','history','webcache']):
            return 'browser'
        if any(k in s for k in ['registry','reg key','run key','autorun']):
            return 'registry'
        if st == 'event_logs_v2':
            return 'event_logs'
        if any(k in s for k in ['prefetch']):
            return 'prefetch'
        if any(k in s for k in ['amcache']):
            return 'amcache'
        if any(k in s for k in ['jump list','jumplist']):
            return 'jump_lists'
        if any(k in s for k in ['mft','usn','$logfile']):
            return 'mft_usn_logfile'
        if any(k in s for k in ['lnk','shortcut']):
            return 'lnk'
        if any(k in s for k in ['defender','securityhealth']):
            return 'defender'
        return 'other'

    def has_min_tuple(x):
        return bool((x.get('source_table') or '').strip() and (x.get('source_ref') or '').strip() and ('event_ts' in x))

    def _dist_anchor_sec(x):
        try:
            if not tw.get('anchor_ts') or not x.get('event_ts'):
                return 10**12
            a = datetime.fromisoformat(tw.get('anchor_ts').replace('Z','+00:00'))
            e = datetime.fromisoformat(x.get('event_ts').replace('Z','+00:00'))
            return abs((e-a).total_seconds())
        except Exception:
            return 10**12

    def _blob(x):
        return ((x.get('trigger') or '') + ' ' + (x.get('artifact_family') or '') + ' ' + (x.get('snippet') or '')).lower()

    # helper sets for corroboration signals
    exec_set = {(x.get('source_table') or '', x.get('source_ref') or '', x.get('event_ts')) for x in rows if any(k in _blob(x) for k in ['powershell','cmd','wscript','cscript','execute','run','process'])}
    provenance_set = {(x.get('source_table') or '', x.get('source_ref') or '', x.get('event_ts')) for x in rows if any(k in _blob(x) for k in ['browser','url','download','zone.identifier','registry','run key'])}
    payload_set = {(x.get('source_table') or '', x.get('source_ref') or '', x.get('event_ts')) for x in rows if any(k in _blob(x) for k in ['payload','dropper','archive','attachment','script'])}

    def corroboration_profile(x):
        reasons=[]
        p = source_priority.get(classify_source_bucket(x), 10)
        sc = float(x.get('score') or 0)
        d = _dist_anchor_sec(x)
        if p <= 2:
            reasons.append('high_source_priority')
        elif p <= 4:
            reasons.append('medium_source_priority')
        if d <= 14*86400:
            reasons.append('near_anchor_14d')
        elif d <= 45*86400:
            reasons.append('near_anchor_45d')
        if sc >= 80:
            reasons.append('high_score')
        elif sc >= 30:
            reasons.append('medium_score')
        if any(k in _blob(x) for k in ['url','download','browser','zone.identifier']):
            reasons.append('browser_provenance_signal')
        if (str(x.get('source_table') or '') == 'browser_provenance_v1') and ('kind=native' in _blob(x)):
            reasons.append('native_browser_provenance_strict')
        if (str(x.get('source_table') or '') == 'browser_provenance_v1') and ('zone=' in _blob(x)):
            reasons.append('motw_zone_linkage_signal')
        if any(k in _blob(x) for k in ['registry','run key','autorun']):
            reasons.append('registry_linkage_signal')
        # cross-linkage by close time/source context
        if any(abs(_dist_anchor_sec({'event_ts':t,'source_table':s,'source_ref':r}) - d) <= 6*3600 for (s,r,t) in exec_set if t):
            reasons.append('execution_linkage_signal')
        if any(abs(_dist_anchor_sec({'event_ts':t,'source_table':s,'source_ref':r}) - d) <= 12*3600 for (s,r,t) in payload_set if t):
            reasons.append('payload_dropper_linkage_signal')
        if any(abs(_dist_anchor_sec({'event_ts':t,'source_table':s,'source_ref':r}) - d) <= 12*3600 for (s,r,t) in provenance_set if t):
            reasons.append('multi_evidence_nearby')

        corr_count=len(reasons)
        bx = _blob(x)
        st = str(x.get('source_table') or '')
        has_delivery_sig = (('dl=' in bx and 'dl=;' not in bx) or ('local=' in bx and 'local=;' not in bx) or ('zone=' in bx and 'zone=;' not in bx) or any(k in bx for k in ['.exe','.bat','.cmd','.js','.vbs','.zip','.rar','.7z','download']))
        if st == 'browser_provenance_v1' and ('kind=native' in bx) and has_delivery_sig and d <= 90*86400:
            strength='strong'
        elif st == 'browser_provenance_v1' and has_delivery_sig and d <= 120*86400:
            strength='medium'
        elif corr_count >= 5 and p <= 4 and d <= 90*86400:
            strength='strong'
        elif corr_count >= 3 and p <= 7 and d <= 120*86400:
            strength='medium'
        else:
            strength='weak'
        return corr_count, reasons, strength

    def mk_candidate(title, x, why, fallback=False, extras=None):
        p_bucket = classify_source_bucket(x)
        p_rank = source_priority.get(p_bucket, 10)
        corr_count, corr_reasons, strength = corroboration_profile(x)
        conf = 'high' if strength == 'strong' else ('medium' if strength == 'medium' else 'low')
        base = {
            'title': title,
            'rationale': x.get('snippet') or x.get('trigger') or x.get('artifact_family') or '',
            'source_table': x.get('source_table') or '',
            'source_ref': x.get('source_ref') or '',
            'event_ts': x.get('event_ts'),
            'confidence': conf,
            'why_candidate': why,
            'source_priority_rank': p_rank,
            'candidate_strength': strength,
            'is_fallback': bool(fallback),
            'corroboration_count': corr_count,
            'corroboration_reasons': corr_reasons,
        }
        if isinstance(extras, dict):
            base.update(extras)
        return base

    # initial-access pool (Step-11R strict guardrails)
    init_pool=[]
    try:
        w_start = datetime.fromisoformat(str(tw.get('window_start')).replace('Z','+00:00')) if tw.get('window_start') else None
    except Exception:
        w_start = None
    try:
        w_end = datetime.fromisoformat(str(tw.get('window_end')).replace('Z','+00:00')) if tw.get('window_end') else None
    except Exception:
        w_end = None

    def _parse_ts_iso(v):
        try:
            if not v:
                return None
            return datetime.fromisoformat(str(v).replace('Z','+00:00'))
        except Exception:
            return None

    for x in rows:
        if not has_min_tuple(x):
            continue
        b = _blob(x)
        st = str(x.get('source_table') or '').lower()
        ts = _parse_ts_iso(x.get('event_ts'))
        if ts is None:
            continue

        # hard time-window gate: no historical/out-of-window candidates
        if w_start and ts < w_start:
            continue
        if w_end and ts > w_end:
            continue

        has_delivery = any(k in b for k in ['url','download','browser','zone.identifier','attachment','.exe','.bat','.cmd','.vbs','.js','.zip','.rar','.7z'])
        has_delivery_strict = any(k in b for k in ['download','zone.identifier','attachment','.exe','.bat','.cmd','.vbs','.js','.zip','.rar','.7z'])
        has_native = ('kind=native' in b) or ('zone=' in b and 'zone=;' not in b)
        has_registry = any(k in b for k in ['registry','reg key','run key','autorun','keypath'])
        has_exec_link = any(abs(_dist_anchor_sec({'event_ts':t,'source_table':s,'source_ref':r}) - _dist_anchor_sec(x)) <= 6*3600 for (s,r,t) in exec_set if t)
        has_payload_link = any(abs(_dist_anchor_sec({'event_ts':t,'source_table':s,'source_ref':r}) - _dist_anchor_sec(x)) <= 12*3600 for (s,r,t) in payload_set if t)

        src_ref = str(x.get('source_ref') or '')
        m_cnt = re.search(r'(?i)count\s*=\s*(\d+)', src_ref)
        cnt = int(m_cnt.group(1)) if m_cnt else None

        # source-priority gates
        if st == 'browser_provenance_v1':
            if not (has_delivery or has_native):
                continue
            init_pool.append(x)
            continue

        if st == 'raw_fallback_v2' or has_registry:
            if not (has_registry and (has_exec_link or has_payload_link or has_delivery)):
                continue
            init_pool.append(x)
            continue

        if st in ('event_logs_v2','tool_alerts_v2'):
            # generic event/tool rows: strict gate to avoid aggregate/noisy fallback dominating top-1/top-2
            if cnt is not None and cnt > 100:
                continue
            if not (has_delivery_strict and (has_exec_link or has_payload_link)):
                continue
            init_pool.append(x)
            continue

        # all other tables only with strong delivery + linkage
        if has_delivery and (has_exec_link or has_payload_link):
            init_pool.append(x)

    ranked = sorted(init_pool, key=lambda z: (
        {'strong':0,'medium':1,'weak':2}.get(corroboration_profile(z)[2],2),
        source_priority.get(classify_source_bucket(z),10),
        1 if str(z.get('source_table') or '').lower() in ('event_logs_v2','tool_alerts_v2') else 0,
        0 if (_dist_anchor_sec(z) <= 45*86400) else 1,
        _dist_anchor_sec(z),
        -float(z.get('score') or 0)
    ))

    # Step-11R.2 hard allowlist: top-1/top-2 only from native/browser/registry-backed sources
    def _is_preferred_initial_source(x):
        st = str(x.get('source_table') or '').lower()
        b = _blob(x)
        # browser/native provenance
        if st == 'browser_provenance_v1':
            return True
        # registry-backed provenance
        if st == 'raw_fallback_v2' or any(k in b for k in ['registry','reg key','run key','autorun','keypath']):
            return True
        # mixed native provenance (browser+registry linkage signals in same row)
        if (('browser' in b or 'zone.identifier' in b or 'download' in b) and ('registry' in b or 'run key' in b)):
            return True
        return False

    preferred_rows = [x for x in ranked if _is_preferred_initial_source(x)]
    generic_rows = [x for x in ranked if not _is_preferred_initial_source(x)]

    selected = []
    used_identity = set()

    def _cand_identity(x):
        st = str(x.get('source_table') or '')
        sr = str(x.get('source_ref') or '')
        ts = str(x.get('event_ts') or '')
        sn = str((x.get('snippet') or '')[:120])
        return (st, sr, ts, sn)

    # Fill top-1/top-2 from preferred rows with dedup + diversity guard
    for x in preferred_rows:
        cid = _cand_identity(x)
        if cid in used_identity:
            continue
        c = mk_candidate('Initial access candidate', x, 'ranked by corroboration + source priority + anchor proximity', fallback=False)
        selected.append(c)
        used_identity.add(cid)
        if len(selected) >= 1:
            break

    # second slot: try different supporting evidence type/source where possible
    if len(selected) < 2:
        p0 = str((selected[0].get('source_table') if selected else '') or '').lower()
        for x in preferred_rows:
            cid = _cand_identity(x)
            if cid in used_identity:
                continue
            st = str(x.get('source_table') or '').lower()
            if p0 and st == p0:
                continue
            c = mk_candidate('Initial access candidate', x, 'ranked by corroboration + source priority + anchor proximity', fallback=False)
            selected.append(c)
            used_identity.add(cid)
            break

    # if diversity slot still empty, allow next best preferred (dedup only)
    if len(selected) < 2:
        for x in preferred_rows:
            cid = _cand_identity(x)
            if cid in used_identity:
                continue
            c = mk_candidate('Initial access candidate', x, 'ranked by corroboration + source priority + anchor proximity', fallback=False)
            selected.append(c)
            used_identity.add(cid)
            break

    # Slot-3 fallback from generic event/tool rows only if strict filters already admitted them into ranked pool
    if len(selected) < 3:
        for x in generic_rows:
            c = mk_candidate(
                'Initial access candidate',
                x,
                'fallback candidate from narrowed staging window',
                fallback=True,
                extras={
                    'candidate_strength': 'weak',
                    'confidence': 'low',
                    'is_fallback': True,
                }
            )
            if any((c['source_table']==y['source_table'] and c['source_ref']==y['source_ref'] and c['event_ts']==y['event_ts']) for y in selected):
                continue
            selected.append(c)
            break

    # if no preferred candidates exist, keep honest fallback set (weak-only) without pretending strict top-1/top-2 proof
    if not selected:
        for x in generic_rows[:3]:
            selected.append(mk_candidate(
                'Initial access candidate',
                x,
                'fallback candidate from narrowed staging window',
                fallback=True,
                extras={
                    'candidate_strength': 'weak',
                    'confidence': 'low',
                    'is_fallback': True,
                }
            ))

    out['likely_initial_access_candidates']=selected[:3]

    exec_like = [x for x in rows if x.get('source_table') in ('program_exec_v2','event_logs_v2') and any(k in ((x.get('trigger') or '')+' '+(x.get('artifact_family') or '')+' '+(x.get('snippet') or '')).lower() for k in ['powershell','cmd','wscript','cscript','execute','run'])]
    pers_like = [x for x in rows if any(k in ((x.get('trigger') or '')+' '+(x.get('artifact_family') or '')+' '+(x.get('snippet') or '')).lower() for k in ['service','autorun','scheduled','rdp','remote'])]
    tamp_like = [x for x in rows if any(k in ((x.get('trigger') or '')+' '+(x.get('artifact_family') or '')+' '+(x.get('snippet') or '')).lower() for k in ['tamper','log clear','defender','security'])]

    for x in sorted(exec_like, key=lambda z:(z.get('event_ts') or '9999', -float(z.get('score') or 0)))[:6]:
        out['likely_execution_paths'].append({'source_table':x.get('source_table') or '','source_ref':x.get('source_ref') or '','event_ts':x.get('event_ts'),'summary':x.get('snippet') or x.get('trigger') or '','confidence':'medium' if float(x.get('score') or 0)>=50 else 'low'})
    for x in sorted(pers_like, key=lambda z:(z.get('event_ts') or '9999', -float(z.get('score') or 0)))[:6]:
        out['likely_persistence_paths'].append({'source_table':x.get('source_table') or '','source_ref':x.get('source_ref') or '','event_ts':x.get('event_ts'),'summary':x.get('snippet') or x.get('trigger') or '','confidence':'medium' if float(x.get('score') or 0)>=50 else 'low'})
    for x in sorted(tamp_like, key=lambda z:(z.get('event_ts') or '9999', -float(z.get('score') or 0)))[:6]:
        out['likely_tampering_paths'].append({'source_table':x.get('source_table') or '','source_ref':x.get('source_ref') or '','event_ts':x.get('event_ts'),'summary':x.get('snippet') or x.get('trigger') or '','confidence':'medium' if float(x.get('score') or 0)>=50 else 'low'})

    # Next deterministic SQL/script steps (focused on initial access recovery in narrowed window)
    out['prioritized_next_steps'] = [
        {'priority':1,'type':'sql','action':'browser_provenance_checks','within_window':bool(tw.get('window_start') and tw.get('window_end')),'reason':'recover download/url/referrer chain for top initial access candidates'},
        {'priority':2,'type':'sql','action':'registry_linkage_checks','within_window':True,'reason':'link initial access artifacts to registry persistence/launch hints'},
        {'priority':3,'type':'sql','action':'payload_dropper_linkage','within_window':True,'reason':'connect delivery artifact to execution process lineage'},
        {'priority':4,'type':'sql','action':'execution_follow_up_chain','within_window':True,'reason':'trace child process and remote/persistence continuation'},
    ]

    out['manual_checks'] = [
        'Validate browser download provenance around top initial access candidates',
        'Validate parent-child process lineage around execution candidates',
        'Validate persistence artifacts against event timeline boundaries',
    ]
    if tw:
        out['notes'].append('window=' + json.dumps(tw, ensure_ascii=False))

    # merge existing triage text fields if present (non-breaking)
    for k in ['summary','verdict','hypotheses']:
        if k in tri_raw and k not in out:
            out[k] = tri_raw[k]

    return out
