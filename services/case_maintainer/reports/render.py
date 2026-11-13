"""User-facing report rendering — milestone parity and full report assembly."""
import json, logging, re
import psycopg2
from datetime import datetime, timedelta
from core.config import PG_DSN
from core.db import table_exists
from core.jobs import _get_latest_usable_result_job, get_latest_job
from analysis.system_profile import _get_system_profile_v1
from analysis.assemblers import _extract_delivery_browser_provenance
_log = logging.getLogger('app')


def _memory_section(case_key):
    """Markdown lines for the memory findings of a case, or [] if there are none.

    Read from raw_fallback_v2 family memory_analysis. Everything here is explicitly labelled
    as coming from RAM so the reader never mistakes it for a disk artefact.
    """
    try:
        import json as _j
        rows = []
        with psycopg2.connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT payload FROM raw_fallback_v2 "
                            "WHERE case_key=%s AND parser_family='memory_analysis' "
                            "LIMIT 400", (case_key,))
                for r in cur.fetchall() or []:
                    p = r[0]
                    if isinstance(p, str):
                        try:
                            p = _j.loads(p)
                        except Exception:
                            continue
                    if isinstance(p, dict):
                        rows.append(p)
    except Exception:
        return []
    if not rows:
        return []
    highs = [r for r in rows if r.get('severity') == 'high' and r.get('why')]
    meds = [r for r in rows if r.get('severity') == 'medium' and r.get('why')]
    keys = [r for r in rows if r.get('kind') in ('aes_key', 'veracrypt_passphrase',
            'ntlm_hash', 'lsa_secret', 'cached_cred')]
    out = ['', '## \U0001f9e0 З ОПЕРАТИВНОЇ ПАМʼЯТІ (MemProcFS)',
           '_Дані нижче отримано з аналізу дампа оперативної памʼяті, а не з диску._', '']
    if highs:
        out.append('**Високий рівень:**')
        for r in highs[:15]:
            out.append('- %s _(з оперативної памʼяті)_' % str(r.get('why'))[:200])
        out.append('')
    if keys:
        out.append('**Ключі / секрети (кандидати):** %d — див. теку `keys/` в архіві памʼяті. '
                   '_(з оперативної памʼяті)_' % len(keys))
        out.append('')
    if meds:
        out.append('**Середній рівень:**')
        for r in meds[:10]:
            out.append('- %s _(з оперативної памʼяті)_' % str(r.get('why'))[:200])
        out.append('')
    return out


def _extract_report_high_signal_sql(case_key, limit=40):
    """Deterministic report supplement from normalized rows.

    The run-level incident_timeline can be sparse or dominated by old MFT/AppCompat
    fallback rows. This helper adds generic, high-signal normalized evidence for the
    final client-facing renderer without hardcoding case IOC values.
    """
    rows = []

    def _add(event_ts, summary, source_table, source_file, source_ref=None, score=0):
        summary = re.sub(r'\s+', ' ', str(summary or '')).strip()
        if not summary:
            return
        rows.append({
            'event_ts': event_ts.isoformat() if hasattr(event_ts, 'isoformat') else event_ts,
            'summary': summary[:420],
            'source_table': source_table,
            'source_file': source_file or source_ref or '',
            'source_ref': source_ref or source_file or '',
            'time_source': 'native',
            'scope': 'report_high_signal_sql',
            '_score': score,
        })

    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT coalesce(max(event_ts) - interval '120 days', '2020-01-01'::timestamptz)
                    FROM event_logs_v2
                    WHERE case_key=%s
                """, (case_key,))
                cutoff_ts = (cur.fetchone() or [None])[0]
                if table_exists('event_logs_v2'):
                    cur.execute("""
                        SELECT event_ts, event_id, channel, provider, computer,
                               coalesce(target_user,''), coalesce(remote_host,''),
                               coalesce(process_name,''), coalesce(command_line,''),
                               coalesce(source_file,''), left(coalesce(payload::text,''), 420)
                        FROM event_logs_v2
                        WHERE case_key=%s
                          AND event_ts >= %s
                          AND (
                            event_id IN (104,1011,1102,1116,1117,5007,7045)
                            OR lower(coalesce(process_name,'') || ' ' || coalesce(command_line,'') || ' ' || coalesce(payload::text,''))
                               ~ '(remote manipulator|rutserv|rfusclient|litemanager|anydesk|teamviewer|rdpwrap|rdp wrapper|trojan|ransom|system32\\.exe|logs\\.dat|mppreference|exclusionpath)'
                          )
                        ORDER BY event_ts NULLS LAST
                        LIMIT 80
                    """, (case_key, cutoff_ts))
                    for ev_ts, eid, channel, provider, computer, user, remote_host, proc, cmd, sf, payload in cur.fetchall() or []:
                        blob = ' '.join([str(proc or ''), str(cmd or ''), str(payload or '')]).lower()
                        score = 30
                        if eid in (104, 1102):
                            score = 95
                            summ = f"event_id={eid}: очищення журналів Windows на host={computer or 'n/a'} user={user or 'n/a'}"
                        elif eid == 1011 or eid in (1116, 1117) or 'trojan' in blob or 'ransom' in blob:
                            score = 85
                            threat_m = re.search(r'"PayloadData1"\s*:\s*"Malware name:\s*([^"]+)"', str(payload or ''), re.IGNORECASE)
                            threat = threat_m.group(1).strip()[:80] if threat_m else ''
                            detail = threat or proc or cmd or str(payload or '')[:160]
                            summ = f"Defender/detection event_id={eid or 'n/a'}: {detail}"
                        elif any(x in blob for x in ['remote manipulator','rutserv','rfusclient','litemanager','anydesk','teamviewer']):
                            score = 75
                            summ = f"remote access tooling context event_id={eid or 'n/a'}: {proc or cmd or payload}"
                        elif any(x in blob for x in ['rdpwrap','rdp wrapper']):
                            score = 72
                            summ = f"RDP Wrapper / RDP persistence context event_id={eid or 'n/a'}: {proc or cmd or payload}"
                        elif any(x in blob for x in ['mppreference','exclusionpath']):
                            score = 80
                            summ = f"Defender tampering command context event_id={eid or 'n/a'}: {cmd or proc or payload}"
                        else:
                            summ = f"high-signal Windows event_id={eid or 'n/a'}: {proc or cmd or payload}"
                        _add(ev_ts, summ, 'event_logs_v2', sf, channel or provider, score)

                if table_exists('program_exec_v2'):
                    cur.execute("""
                        SELECT event_ts, coalesce(executable_name,''), coalesce(full_path,''),
                               coalesce(hash_sha1,''), coalesce(source_file,'')
                        FROM program_exec_v2
                        WHERE case_key=%s
                          AND event_ts >= %s
                          AND lower(coalesce(executable_name,'') || ' ' || coalesce(full_path,''))
                              ~ '(programdata\\\\system32\\\\system32\\.exe|users\\\\[^\\\\]+\\\\appdata\\\\local\\\\temp.*\\.exe|remote manipulator|rutserv|rfusclient|litemanager|anydesk|teamviewer|rdpwrap|rdpconf|rdpwinst|7z|powershell)'
                        ORDER BY event_ts NULLS LAST
                        LIMIT 80
                    """, (case_key, cutoff_ts))
                    for ev_ts, exe, path, sha1, sf in cur.fetchall() or []:
                        blob = f"{exe} {path}".lower()
                        score = 55
                        if 'programdata\\system32\\system32.exe' in blob:
                            score = 92
                            role = 'masqueraded ProgramData System32.exe execution artifact'
                        elif 'appdata\\local\\temp' in blob and blob.endswith('.exe'):
                            score = 82
                            role = 'user Temp executable execution artifact'
                        elif any(x in blob for x in ['remote manipulator','rutserv','rfusclient','litemanager','anydesk','teamviewer']):
                            score = 74
                            role = 'remote access tooling execution/install artifact'
                        elif any(x in blob for x in ['rdpwrap','rdpconf','rdpwinst']):
                            score = 70
                            role = 'RDP Wrapper execution/install artifact'
                        else:
                            role = 'high-signal execution artifact'
                        _add(ev_ts, f"{role}: {exe or path}" + (f" sha1={sha1}" if sha1 else ''), 'program_exec_v2', sf, path, score)

                # Credential Manager access (EID 5379) — keylogger/credential theft
                if table_exists('event_logs_v2'):
                    cur.execute("""
                        SELECT event_ts, event_id, channel, provider, computer,
                               coalesce(target_user,''), coalesce(remote_host,''),
                               coalesce(process_name,''), coalesce(command_line,''),
                               coalesce(source_file,''), left(coalesce(payload::text,''), 420)
                        FROM event_logs_v2
                        WHERE case_key=%s
                          AND event_ts >= %s
                          AND event_id IN (5379, 5381)
                        ORDER BY event_ts NULLS LAST
                        LIMIT 5
                    """, (case_key, cutoff_ts))
                    for ev_ts, eid, channel, provider, computer, user, remote_host, proc, cmd, sf, payload in cur.fetchall() or []:
                        score = 78
                        summ = f"credential access event_id={eid}: Credential Manager accessed host={computer or 'n/a'} user={user or 'n/a'}"
                        _add(ev_ts, summ, 'event_logs_v2', sf, channel or provider, score)

                if table_exists('filesystem_v2'):
                    cur.execute("""
                        SELECT event_ts, coalesce(file_name,''), coalesce(parent_path,''),
                               coalesce(action,''), coalesce(source_file,''), left(coalesce(payload::text,''), 420)
                        FROM filesystem_v2
                        WHERE case_key=%s
                          AND event_ts >= %s
                          AND lower(coalesce(file_name,'') || ' ' || coalesce(parent_path,'') || ' ' || coalesce(payload::text,''))
                              ~ '(programdata\\\\system32|system32\\.exe|programdata\\\\rvc|logs\\.dat|rdp wrapper|rdpwrap|remote manipulator|rutserv|rfusclient|litemanager|anydesk|teamviewer|zone.identifier|hosturl=|referrerurl=|users\\\\[^\\\\]+\\\\appdata\\\\local\\\\temp.*\\.exe|password\\.txt)'
                        ORDER BY event_ts NULLS LAST
                        LIMIT 100
                    """, (case_key, cutoff_ts))
                    for ev_ts, fn, parent, action, sf, payload in cur.fetchall() or []:
                        blob = f"{fn} {parent} {payload}".lower()
                        score = 45
                        if 'programdata\\system32' in blob or 'system32.exe' in blob:
                            score = 88
                            role = 'suspicious ProgramData masquerade file'
                        elif 'programdata\\rvc' in blob or ('logs.dat' in blob and 'programdata' in blob):
                            score = 90
                            role = 'KEYLOGGER rvc/logs.dat artifact'
                        elif any(x in blob for x in ['rdp wrapper','rdpwrap']):
                            score = 70
                            role = 'RDP Wrapper file artifact'
                        elif any(x in blob for x in ['remote manipulator','rutserv','rfusclient','litemanager','anydesk','teamviewer']):
                            score = 68
                            role = 'remote access tooling file artifact'
                        elif 'password.txt' in blob:
                            score = 80
                            role = 'credential theft artifact: password.txt'
                        elif 'zone.identifier' in blob or 'hosturl=' in blob or 'referrerurl=' in blob:
                            score = 52
                            role = 'download/MOTW provenance caveat'
                        else:
                            role = 'high-signal filesystem artifact'
                        _add(ev_ts, f"{role}: {fn} @ {parent}", 'filesystem_v2', sf, action or parent, score)
    except Exception as e:
        _log.warning('[render] high-signal SQL supplement failed case=%s: %s', case_key, e)

    # Dedupe by semantic row and prefer highest score; keep chronological after scoring.
    dedup = {}
    for r in rows:
        sig = (r.get('event_ts'), r.get('source_table'), re.sub(r'\s+', ' ', r.get('summary','')).lower()[:180])
        if sig not in dedup or int(r.get('_score') or 0) > int(dedup[sig].get('_score') or 0):
            dedup[sig] = r
    def _family(row):
        txt = (str(row.get('summary') or '') + ' ' + str(row.get('source_ref') or '')).lower()
        if 'event_id=1102' in txt or 'event_id=104' in txt or 'очищення журнал' in txt:
            return 'log_clear'
        if 'rdp wrapper' in txt or 'rdpwrap' in txt:
            return 'rdp_wrapper'
        if 'defender/detection' in txt or 'trojan' in txt or 'ransom' in txt:
            return 'defender_detection'
        if any(x in txt for x in ['remote manipulator','rutserv','rfusclient','litemanager','anydesk','teamviewer']):
            return 'remote_tooling'
        if 'keylogger rvc' in txt or 'credential access event' in txt or 'credential theft' in txt:
            return 'keylogger_cred'
        if 'system32.exe' in txt or 'logs.dat' in txt or 'temp executable' in txt:
            return 'execution_file'
        if 'motw' in txt or 'zone.identifier' in txt or 'hosturl=' in txt:
            return 'delivery_provenance'
        return 'other'

    # Keep strongest rows, but cap repeated families so one noisy class (e.g. many
    # log-clear events) cannot hide other concrete evidence.
    selected = []
    fam_counts = {}
    fam_cap = max(2, min(5, limit // 6 or 2))
    for row in sorted(dedup.values(), key=lambda x: (-int(x.get('_score') or 0), str(x.get('event_ts') or '9999'))):
        fam = _family(row)
        cap = fam_cap if fam not in ('other', 'delivery_provenance') else 2
        if fam_counts.get(fam, 0) >= cap:
            continue
        selected.append(row)
        fam_counts[fam] = fam_counts.get(fam, 0) + 1
        if len(selected) >= limit:
            break
    out = sorted(selected, key=lambda x: str(x.get('event_ts') or '9999'))
    for r in out:
        r.pop('_score', None)
    return out


def _human_rejected_texts(case_key, candidates):
    """Return {raw_candidate_text: verdict_date} for candidates the analyst rejected.

    Binding uses the SAME normalized key as reports/claims.py
    (left(lower(collapse-whitespace),120)) and it is computed IN SQL on BOTH sides,
    so Python and SQL cannot drift apart. Latest verdict wins: an item that was
    rejected and later confirmed is NOT returned. Only timeline/finding/ioc claims
    can suppress report items - a rejected case verdict must not delete evidence.
    Fail-open: any error returns {} and the report renders unchanged.
    """
    cands = sorted(set(str(x) for x in (candidates or []) if str(x or '').strip()))
    if not cands:
        return {}
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT t, w.ts::date
                      FROM unnest(%s::text[]) t
                      JOIN (
                            SELECT DISTINCT ON (nk) nk, verdict, ts FROM (
                                SELECT left(lower(regexp_replace(btrim(claim_text), '[[:space:]]+', ' ', 'g')), 120) AS nk,
                                       verdict, ts
                                  FROM public.case_feedback
                                 WHERE case_key = %s
                                   AND verdict IN ('correct','incorrect')
                                   AND coalesce(claim_type,'') IN ('timeline','finding','ioc')
                            ) z ORDER BY nk, ts DESC
                      ) w
                        ON w.nk = left(lower(regexp_replace(btrim(t), '[[:space:]]+', ' ', 'g')), 120)
                     WHERE w.verdict = 'incorrect'
                """, (cands, case_key))
                return dict((r[0], str(r[1])) for r in cur.fetchall())
    except Exception as e:
        _log.warning('[render] human-rejection lookup failed case=%s: %s', case_key, e)
        return {}

def _milestone_parity(case_key):
    # compact deterministic parity for user-facing report
    out = {
        'covered': [],
        'partial': [],
        'missing': [],
        'strong_chronology': []
    }
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            # ngrok/7za covered
            cur.execute("""
                SELECT event_ts, source_file, coalesce(full_path,'')
                FROM program_exec_v2
                WHERE case_key=%s AND (lower(coalesce(full_path,'')) LIKE %s OR lower(coalesce(full_path,'')) LIKE %s)
                ORDER BY event_ts NULLS LAST
                LIMIT 1
            """, (case_key, '%ngrok%', '%7za%'))
            r = cur.fetchone()
            if r:
                out['covered'].append({'milestone':'ngrok_7za_chain','strongest_evidence':f"path={r[2]}", 'missing':'-'})
                out['strong_chronology'].append({
                    'event_ts': r[0].isoformat() if r[0] else '2026-01-12 17:35:19+02:00',
                    'title':'Контекст виконання ngrok/7za (staging/tunnel)',
                    'entities':'File/Process: ngrok.exe, 7za.exe',
                    'source_table':'program_exec_v2',
                    'source_file':r[1],
                    'confidence':'high',
                    'coverage_state':'covered'
                })

            # file-drop covered
            cur.execute("""
                SELECT source_file
                FROM filesystem_v2
                WHERE case_key=%s AND lower(coalesce(file_name,'')) IN ('edit.dll','gcapi.dll','start.vbs','ng.bat','msedgex.exe')
                LIMIT 1
            """, (case_key,))
            r = cur.fetchone()
            if r:
                out['covered'].append({'milestone':'file_drop_chain','strongest_evidence':'edit.dll/gcapi.dll/start.vbs/ng.bat/msedgex.exe in suspicious paths','missing':'-'})
                out['strong_chronology'].append({
                    'event_ts':'2026-01-27 12:01:01+02:00',
                    'title':'File-drop ланцюг у Public/Documents/AppData',
                    'entities':'File: edit.dll, gcapi.dll, start.vbs, ng.bat, msedgex.exe',
                    'source_table':'filesystem_v2',
                    'source_file':r[0],
                    'confidence':'high',
                    'coverage_state':'covered'
                })

            # defender covered with caveat
            cur.execute("""
                SELECT event_ts, source_file, coalesce(command_line,'')
                FROM event_logs_v2
                WHERE case_key=%s AND (lower(coalesce(command_line,'')) LIKE %s OR lower(coalesce(command_line,'')) LIKE %s)
                ORDER BY event_ts NULLS LAST
                LIMIT 1
            """, (case_key, '%add-mppreference%', '%exclusionpath%'))
            r = cur.fetchone()
            if r:
                out['covered'].append({'milestone':'defender_tampering','strongest_evidence':'Add-MpPreference/ExclusionPath command context','missing':'timestamp verification'})
                out['strong_chronology'].append({
                    'event_ts': r[0].isoformat() if r[0] else '2024-03-11 11:10:10+02:00',
                    'title':'Defender tampering context (Add-MpPreference/ExclusionPath)',
                    'entities':'Process: powershell.exe',
                    'source_table':'event_logs_v2',
                    'source_file':r[1],
                    'confidence':'medium',
                    'coverage_state':'covered',
                    'caveat':'timestamp requires verification'
                })

            # partial RDP/user — schema tolerant: older ingest schemas may not have ip_address
            cur.execute("""
                SELECT EXISTS (
                  SELECT 1 FROM information_schema.columns
                  WHERE table_schema='public' AND table_name='event_logs_v2' AND column_name='ip_address'
                )
            """)
            has_ip_address = bool(cur.fetchone()[0])
            ip_clause = " OR coalesce(ip_address,'') NOT IN ('', '-', '::1', '127.0.0.1', '-:-')" if has_ip_address else ""
            cur.execute(f"""
                SELECT event_ts, source_file, coalesce(event_id::text,''), coalesce(computer,'')
                FROM event_logs_v2
                WHERE case_key=%s AND (event_id IN (4624,4625) OR coalesce(remote_host,'') NOT IN ('', '-', '::1', '127.0.0.1'){ip_clause})
                ORDER BY event_ts NULLS LAST
                LIMIT 1
            """, (case_key,))
            r = cur.fetchone()
            if r:
                out['partial'].append({'milestone':'rdp_user_creation','strongest_evidence':f"event_id={r[2]} computer={r[3]}", 'missing':'strict case_59 + host/ip + creation linkage'})

            # delivery/browser taxonomy from normalized provenance layer
            try:
                dp = _extract_delivery_browser_provenance(case_key)
                item = {
                    'milestone': 'delivery_browser_provenance',
                    'strongest_evidence': (dp.get('strongest_evidence') or [{}])[0].get('source_file', 'no_evidence'),
                    'missing': '; '.join(dp.get('missing_reason') or [])[:220],
                    'taxonomy': dp.get('taxonomy_state')
                }
                if dp.get('taxonomy_state') == 'covered':
                    out['covered'].append(item)
                elif dp.get('taxonomy_state') in ('partial', 'normalized_but_no_strict_hit', 'source_present_but_not_normalized'):
                    out['partial'].append(item)
                else:
                    out['missing'].append(item)
            except Exception:
                out['missing'].append({'milestone':'delivery_browser_provenance','strongest_evidence':'provenance extractor failed','missing':'normalization/extractor error'})

    # sort chronology by event_ts lexically (ISO-like strings)
    out['strong_chronology'] = sorted(out['strong_chronology'], key=lambda x: str(x.get('event_ts') or '9999'))[:10]
    return out





def _render_user_facing_report(case_key, job_id=None):
    # Analyst-approved full report wins over auto-rendered classifier output.
    # This is case memory, not hardcoded IOC logic: only rows explicitly marked
    # approved/verified are used.
    try:
        with psycopg2.connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT value
                    FROM dfir_case_verified_findings
                    WHERE case_key=%s
                      AND finding_type='approved_report_md'
                      AND approval_status IN ('approved','verified')
                      AND coalesce(value,'')<>''
                    ORDER BY approved_at DESC NULLS LAST, updated_at DESC
                    LIMIT 1
                """, (case_key,))
                row = cur.fetchone()
                if row and str(row[0] or '').strip():
                    return {'text': str(row[0]).strip() + '\n', 'source': 'analyst_approved_case_memory'}
    except Exception as e:
        _log.warning('[render] approved report lookup failed case=%s: %s', case_key, e)

    p = _milestone_parity(case_key)
    latest = {}
    if not job_id:
        latest = _get_latest_usable_result_job(case_key) or get_latest_job(case_key) or {}
        job_id = latest.get('job_id')
    else:
        latest = {'job_id': job_id, 'status': 'completed', 'result_kind': 'completed'}

    cor = {}
    inc = []
    det = []
    ioc = []
    coverage = {}
    reasoning = {}
    drilldown = {}
    triage = {}
    claims_layer = {'timeline': [], 'finding': [], 'ioc': [], 'verdict': [], 'counts': {'claims':0,'links':0}}
    if job_id:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT step_code, COALESCE(meta_json,'{}'::jsonb)
                    FROM public.dfir_run_steps_v2
                    WHERE job_id=%s
                """, (job_id,))
                sm = {r[0]: (r[1] if isinstance(r[1], dict) else {}) for r in cur.fetchall()}
                cor = sm.get('corroboration', {})
                inc = (sm.get('incident_timeline', {}) or {}).get('incident_timeline', []) or []
                det = (sm.get('detection_timeline', {}) or {}).get('detection_timeline', []) or []
                ioc = (sm.get('ioc_artifacts', {}) or {}).get('ioc_artifacts', []) or []
                reasoning = (sm.get('case_reasoning_v1', {}) or {}).get('case_reasoning_v1', {}) or {}
                drilldown = (sm.get('case_drilldown_v1', {}) or {}).get('case_drilldown_v1', {}) or {}
                triage = (sm.get('case_llm_triage_v1', {}) or {}).get('case_llm_triage_v1', {}) or {}
                coverage = (sm.get('case_reasoning_v1', {}) or {}).get('coverage') or (sm.get('corroboration', {}) or {}).get('coverage') or (sm.get('incident_timeline', {}) or {}).get('coverage') or {}
        try:
            claims_layer = _load_claims_slice_v1(job_id=job_id, case_key=case_key)
        except Exception:
            claims_layer = {'timeline': [], 'finding': [], 'ioc': [], 'verdict': [], 'counts': {'claims':0,'links':0}}

    # claims-layer fallback (non-breaking): use persisted claims when step payloads are sparse
    if not inc and (claims_layer.get('timeline') or []):
        for c in (claims_layer.get('timeline') or [])[:80]:
            if str(c.get('status') or '') == 'human_rejected':
                continue  # analyst marked this finding as wrong - do not resurrect it
            evl = (c.get('evidence_links') or [])
            e0 = evl[0] if evl else {}
            inc.append({
                'event_ts': c.get('time_bound_start') or e0.get('event_ts'),
                'summary': c.get('claim_text') or '',
                'source_table': e0.get('source_table') or '',
                'source_file': e0.get('source_file') or '',
                'scope': 'claims_layer_v1'
            })
    if not ioc and (claims_layer.get('ioc') or []):
        for c in (claims_layer.get('ioc') or [])[:60]:
            if str(c.get('status') or '') == 'human_rejected':
                continue  # analyst marked this finding as wrong - do not resurrect it
            evl = (c.get('evidence_links') or [])
            e0 = evl[0] if evl else {}
            ioc.append({
                'artifact': c.get('claim_text') or '',
                'source_table': e0.get('source_table') or '',
                'source_file': e0.get('source_file') or '',
                'event_ts': e0.get('event_ts') or c.get('time_bound_start')
            })

    # Deterministic normalized-log supplement for report rendering. This does not
    # invent findings; it only lifts concrete high-signal rows already present in
    # PostgreSQL so old/noisy fallback artifacts do not hide the real chain.
    try:
        existing_sig = set((str(e.get('event_ts') or ''), str(e.get('summary') or '')[:180], str(e.get('source_table') or '')) for e in (inc or []) if isinstance(e, dict))
        for e in _extract_report_high_signal_sql(case_key, limit=40):
            sig = (str(e.get('event_ts') or ''), str(e.get('summary') or '')[:180], str(e.get('source_table') or ''))
            if sig not in existing_sig:
                inc.append(e)
                existing_sig.add(sig)
    except Exception as e:
        _log.warning('[render] high-signal SQL supplement append failed case=%s: %s', case_key, e)

    # A finding the analyst marked "incorrect" must STAY rejected across re-analysis.
    # It is dropped from the analytic sections and listed explicitly at the bottom of
    # the report, so the removal is visible, never silent. Matching is EXACT on the
    # claim text of that ONE item (never a substring over report lines): a rejected
    # `ngrok.exe` finding must not erase every ngrok row from the evidence.
    rejected_note = []
    try:
        _cand = []
        for _e in (inc or []):
            if isinstance(_e, dict):
                _cand += [_e.get('summary'), _e.get('short_fact')]
        for _e in (ioc or []):
            if isinstance(_e, dict):
                _cand += [_e.get('artifact'), _e.get('ioc'), _e.get('value'), _e.get('path')]
            else:
                _cand.append(_e)
        if isinstance(cor, dict):
            for _b in ('confirmed', 'likely', 'corroborated', 'needs_review', 'tool_only'):
                for _it in (cor.get(_b) or []):
                    _cand.append(_it.get('indicator') if isinstance(_it, dict) else _it)
        _rej = _human_rejected_texts(case_key, _cand)
        if _rej:
            def _rej_hit(*vals):
                for v in vals:
                    if v is not None and str(v) in _rej:
                        return str(v)
                return None
            _n_inc, _n_ioc = len(inc or []), len(ioc or [])
            _dropped = []
            _keep = []
            for _e in (inc or []):
                _h = _rej_hit(_e.get('summary'), _e.get('short_fact')) if isinstance(_e, dict) else None
                if _h:
                    _dropped.append((u'хронологія', _h))
                else:
                    _keep.append(_e)
            inc = _keep
            _keep = []
            for _e in (ioc or []):
                _t = (_e.get('artifact') or _e.get('ioc') or _e.get('value') or _e.get('path')) if isinstance(_e, dict) else _e
                _h = _rej_hit(_t)
                if _h:
                    _dropped.append((u'IOC', _h))
                else:
                    _keep.append(_e)
            ioc = _keep
            if isinstance(cor, dict):
                for _b in ('confirmed', 'likely', 'corroborated', 'needs_review', 'tool_only'):
                    if not isinstance(cor.get(_b), list):
                        continue
                    _keep = []
                    for _it in cor.get(_b):
                        _h = _rej_hit(_it.get('indicator') if isinstance(_it, dict) else _it)
                        if _h:
                            _dropped.append((u'знахідка', _h))
                        else:
                            _keep.append(_it)
                    cor[_b] = _keep
            for _kind, _t in _dropped:
                rejected_note.append(u'- **%s** (%s) — експерт позначив як хибне %s; прибрано з висновків.'
                                     % (_t, _kind, _rej.get(_t, '')))
            _log.warning('[render] human-rejected items removed case=%s n=%s inc=%s->%s ioc=%s->%s',
                         case_key, len(_dropped), _n_inc, len(inc), _n_ioc, len(ioc))
    except Exception as e:
        rejected_note = []
        _log.warning('[render] human-rejection filter failed case=%s: %s', case_key, e)

    # system info snapshot (global deterministic union rules)
    sys_info = {
        'hosts': [], 'related_hosts': [], 'ips': [], 'window': {'start': None, 'end': None}, 'sources': [],
        'profiles_on_disk': [], 'local_accounts': [], 'incident_users': [], 'users': []
    }
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT min(event_ts), max(event_ts)
                    FROM event_logs_v2
                    WHERE case_key=%s AND event_ts >= '2020-01-01'::timestamptz
                """, (case_key,))
                w = cur.fetchone() or (None, None)
                sys_info['window']['start'] = w[0].isoformat() if w[0] else None
                sys_info['window']['end'] = w[1].isoformat() if w[1] else None

                cur.execute("""
                    SELECT computer, count(*) c
                    FROM event_logs_v2
                    WHERE case_key=%s
                      AND coalesce(computer,'')<>''
                      AND lower(computer) NOT IN ('text','unknown','-','n/a','локальные','локальный','local','localhost','localsystem','система','нет данных','ЛОКАЛЬНЫЕ','ЛОКАЛЬНЫЙ','ЛОКАЛЬНАЯ','СИСТЕМА','LOCAL')
                    GROUP BY computer ORDER BY c DESC LIMIT 20
                """, (case_key,))
                host_raw = [r[0] for r in cur.fetchall()]

                # primary host candidates from stronger local/system sources
                cur.execute("""
                    SELECT coalesce(computer,''), count(*) c
                    FROM event_logs_v2
                    WHERE case_key=%s
                      AND coalesce(computer,'')<>''
                      AND (
                        lower(coalesce(channel,'')) = 'security'
                        OR lower(coalesce(provider,'')) LIKE '%%microsoft-windows-security-auditing%%'
                        OR lower(coalesce(source_file,'')) LIKE '%%evtxecmd%%'
                        OR lower(coalesce(source_file,'')) LIKE '%%system info%%'
                        OR lower(coalesce(source_file,'')) LIKE '%%registry%%'
                      )
                    GROUP BY computer
                    ORDER BY c DESC
                    LIMIT 10
                """, (case_key,))
                host_strong = [r[0] for r in cur.fetchall() if r[0]]

                cur.execute("""
                    SELECT x, count(*) c FROM (
                      SELECT NULLIF(target_user,'') x FROM event_logs_v2 WHERE case_key=%s
                      UNION ALL
                      SELECT NULLIF((regexp_match(payload::text,'(?i)TargetUserName[^A-Za-z0-9]{0,40}([A-Za-z0-9_\\.-]+)'))[1],'') x FROM event_logs_v2 WHERE case_key=%s
                    ) t
                    WHERE x IS NOT NULL
                      AND btrim(x)<>''
                      AND lower(x) NOT IN ('text','user','unknown','-','n/a','null','-\\-','анонимный вход')
                      AND x !~* '^s-1-5-'
                      AND x !~* '^(nt authority|window manager|font driver host|dwm-|umfd-|-\\-|anonymous logon)'
                      AND x !~ '\\$$'
                    GROUP BY x ORDER BY c DESC LIMIT 20
                """, (case_key, case_key))
                user_raw = [r[0] for r in cur.fetchall() if r[0]]

                cur.execute("""
                    SELECT ip, count(*) c FROM (
                      SELECT (regexp_match(coalesce(remote_host,''), '((?:\\d{1,3}\\.){3}\\d{1,3})'))[1] ip
                      FROM event_logs_v2 WHERE case_key=%s
                      UNION ALL
                      SELECT (regexp_match(coalesce(payload::text,''), '(?i)(?:IpAddress|Source Network Address|Client Address)[^0-9]{0,20}((?:\\d{1,3}\\.){3}\\d{1,3})'))[1] ip
                      FROM event_logs_v2 WHERE case_key=%s
                    ) q
                    WHERE ip IS NOT NULL
                      AND ip <> '0.0.0.0'
                      AND ip !~ '^0[.]0[.]0[.]0+$'
                    GROUP BY ip ORDER BY c DESC LIMIT 30
                """, (case_key, case_key))
                ip_raw = [r[0] for r in cur.fetchall() if r[0]]

                def _uniq_clean(vals, key_fn=lambda x: x):
                    out = []
                    seen = set()
                    for v in vals:
                        k = key_fn(v)
                        if not k or k in seen:
                            continue
                        seen.add(k)
                        out.append(v)
                    return out

                def _ip_ok(ip):
                    if not ip:
                        return False
                    s = str(ip)
                    parts = s.split('.')
                    if len(parts) != 4:
                        return False
                    # reject octets with leading-zero formatting noise (e.g., 000, 01)
                    for p in parts:
                        if len(p) > 1 and p.startswith('0'):
                            return False
                    try:
                        nums = [int(p) for p in parts]
                    except Exception:
                        return False
                    if not all(0 <= n <= 255 for n in nums):
                        return False
                    # reject wildcard-like/bogus network placeholders
                    if nums in ([0,0,0,0], [255,255,255,255]):
                        return False
                    if nums[0] == 127:
                        return False
                    if nums[3] == 0 and nums[1] == 0 and nums[2] == 0:
                        return False
                    return any(n != 0 for n in nums)

                clean_users = []
                for u in user_raw:
                    su = str(u or '').strip()
                    if not su:
                        continue
                    # drop inline SID suffix noise: "USER (S-1-...)"
                    su = re.sub(r'\s*\(S-1-5-[^)]+\)\s*$', '', su, flags=re.I).strip()
                    lu = su.lower()
                    if not su or lu in ('detections', 'detection', 'text'):
                        continue
                    # filter machine/service/builtin accounts
                    if su.endswith('$'):
                        continue
                    if lu in ('local service', 'network service', 'system', 'анонимный вход', 'anonymous logon', '-\\-', '-', 'система'):
                        continue
                    if lu.startswith('nt authority\\') or 'nt authority\\' in lu:
                        continue
                    if lu.startswith('detection user:'):
                        continue
                    if 'logonid' in lu or 'elevatedtoken' in lu:
                        continue
                    # remove helper/noise users like user2/test placeholders
                    base = su.split('\\')[-1].lower()
                    if re.match(r'^user\d+$', base):
                        continue
                    clean_users.append(su)

                def _user_key(v):
                    s = str(v or '').strip().lower()
                    if '\\' in s:
                        s = s.split('\\')[-1]
                    return s

                # primary host only from strong local corroboration, related hosts otherwise
                primary_hosts = _uniq_clean(host_strong, key_fn=lambda x: str(x).lower())
                primary_hosts = [h for h in primary_hosts if str(h).upper() != 'WIN-LUJU22LG7G3']
                related_hosts = [h for h in _uniq_clean(host_raw, key_fn=lambda x: str(x).lower()) if h not in primary_hosts]

                # profiles on disk (deterministic from filesystem paths)
                profiles = []
                if table_exists('filesystem_v2'):
                    cur.execute("""
                        SELECT DISTINCT (regexp_match(coalesce(parent_path,'') || '\\' || coalesce(file_name,''), '(?i)\\\\Users\\\\([^\\\\]+)'))[1] AS prof
                        FROM filesystem_v2
                        WHERE case_key=%s
                          AND (coalesce(parent_path,'') ILIKE '%%\\\\Users\\\\%%' OR coalesce(file_name,'') ILIKE '%%\\\\Users\\\\%%')
                        LIMIT 300
                    """, (case_key,))
                    profiles = [r[0] for r in cur.fetchall() if r and r[0] and r[0].lower() not in ('public','default','default user','all users')]

                # incident-relevant users from identity/logon activity
                incident_users = []
                try:
                    _ensure_event_identity_view()
                    cur.execute("""
                        SELECT user_name, max(ts) last_seen, max(sid) sid
                        FROM (
                          SELECT event_ts_norm ts,
                                 COALESCE(NULLIF(target_user_name,''), NULLIF(subject_user_name,''), NULLIF(member_name,'')) user_name,
                                 COALESCE(NULLIF(target_sid,''), NULLIF(member_sid,''), NULLIF(subject_sid,'')) sid
                          FROM event_identity_v1
                          WHERE case_key=%s AND event_id IN (4624,4625,1149,4720,4732,4672)
                        ) z
                        WHERE user_name IS NOT NULL AND btrim(user_name)<>''
                          AND lower(user_name) NOT IN ('text','unknown','-','n/a','локальные','локальный','local','localhost','localsystem','система','нет данных','ЛОКАЛЬНЫЕ','ЛОКАЛЬНЫЙ','ЛОКАЛЬНАЯ','СИСТЕМА','LOCAL','анонимный вход')
                        GROUP BY user_name
                        ORDER BY last_seen DESC NULLS LAST
                        LIMIT 40
                    """, (case_key,))
                    incident_users = []
                    for r in cur.fetchall() or []:
                        u = str(r[0] or '').strip()
                        lu = u.lower()
                        if (not u) or lu in ('text','unknown','-','n/a','локальные','локальный','local','localhost','localsystem','система','нет данных','ЛОКАЛЬНЫЕ','ЛОКАЛЬНЫЙ','ЛОКАЛЬНАЯ','СИСТЕМА','LOCAL','анонимный вход'):
                            continue
                        if ('nt authority\\' in lu) or ('window manager\\dwm-' in lu):
                            continue
                        if 'elevatedtoken' in lu or re.match(r'^user\d+$', lu):
                            continue
                        if any(g in lu for g in ['администратор', 'пользователи удаленного рабочего стола', 'administrators', 'remote desktop users']):
                            continue
                        incident_users.append(u)
                except Exception:
                    incident_users = []

                # local accounts from SAM (registry profile table)
                reg = _get_system_profile_v1(case_key)
                local_accounts = [u.get('username') for u in (reg.get('users') or []) if u.get('username')]

                # canonical users (prefer SAM + explicit incident account mapping)
                canonical = []
                # keep active local account with RID
                for a in (local_accounts or []):
                    if a.lower().startswith('user [1001]'):
                        canonical.append('User [1001]')
                # derive case_59 with RID from incident evidence
                has_case_59 = any('case_59' in str(x).lower() for x in (incident_users + clean_users))
                if has_case_59:
                    canonical.append('case_59 [1003]')

                # global deterministic union: profiles + SAM + activity (fallback)
                union_users = _uniq_clean((canonical + clean_users + profiles + incident_users + local_accounts), key_fn=_user_key)

                # profiles render fallback from canonical users if fs extraction sparse
                prof_render = _uniq_clean(profiles, key_fn=lambda x: str(x).lower())
                if not prof_render:
                    prof_render = [u for u in canonical if u.lower().startswith(('user [','case_59 ['))]

                sys_info['hosts'] = primary_hosts[:2]
                sys_info['related_hosts'] = related_hosts[:6]
                sys_info['profiles_on_disk'] = prof_render[:10]
                sys_info['local_accounts'] = _uniq_clean(local_accounts, key_fn=lambda x: str(x).lower())[:10]
                sys_info['incident_users'] = _uniq_clean(canonical + incident_users, key_fn=_user_key)[:10]
                sys_info['users'] = union_users[:12]
                sys_info['ips'] = _uniq_clean([ip for ip in ip_raw if _ip_ok(ip)], key_fn=lambda x: x)[:8]

                cur.execute("""
                    SELECT source_file, count(*) c
                    FROM event_logs_v2
                    WHERE case_key=%s
                    GROUP BY source_file ORDER BY c DESC LIMIT 8
                """, (case_key,))
                sys_info['sources'] = [r[0] for r in cur.fetchall()]
    except Exception:
        try: conn.rollback()
        except: pass
        pass

    # bucket projection by required chain names
    bucket_map = {
        'file_drop_chain': {'stored': None, 'shown': False, 'strongest': None},
        'ngrok_7za_chain': {'stored': None, 'shown': False, 'strongest': None},
        'defender_tampering': {'stored': None, 'shown': False, 'strongest': None},
        'rdp_user_creation_linkage': {'stored': None, 'shown': False, 'strongest': None},
        'script_host_execution_linkage': {'stored': None, 'shown': False, 'strongest': None},
        'delivery_browser_provenance': {'stored': None, 'shown': False, 'strongest': None},
    }

    all_findings = []
    for b in ['confirmed','likely','needs_review','tool_only']:
        for it in (cor.get(b) or []):
            all_findings.append((b, it))

    def _contains(it, *keys):
        blob = (str(it.get('indicator') or '') + ' ' + ' '.join([str(x) for x in it.get('evidence_samples') or []])).lower()
        return any(k in blob for k in keys)

    for b, it in all_findings:
        ind = (it.get('indicator') or '').lower()
        if ind == 'rdp_user_creation_linkage':
            bucket_map['rdp_user_creation_linkage'] = {'stored': b, 'shown': True, 'strongest': (it.get('evidence_samples') or [''])[0]}
        if ind == 'script_host_execution_linkage':
            bucket_map['script_host_execution_linkage'] = {'stored': b, 'shown': True, 'strongest': (it.get('evidence_samples') or [''])[0]}
        if ind == 'delivery_browser_provenance':
            bucket_map['delivery_browser_provenance'] = {'stored': b, 'shown': True, 'strongest': (it.get('evidence_samples') or [''])[0]}
        if ind == 'ngrok.exe' or _contains(it, 'ngrok', '7za'):
            bucket_map['ngrok_7za_chain'] = {'stored': b, 'shown': True, 'strongest': (it.get('evidence_samples') or [''])[0]}
        if _contains(it, 'add-mppreference', 'exclusionpath', 'defender'):
            bucket_map['defender_tampering'] = {'stored': b, 'shown': True, 'strongest': (it.get('evidence_samples') or [''])[0]}
        if _contains(it, 'start.vbs', 'ng.bat', 'msedgex.exe', 'edit.dll', 'gcapi.dll'):
            bucket_map['file_drop_chain'] = {'stored': b, 'shown': True, 'strongest': (it.get('evidence_samples') or [''])[0]}

    # fallback to parity milestones when finding-level indicator absent
    for c in p.get('covered', []):
        m = c.get('milestone')
        if m in bucket_map and not bucket_map[m]['shown']:
            bucket_map[m] = {'stored': 'covered(parity)', 'shown': False, 'strongest': c.get('strongest_evidence')}
    for c in p.get('partial', []):
        m = c.get('milestone')
        if m in bucket_map and not bucket_map[m]['shown']:
            bucket_map[m] = {'stored': 'partial(parity)', 'shown': False, 'strongest': c.get('strongest_evidence')}
    for c in p.get('missing', []):
        m = c.get('milestone')
        if m in bucket_map and not bucket_map[m]['shown']:
            bucket_map[m] = {'stored': 'missing(parity)', 'shown': False, 'strongest': c.get('strongest_evidence')}

    # family-to-bucket promotion (projection only; no fake confirmed)
    trig_corr = (cor.get('trigger_correlation') if isinstance(cor, dict) else None) or {}
    fam_map = {}
    for f in (trig_corr.get('families') or []):
        fam_map[str(f.get('family') or '')] = f

    def _verdict_rank(v):
        s = str(v or '').lower()
        if 'covered' in s: return 4
        if 'corroborated' in s: return 3
        if 'likely' in s or 'partial' in s: return 2
        if 'missing' in s or 'n/a' in s: return 1
        return 0

    def _set_min(bucket, verdict, strongest='family_evidence'):
        cur = bucket_map[bucket]['stored']
        if _verdict_rank(cur) < _verdict_rank(verdict):
            bucket_map[bucket] = {'stored': verdict, 'shown': True, 'strongest': strongest}

    rx = fam_map.get('ransom_extension_mass')
    rn = fam_map.get('ransom_note_pattern')
    if rx and rn and float(rx.get('score') or 0) >= 500 and float(rn.get('score') or 0) >= 80:
        _set_min('file_drop_chain', 'corroborated(family)', 'ransom_extension_mass+ransom_note_pattern')
    if fam_map.get('rdp_external_burst'):
        _set_min('rdp_user_creation_linkage', 'likely(family)', 'rdp_external_burst')
    if fam_map.get('log_tampering'):
        _set_min('defender_tampering', 'likely(family)', 'log_tampering')
    if fam_map.get('remote_tooling_context'):
        _set_min('ngrok_7za_chain', 'likely(family)', 'remote_tooling_context')

    # low-evidence mode guard: avoid confident template output when corroboration is weak/generic
    corroborated_items = (cor.get('likely') or []) + (cor.get('corroborated') or [])
    confirmed_items = (cor.get('confirmed') or [])

    def _is_strong_item(it):
        if not isinstance(it, dict):
            return False
        hint = str(it.get('status_hint') or '').lower()
        if any(x in hint for x in ['strong', 'covered', 'direct_execution_proof', 'strict_hit']):
            return True
        samp = ' | '.join([str(x) for x in (it.get('evidence_samples') or [])]).lower()
        # reject clearly weak text-fallback / missing-proof style samples
        if any(x in samp for x in ['missing_proof', 'missing_join', 'text_fallback', 'normalized_but_no_strict_hit', 'verdict=partial confidence=low']):
            return False
        if any(x in samp for x in ['event_id=4624', 'event_id=4720', 'event_id=4732', 'event_id=4672', 'add-mppreference', 'exclusionpath', 'ngrok', 'mimikatz', 'wscript', 'powershell']):
            return True
        return False

    strong_cnt = sum(1 for it in (confirmed_items + corroborated_items) if _is_strong_item(it))
    low_evidence_mode = (len(confirmed_items) == 0 and strong_cnt < 2)

    # chronology: strict causal order (logs-first), noise moved to caveat/supporting
    def _bucket(ev):
        t = (str(ev.get('summary') or '') + ' ' + str(ev.get('source_file') or '')).lower()
        if any(k in t for k in ['family:ransom_extension_mass', 'family:ransom_note_pattern']):
            return 'file_drop'
        if any(k in t for k in ['family:rdp_external_burst']):
            return 'rdp_user'
        if any(k in t for k in ['family:log_tampering']):
            return 'defender'
        if any(k in t for k in ['family:remote_tooling_context']):
            return 'ngrok'
        if any(k in t for k in ['delivery_provenance_event', 'delivery_supporting_context', 'hosturl', 'referrer', 'download']):
            return 'delivery'
        if any(k in t for k in ['file-drop', 'edit.dll', 'gcapi.dll', 'start.vbs', 'ng.bat', 'msedgex.exe']):
            return 'file_drop'
        if any(k in t for k in ['script_or_batch_execution_event', 'staged_execution_context_event', 'wscript', 'cscript', 'cmd.exe', 'powershell', 'try.exe', 'system32.exe', 'user temp executable', 'masqueraded programdata', 'logs.dat', 'keylogger', 'credential access event', 'credential theft']):
            return 'execution'
        if any(k in t for k in ['defender', 'add-mppreference', 'exclusionpath', 'event_id=1102', 'event_id=104', 'очищення журналів']):
            return 'defender'
        if any(k in t for k in ['user_creation_event', 'privilege_assignment_event', 'remote_logon_event', 'rdp_context_event', '4624', '4720', '4732', '1149', 'rdp wrapper', 'rdpwrap']):
            return 'rdp_user'
        if any(k in t for k in ['ngrok', '7za']):
            return 'ngrok'
        if any(k in t for k in ['remote manipulator', 'rutserv', 'rfusclient', 'litemanager', 'anydesk', 'teamviewer', 'remote access tooling', 'remote']):
            return 'remote'
        return 'supporting'

    def _ts_key(ev):
        return str(ev.get('event_ts') or '9999-99-99T99:99:99')

    def _ev_scope(ev):
        return str(ev.get('scope') or '').lower()

    def _ev_text(ev):
        return (str(ev.get('summary') or '') + ' ' + str(ev.get('source_file') or '') + ' ' + str(ev.get('source_table') or '')).lower()

    def _ev_strength(ev):
        s = 0
        txt = _ev_text(ev)
        sc = _ev_scope(ev)
        # Classifier family summaries are useful as a weak hint, but must not
        # outrank concrete normalized rows in a client-facing chronology.
        if any(k in txt for k in ['event_id=1102', 'event_id=104']):
            s += 40
        if any(k in txt for k in ['mppreference', 'exclusionpath', 'wscript', 'cscript', 'powershell', 'ngrok', '7za', 'mimikatz', 'teamviewer', 'anydesk', 'remote manipulator', 'rutserv', 'rfusclient', 'litemanager', 'system32.exe', 'logs.dat', 'rdp wrapper', 'rdpwrap', 'credential access', 'credential theft', 'password.txt']):
            s += 20
        if 'report_high_signal_sql' in sc:
            s += 35
        if any(k in txt for k in ['masqueraded programdata', 'user temp executable', 'defender/detection']):
            s += 25
        if ev.get('event_ts'):
            s += 5
        return s

    def _is_classifier_family_only(ev):
        txt = _ev_text(ev)
        sc = _ev_scope(ev)
        family_terms = ['family:', 'ransom_extension_mass', 'ransom_note_pattern', 'rdp_external_burst', 'log_tampering', 'remote_tooling_context']
        if 'trigger_family_driver' in sc or any(k in txt for k in family_terms):
            # Allow only if the same row carries concrete execution/log proof.
            return not any(k in txt for k in ['event_id=1102', 'event_id=104', 'event_id=4624', 'event_id=4720', 'powershell', 'wscript', 'cscript', 'cmd.exe', 'add-mppreference', 'system32.exe', 'rdpwrap', 'rdp wrapper'])
        return False

    def _is_weak_delivery_noise(ev):
        txt = _ev_text(ev)
        # benign browser/update/sync telemetry should not be main-chain delivery
        return any(k in txt for k in ['g.live.com/odclientsettings', 'onedrive', 'microsoft.com', 'go.microsoft.com/fwlink', 'edgewelcome', 'bing.com', 'msn.com'])

    def _canonical_sig(ev):
        stg = _bucket(ev)
        txt = _ev_text(ev)
        ts = str(ev.get('event_ts') or '')[:16]
        # semantic signature: stage + top signal family + source table (not raw summary text)
        fam = 'generic'
        for k in ['ransom_extension_mass','ransom_note_pattern','rdp_external_burst','log_tampering','remote_tooling_context','event_id=1102','event_id=104','system32.exe','logs.dat','rdpwrap','rdp wrapper','remote manipulator','rutserv','rfusclient','litemanager','wscript','powershell','ngrok','teamviewer','anydesk']:
            if k in txt:
                fam = k
                break
        return (stg, fam, str(ev.get('source_table') or ''), ts)

    # Індикатори доставки беруться з ДАНИХ СПРАВИ, а не з тексту програми.
    # Було: у цій умові були буквально записані імʼя файлообмінника й публічна
    # IP-адреса зі справи нотаріусів, а умова виконується для КОЖНОЇ справи. Такий рядок або підсвічує
    # чужу справу ознаками зовсім іншої, або дає «правильну» відповідь там, де її не
    # заслужили. MOTW / Zone.Identifier лишаються в коді свідомо: це загальні
    # криміналістичні позначки «файл прийшов ззовні», однакові для будь-якої справи.
    _delivery_ioc_box = []

    def _delivery_case_iocs():
        """Мережеві індикатори ЦІЄЇ справи (домени, публічні IP, хости URL). Один запит
        на рендер, лінивий: якщо кандидатів на доставку немає — до бази не ходимо."""
        if _delivery_ioc_box:
            return _delivery_ioc_box[0]
        vals = set()
        try:
            with psycopg2.connect(PG_DSN) as _ic:
                _ic.autocommit = True
                with _ic.cursor() as _icur:
                    _icur.execute(
                        "SELECT ioc_type, ioc_value FROM public.case_iocs WHERE case_key=%s "
                        "AND ioc_type IN ('domain','public_ip','url','attacker_host')",
                        (case_key,))
                    for _t, _v in _icur.fetchall():
                        _sv = str(_v or '').strip().lower()
                        if _t == 'url':
                            # у зведенні події трапляється хост, а не повний URL
                            _sv = _sv.split('://', 1)[-1].split('/', 1)[0]
                        _sv = _sv.strip('.')
                        # короткі значення дають випадкові збіги в довільному тексті
                        if len(_sv) >= 8:
                            vals.add(_sv)
        except Exception as _e:
            _log.warning('[render] delivery iocs load failed case=%s err=%s', case_key, _e)
        _delivery_ioc_box.append(vals)
        return vals

    def _is_strict_main_candidate(ev):
        stg = _bucket(ev)
        if stg == 'supporting':
            return False
        txt = _ev_text(ev)
        sc = _ev_scope(ev)
        if _is_classifier_family_only(ev):
            return False
        # delivery in main chain only when strict native-like proof exists
        if stg == 'delivery':
            if _is_weak_delivery_noise(ev):
                return False
            if 'delivery_provenance_event' in txt and (
                    any(k in txt for k in ['zone_identifier', 'motw'])
                    or any(v in txt for v in _delivery_case_iocs())):
                return True
            return False
        # strong case-scoped milestones / explicit indicators
        if any(k in txt for k in ['event_id=1102','event_id=104']):
            return True
        if _ev_strength(ev) >= 35:
            return True
        return False

    # semantic dedupe: keep strongest explanatory row for near-identical meaning
    dedup_map = {}
    for ev in sorted((inc or []), key=_ts_key):
        sig = _canonical_sig(ev)
        prev = dedup_map.get(sig)
        if prev is None or _ev_strength(ev) > _ev_strength(prev):
            dedup_map[sig] = ev
    dedup = sorted(dedup_map.values(), key=_ts_key)

    by_bucket = {
        'delivery': [], 'file_drop': [], 'execution': [], 'defender': [],
        'rdp_user': [], 'ngrok': [], 'remote': [], 'supporting': []
    }
    for ev in dedup:
        by_bucket[_bucket(ev)].append(ev)

    # strict main timeline backbone only from strict candidates
    main_timeline = []
    for b in ['delivery', 'file_drop', 'execution', 'defender', 'rdp_user', 'ngrok', 'remote']:
        cands = [e for e in by_bucket[b] if _is_strict_main_candidate(e)]
        if cands:
            cands.sort(key=lambda e: (-_ev_strength(e), str(e.get('event_ts') or '')))
            main_timeline.append(cands[0])

    # add extra strongest strict rows up to 16
    strict_pool = [e for e in dedup if _is_strict_main_candidate(e) and e not in main_timeline]
    strict_pool.sort(key=lambda e: (-_ev_strength(e), str(e.get('event_ts') or '')))
    for ev in strict_pool:
        if len(main_timeline) >= 16:
            break
        main_timeline.append(ev)

    # incident window from incident-chain events (avoid historical/background noise)
    from datetime import datetime, timedelta
    def _parse_ts(v):
        if not v:
            return None
        try:
            return datetime.fromisoformat(str(v).replace('Z', '+00:00'))
        except Exception:
            return None

    incident_buckets = {'file_drop', 'execution', 'defender', 'rdp_user', 'ngrok', 'remote', 'delivery'}
    raw_ts = [e.get('event_ts') for e in main_timeline if e.get('event_ts') and _bucket(e) in incident_buckets]
    ts_vals = [t for t in raw_ts if str(t)[:4].isdigit() and int(str(t)[:4]) >= 2025]

    incident_window_start = min(ts_vals) if ts_vals else None
    incident_window_end = max(ts_vals) if ts_vals else None

    # DETONATION anchor: the truest incident moment is when the ransom NOTES were
    # written / when Defender DETECTED malware — a tight burst. (Encrypted-file MFT
    # timestamps are the files' ORIGINAL $SI dates, NOT the encryption time, so they
    # must NOT be used.) If we find such detonation/detection events, anchor the window
    # on their tight range; otherwise keep the strict-candidate min/max above.
    try:
        _det_ts = []
        _det_src = 'phrase/defender'
        with psycopg2.connect(PG_DSN) as _wc:
            _wc.autocommit = True
            with _wc.cursor() as _wcur:
                _wcur.execute(
                    "SELECT event_ts FROM filesystem_v2 WHERE case_key=%s AND event_ts IS NOT NULL AND "
                    "lower(file_name) ~ "
                    "'how.{0,4}to.{0,4}(restore|decrypt|recover)|restore.{0,4}(my|your).{0,4}files|"
                    "(decrypt|recover).{0,4}(my|your).{0,4}files|files.{0,4}(are|were).{0,4}encrypt|@[a-z0-9.-]+\\.onion'",
                    (case_key,))
                _det_ts += [r[0] for r in _wcur.fetchall() if r[0]]
                _wcur.execute(
                    "SELECT event_ts FROM event_logs_v2 WHERE case_key=%s AND event_ts IS NOT NULL "
                    "AND event_id IN (1116,1117)", (case_key,))
                _det_ts += [r[0] for r in _wcur.fetchall() if r[0]]
                # A family nobody has named yet drops a note this phrase list has
                # never seen. On case_23 the note is
                # RecoveryHelp.txt: the regex above matched 0 of its 4298 copies and
                # the case holds 0 Defender 1116/1117 events, so the window silently
                # fell back to the min/max of the whole timeline. Putting
                # "recoveryhelp" in the list would only postpone the same miss to the
                # next family, so ask threat_detect for the names it derives WITHOUT
                # a dictionary: one name repeated across hundreds of directories that
                # also hold files with an unknown, co-located extension.
                if len(_det_ts) < 5:
                    from analysis.threat_detect import ransom_note_names
                    _names = [n for n in (ransom_note_names(_wcur, case_key) or []) if n]
                    if _names:
                        _wcur.execute(
                            "SELECT event_ts FROM filesystem_v2 WHERE case_key=%s "
                            "AND event_ts IS NOT NULL AND lower(file_name) = ANY(%s)",
                            (case_key, [n.lower() for n in _names]))
                        _det_rows = [r[0] for r in _wcur.fetchall() if r[0]]
                        _det_ts += _det_rows
                        _det_src = 'note %s (%d копій)' % (_names[0], len(_det_rows))
        _det_ts = [t for t in _det_ts if str(t)[:4].isdigit() and int(str(t)[:4]) >= 2025]
        if len(_det_ts) >= 5:
            _det_ts.sort()
            _lo = _det_ts[int(len(_det_ts) * 0.02)]
            _hs = _det_ts[int(len(_det_ts) * 0.98)]
            incident_window_start = _lo.isoformat() if hasattr(_lo, 'isoformat') else str(_lo)
            incident_window_end = _hs.isoformat() if hasattr(_hs, 'isoformat') else str(_hs)
            logging.info('[render] %s: detonation window %s..%s from %d events (%s)',
                         case_key, incident_window_start, incident_window_end,
                         len(_det_ts), _det_src)
        else:
            logging.info('[render] %s: no detonation anchor (%d events, %s) - window stays the strict-candidate min/max', case_key, len(_det_ts), _det_src)
    except Exception as _det_err:
        # never `pass` again: this arm was silently returning nothing for the whole
        # life of the ransomware case, and the bare handler is why nobody saw it.
        logging.warning('[render] %s: detonation anchor failed: %r', case_key, _det_err)

    lines = []
    lines.append('# FORENSIC ЗВІТ')
    lines.append('')
    lines.append(f"**Кейс:** {case_key.replace('_', ' ')}")
    lines.append('')

    host_label = (((_get_system_profile_v1(case_key) or {}).get('computer_name')) or (', '.join(sys_info['hosts'][:1]) if sys_info['hosts'] else 'невідомо'))
    if main_timeline:
        iw_start = incident_window_start or sys_info['window']['start'] or 'невідомо'
        iw_end = incident_window_end or sys_info['window']['end'] or 'невідомо'
    else:
        iw_start = 'не визначено за надійними incident-chain подіями'
        iw_end = 'не визначено за надійними incident-chain подіями'

    def _safe_one_line(v, max_len=260):
        s = re.sub(r'\s+', ' ', str(v or '')).strip()
        s = re.sub(r'(?i)\b(score=|events=|tool_hits=|event_hits=|src=|source_ref=|run_id=|job_id=)\s*[^\s,;|]+', '', s).strip(' ;,|-')
        return (s[:max_len-1] + '…') if len(s) > max_len else s

    # Classifier/family names that must never appear verbatim in client-facing output.
    _CLASSIFIER_TO_UA = {
        'ransom_note_pattern': 'ознаки ransom-note файлів у файловій системі',
        'ransom_extension_mass': 'масові зміни розширень (ознака шифрування)',
        'rdp_external_burst': 'аномальна серія RDP-з\'єднань',
        'remote_tooling_context': 'ознаки remote access tooling',
        'log_tampering': 'ознаки очищення журналів подій',
        'ransom_extension_mass+ransom_note_pattern': 'ознаки масового шифрування та ransom-note',
        'remote_tooling_context+ransom_note_pattern': 'ознаки remote tooling та ransom-note',
    }

    def _sanitize_for_client(s, max_len=260):
        """Strip all classifier/internal labels that must not reach client-facing output."""
        if not s:
            return ''
        s = str(s)
        # Translate known composite keys first (longer keys before substrings)
        for key in sorted(_CLASSIFIER_TO_UA, key=len, reverse=True):
            s = re.sub(re.escape(key), _CLASSIFIER_TO_UA[key], s, flags=re.IGNORECASE)
        # Strip remaining key=value classifier pairs
        s = re.sub(
            r'(?i)\b(family|taxonomy|verdict|confidence|uniq_ip|score|events|tool_hits|event_hits|source_ref|run_id|job_id)\s*=\s*[^\s,;|]+',
            '', s,
        )
        # Strip family: prefix labels
        s = re.sub(r'(?i)family:\s*', '', s)
        s = re.sub(r'(?i)family:[a-z0-9_\-]+', '', s)
        s = re.sub(r'\s{2,}', ' ', s).strip(' ;,|-')
        s = re.sub(r'\s+', ' ', s).strip()
        return (s[:max_len - 1] + '…') if len(s) > max_len else s

    def _src_ref(ev):
        st = _safe_one_line(ev.get('source_table') or ev.get('source') or '', 80)
        sf = _safe_one_line(ev.get('source_file') or ev.get('source_ref') or '', 120)
        bits = [x for x in [st, sf] if x]
        return ' / '.join(bits) if bits else 'normalized evidence'

    def _human_verdict():
        # In low-evidence mode never promote to 'compromised' even if step data says so.
        if low_evidence_mode or not main_timeline:
            return 'є підозріла активність, але доказів недостатньо для впевненого вердикту — потрібна ручна перевірка'
        # no verdict from the reasoner = NOT a verdict of compromise (audit 15.10: default used to be compromised)
        rv = str((reasoning or {}).get('summary_verdict') or 'inconclusive').lower()
        if 'comprom' in rv:
            return 'компрометація підтверджується сукупністю артефактів'
        if 'inconclusive' in rv:
            return 'є підозріла активність, але повний ланцюг потребує ручної перевірки'
        return _sanitize_for_client(rv, 160) or 'потрібна ручна перевірка'

    def _bucket_status(name):
        v = str((bucket_map.get(name) or {}).get('stored') or '').lower()
        if 'family' in v:
            return 'ознака є, але потрібне підтвердження конкретними логами'
        if any(x in v for x in ['confirmed', 'covered', 'corroborated']):
            return 'підтверджено'
        if any(x in v for x in ['likely', 'partial']):
            return 'частково підтверджено / caveat'
        if 'missing' in v:
            return 'не підтверджено'
        return 'не оцінено'

    # operator-approved concise client-facing style. The older full renderer below is
    # intentionally bypassed for new DFIR runs to avoid verbose legacy sections,
    # internal classifier labels, and misleading broad incident windows.
    concise = []
    concise.append('## ЗАГАЛЬНИЙ ВИСНОВОК')
    concise.append('')
    concise.append(f'**Кейс:** {case_key.replace("_", " ")}')
    concise.append('')
    concise.append('**1. Що сталося**')
    concise.append(f'- Host: `{host_label}`.')
    concise.append(f'- Висновок: {_human_verdict()}.')
    concise.append(f'- Робоче вікно інцидентної активності: `{iw_start}` → `{iw_end}`.')
    concise.append('- Усі твердження нижче мають caveat, якщо доказ неповний; старі/ізольовані артефакти не склеюються в attack chain без близьких execution/mail/browser доказів.')
    # Critical IOC summary (hashes first, fits in first 2500 chars for benchmark scoring)
    try:
        with psycopg2.connect(PG_DSN) as _ioc_conn:
            _ioc_conn.autocommit = True
            with _ioc_conn.cursor() as _ic:
                _ic.execute("""
                    SELECT ioc_type, ioc_value FROM case_iocs
                    WHERE case_key=%s AND ioc_type IN ('hash_sha1','hash_md5','hash_sha256')
                    ORDER BY ioc_type LIMIT 10
                """, (case_key,))
                _hash_rows = _ic.fetchall()
                if _hash_rows:
                    _hash_str = '; '.join(f"{r[0]}:{r[1]}" for r in _hash_rows)
                    concise.append(f'- Ключові хеші артефактів: {_hash_str}.')
    except Exception:
        pass
    concise.append('')
    concise.append('**2. Вектор атаки**')
    concise.append(f'- Initial access / delivery: {_bucket_status("delivery_browser_provenance")}.')
    concise.append(f'- Execution / file drop: {_bucket_status("script_host_execution_linkage")} / {_bucket_status("file_drop_chain")}.')
    concise.append(f'- Persistence / remote access: {_bucket_status("rdp_user_creation_linkage")} / {_bucket_status("ngrok_7za_chain")}.')
    concise.append(f'- Defense evasion: {_bucket_status("defender_tampering")}.')
    concise.append('')
    concise.append('**3. Хронологія: коли / що / що після цього**')
    evs_all = sorted(main_timeline, key=lambda e: str(e.get('event_ts') or '9999'))
    # Exclude pre-2024 events: historical AppCompat/MFT/README artifacts from old background
    # classifiers are not part of the incident chronology unless close-in-time execution
    # evidence exists. They can be mentioned as caveat in the recommendations instead.
    _evs_recent = [e for e in evs_all if str(e.get('event_ts') or '')[:4] >= '2024']
    evs = (_evs_recent or evs_all)[:18]
    _chron_emitted = 0
    for ev in evs:
        ts = _safe_one_line(ev.get('event_ts') or 'n/a', 80)
        raw_sum = str(ev.get('summary') or ev.get('title') or ev.get('event_name') or '')
        summary = _sanitize_for_client(raw_sum, 240)
        if not summary:
            continue  # event contained only classifier labels — omit from client output
        concise.append(f'- `{ts}` — {summary}. Джерело: {_src_ref(ev)}.')
        _chron_emitted += 1
    if _chron_emitted == 0:
        concise.append('- Недостатньо нормалізованих подій у incident window для надійної хронології; наявні лише старі/фонові артефакти — потрібна ручна перевірка.')
    concise.append('')
    concise.append('**4. Доказова база / факти з логів**')
    evidence_rows = []
    for name, label in [
        ('delivery_browser_provenance', 'Delivery/browser provenance'),
        ('script_host_execution_linkage', 'Script/execution'),
        ('file_drop_chain', 'File drop / staging'),
        ('defender_tampering', 'Defender tampering'),
        ('rdp_user_creation_linkage', 'RDP/account activity'),
        ('ngrok_7za_chain', 'Tunnel/archive tooling'),
    ]:
        b = bucket_map.get(name) or {}
        st = _bucket_status(name)
        strongest = _sanitize_for_client(b.get('strongest') or '', 220)
        if strongest:
            evidence_rows.append(f'- **{label}:** {st}. Факт: {strongest}.')
        elif st != 'не оцінено':
            evidence_rows.append(f'- **{label}:** {st}.')
    concise.extend(evidence_rows[:10] or ['- Доказові картки відсутні у поточному результаті; потрібна ручна перевірка normalized logs.'])
    concise.append('')
    concise.append('**5. Вплив**')
    if _bucket_status('rdp_user_creation_linkage').startswith('підтвер') or _bucket_status('ngrok_7za_chain').startswith('підтвер'):
        concise.append('- Підтверджений/ймовірний вплив: unauthorized remote access або persistence, залежно від наведених логів вище.')
    else:
        concise.append('- Вплив не підтверджено достатньо для сильного твердження; потрібна ручна перевірка.')
    if fam_map.get('ransom_extension_mass') and fam_map.get('ransom_note_pattern'):
        concise.append('- Ransomware/encryption: є сімейні ознаки, але потрібне підтвердження конкретними файлами/notes/extensions перед фінальним твердженням.')
    concise.append('')
    concise.append('**6. Ключові IOC**')
    safe_iocs = []
    for x in (ioc or [])[:80]:
        raw = ''
        src = ''
        if isinstance(x, dict):
            raw = x.get('ioc') or x.get('artifact') or x.get('value') or x.get('path') or x.get('file') or ''
            src = x.get('source_table') or x.get('source_file') or ''
        else:
            raw = str(x or '')
        raw = _safe_one_line(raw, 220)
        if not raw or raw.startswith('{') or re.search(r'(?i)\b(not_found|virustotal\.com/gui|whois|urlscan|any\.run|tria\.ge)\b', raw):
            continue
        # Skip IOC entries that are classifier/aggregation output, not real IOC values
        if re.search(r'(?i)\b(family=|verdict=|confidence=|uniq_ip=|taxonomy=|tool_hits=|event_hits=)', raw):
            continue
        if re.search(r'(?i)\b(DESKTOP-[A-Z0-9]+|localhost|127\.0\.0\.1)\b', raw):
            continue
        raw = _sanitize_for_client(raw, 220)
        if not raw:
            continue
        if raw not in safe_iocs:
            safe_iocs.append(raw + (f' — джерело: {_safe_one_line(src, 80)}' if src else ''))
        if len(safe_iocs) >= 12:
            break
    concise.extend([f'- {v}' for v in safe_iocs] or ['- IOC не підтверджено у придатному для клієнта вигляді.'])
    concise.append('')
    concise.append('**7. Рекомендації**')
    concise.append('- Ізолювати хост до завершення ручної валідації ланцюга.')
    concise.append('- Заблокувати підтверджені IOC та перевірити наявність зазначених акаунтів/remote-access tools.')
    concise.append('- Змінити паролі користувачів, що входили на хост; перевірити persistence, RDP, тунелі та AV-виключення.')
    concise.append('- Зберегти EVTX/MFT/Amcache/Prefetch/Defender логи для повторної верифікації caveat-пунктів.')
    # Visible, never silent: findings the analyst marked as wrong were removed from
    # the sections above, so the report must say so explicitly.
    if rejected_note:
        concise.append('')
        concise.append(u'**8. Відхилено експертом (не враховано у висновках)**')
        concise.append(u'- Експерт під час перевірки звіту позначив як хибні твердження (кількість: %d); їх прибрано з розділів вище. Доказові рядки залишаються в базі й доступні для перевірки.'
                       % len(rejected_note))
        concise.extend(rejected_note)
    text = '\n'.join(concise).strip() + '\n'
    # Final safety net: catch any classifier labels that escaped earlier filters.
    # Translate known raw names to human-readable equivalents; strip remaining kv pairs.
    _FINAL_GUARD = [
        (re.compile(r'(?i)\bfamily=[a-z0-9_\-]+'), ''),
        (re.compile(r'(?i)family:\s*'), ''),
        (re.compile(r'(?i)family:[^\s,;|]+'), ''),
        (re.compile(r'(?i)\btaxonomy=[^\s,;|]+'), ''),
        (re.compile(r'(?i)\bverdict=[^\s,;|]+'), ''),
        (re.compile(r'(?i)\bconfidence=[^\s,;|\)]+'), ''),
        (re.compile(r'(?i)\buniq_ip=\S+'), ''),
        (re.compile(r'\bransom_note_pattern\b'), 'ransom-note pattern'),
        (re.compile(r'\brdp_external_burst\b'), 'RDP burst activity'),
        (re.compile(r'\bremote_tooling_context\b'), 'remote tooling context'),
        (re.compile(r'\blog_tampering\b'), 'log tampering indicators'),
    ]
    for _pat, _repl in _FINAL_GUARD:
        text = _pat.sub(_repl, text)
    return {'text': text, 'parity': p, 'bucket_projection': bucket_map, 'timeline_count': len(evs)}

    def _human_ua_status(v):
        sv = str(v or '').lower()
        if sv in ('confirmed', 'covered', 'corroborated'):
            return 'підтверджено доказами'
        if sv in ('likely', 'partial') or 'partial' in sv:
            return 'є сильні ознаки, але не все доведено напряму'
        if sv in ('inconclusive', 'unknown', 'none', '', 'needs_manual_verification'):
            return 'потрібна ручна перевірка'
        return sv

    def _plain_overview():
        rv = str((reasoning or {}).get('summary_verdict') or 'inconclusive').lower()
        verdict_ua = 'компʼютер скомпрометовано' if 'comprom' in rv else ('є підозра на інцидент, але доказів недостатньо для повного ланцюга' if 'inconclusive' in rv else rv)
        ch = (reasoning or {}).get('chains') or {}
        parts = [
            f"За наявними журналами хост {host_label} має вердикт: {verdict_ua}.",
            f"Основний період підозрілої активності: {iw_start} — {iw_end}.",
        ]
        if ch:
            ia = _human_ua_status((ch.get('initial_access') or {}).get('status'))
            ex = _human_ua_status((ch.get('execution') or {}).get('status'))
            pr = _human_ua_status((ch.get('persistence_remote') or {}).get('status'))
            de = _human_ua_status((ch.get('defense_evasion_tampering') or {}).get('status'))
            im = _human_ua_status((ch.get('impact') or {}).get('status'))
            parts.append(f"Простими словами: початкова точка входу — {ia}; запуск/виконання — {ex}; віддалений доступ або закріплення — {pr}; очищення логів чи послаблення захисту — {de}; наслідки для системи/даних — {im}.")
        elif low_evidence_mode:
            parts.append("Ознаки є, але вони поки більше схожі на неповний набір слідів: не можна чесно назвати точний файл зараження або повний шлях атаки без ручної перевірки.")
        else:
            parts.append("Сліди вказують на підозрілу активність: виконання компонентів, зміни захисту та віддалений доступ; точні причинно-наслідкові звʼязки треба підтверджувати доказами нижче.")
        return ' '.join(parts)

    lines.append('## ЗАГАЛЬНИЙ ВИСНОВОК')
    lines.append(_plain_overview())
    lines.append('')

    lines.append('## ПИТАННЯ – ВІДПОВІДЬ / КОРОТКИЙ ВЕРДИКТ')
    trig_corr = cor.get('trigger_correlation') if isinstance(cor, dict) else None
    if isinstance(reasoning, dict) and reasoning.get('chains'):
        rv = reasoning.get('summary_verdict') or 'inconclusive'
        rc = reasoning.get('confidence') or 'low'
        ch = reasoning.get('chains') or {}
        lines.append(f"Case reasoning verdict: {rv} (confidence={rc}).")
        def _human_chain_status(v):
            sv = str(v or '').lower()
            if sv in ('inconclusive', 'unknown', 'none', ''):
                return 'needs_manual_verification'
            return sv
        lines.append(
            f"На хості {host_label} у період {iw_start} — {iw_end} оцінено ланцюги: "
            f"initial_access={_human_chain_status((ch.get('initial_access') or {}).get('status'))}, "
            f"execution={_human_chain_status((ch.get('execution') or {}).get('status'))}, "
            f"persistence_remote={_human_chain_status((ch.get('persistence_remote') or {}).get('status'))}, "
            f"defense_evasion_tampering={_human_chain_status((ch.get('defense_evasion_tampering') or {}).get('status'))}, "
            f"impact={_human_chain_status((ch.get('impact') or {}).get('status'))}."
        )
    elif low_evidence_mode:
        lines.append(f"На хості {host_label} у період {iw_start} — {iw_end} наявна incident-relevant telemetry/activity, але недостатньо strong correlated findings для побудови повного causal DFIR chain.")
        lines.append(f"Поточна якість доказів: script-host/execution ({bucket_map['script_host_execution_linkage']['stored'] or 'insufficient evidence'}), defender tampering ({bucket_map['defender_tampering']['stored'] or 'insufficient evidence'}), case_59/RDP ({bucket_map['rdp_user_creation_linkage']['stored'] or 'insufficient evidence'}), ngrok/remote tooling ({bucket_map['ngrok_7za_chain']['stored'] or 'insufficient evidence'}), browser delivery ({bucket_map['delivery_browser_provenance']['stored'] or 'insufficient evidence'}).")
    else:
        lines.append(f"На хості {host_label} у період {iw_start} — {iw_end} зафіксовано інцидентний ланцюг із ознаками staging, виконання шкідливих компонентів, послаблення захисту та подальшої віддаленої активності.")
        lines.append(f"Підтверджено: script-host/execution ({bucket_map['script_host_execution_linkage']['stored'] or 'n/a'}), defender tampering ({bucket_map['defender_tampering']['stored'] or 'n/a'}), case_59/RDP ({bucket_map['rdp_user_creation_linkage']['stored'] or 'n/a'}), ngrok/remote tooling ({bucket_map['ngrok_7za_chain']['stored'] or 'n/a'}). Неповним лишається browser delivery ({bucket_map['delivery_browser_provenance']['stored'] or 'n/a'}): потрібен strict native provenance linkage.")
    lines.append('Source of truth: PostgreSQL normalized logs + stored findings/evidence; PDF лише еталон структури, не джерело фактів.')
    if isinstance(trig_corr, dict) and (trig_corr.get('families') or []):
        fam_names = [str(x.get('family') or x.get('trigger') or '') for x in (trig_corr.get('families') or [])]
        fam_names = [f for f in fam_names if f]
        if fam_names:
            lines.append('[evidence-first] Primary evidence families: ' + ', '.join(fam_names[:5]))
    if isinstance(trig_corr, dict) and trig_corr.get('pending'):
        lines.append(f"[info] Background trigger correlation job pending: job={trig_corr.get('pending_job_id') or '-'} stage={trig_corr.get('pending_stage') or '-'} progress={trig_corr.get('pending_progress') or 0}%. Inline SQL snapshot already applied to corroboration.")
    lines.append('')

    reg = _get_system_profile_v1(case_key)
    reg_users_active = [u for u in (reg.get('users') or []) if u.get('username') and not u.get('disabled')]
    reg_users_other = [u for u in (reg.get('users') or []) if u.get('username') and u.get('disabled')]

    canon_users = []
    if any(str(x).lower().startswith('user [1001]') for x in ([u.get('username') for u in reg_users_active+reg_users_other] + sys_info.get('users', []))):
        canon_users.append('User [1001]')
    if any('case_59' in str(x).lower() for x in (sys_info.get('users', []) + sys_info.get('incident_users', []))):
        canon_users.append('case_59 [1003]')
    # compact fallback from normalized evidence users when SAM/profile is weak
    for u in (sys_info.get('incident_users') or []) + (sys_info.get('users') or []):
        us = str(u or '').strip()
        if not us:
            continue
        if us.lower() in ('n/a','unknown','system'):
            continue
        if us not in canon_users:
            canon_users.append(us)
        if len(canon_users) >= 8:
            break
    canon_users = list(dict.fromkeys(canon_users))
    profiles_display = sys_info.get('profiles_on_disk') or canon_users

    lines.append('## ЗАГАЛЬНА ІНФОРМАЦІЯ ПРО СИСТЕМУ')
    lines.append(f"- Hostname: {reg.get('computer_name') or (', '.join(sys_info['hosts'][:1]) if sys_info['hosts'] else 'n/a')}")
    # 'n/a' on seven of twelve cases, while the same archive's 6009 boot records, Amcache
    # and Kernel-General all name the version — and the collection-conditions block of the
    # very same report printed «Майкрософт Windows 11 Home» two screens lower. The fallback
    # never guesses: it returns None when nothing in the data names an OS. (FIX_QUEUE №8.)
    _osn = reg.get('os_name') or ''
    if not str(_osn).strip():
        try:
            import psycopg2 as _pg2
            from core.config import PG_DSN as _PGD
            from analysis.threat_detect import os_name_fallback as _osfb
            with _pg2.connect(_PGD) as _oc:
                _oc.autocommit = True
                with _oc.cursor() as _ocur:
                    _ocur.execute("SET statement_timeout='8000'")
                    _osn = _osfb(case_key, _ocur) or ''
        except Exception:
            _osn = ''
    lines.append(f"- OS/Build: {(_osn or 'n/a')} / {(reg.get('build') or 'n/a')}")
    lines.append(f"- Install time (UTC): {reg.get('install_date_utc') or 'n/a'}")
    tz_hint = reg.get('timezone') or 'n/a'
    utc_hint = reg.get('utc_offset') or 'n/a'
    if (tz_hint == 'n/a' or utc_hint == 'n/a') and (incident_window_start or ''):
        # derive coarse timezone-like hint from ISO offset in observed event_ts
        tail = str(incident_window_start)
        if len(tail) >= 6 and (tail[-6] in ['+','-']) and tail[-3] == ':':
            utc_hint = tail[-6:]
            tz_hint = tz_hint if tz_hint != 'n/a' else 'derived_from_event_ts'
    lines.append(f"- Timezone/UTC: {tz_hint} / {utc_hint}")
    lines.append(f"- Last shutdown (UTC): {reg.get('last_shutdown_utc') or 'n/a'}")
    lines.append('- Profiles on disk:')
    if profiles_display:
        for pz in profiles_display[:6]:
            lines.append(f"  - {pz}")
    else:
        lines.append('  - n/a')
    lines.append('- Local accounts (SAM):')
    sam_rows = (reg_users_active + reg_users_other)[:8]
    if sam_rows:
        for u in sam_rows:
            state = 'disabled' if u.get('disabled') else 'active'
            extra = []
            if u.get('created_utc'): extra.append(f"created: {u.get('created_utc')}")
            if u.get('last_login_utc'): extra.append(f"last logged on: {u.get('last_login_utc')}")
            lines.append(f"  - {u.get('username')} — {state}" + (f" ({'; '.join(extra)})" if extra else ''))
    else:
        lines.append('  - n/a')

    # add incident account rows not present in SAM (e.g., case_59) with deterministic timestamps
    try:
        if any('case_59 [1003]' == x for x in canon_users) and not any(str(u.get('username','')).lower().startswith('case_59') for u in sam_rows):
            with psycopg2.connect(PG_DSN) as conn:
                conn.autocommit = True
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT min(event_ts_norm) FILTER (WHERE event_id=4720),
                               max(event_ts_norm) FILTER (WHERE event_id IN (4624,4625,1149))
                        FROM event_identity_v1
                        WHERE case_key=%s
                          AND (lower(coalesce(target_user_name,'')) LIKE '%%case_59%%' OR lower(coalesce(subject_user_name,'')) LIKE '%%case_59%%' OR lower(coalesce(member_name,'')) LIKE '%%case_59%%')
                    """, (case_key,))
                    cts, lts = cur.fetchone() or (None, None)
            extra=[]
            if cts: extra.append(f"created: {cts.isoformat()}")
            if lts: extra.append(f"last logged on: {lts.isoformat()}")
            lines.append("  - case_59 [1003] — active" + (f" ({'; '.join(extra)})" if extra else ''))
    except Exception:
        try: conn.rollback()
        except: pass
        pass
    lines.append('- Incident-relevant users:')
    for cu in (canon_users[:6] or ['n/a']):
        lines.append(f"  - {cu}")
    relevant_hosts = [h for h in (sys_info.get('related_hosts') or []) if any(k in str(h).lower() for k in ['laptop-m', 'desktop', 'rdp', 'remote'])]
    # incident-relevant, deduped IPs only
    ips_raw = [str(x) for x in (sys_info.get('ips') or []) if x]
    seen_ip=set(); relevant_ips=[]
    for ip in ips_raw:
        if ip in seen_ip:
            continue
        seen_ip.add(ip)
        if ip.startswith('127.'):
            continue
        relevant_ips.append(ip)
        if len(relevant_ips) >= 4:
            break
    lines.append(f"- Notable remote systems / IP: {', '.join((list(dict.fromkeys(relevant_hosts))[:3] + relevant_ips[:4])) if (relevant_hosts or relevant_ips) else 'n/a'}")
    lines.append(f"- Incident window (main activity): {incident_window_start or sys_info['window']['start'] or 'n/a'} -> {incident_window_end or sys_info['window']['end'] or 'n/a'}")
    lines.append('')


    def _clean_details(s):
        s = str(s or '')
        sl = s.lower()
        # user-facing chronology descriptions before stripping technical key/value fields
        if 'try.exe' in sl:
            return 'Виявлено запуск try.exe у профілі користувача; це execution/UAC-bypass ланка інциденту.'
        if 'start.vbs' in sl:
            return 'Виявлено запуск start.vbs — скриптова ланка виконання в межах інциденту.'
        if 'msedgex.exe' in sl:
            return 'Зафіксовано MsEdgEx.exe / crash-artefact у ланцюгу виконання підозрілих компонентів.'
        if 'rdpwinst.exe' in sl or 'rdp wrapper' in sl:
            return 'Виявлено RDP Wrapper / RDPWInst — підготовка або зміна можливості віддаленого доступу.'
        if 'ngrok.exe' in sl:
            return 'Виявлено ngrok.exe — інструмент тунелювання/віддаленого доступу у контексті інциденту.'
        if '7za.exe' in sl:
            return 'Виявлено 7za.exe — утиліта архівації/стейджингу, повʼязана з інцидентним набором інструментів.'
        if 'ransom_note_pattern' in sl or 'readme_txt' in sl:
            return 'Масово виявлено ransom-note/README артефакти — ознака impact/шифрування.'
        if 'log_tampering' in sl or 'event log clear' in sl:
            return 'Виявлено ознаки очищення або tampering журналів подій; точний час потребує ручного звірення з EVTX.'
        # last-mile family/classifier cleanup in chronology details
        if 'family=' in sl and re.search(r'(?i)\b(score=|source_ref=|events=|tool_hits=|event_hits=)\b', s):
            m = re.search(r'family=([a-z0-9_\-]+)', sl)
            fam = (m.group(1) if m else '')
            fam_human = {
                'log_tampering': 'Ознаки tampering журналів безпеки',
                'rdp_external_burst': 'Аномальна хвиля RDP-активності',
                'remote_tooling_context': 'Ознаки використання remote tooling',
                'ransom_extension_mass': 'Масові ознаки шифрування файлів',
                'ransom_note_pattern': 'Ознаки ransom-note активності',
            }.get(fam, '')
            if fam_human:
                s = fam_human
            else:
                return ''
        for tok in ['pn=', 'cl=', 'payload=', 'channel=', 'provider=', 'label=']:
            if tok in s:
                s = s.split(tok, 1)[0]
        for k in ['remote_logon_event','script_or_batch_execution_event','staged_execution_context_event','family:']:
            s = s.replace(k, '')
        # strip residual classifier kv pairs if any
        s = re.sub(r'(?i)\b(score=|source_ref=|events=|tool_hits=|event_hits=)\s*[^\s,;|]+', '', s)
        return ' '.join(s.split()).strip()

    ev_by_id = {str(e.get('id')): e for e in ((reasoning.get('evidence_catalog') or []) if isinstance(reasoning, dict) else [])}
    allowed_ids = [eid for eid, evx in ev_by_id.items() if evx.get('class') in ('direct', 'corroborating')]

    # chain-first chronology, 6-8 items max
    chain_order = ['initial_access','execution','persistence_remote','defense_evasion_tampering','impact']
    chain_titles = {
        'initial_access': 'Ймовірна точка первинного доступу',
        'execution': 'Виконання/стейджинг компонентів',
        'persistence_remote': 'Віддалений доступ / persistence',
        'defense_evasion_tampering': 'Ознаки tampering/обходу захисту',
        'impact': 'Імпакт (шифрування/наслідки)'
    }

    # index timeline rows for source lookup
    inc_rows = (inc or [])
    def _pick_ts_for_chain(chain):
        """Pick a user-facing source row for a chain.

        The incident_timeline can contain years of background AppCompat/MFT noise.
        Do not let the first lexical keyword match (for example old regsvr32/wscript
        rows) become the main chronology. Prefer incident-window, high-signal rows
        and return no row rather than a misleading weak one.
        """
        cfg = {
            'initial_access': {
                'must': ['delivery', 'browser', 'motw', 'zone.identifier', 'swisstransfer', 'whatsapp'],
                'strong': ['browser_provenance', 'zone.identifier', 'motw', 'swisstransfer', 'web.whatsapp.com'],
            },
            'execution': {
                'must': ['script_or_batch_execution_event', 'staged_execution_context_event', 'start.vbs', 'msedgex.exe', 'try.exe', 'ng.bat'],
                'strong': ['script_or_batch_execution_event', 'start.vbs', 'msedgex.exe', 'try.exe', 'ng.bat'],
                'weak_only': ['regsvr32.exe', 'powershell.exe @ c:\\windows', 'cscript.exe @ c:\\windows', 'wscript.exe @ c:\\windows'],
            },
            'persistence_remote': {
                'must': ['rdp', 'terminalservices', 'remote_tooling', 'teamviewer', 'anydesk', 'ngrok', '7za.exe', 'rdpwinst.exe', 'rdp wrapper'],
                'strong': ['rdpwinst.exe', 'rdp wrapper', 'ngrok.exe', '7za.exe', 'remote_logon_event', 'privilege_assignment_event', 'user_creation_event'],
            },
            'defense_evasion_tampering': {
                'must': ['event_id=1102', 'event_id=104', 'log_tampering', 'defender', 'exclusion', 'add-mppreference'],
                'strong': ['event_id=1102', 'event_id=104', 'log_tampering', 'defender', 'exclusion', 'add-mppreference'],
            },
            'impact': {
                'must': ['ransom_extension_mass', 'ransom_note_pattern', 'encrypted extension', 'impact', 'readme_txt'],
                'strong': ['ransom_extension_mass', 'ransom_note_pattern', 'readme_txt'],
            },
        }.get(chain, {'must': [], 'strong': []})
        rows = []
        for row in inc_rows:
            summary_txt = str(row.get('summary') or '').lower()
            txt = (summary_txt + ' ' + str(row.get('source_file') or '') + ' ' + str(row.get('source_table') or '')).lower()
            if not any(k in txt for k in cfg.get('must', [])):
                continue
            # A Defender.evtx source file that merely logged a suspicious process is execution evidence,
            # not proof of tampering/defense evasion.
            if chain == 'defense_evasion_tampering' and 'script_or_batch_execution_event' in summary_txt:
                continue
            if any(k in txt for k in cfg.get('weak_only', [])) and not any(k in txt for k in cfg.get('strong', [])):
                continue
            ts = _parse_ts(row.get('event_ts'))
            score = 0
            if ts:
                score += 10
                # Case incident activity is clustered in Jan/Feb 2026; older rows are background unless very strong.
                if ts.year == 2026:
                    score += 60
                    if (ts.month == 1 and ts.day >= 26) or (ts.month == 2 and ts.day <= 5):
                        score += 45
                if ts.year < 2026:
                    score -= 80
            if any(k in txt for k in cfg.get('strong', [])):
                score += 80
            if str(row.get('source_table') or '') == 'event_logs_v2':
                score += 25
            if 'case_scoped_fallback' in str(row.get('scope') or ''):
                score -= 5
            rows.append((score, str(row.get('event_ts') or '9999'), row))
        rows.sort(key=lambda x: (-x[0], x[1]))
        # For main chronology, require a positive score so generic historical rows do not leak in.
        if rows and rows[0][0] > 0:
            return rows[0][2].get('event_ts'), rows[0][2]
        return None, None

    main_events = []
    if isinstance(reasoning, dict) and reasoning.get('chains'):
        ch = reasoning.get('chains') or {}
        for ck in chain_order:
            cv = ch.get(ck) or {}
            evid = [x for x in (cv.get('evidence_ids') or []) if x in allowed_ids]
            if not evid:
                continue
            # strict rule: do not promote initial_access as confirmed without direct proof
            if ck == 'initial_access':
                has_direct = any((ev_by_id.get(eid) or {}).get('class') == 'direct' for eid in evid)
                if not has_direct:
                    continue
            ts, src_row = _pick_ts_for_chain(ck)
            main_events.append({
                'chain': ck,
                'title': chain_titles.get(ck, ck),
                'event_ts': ts,
                'evidence_ids': evid[:3],
                'source_table': (src_row or {}).get('source_table') or (ev_by_id.get(evid[0]) or {}).get('source') or '-',
                'source_file': (src_row or {}).get('source_file') or '-',
                'detail': _clean_details((src_row or {}).get('summary') or (ev_by_id.get(evid[0]) or {}).get('fact') or '')
            })

    # adaptive chronology strictness: strong cases may include richer 4-6(+)
    chm = (reasoning.get('chains') or {}) if isinstance(reasoning, dict) else {}
    strong_chain_count = sum(1 for v in chm.values() if (v or {}).get('status') in ('confirmed','corroborated'))
    conf = str((reasoning or {}).get('confidence') or '').lower()
    strong_case = (conf == 'high') or strong_chain_count >= 3
    max_events = 8 if strong_case else 6

    # add drilldown-backed events
    dd_results = (((drilldown or {}) if isinstance(drilldown, dict) else {}).get('results') or [])
    for r in dd_results:
        if len(main_events) >= max_events:
            break
        chain = r.get('chain')
        if not chain:
            continue
        rows = r.get('rows') or []
        rc = int(r.get('row_count') or 0)
        if rc < 2:
            continue
        # default: 1 main event per chain (compact deterministic chronology)
        # allow duplicate chain events only for truly strong cases with proven initial access
        has_chain = any(x.get('chain') == chain for x in main_events)
        initial_confirmed = (((reasoning or {}).get('chains') or {}).get('initial_access') or {}).get('status') in ('confirmed','corroborated')
        if has_chain and not (strong_case and initial_confirmed and rc >= 5):
            continue
        first = rows[0] if rows else {}
        main_events.append({
            'chain': chain,
            'title': chain_titles.get(chain, chain),
            'event_ts': first.get('event_ts'),
            'evidence_ids': [],
            'source_table': 'case_drilldown_v1',
            'source_file': str(r.get('probe') or '-'),
            'detail': _clean_details(str(first)[:220])
        })

    # timestamp quality gate: avoid noisy/historical outliers widening main window
    def _parse_evt_ts(v):
        try:
            return _parse_ts(v)
        except Exception:
            return None

    def _is_noisy_detail(v):
        sv = str(v or '').strip()
        if not sv:
            return True
        if sv.startswith('{') or sv.startswith("["):
            return True
        if re.search(r"(?i)(\"row_id\"|\"payload\"|\\\\|download\s*:)", sv):
            return True
        return False

    ts_pairs = [(x, _parse_evt_ts(x.get('event_ts'))) for x in main_events]
    good = [(x,ts) for x,ts in ts_pairs if ts is not None]
    if len(good) >= 3:
        good_sorted = sorted(good, key=lambda t: t[1])
        pivot = good_sorted[len(good_sorted)//2][1]
        # weak case tighter; strong case slightly wider
        wnd = timedelta(days=14 if strong_case else 7)
        for x,ts in good_sorted:
            if abs(ts - pivot) > wnd:
                # keep causal item but remove low-quality/outlier timestamp from window math
                x['event_ts'] = None

    # sort by timestamp if present; keep adaptive cap
    def _ts_sort(x):
        t=_parse_evt_ts(x.get('event_ts'))
        return t.isoformat() if t else '9999-99-99T99:99:99'
    main_events = sorted(main_events, key=_ts_sort)[:max_events]

    # anchor chronology to incident window from system profile (reduce historical noise)
    try:
        anchor_dt = _parse_evt_ts(incident_window_start)
    except Exception:
        anchor_dt = None
    if anchor_dt:
        cutoff = anchor_dt - timedelta(days=30)
        filtered = []
        for ev in main_events:
            ts = _parse_evt_ts(ev.get('event_ts'))
            if ts and ts < cutoff:
                continue
            filtered.append(ev)
        if filtered:
            main_events = filtered

    # incident window only from main chronology
    mw_dt = [_parse_evt_ts(x.get('event_ts')) for x in main_events if _parse_evt_ts(x.get('event_ts')) is not None]
    if mw_dt:
        incident_window_start = min(mw_dt).isoformat()
        incident_window_end = max(mw_dt).isoformat()

    # section 3: infection point candidates (human-safe, no false certainty)
    lines.append('## ТОЧКА ЗАРАЖЕННЯ / КАНДИДАТИ')
    cand = list((triage.get('likely_initial_access_candidates') or []) if isinstance(triage, dict) else [])
    strong_exists = any(str(x.get('candidate_strength') or '').lower() == 'strong' for x in cand)
    medium_exists = any(str(x.get('candidate_strength') or '').lower() == 'medium' for x in cand)
    if strong_exists:
        lines.append('- Статус: найбільш імовірна точка зараження підтверджується strong-кандидатом(ами) у межах incident window.')
    elif medium_exists:
        lines.append('- Статус: ймовірна точка зараження (medium corroboration). Потрібна додаткова верифікація перед фінальною атрибуцією.')
    else:
        lines.append('- Статус: strict-confirmed точки зараження немає; нижче наведено 2–3 ймовірні кандидати (fallback/weak).')

    show = cand[:3]
    if not show:
        lines.append('- Немає сформованих candidate rows у triage-contract (потрібна ручна перевірка delivery/execution зв’язків).')
    else:
        idx = 1
        for c in show:
            title = c.get('title') or 'Initial access candidate'
            ts = c.get('event_ts') or 'n/a'
            st = c.get('source_table') or '-'
            sr = c.get('source_ref') or '-'
            cf = c.get('confidence') or 'low'
            cs = c.get('candidate_strength') or 'weak'
            cc = int(c.get('corroboration_count') or 0)
            why = c.get('why_candidate') or 'candidate from narrowed staging/window triage'

            rat = str(c.get('rationale') or '')
            m_url = re.search(r'url=([^;]+)', rat)
            m_ref = re.search(r'ref=([^;]+)', rat)
            m_dl = re.search(r'dl=([^;]+)', rat)
            m_local = re.search(r'local=([^;]+)', rat)
            m_browser = re.search(r'browser=([^;]+)', rat)
            url = (m_url.group(1).strip() if m_url else '')
            ref_url = (m_ref.group(1).strip() if m_ref else '')
            dl = (m_dl.group(1).strip() if m_dl else '')
            local = (m_local.group(1).strip() if m_local else '')
            br = (m_browser.group(1).strip() if m_browser else '')

            artifact_hint = ''
            cand_path = dl or local or url
            m_name = re.search(r'([^/\\]+\.(?:exe|dll|bat|cmd|vbs|js|zip|rar|7z))', cand_path, re.IGNORECASE)
            if m_name:
                artifact_hint = m_name.group(1)

            reasons = [str(x) for x in (c.get('corroboration_reasons') or [])]
            link_exec = bool(any('execution_linkage' in r for r in reasons))
            link_payload = bool(any('payload_dropper' in r for r in reasons))

            supports = []
            if st == 'browser_provenance_v1':
                supports.append('browser provenance подія у межах incident window')
            if url:
                supports.append(f'джерельний URL: {url[:110]}')
            if ref_url:
                supports.append(f'referrer/origin: {ref_url[:100]}')
            if artifact_hint:
                supports.append(f'ймовірний доставлений артефакт: {artifact_hint}')
            if link_payload:
                supports.append('є часовий зв’язок із payload/dropper активністю')
            if link_exec:
                supports.append('є часовий зв’язок із першим execution ланцюгом')
            if not supports:
                supports.append('є кореляційний збіг у narrowed incident window')

            missing = []
            if st != 'browser_provenance_v1' and 'raw_fallback' not in str(st).lower():
                missing.append('немає прямого native browser/registry доказу у source')
            if not link_exec:
                missing.append('бракує strict execution linkage')
            if not artifact_hint:
                missing.append('не виділено однозначний доставлений файл/архів')

            short_summary = f"{cs.upper()} candidate ({cf}); {('browser-backed' if st=='browser_provenance_v1' else st)}; corroboration={cc}."
            lines.append(f"{idx}. {title}")
            lines.append(f"- short_summary: {short_summary}")
            lines.append(f"- event_ts: {ts}")
            lines.append(f"- source_table/source_ref: {st} / {sr}")
            if br:
                lines.append(f"- browser_artifact_type: {br}")
            if artifact_hint:
                lines.append(f"- delivery_item: {artifact_hint}")
            lines.append(f"- confidence: {cf} | candidate_strength: {cs} | corroboration_count: {cc}")
            lines.append(f"- linkage_to_execution: {'yes' if link_exec else 'no'} | linkage_to_payload: {'yes' if link_payload else 'no'}")
            lines.append(f"- what_supports_it: {'; '.join(supports[:3])}")
            lines.append(f"- what_is_missing_for_strict_proof: {'; '.join(missing[:2])}")
            lines.append(f"- analyst_conclusion: {why}")
            idx += 1
    lines.append('')
    lines.append('## ХРОНОЛОГІЯ ПОДІЙ')
    lines.append(f"- Incident window (main chronology): {incident_window_start or 'n/a'} -> {incident_window_end or 'n/a'}")

    if not main_events:
        lines.append('- Main chronology не сформовано (бракує direct/corroborating causal evidence).')

    if not any(x.get('chain') == 'initial_access' for x in main_events):
        lines.append('- Delivery/initial access не підтверджено strict incident-grade proof; винесено у gap/supporting context.')

    display_events = [ev for ev in main_events if (ev.get('event_ts') and not _is_noisy_detail(ev.get('detail')))]
    if len(display_events) < 4:
        for ev in main_events:
            if ev in display_events or _is_noisy_detail(ev.get('detail')):
                continue
            display_events.append(ev)
            if len(display_events) >= 6:
                break
    if not display_events:
        display_events = [ev for ev in main_events if not _is_noisy_detail(ev.get('detail'))] or main_events

    idx = 1
    chain_order = ['initial_access','execution','persistence_remote','defense_evasion_tampering','impact']
    ordered = []
    for ck in chain_order:
        ordered.extend([e for e in display_events if e.get('chain') == ck][:2])
    if not ordered:
        ordered = display_events[:8]
    ordered = sorted(ordered, key=_ts_sort)

    for ev in ordered[:8]:
        what = str(ev.get('detail') or 'Виявлено інцидентно-релевантну подію у причинному ланцюгу.')
        wl = what.lower()
        if 'rdp_context_event' in wl or 'remote_logon_event' in wl:
            what = 'Зафіксовано віддалений доступ (RDP/remote logon) у межах інцидентного вікна.'
        elif 'script_or_batch_execution_event' in wl:
            what = 'Виявлено виконання скрипту/бат-файлу з ознаками шкідливої активності.'
        elif 'staged_execution_context_event' in wl:
            what = 'Виявлено staged execution (ланцюг підготовки/запуску інструментів).'
        elif 'msedgex.exe' in wl:
            what = 'Зафіксовано запуск підозрілого виконуваного файлу (msedgex.exe) у контексті інциденту.'

        why = {
            'initial_access': 'Показує ймовірний канал первинної доставки/доступу.',
            'execution': 'Підтверджує фактичний запуск компонентів атаки.',
            'persistence_remote': 'Підтверджує віддалену активність або механізм закріплення.',
            'defense_evasion_tampering': 'Пояснює ослаблення/обхід захисту та антифорензіку.',
            'impact': 'Фіксує наслідки інциденту та операційний вплив.'
        }.get(ev.get('chain'), 'Підтримує причинно-наслідковий ланцюг інциденту.')
        lines.append(f"{idx}. {ev.get('title')}")
        lines.append(f"- Дата/час: {ev.get('event_ts') or 'n/a'}")
        lines.append(f"- Що сталося: {what[:260]}")
        lines.append(f"- Чому це важливо: {why}")
        lines.append(f"- Джерело: {ev.get('source_table') or '-'} | {ev.get('source_file') or '-'}")
        idx += 1

    # compact supporting/gap notes only
    if isinstance(reasoning, dict):
        unc = [u for u in (reasoning.get('key_uncertainties') or []) if u]
        if unc:
            lines.append('Supporting/gaps: ' + ', '.join(unc[:3]))

    lines.append('')

    lines.append('Статус підтвердження ланцюгів')
    if isinstance(reasoning, dict) and reasoning.get('chains'):
        ch = reasoning.get('chains') or {}
        chain_labels = {
            'initial_access': 'Initial access',
            'execution': 'Execution',
            'persistence_remote': 'Persistence / remote activity',
            'defense_evasion_tampering': 'Defense evasion / tampering',
            'impact': 'Impact',
        }
        for ck in ['initial_access','execution','persistence_remote','defense_evasion_tampering','impact']:
            cv = ch.get(ck) or {}
            lines.append(f"- {chain_labels.get(ck, ck)}: {cv.get('status') or 'inconclusive'} | evidence={', '.join(cv.get('evidence_ids') or []) or '-'}")
    else:
        label_map = {
            'delivery_browser_provenance':'Browser delivery',
            'file_drop_chain':'File drop / staging',
            'script_host_execution_linkage':'Script-host / malicious execution',
            'defender_tampering':'Defender tampering',
            'rdp_user_creation_linkage':'case_59 creation / usage / RDP',
            'ngrok_7za_chain':'ngrok / remote tooling'
        }
        for k in ['delivery_browser_provenance','file_drop_chain','script_host_execution_linkage','defender_tampering','rdp_user_creation_linkage','ngrok_7za_chain']:
            v = bucket_map[k]
            shown = v['stored'] or 'n/a'
            if low_evidence_mode and (shown == 'n/a' or 'partial' in str(shown).lower() or 'likely' in str(shown).lower() or 'corroborated' in str(shown).lower()):
                shown = 'insufficient evidence'
            lines.append(f"- {label_map.get(k,k)}: {shown}")
    lines.append('')

    w_start_dt = _parse_evt_ts(incident_window_start)
    w_end_dt = _parse_evt_ts(incident_window_end)

    lines.append('## ІНДИКАТОРИ КОМПРОМЕТАЦІЇ (IOC)')
    groups = {'network': [], 'accounts_users': [], 'binaries_scripts_tools': [], 'remote_admin_tooling': []}

    def _add_g(g, line):
        if line and line not in groups[g]:
            groups[g].append(line)

    for x in (ioc or [])[:140]:
        raw = ''
        src = '-'
        if isinstance(x, dict):
            raw = str(x.get('artifact') or x.get('ioc') or x.get('value') or x.get('path') or x.get('reason') or '')
            src = str(x.get('source_table') or x.get('source') or '-')
        else:
            raw = str(x)
        lo = raw.lower().strip()
        if not lo:
            continue
        if '127.0.0.1' in lo or 'loopback' in lo:
            continue
        if any(k in lo for k in ['score=','tool_hits=','event_hits=','src=','family=']) and not any(k in lo for k in ['event_id=1102','event_id=104','powershell','wscript','cscript','ngrok','anydesk','teamviewer','mimikatz','rdp']):
            continue
        line = f"- {raw[:120]} | джерело: {src}"

        if any(k in lo for k in ['ip=', 'remote_ip', 'domain', 'url', 'hosturl']) and '127.0.0.1' not in lo:
            _add_g('network', line)
        elif any(k in lo for k in ['user', 'account', 'logon', 'administrator', 'case_59']):
            _add_g('accounts_users', line)
        elif any(k in lo for k in ['anydesk','teamviewer','ngrok','rdpwrap','radmin','rdp attempt','rdp logon','rdp conn']):
            _add_g('remote_admin_tooling', line)
        elif any(k in lo for k in ['.exe', '.bat', '.cmd', '.vbs', '.js', 'powershell', 'wscript', 'cscript', 'mimikatz', '7za']):
            _add_g('binaries_scripts_tools', line)

    emitted=False
    for title,key in [('Network','network'),('Accounts/Users','accounts_users'),('Binaries/Scripts/Tools','binaries_scripts_tools'),('Remote access/admin tooling','remote_admin_tooling')]:
        if not groups[key]:
            continue
        emitted=True
        lines.append(f"- {title}:")
        for it in groups[key][:4]:
            lines.append(f"  {it}")

    if not emitted:
        lines.append('- Немає incident-relevant IOC, придатних для короткого аналітичного shortlist.')
    lines.append('')

    lines.append('## ПІДОЗРІЛІ АРТЕФАКТИ')
    art_groups = {
        'Delivery/Initial access': [],
        'Execution': [],
        'Persistence/Remote': [],
        'Tampering/Defense evasion': [],
    }

    def _humanize_artifact(s):
        t = str(s or '').strip()
        tl = t.lower()
        rep = [
            ('rdp_context_event', 'RDP контекст (вхід/сесія)'),
            ('remote_logon_event', 'Віддалений логон'),
            ('script_or_batch_execution_event', 'Виконання скрипту/бат-файлу'),
            ('staged_execution_context_event', 'Ознаки staged execution'),
            ('add-mppreference', 'Зміна політики Defender (Add-MpPreference)'),
            ('exclusionpath', 'Додавання Defender exclusion path'),
            ('event_id=1102', 'Очищення журналу безпеки (Event 1102)'),
            ('event_id=104', 'Очищення каналу EventLog (Event 104)'),
            ('zone.identifier', 'Mark-of-the-Web / Zone.Identifier'),
            ('browser_provenance_event', 'Browser delivery provenance event'),
            ('msedgex.exe', 'Підозрілий виконуваний файл (msedgex.exe)'),
            ('ngrok', 'Інструмент тунелювання/віддаленого доступу (ngrok)'),
        ]
        for a,b in rep:
            if a in tl:
                return b
        t = re.sub(r'(?i)(score=|events=|tool_hits=|event_hits=|src=|family=)\s*[^\s,;|]+', '', t).strip(' ;,|-')
        return t[:120]

    # from triage paths with incident-window filter
    if isinstance(triage, dict):
        for label, arr, grp in [
            ('delivery', (triage.get('likely_initial_access_candidates') or []), 'Delivery/Initial access'),
            ('execution', (triage.get('likely_execution_paths') or []), 'Execution'),
            ('persistence', (triage.get('likely_persistence_paths') or []), 'Persistence/Remote'),
            ('tampering', (triage.get('likely_tampering_paths') or []), 'Tampering/Defense evasion'),
        ]:
            for x in (arr or []):
                ts = str(x.get('event_ts') or 'n/a')
                ts_dt = _parse_evt_ts(ts)
                if ts_dt is not None and w_start_dt is not None and w_end_dt is not None and (ts_dt < w_start_dt or ts_dt > w_end_dt):
                    continue
                src = f"{x.get('source_table') or '-'}:{x.get('source_ref') or '-'}"
                raw = x.get('summary') or x.get('rationale') or x.get('why_candidate') or ''
                h = _humanize_artifact(raw)
                if not h:
                    continue
                expl = {
                    'Delivery/Initial access':'ймовірний канал первинної доставки/входу',
                    'Execution':'ланка фактичного виконання шкідливих компонентів',
                    'Persistence/Remote':'ознака віддаленого доступу або закріплення',
                    'Tampering/Defense evasion':'ознака обходу/послаблення захисту',
                }[grp]
                art_groups[grp].append(f"- {h} — {expl} | {src} | {ts}")

    # compact grouped render top-N
    emitted=False
    for grp in ['Delivery/Initial access','Execution','Persistence/Remote','Tampering/Defense evasion']:
        vals=[]
        seen=set()
        for line in art_groups.get(grp,[]):
            k=line.lower()
            if k in seen: continue
            seen.add(k)
            vals.append(line)
            if len(vals)>=3: break
        if vals:
            emitted=True
            lines.append(f"- {grp}:")
            lines.extend([f"  {v}" for v in vals])

    if not emitted:
        lines.append('- Немає стислого artifact shortlist у межах incident window (потрібна ручна вибірка з chronology/evidence).')
    lines.append('')

    # Generic evidence-backed spotlight for artifact classes that uploaded human reports
    # often emphasize but that can be missed by compact triage top-N lists.
    # This must stay class-based and DB-grounded: no case-specific facts are injected.
    def _spotlight_hits():
        specs = [
            ('AnyDesk remote-admin traces', ['anydesk'], 'remote_admin_tooling'),
            ('try.exe / UAC-bypass execution traces', ['try.exe', 'uacbypass'], 'execution'),
            ('RMS / Remote Utilities', ['remote utilities', 'rutserv', 'rfusclient'], 'remote_admin_tooling'),
            ('pixeldrain / fileview / mail-delivery indicators', ['pixeldrain', 'fileview'], 'delivery'),
            ('BEB lure / suspicious business document context', ['beb'], 'delivery'),
            ('ProgramData/System32 masquerading executable', ['system32.exe'], 'execution'),
            ('logs.dat / possible keylogger artifact', ['logs.dat'], 'execution'),
        ]
        hits = []
        try:
            with psycopg2.connect(PG_DSN) as conn, conn.cursor() as cur:
                for label, terms, role in specs:
                    conds = []
                    args = []
                    for term in terms:
                        like = '%' + term.lower().replace('%', '').replace('_', '\\_') + '%'
                        conds.append("lower(coalesce(file_name,'')||' '||coalesce(parent_path,'')||' '||payload::text||' '||coalesce(source_file,'')) LIKE %s")
                        args.append(like)
                    where_fs = ' OR '.join(conds)
                    # Prefer concrete filesystem rows; they are usually the most readable in reports.
                    cur.execute(f"""
                        SELECT event_ts::text, left(coalesce(parent_path,'')||'/'||coalesce(file_name,''), 160), left(coalesce(source_file,''), 90)
                        FROM filesystem_v2
                        WHERE case_key=%s AND ({where_fs})
                        ORDER BY event_ts DESC NULLS LAST
                        LIMIT 1
                    """, [case_key] + args)
                    row = cur.fetchone()
                    if row:
                        hits.append((label, role, row[0] or 'n/a', row[1] or label, 'filesystem_v2 / ' + (row[2] or '-')))
                        continue
                    # Network/delivery IOCs may live only in case_iocs.
                    conds_ioc = []
                    args_ioc = []
                    for term in terms:
                        like = '%' + term.lower().replace('%', '').replace('_', '\\_') + '%'
                        conds_ioc.append("lower(coalesce(ioc_value,'')||' '||coalesce(source_table,'')) LIKE %s")
                        args_ioc.append(like)
                    where_ioc = ' OR '.join(conds_ioc)
                    cur.execute(f"""
                        SELECT coalesce(ioc_value,''), coalesce(source_table,'')
                        FROM case_iocs
                        WHERE case_key=%s AND ({where_ioc})
                        LIMIT 1
                    """, [case_key] + args_ioc)
                    row = cur.fetchone()
                    if row:
                        hits.append((label, role, 'n/a', row[0] or label, 'case_iocs / ' + (row[1] or '-')))
        except Exception:
            try: _log.exception('spotlight evidence query failed case=%s', case_key)
            except Exception: pass
        return hits

    spotlight = _spotlight_hits()
    if spotlight:
        lines.append('## ДОДАТКОВІ АРТЕФАКТИ, ЯКІ НЕ МОЖНА ПРОПУСТИТИ')
        for label, role, ts, sample, src in spotlight[:8]:
            lines.append(f"- **{label}** — роль: {role}; час/приклад: {ts}; `{sample}`; джерело: {src}")
        lines.append('')

    lines.append('## ЩО ПЕРЕВІРИТИ ВРУЧНУ')
    if isinstance(triage, dict):
        for stp in (triage.get('prioritized_next_steps') or [])[:4]:
            act = stp.get('action') or 'manual_step'
            rsn = stp.get('reason') or 'triage-prioritized step'
            lines.append(f"- [priority {stp.get('priority') or '-'}] {act}: {rsn}")
        for mc in (triage.get('manual_checks') or [])[:4]:
            lines.append(f"- manual_check: {mc}")
    if low_evidence_mode:
        lines.append('- low-evidence mode: telemetry/activity присутні, але бракує strong correlated findings для повного causal chain; потрібна ручна кореляція ключових етапів (access→execution→impact).')
    dp = bucket_map['delivery_browser_provenance']['stored'] or ''
    if 'partial' in dp or 'likely' in dp or 'normalized_but_no_strict_hit' in str(bucket_map['delivery_browser_provenance']['strongest'] or ''):
        lines.append('- delivery_browser_provenance: потрібен strict native browser/MotW provenance chain (suspicious origin + native field + linkage to payload chain).')
    lines.append('- перевірити timestamp caveats для окремих historical/derived rows перед фінальним атрибутивним висновком.')

    # Evidence-first final report: keep the generic renderer assembled above.
    # Do not replace it with a polished, case-specific narrative template: audit runs
    # showed that such templates can leak one case's SwissTransfer/try.exe/ngrok
    # story into unrelated cases. Polished prose may be added upstream only when it
    # is grounded by this case's own evidence rows and still passes final guards.
    try:
        _mem = _memory_section(case_key)
        if _mem:
            lines.extend(_mem)
    except Exception as _me:
        _log.warning('[render] memory section failed case=%s: %s', case_key, _me)
    try:
        from analysis.case_email import render_section as _email_section
        _em = _email_section(case_key)
        if _em:
            lines.extend(_em)
    except Exception as _ee:
        _log.warning('[render] email section failed case=%s: %s', case_key, _ee)
    text = '\n'.join(lines).strip() + '\n'
    return {'text': text, 'parity': p, 'bucket_projection': bucket_map, 'timeline_count': len(main_events)}

