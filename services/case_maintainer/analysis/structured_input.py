"""Build and trim structured input for LLM analysis steps."""
import json, logging, ntpath, os, psycopg2, re, time
from core.config import PG_DSN
from core.db import table_exists
from analysis.system_profile import _get_system_profile_v1

_log = logging.getLogger('app')


def _clean_bp(t):
    """Strip PowerShell/script boilerplate (# Copyright, :: ====, MS headers,
    separators) from an event summary so it does not pollute the chronology."""
    if not t:
        return ''
    keep = []
    for _l in str(t).replace(chr(13), chr(10)).split(chr(10)):
        _l = _l.strip()
        if not _l:
            continue
        _ll = _l.lower()
        if _l[0] in '#=:':
            continue
        if 'copyright' in _ll or 'all rights reserved' in _ll or 'microsoft corporation' in _ll:
            continue
        if len(_l) >= 6 and all(_c in '=-_:.# ' for _c in _l):
            continue
        keep.append(_l)
    return ' '.join(keep).strip()


def _build_structured_input(job_id, case_key):
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
                SELECT job_id, case_key, status, result_kind, result_ref, progress_pct, current_step, total_steps,
                       latest_step_code, last_heartbeat_at, updated_at, error_short
                FROM public.dfir_run_jobs_v2
                WHERE job_id=%s
                LIMIT 1
            """, (job_id,))
            jr = cur.fetchone()
            if not jr:
                raise RuntimeError('job_not_found')

            cur.execute("""
                SELECT step_no, step_code, step_status, meta_json
                FROM public.dfir_run_steps_v2
                WHERE job_id=%s
                ORDER BY step_no
            """, (job_id,))
            rows = cur.fetchall()

    steps = {r[1]: (r[3] if isinstance(r[3], dict) else {}) for r in rows}
    corroboration = steps.get('corroboration', {})
    incident = (steps.get('incident_timeline', {}) or {}).get('incident_timeline', [])
    detection = (steps.get('detection_timeline', {}) or {}).get('detection_timeline', [])
    iocs = (steps.get('ioc_artifacts', {}) or {}).get('ioc_artifacts', [])

    # Curate top sets for Ollama input (rule #4)
    curated = {
        'confirmed': (corroboration.get('confirmed') or [])[:12],
        'corroborated': (corroboration.get('likely') or [])[:20],
        'tool_only': (corroboration.get('tool_only') or [])[:20],
        'needs_review': (corroboration.get('needs_review') or [])[:20],
        'attack_chronology_events': [],
        'ioc_artifacts': iocs[:80],
    }

    # convert timelines to event objects with mandatory fields (rule #1/#2)
    for x in incident[:60]:
        ev = {
            'event_ts': x.get('event_ts'),
            'time_source': x.get('time_source') or 'native',
            'stage': 'unknown',
            'short_fact': _clean_bp(x.get('summary')),
            'entities': {'users': [], 'hosts': [], 'ips': [], 'files': [], 'processes': []},
            'evidence': [{
                'source_table': x.get('source_table'),
                'source_file': x.get('source_file'),
                'event_ts': x.get('event_ts'),
                'evidence_text': _clean_bp(x.get('summary'))
            }],
            'confidence': 'medium',
            'status': 'corroborated'
        }
        # simple stage mapping
        sf = (ev['short_fact'] or '').lower()
        if any(k in sf for k in ['ngrok', 'swisstransfer', 'hosturl']): ev['stage']='delivery'
        elif any(k in sf for k in ['start.vbs', 'ng.bat', 'edit.dll', 'gcapi.dll']): ev['stage']='file_drop'
        elif any(k in sf for k in ['add-mppreference', 'exclusionpath', 'tamper']): ev['stage']='defense_evasion'
        elif any(k in sf for k in ['rdpwrap', 'rdpwinst', 'rdpconf', 'rdpcheck']): ev['stage']='persistence_or_remote_access'
        elif any(k in sf for k in ['mimikatz', 'sekurlsa', 'lsadump']): ev['stage']='credential_access'
        elif any(k in sf for k in ['7za', 'msedgex']): ev['stage']='staging_or_exfil'
        else: ev['stage']='execution'
        curated['attack_chronology_events'].append(ev)

    for x in detection[:60]:
        curated['attack_chronology_events'].append({
            'event_ts': x.get('event_ts'),
            'time_source': x.get('time_source') or 'derived',
            'stage': 'detection_signal',
            'short_fact': _clean_bp(x.get('summary')),
            'entities': {'users': [], 'hosts': [], 'ips': [], 'files': [], 'processes': []},
            'evidence': [{
                'source_table': x.get('source_table'),
                'source_file': x.get('source_file'),
                'event_ts': x.get('event_ts'),
                'evidence_text': _clean_bp(x.get('summary'))
            }],
            'confidence': 'low',
            'status': 'tool-only'
        })

    # dedupe chronology by (event_ts, short_fact)
    seen=set(); evs=[]
    for e in curated['attack_chronology_events']:
        k=(e.get('event_ts'), e.get('short_fact'))
        if k in seen: continue
        seen.add(k); evs.append(e)
    curated['attack_chronology_events']=evs[:120]

    # Enrich meta with system profile
    _sys = {}
    try:
        _sys = _get_system_profile_v1(case_key) or {}
    except Exception:
        try: conn.rollback()
        except: pass
        pass

    # High-priority initial-access highlights. These must not be lost in a long
    # chronology. This is generic scoring, not a case-specific filename rule:
    # suspicious executables/scripts from user-writable locations are ranked by
    # path, extension, lure-like name, timing, and known tradecraft signals.
    initial_access_highlights = []
    try:
        if table_exists('program_exec_v2'):
            chronology_ts = []
            for _e in curated.get('attack_chronology_events') or []:
                _ts = _e.get('event_ts')
                if _ts:
                    chronology_ts.append(str(_ts))
            anchor_start = min(chronology_ts) if chronology_ts else None
            with psycopg2.connect(PG_DSN) as conn2:
                conn2.autocommit = True
                with conn2.cursor() as cur2:
                    cur2.execute("""
                        SELECT event_ts, source_file,
                               coalesce(executable_name,'') AS executable_name,
                               coalesce(full_path,'') AS full_path,
                               trim(coalesce(executable_name,'') || ' @ ' || coalesce(full_path,'')) AS artifact
                        FROM program_exec_v2
                        WHERE case_key=%s AND event_ts IS NOT NULL
                          AND lower(coalesce(executable_name,'') || ' ' || coalesce(full_path,''))
                              ~ '(downloads|\\\\users\\\\[^\\\\]+\\\\appdata|appdata|\\\\temp\\\\|\\\\users\\\\public|public\\\\documents|desktop|\\\\documents\\\\|[.]exe|[.]scr|[.]bat|[.]cmd|[.]ps1|[.]vbs|[.]js|[.]msi)'
                        ORDER BY event_ts ASC
                        LIMIT 500
                    """, (case_key,))
                    program_rows = cur2.fetchall()
                    browser_rows = []
                    if table_exists('browser_provenance_v1'):
                        try:
                            cur2.execute("""
                                SELECT event_ts, source_file,
                                       coalesce(local_path,'') AS local_path,
                                       coalesce(download_path,'') AS download_path,
                                       coalesce(zone_identifier_host_url,'') AS host_url,
                                       coalesce(zone_identifier_referrer_url,'') AS referrer_url,
                                       coalesce(url,'') AS url,
                                       coalesce(domain,'') AS domain,
                                       coalesce(source_type,'') AS source_type
                                FROM browser_provenance_v1
                                WHERE case_key=%s AND event_ts IS NOT NULL
                                  AND lower(coalesce(local_path,'') || ' ' || coalesce(download_path,'') || ' ' || coalesce(zone_identifier_host_url,'') || ' ' || coalesce(zone_identifier_referrer_url,'') || ' ' || coalesce(url,'') || ' ' || coalesce(domain,''))
                                      ~ '(downloads|desktop|[.]exe|[.]scr|[.]msi|[.]zip|[.]rar|[.]7z|zone[.]identifier)'
                                ORDER BY event_ts ASC
                                LIMIT 1500
                            """, (case_key,))
                            browser_rows = cur2.fetchall()
                        except Exception:
                            try: conn2.rollback()
                            except Exception: pass
                            browser_rows = []
                    candidates = []
                    for ts, sf, exe, full_path, artifact in program_rows:
                        try:
                            if getattr(ts, 'year', 9999) < 2020:
                                continue
                        except Exception:
                            pass
                        text = f"{exe} {full_path} {artifact}".lower()
                        base = ntpath.basename((full_path or exe or artifact).split('@', 1)[0].strip()).lower()
                        score = 0
                        reasons = []
                        if re.search(r'\\downloads\\|/downloads/|\\desktop\\|/desktop/', text):
                            score += 30; reasons.append('download_or_desktop_path')
                        if re.search(r'\\documents\\|/documents/', text):
                            score += 8; reasons.append('documents_path')
                        if re.search(r'\\appdata\\|/appdata/|\\temp\\|/temp/', text):
                            score += 22; reasons.append('user_writable_path')
                        if re.search(r'\\users\\public\\|/users/public/', text):
                            score += 12; reasons.append('public_user_path')
                        if re.search(r'[.](exe|scr|msi)$', base):
                            score += 20; reasons.append('interactive_executable')
                        if re.search(r'[.](bat|cmd|ps1|vbs|js)$', base):
                            score += 18; reasons.append('script_execution')
                        if re.search(r'(pdf|doc|xls|акт|рахунок|лист|заява|повідом|до відома|довідка|нотар|notar|invoice|scan|document|payment)', base):
                            score += 26; reasons.append('document_lure_filename')
                        if re.search(r'\([^)]+\)[.](exe|scr|msi)$', base) or re.search(r'\s\(\d+\)[.](exe|scr|msi)$', base):
                            score += 8; reasons.append('download_duplicate_name')
                        if re.search(r'(ngrok|anydesk|teamviewer|rustdesk|rms|litemanager|7za|rclone|mimikatz|regsvr32|powershell)', text):
                            score += 16; reasons.append('known_attack_tool_or_lolbin')
                        if re.search(r'[а-яіїєґ]', base):
                            score += 8; reasons.append('localized_lure_name')
                        browser_match = None
                        try:
                            exe_stem = re.sub(r'\s*\(\d+\)(?=\.)', '', base)
                            for br_ts, br_sf, br_local, br_download, br_host, br_ref, br_url, br_domain, br_type in browser_rows:
                                br_text = f"{br_local} {br_download} {br_host} {br_ref} {br_url} {br_domain}".lower()
                                br_base = ntpath.basename(str(br_local).replace(':Zone.Identifier','')).lower()
                                br_stem = re.sub(r'\s*\(\d+\)(?=\.)', '', br_base)
                                same_name = base and (base in br_text or exe_stem in br_text or br_stem == exe_stem)
                                near_time = False
                                try:
                                    near_time = abs((ts - br_ts).total_seconds()) <= 7200
                                except Exception:
                                    near_time = str(ts)[:10] == str(br_ts)[:10]
                                if same_name and near_time:
                                    browser_match = {
                                        'event_ts': br_ts.isoformat() if hasattr(br_ts, 'isoformat') else str(br_ts),
                                        'local_path': br_local,
                                        'download_path': br_download,
                                        'host_url': br_host,
                                        'referrer_url': br_ref,
                                        'source_file': br_sf,
                                        'source_type': br_type,
                                    }
                                    if ':zone.identifier' in br_text:
                                        score += 28; reasons.append('zone_identifier_or_download_artifact_near_execution')
                                    else:
                                        score += 20; reasons.append('browser_download_artifact_near_execution')
                                    break
                        except Exception:
                            browser_match = None
                        if browser_match is None and table_exists('browser_provenance_v1'):
                            try:
                                _key = re.sub(r'\s*\(\d+\)(?=\.)', '', base)
                                if _key and len(_key) >= 5:
                                    cur2.execute("""
                                        SELECT event_ts, source_file,
                                               coalesce(local_path,''), coalesce(download_path,''),
                                               coalesce(zone_identifier_host_url,''), coalesce(zone_identifier_referrer_url,''),
                                               coalesce(url,''), coalesce(domain,''), coalesce(source_type,'')
                                        FROM browser_provenance_v1
                                        WHERE case_key=%s
                                          AND event_ts BETWEEN %s::timestamptz - interval '2 hours' AND %s::timestamptz + interval '2 hours'
                                          AND lower(coalesce(local_path,'') || ' ' || coalesce(download_path,'') || ' ' || coalesce(zone_identifier_host_url,'') || ' ' || coalesce(zone_identifier_referrer_url,'')) LIKE %s
                                        ORDER BY CASE WHEN lower(coalesce(local_path,'')) LIKE '%%:zone.identifier%%' THEN 0 ELSE 1 END, event_ts ASC
                                        LIMIT 1
                                    """, (case_key, ts, ts, '%' + _key.lower() + '%'))
                                    _br = cur2.fetchone()
                                    if _br:
                                        br_ts, br_sf, br_local, br_download, br_host, br_ref, br_url, br_domain, br_type = _br
                                        browser_match = {
                                            'event_ts': br_ts.isoformat() if hasattr(br_ts, 'isoformat') else str(br_ts),
                                            'local_path': br_local,
                                            'download_path': br_download,
                                            'host_url': br_host,
                                            'referrer_url': br_ref,
                                            'source_file': br_sf,
                                            'source_type': br_type,
                                        }
                                        _txt = f"{br_local} {br_host} {br_ref}".lower()
                                        score += 28 if ':zone.identifier' in _txt else 20
                                        reasons.append('direct_filename_browser_or_zone_correlation_near_execution')
                                        if re.search(r'(iit[.]com[.]ua|id[.]gov[.]ua|regdracs[.]minjust|notary[.]just|register[.]minjust|microsoft[.]com|google[.]com)', _txt):
                                            score -= 24
                                            reasons.append('known_legitimate_source_domain')
                            except Exception:
                                try: conn2.rollback()
                                except Exception: pass
                        if re.search(r'(eusign|єдиний державний|кристал|iit|ІІТ|ca\.iit|acsk|software_sign|id[.]gov[.]ua|regdracs[.]minjust)', text):
                            score -= 28; reasons.append('likely_legitimate_signing_software')
                        # If the candidate predates the main attack chain, keep it as a plausible delivery/execution anchor.
                        if anchor_start and str(ts) <= anchor_start:
                            score += 6; reasons.append('before_main_attack_chain')
                        norm_key = re.sub(r'\s*\(\d+\)(?=\.)', '', base)
                        if score >= 42:
                            candidates.append((score, ts, sf, artifact, reasons, browser_match, norm_key))
                    dedup = {}
                    for item in candidates:
                        score, ts, sf, artifact, reasons, browser_match, norm_key = item
                        k = norm_key or str(artifact).lower()
                        prev = dedup.get(k)
                        if prev is None:
                            dedup[k] = item
                        else:
                            pscore, pts = prev[0], prev[1]
                            # Prefer the first execution for the same normalized filename unless
                            # the later candidate is much stronger.
                            if score > pscore + 15 or (abs(score - pscore) <= 15 and str(ts) < str(pts)):
                                dedup[k] = item
                    candidates = list(dedup.values())
                    candidates.sort(key=lambda x: (-x[0], str(x[1])))
                    for score, ts, sf, artifact, reasons, browser_match, norm_key in candidates[:8]:
                        conf = 'high' if score >= 70 else 'medium' if score >= 55 else 'low'
                        initial_access_highlights.append({
                            'event_ts': ts.isoformat() if hasattr(ts, 'isoformat') else str(ts),
                            'artifact': artifact,
                            'source_table': 'program_exec_v2',
                            'source_file': sf,
                            'reason': '; '.join(reasons[:5]),
                            'score': int(score),
                            'confidence': conf,
                            'correlated_browser_or_zone': browser_match
                        })
    except Exception:
        try: conn.rollback()
        except Exception: pass

    return {
        'meta': {
            'case_key': jr[1],
            'job_id': jr[0],
            'status': jr[2],
            'result_kind': jr[3] or ('completed' if jr[2]=='completed' else 'partial' if jr[2]=='partial' else 'n/a'),
            'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'scope_mode': 'case_scoped_fallback',
            'coverage': corroboration.get('coverage') or {'available_tables': [], 'missing_tables': [], 'coverage_ratio': 0.0},
            'computer_name': _sys.get('computer_name') or '',
            'hostname': _sys.get('hostname') or '',
            'os_name': _sys.get('os_name') or '',
            'build': _sys.get('build') or '',
            'timezone': _sys.get('timezone') or '',
            'utc_offset': _sys.get('utc_offset') or '',
            'install_date_utc': _sys.get('install_date_utc') or '',
            'last_shutdown_utc': str(_sys.get('last_shutdown_utc') or ''),
            'users': _sys.get('users') or [],
        },
        'findings': {
            'confirmed': curated['confirmed'],
            'corroborated': curated['corroborated'],
            'tool_only': curated['tool_only'],
            'needs_review': curated['needs_review']
        },
        'initial_access_highlights': initial_access_highlights,
        'attack_chronology_events': curated['attack_chronology_events'],
        'ioc_artifacts': curated['ioc_artifacts'],
        'gaps': {
            'missing_native_proof': ['mimikatz direct execution', 'ng.bat execution trace', 'start.vbs script-host execution'],
            'missing_sources': (corroboration.get('coverage') or {}).get('missing_tables', []),
            'manual_checks_needed': ['RDP logon pivots (host/ip/user)', 'user creation/privilege chain for case_59']
        },
        'kb_context': {
            'enabled': True,
            'note': 'Methodological context only; not a source of new case facts.'
        }
    }


def _trim_structured_input_for_llm(si):
    """Trim to ≤18KB JSON for LM Studio (total request must stay under 30KB)."""
    def _trim_finding(f):
        if not isinstance(f, dict): return f
        return {k: (f[k][:2] if isinstance(f.get(k), list) else f[k])
                for k in ('status','indicator','first_seen','last_seen','evidence_count','evidence_samples')
                if k in f}

    def _trim_event(e):
        if not isinstance(e, dict): return e
        out = {k: e[k] for k in ('event_ts','stage','time_source','short_fact') if k in e}
        # trim short_fact to 120 chars
        if 'short_fact' in out and isinstance(out['short_fact'], str):
            out['short_fact'] = out['short_fact'][:120]
        # keep only first evidence source
        evs = e.get('evidence') or []
        if evs:
            out['source'] = f"{evs[0].get('source_table','')} | {evs[0].get('source_file','')}"
        return out

    def _trim_ioc(x):
        if not isinstance(x, dict): return x
        return {k: x[k] for k in ('ioc_type','value','context','source_table','ioc','source_file') if k in x}

    def _trim_initial_access(x):
        if not isinstance(x, dict): return x
        out = {k: x[k] for k in ('event_ts','artifact','source_table','source_file','reason','score','confidence','correlated_browser_or_zone') if k in x}
        if isinstance(out.get('artifact'), str):
            out['artifact'] = out['artifact'][:260]
        return out

    def _select_chronology_events(events, limit=35):
        selected = []
        seen = set()
        for e in events or []:
            if not isinstance(e, dict):
                continue
            text = ((e.get('short_fact') or '') + ' ' + (e.get('stage') or '')).lower()
            score = 0
            if any(k in text for k in ['до відома', 'zone.identifier', 'downloads\\', '/downloads/', 'initial']): score += 45
            if any(k in text for k in ['ngrok', 'try.exe', '7za.exe', 'rdpwinst', 'rdp wrapper', 'anydesk', 'fiddler']): score += 38
            if any(k in text for k in ['add-mppreference', 'exclusionpath', 'defender', 'tamper', 'карантин']): score += 34
            if any(k in text for k in ['rdp', 'remoteconnectionmanager', 'localsessionmanager', '4624', '1149', 'case_59']): score += 52
            if any(k in text for k in ['1102', 'event log', 'очищ', 'log clear', 'eid 104']): score += 46
            if any(k in text for k in ['regsvr32', 'powershell', 'wscript', 'cscript']): score += 18
            if any(k in text for k in ['password', 'парол', '4724', '4720', '4732', 'account']): score += 44
            if any(k in text for k in ['svchost', 'readme', 'ransom', 'encrypted', 'impact']): score += 26
            if any(k in text for k in ['rmiregistry', 'eusign', 'edgeupdate', 'microsoft-edge', 'widevine', 'wlan', 'intel', 'realtek']): score -= 35
            if any(k in text for k in ['.pdf', '.xlsx', '.doc']) and not any(k in text for k in ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js']): score -= 65
            try:
                if str(e.get('event_ts') or '')[:4].isdigit() and int(str(e.get('event_ts'))[:4]) < 2020:
                    score -= 50
            except Exception:
                pass
            if score < 15:
                continue
            norm = re.sub(r'pid:\d+|processstart:\d+|\s+', ' ', text[:180])
            ts_s = str(e.get('event_ts') or '')
            if 'try.exe' in text:
                key = ('try.exe', ts_s[:16])
            elif any(p in text for p in ['cscript.exe', 'wscript.exe', 'powershell.exe', 'regsvr32.exe', 'rdpclip.exe']):
                proc = next((p for p in ['cscript.exe', 'wscript.exe', 'powershell.exe', 'regsvr32.exe', 'rdpclip.exe'] if p in text), 'lolbin')
                key = (proc, ts_s[:13])
            elif 'rdp' in text or 'case_59' in text:
                key = (ts_s[:16], norm[:120])
            else:
                key = (ts_s, norm[:120])
            if key in seen:
                continue
            seen.add(key)
            selected.append((score, str(e.get('event_ts') or ''), e))
        # top by relevance, then chronological for report readability
        selected = sorted(selected, key=lambda x: (-x[0], x[1]))[:limit]
        selected = sorted(selected, key=lambda x: x[1])
        return [x[2] for x in selected]

    findings = si.get('findings', {})
    chronology_events = _select_chronology_events(si.get('attack_chronology_events') or [], 35)
    trimmed = {
        'meta': {k: v for k, v in (si.get('meta') or {}).items() if k in ('case_key','scope_mode')},
        'findings': {
            'confirmed':    [_trim_finding(x) for x in (findings.get('confirmed') or [])[:5]],
            'corroborated': [_trim_finding(x) for x in (findings.get('corroborated') or [])[:7]],
            'tool_only':    [_trim_finding(x) for x in (findings.get('tool_only') or [])[:3]],
        },
        'initial_access_highlights': [_trim_initial_access(x) for x in (si.get('initial_access_highlights') or [])[:8]],
        # Product-quality reports need enough material for a real 20–30 item timeline.
        # Keep 35 so the LLM can select/merge without inventing events.
        'chronology': [_trim_event(x) for x in chronology_events],
        'iocs': [_trim_ioc(x) for x in (si.get('ioc_artifacts') or [])[:25]],
        'gaps': si.get('gaps', {}),
    }
    # safety cap at 28KB; 40k+ ctx LM Studio configs can handle this while staying stable.
    s = json.dumps(trimmed, ensure_ascii=False)
    if len(s.encode('utf-8')) > 28000:
        trimmed['chronology'] = trimmed['chronology'][:25]
        trimmed['iocs'] = trimmed['iocs'][:15]
        trimmed['findings']['corroborated'] = trimmed['findings']['corroborated'][:6]
        trimmed['findings']['tool_only'] = trimmed['findings']['tool_only'][:2]
    return trimmed


# ---------------------------------------------------------------------------
# DFIR Agentic Loop — tool calling, повний автономний аналіз
# ---------------------------------------------------------------------------

DFIR_AGENT_TOOLS = [
    {"type": "function", "function": {
        "name": "get_system_profile",
        "description": "Отримати профіль хоста: ім'я, ОС, build, користувачі, часовий пояс, дата встановлення.",
        "parameters": {"type": "object", "properties": {}}
    }},
    {"type": "function", "function": {
        "name": "get_top_alerts",
        "description": "Отримати топ детекцій від Hayabusa, THOR, reg_hunter, dfir_report. Використовуй для огляду загроз.",
        "parameters": {"type": "object", "properties": {
            "tool": {"type": "string", "description": "Фільтр по інструменту: hayabusa, reg_hunter, dfir_report. Залиш порожнім для всіх."},
            "severity": {"type": "string", "description": "Фільтр: high, medium, low"},
            "limit": {"type": "integer", "description": "Кількість рядків (макс 50)"}
        }}
    }},
    {"type": "function", "function": {
        "name": "search_events",
        "description": "Пошук у Windows event logs по ключовому слову (process, command, user, IP). Повертає події з часом.",
        "parameters": {"type": "object", "properties": {
            "keyword": {"type": "string", "description": "Ключове слово для пошуку"},
            "event_id": {"type": "integer", "description": "Фільтр по Event ID (4624=logon, 4688=process, 7045=service)"},
            "limit": {"type": "integer", "description": "Кількість рядків (макс 50)"}
        }, "required": ["keyword"]}
    }},
    {"type": "function", "function": {
        "name": "get_filesystem_artifacts",
        "description": "Пошук файлів у MFT по шаблону імені. Використовуй % як wildcard.",
        "parameters": {"type": "object", "properties": {
            "pattern": {"type": "string", "description": "Шаблон імені файлу, напр. '%ngrok%', '%readme%', '%.bat'"},
            "limit": {"type": "integer", "description": "Кількість рядків (макс 50)"}
        }, "required": ["pattern"]}
    }},
    {"type": "function", "function": {
        "name": "get_srum_network_traffic",
        "description": "SRUM мережева активність: скільки байт відправив/отримав кожен процес по днях. Виявляє C2-трафік (RMS, LiteManager, ngrok) і великі exfil/download потоки. Викликай ЗАВЖДИ для виявлення RAT-трафіку.",
        "parameters": {"type": "object", "properties": {
            "limit": {"type": "integer", "description": "Кількість рядків (макс 100)"}
        }}
    }},
    {"type": "function", "function": {
        "name": "get_context_window",
        "description": "Всі події ±N годин навколо вказаного timestamp з УСІХ таблиць. Використовуй щоразу коли знайшов підозрілу подію — покаже що відбувалось ДО і ПІСЛЯ. Критично для attack chain.",
        "parameters": {"type": "object", "properties": {
            "timestamp": {"type": "string", "description": "Timestamp у форматі YYYY-MM-DD HH:MM або ISO"},
            "hours_before": {"type": "number", "description": "Годин ДО (default 6)"},
            "hours_after":  {"type": "number", "description": "Годин ПІСЛЯ (default 6)"}
        }, "required": ["timestamp"]}
    }},
    {"type": "function", "function": {
        "name": "pivot",
        "description": "Pivot по IOC: шукає IP/хеш/домен/файл/ключове слово в УСІХ таблицях і в інших кейсах. Використовуй щоразу як знайшов підозрілий артефакт — покаже всі пов'язані сліди.",
        "parameters": {"type": "object", "properties": {
            "ioc_value": {"type": "string", "description": "Значення для пошуку: IP, хеш MD5/SHA256, ім'я файлу, домен, URL"},
            "limit": {"type": "integer", "description": "Рядків на таблицю (макс 50)"}
        }, "required": ["ioc_value"]}
    }},
    {"type": "function", "function": {
        "name": "get_log_gaps",
        "description": "Знаходить розриви (gaps) в хронології event_logs та Events ID 1102/104 (очищення журналів). Розрив > N годин = потенційне видалення слідів.",
        "parameters": {"type": "object", "properties": {
            "min_gap_hours": {"type": "number", "description": "Мінімальний розрив у годинах (default 2)"}
        }}
    }},
    {"type": "function", "function": {
        "name": "get_attack_phases",
        "description": "Кластеризація тригерів по часових фазах атаки (MITRE ATT&CK): Initial Access → Execution → Persistence → C2 → Collection → Exfil. Виклич після get_case_triggers.",
        "parameters": {"type": "object", "properties": {}}
    }},
    {"type": "function", "function": {
        "name": "compare_cases",
        "description": "Порівнює тригери поточного кейсу з усіма попередніми кейсами. Виявляє однакові IOC, інструменти, патерни — індикатор серійного зловмисника.",
        "parameters": {"type": "object", "properties": {}}
    }},
    {"type": "function", "function": {
        "name": "get_user_timeline",
        "description": "Повна хронологія дій конкретного користувача: logon/logoff, виконання процесів, файлова активність. Якщо username не вказано — показує список знайдених користувачів.",
        "parameters": {"type": "object", "properties": {
            "username": {"type": "string", "description": "Ім'я користувача Windows (напр. 'Бухгалтер', 'case_41', 'Admin')"},
            "limit": {"type": "integer", "description": "Кількість подій (макс 200)"}
        }}
    }},
    {"type": "function", "function": {
        "name": "get_registry_persistence",
        "description": "Отримати registry ASEP записи — точки автозапуску та persistence механізми.",
        "parameters": {"type": "object", "properties": {
            "keyword": {"type": "string", "description": "Фільтр по шляху або значенню (опційно)"},
            "limit": {"type": "integer", "description": "Кількість рядків (макс 50)"}
        }}
    }},
    {"type": "function", "function": {
        "name": "get_logon_activity",
        "description": "Отримати logon/logoff події та RDP сесії. Корисно для аналізу lateral movement.",
        "parameters": {"type": "object", "properties": {
            "limit": {"type": "integer", "description": "Кількість рядків (макс 50)"}
        }}
    }},
    {"type": "function", "function": {
        "name": "get_hayabusa_detections",
        "description": "Отримати Hayabusa детекції відсортовані за severity. Повертає rule, рівень, час, хост.",
        "parameters": {"type": "object", "properties": {
            "min_level": {"type": "string", "description": "Мінімальний рівень: critical, high, medium"},
            "limit": {"type": "integer", "description": "Кількість рядків (макс 50)"}
        }}
    }},
    {"type": "function", "function": {
        "name": "run_sql",
        "description": "Виконати READ-ONLY SQL SELECT запит до forensic БД. Таблиці: event_logs_v2, filesystem_v2, program_exec_v2, srum_v2, tool_alerts_v2, raw_fallback_v2. case_key додається автоматично.",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string", "description": "SQL SELECT запит. НЕ включай WHERE case_key=... — він додається автоматично."}
        }, "required": ["query"]}
    }},
    {"type": "function", "function": {
        "name": "search_knowledge_base",
        "description": "Пошук у базі знань DFIR (книги, методики, техніки). Використовуй щоб зрозуміти техніки атаки, значення артефактів, persistence методи.",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string", "description": "Питання або тема для пошуку, напр. 'ngrok tunnel persistence', 'registry ASEP run key', 'RDP lateral movement'"}
        }, "required": ["query"]}
    }},
    {"type": "function", "function": {
        "name": "run_temp_script",
        "description": "Написати і виконати тимчасовий Python скрипт для глибокого аналізу. Має доступ до pg_query(sql) і CASE_KEY. Використовуй коли стандартних інструментів недостатньо: кастомна кореляція даних, підрахунки, об'єднання таблиць, аналіз патернів. Тільки READ-only операції.",
        "parameters": {"type": "object", "properties": {
            "script_code": {"type": "string", "description": "Python код. Доступні: pg_query(sql) -> list[dict], CASE_KEY, psycopg2, json, re, datetime, collections. Пишеш код що виводить результат через print()."},
            "description": {"type": "string", "description": "Що скрипт аналізує (для логів)"}
        }, "required": ["script_code"]}
    }},
    {"type": "function", "function": {
        "name": "finish_report",
        "description": "Завершити розслідування і зберегти фінальний звіт. Виклич ТІЛЬКИ коли зібрав достатньо доказів.",
        "parameters": {"type": "object", "properties": {
            "report": {"type": "string", "description": "Повний DFIR звіт українською мовою"}
        }, "required": ["report"]}
    }},
    {"type": "function", "function": {
        "name": "search_iocs_across_cases",
        "description": "Пошук IOC в інших кейсах — знайти пересічення між кейсами (той самий IP, хеш, домен, файл). Виклич коли знайшов підозрілий IOC щоб перевірити чи він фігурував раніше.",
        "parameters": {"type": "object", "properties": {
            "ioc_value": {"type": "string", "description": "Значення IOC: IP адреса, домен, хеш, ім'я файлу, тощо"},
            "ioc_type": {"type": "string", "description": "Тип IOC: public_ip, domain, hash_md5, hash_sha256, file_name, tool_name (опційно)"}
        }, "required": ["ioc_value"]}
    }},
    {"type": "function", "function": {
        "name": "get_saved_findings",
        "description": "Завантажити збережені знахідки по цьому кейсу. Виклич НА ПОЧАТКУ щоб побачити що вже відомо, і ПЕРЕД finish_report щоб зібрати всі підтверджені факти.",
        "parameters": {"type": "object", "properties": {}}
    }},
    {"type": "function", "function": {
        "name": "save_finding",
        "description": "Зберегти підтверджену знахідку в пам'ять розслідування. Виклич ОДРАЗУ як підтвердив щось важливе: initial_access, persistence, ioc, lateral_movement, credential_theft. Вказуй конкретні джерела (файли/таблиці) що підтверджують.",
        "parameters": {"type": "object", "properties": {
            "finding_type": {"type": "string", "description": "Тип: initial_access | persistence | lateral_movement | credential_theft | ioc | malware | timeline_event"},
            "summary": {"type": "string", "description": "Конкретний опис: що, де, коли, звідки. Наприклад: 'лист нотаріусам.zip завантажений з SwissTransfer о 12:06 2026-01-26, джерело: MFT Zone.Identifier'"},
            "sources": {"type": "array", "items": {"type": "string"}, "description": "Список файлів/таблиць що підтверджують: ['filesystem_v2 Zone.Identifier', 'tool_alerts_v2 thor', 'ForensicTimeliner MFT']"},
            "confidence": {"type": "string", "description": "high | medium | low"},
            "detail": {"type": "object", "description": "Додаткові деталі (url, hash, path, timestamp тощо)"}
        }, "required": ["finding_type", "summary"]}
    }},
    {"type": "function", "function": {
        "name": "get_download_artifacts",
        "description": "КРИТИЧНО для initial access. Zone.Identifier з MFT — показує HostUrl (звідки скачано) і ReferrerUrl (з якої сторінки) для кожного файлу. Це прямий слід: що користувач завантажив і звідки. Фільтруй підозрілі: ZIP/EXE/VBS з незвичних доменів.",
        "parameters": {"type": "object", "properties": {
            "since": {"type": "string", "description": "Фільтр від дати, напр. '2026-01-01' — шукати завантаження після цієї дати"},
            "limit": {"type": "integer", "description": "Кількість записів (макс 80)"}
        }}
    }},
    {"type": "function", "function": {
        "name": "get_case_triggers",
        "description": "ПЕРШИЙ КРОК. Pre-scored тригери з автоматичного аналізу — що система вже визнала підозрілим. Відсортовані за score (вищий = підозріліший). Показує keyword, artifact_family, час. Використовуй ЦЕ ПЕРШИМ щоб зрозуміти що досліджувати.",
        "parameters": {"type": "object", "properties": {
            "limit": {"type": "integer", "description": "Кількість рядків (макс 80, default 40)"}
        }}
    }},
    {"type": "function", "function": {
        "name": "get_forensic_timeline",
        "description": "ГОЛОВНИЙ ІНСТРУМЕНТ. Запити до ForensicTimeliner — попередньо агрегована хронологія всіх forensic артефактів: Event Logs, LNK, JumpLists, MFT, Prefetch, Amcache, Shellbags. Використовуй першим для виявлення підозрілої активності.",
        "parameters": {"type": "object", "properties": {
            "keyword": {"type": "string", "description": "Ключове слово для фільтрації (напр. 'ngrok', 'powershell', 'cmd', 'service'). Залиш порожнім для загального огляду."},
            "artifact": {"type": "string", "description": "Фільтр по типу артефакту: 'Event Logs', 'LNK', 'JumpLists', 'MFT', 'Prefetch', 'Amcache', 'Shellbags'"},
            "limit": {"type": "integer", "description": "Кількість рядків (макс 80)"}
        }}
    }},
    {"type": "function", "function": {
        "name": "get_browser_downloads",
        "description": "Отримати завантаження з браузера — URL, referrer, ім'я файлу. КРИТИЧНО для визначення точки зараження (звідки скачаний шкідливий файл).",
        "parameters": {"type": "object", "properties": {
            "limit": {"type": "integer", "description": "Кількість рядків (макс 50)"}
        }}
    }},
    {"type": "function", "function": {
        "name": "get_regripper_data",
        "description": "Отримати дані RegRipper — WiFi паролі, MRU (recently used), облікові записи, USB девайси, встановлені програми, shellbags. Виклич для отримання детального аналізу реєстру.",
        "parameters": {"type": "object", "properties": {
            "keyword": {"type": "string", "description": "Ключове слово для фільтрації (напр. 'wifi', 'password', 'usb', 'run', 'shell'). Залиш порожнім для огляду всього."},
            "limit": {"type": "integer", "description": "Кількість рядків (макс 50)"}
        }}
    }},
]



