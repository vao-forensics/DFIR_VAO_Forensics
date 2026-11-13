"""IOC extraction — pull IPs/hashes/tools from SQL and store in case_iocs."""
from datetime import timedelta
import logging
import psycopg2
from core.config import PG_DSN
_log = logging.getLogger('app')

# Our own footprint (collector staging folder, dfp_ probes, vao_collector, our tools after
# the collector started) must never become a case IOC: "7za" from the collector's own
# DFIRTriage_ folder was the report's only "attack tool" once. See analysis/own_footprint.py.
try:
    from analysis.own_footprint import is_own as _own_is_own, sql_not_own as _own_sql_not
except Exception:  # pragma: no cover
    def _own_is_own(text, ts=None, case_key=None, conn=None, declared=None):
        return False

    def _own_sql_not(col):
        return 'TRUE'

_MAIL_LINKFILTERS = (
    'secureurl.ukr.net', 'linkfilter', 'safelinks.protection.outlook.com',
    'urldefense.com', 'urldefense.proofpoint.com', 'clicktime.symantec.com',
    'protect-us.mimecast.com', 'protect.checkpoint.com', 'gateway.zscaler.net',
)


def _unwrap_mail_link(url):
    """A mail provider's link filter is the VICTIM's infrastructure, not the attacker's.

    Two cases matching on `secureurl.ukr.net` only means both victims read mail at ukr.net -
    a false link that would pollute the attacker portrait. But these wrappers carry the real
    destination inside, base64-encoded: the case_42 case's filter URL decoded to
    `https://cutt.ly/hyu28fDm`, which IS attacker infrastructure and IS worth matching on.

    Returns (real_url_or_None, is_wrapper).
    """
    import base64 as _b64
    import re as _re
    low = str(url or '').lower()
    if not any(w in low for w in _MAIL_LINKFILTERS):
        return None, False
    for chunk in _re.split(r'[/?&=#]', str(url or '')):
        if len(chunk) < 16 or len(chunk) > 512:
            continue
        if not _re.match(r'^[A-Za-z0-9_\-+/]+={0,2}$', chunk):
            continue
        for variant in (chunk, chunk.replace('-', '+').replace('_', '/')):
            for pad in ('', '=', '=='):
                try:
                    dec = _b64.b64decode(variant + pad).decode('utf-8', errors='strict')
                except Exception:
                    continue
                if dec.lower().startswith('http'):
                    return dec.strip(), True
    return None, True


def _extract_and_store_case_iocs_from_sql(case_key):
    """Extract IOCs from SQL forensic tables and store in case_iocs + ioc_overlap."""
    import re as _re_ioc
    _IP_RE = _re_ioc.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    _PRIV_RE = _re_ioc.compile(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.)')
    _TOOL_RE = {'ngrok', 'litemanager', 'rdpwrap', 'rutserv', 'rms', 'fiddler', 'anydesk', 'teamviewer', 'mimikatz', '7za'}

    # ── shared anti-noise helpers for the new blocks (BLOCK 1/2/3) ──
    _URL_RE = _re_ioc.compile(r'https?://[^\s"\'<>)\]}]+', _re_ioc.I)
    _BENIGN_HOST_RE = _re_ioc.compile(
        r'(^|\.)(microsoft\.com|windows\.com|windowsupdate\.com|msftconnecttest\.com|msftncsi\.com|'
        r'office\.com|office365\.com|live\.com|msn\.com|bing\.com|nuget\.org|schemas\.(xmlsoap|microsoft)|'
        r'digicert\.com|verisign\.com|globalsign\.com|sectigo\.com|mozilla\.org|mozilla\.com|'
        r'googleapis\.com|gstatic\.com|google\.com|ubuntu\.com|nvidia\.com|adobe\.com|apple\.com|'
        r'windows\.net|azureedge\.net|akamai\.net|cloudflare\.com|gov\.ua|rada\.gov\.ua)$', _re_ioc.I)

    def _valid_pub_ip(s):
        m = _re_ioc.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', str(s or '').strip())
        if not m or any(int(o) > 255 for o in m.groups()):
            return False
        # VERSION_AS_IP_FIX: an octet with a leading zero is a version field, never an
        # address ('024.401.617.0' out of AV1VideoExtension_2024.401.617.0), and a
        # .0/.255 tail is a network/broadcast address, not a host an attacker dialled in
        # from. Both shapes reached case_iocs as public_ip.
        _o = [g for g in m.groups()]
        if any(len(g) > 1 and g[0] == '0' for g in _o):
            return False
        if int(_o[3]) in (0, 255):
            return False
        return not _PRIV_RE.match(s)

    # VERSION_AS_IP_FIX: PowerShell text is full of dotted quads that are versions.
    # 'Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201' was stored as a
    # ps_c2 public_ip with confidence 0.8. Reject a quad glued into a name by '-'/'_',
    # carrying a binary extension, or introduced by a version word.
    _VERWORD_RE = _re_ioc.compile(
        r'\b[\w\-]*(?:version|build|release|setup|installer|patch|package|update|revision)'
        r'[\w\-]*\b[\s:=.\-]{0,4}$', _re_ioc.I)
    _VEREXT_RE = _re_ioc.compile(r'^\.(?:exe|dll|msi|sys|pf|zip|rar|cab|bin|nupkg)\b', _re_ioc.I)

    def _ip_is_version_ctx(text, i, j):
        before = text[i - 1] if i > 0 else ''
        after = text[j] if j < len(text) else ''
        if (before and before in '-_') or (after and after in '-_'):
            return True
        if _VEREXT_RE.match(text[j:j + 7]):
            return True
        return bool(_VERWORD_RE.search(text[max(0, i - 30):i]))

    def _reg_dom(host):
        h = str(host or '').lower().strip().rstrip('.').split(':')[0]
        p = h.split('.')
        if len(p) <= 2:
            return h
        _sld = {'com', 'net', 'org', 'gov', 'edu', 'co', 'ac', 'in', 'mil'}
        return '.'.join(p[-3:]) if (p[-2] in _sld and len(p[-1]) == 2) else '.'.join(p[-2:])

    def _extract_net(text):
        """(urls, domains, ips) from one text blob; benign hosts dropped."""
        urls, doms, ips = set(), set(), set()
        for u in _URL_RE.findall(text or ''):
            u = u.rstrip('.,);\'"')
            hm = _re_ioc.match(r'https?://([^/:\s]+)', u, _re_ioc.I)
            host = (hm.group(1) if hm else '').lower()
            if host and _valid_pub_ip(host):
                ips.add(host)
            elif host and '.' in host and not _BENIGN_HOST_RE.search(host):
                urls.add(u[:200]); doms.add(host)
        _t = text or ''
        for _m in _re_ioc.finditer(r'(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])', _t):
            ip = _m.group(1)
            if _valid_pub_ip(ip) and not _ip_is_version_ctx(_t, _m.start(1), _m.end(1)):
                ips.add(ip)
        return urls, doms, ips

    new_iocs = []  # (ioc_type, ioc_value, ioc_norm, source_table, event_ts[, confidence])

    def _add(t, val, norm, src, ts, conf=0.9):
        v = str(val or '').strip()
        if v:
            new_iocs.append((t, v[:200], str(norm or v).lower()[:200], src, ts, conf))
    try:
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                # External IPs from event_logs_v2
                cur.execute("""SELECT DISTINCT remote_host, MIN(event_ts)
                    FROM event_logs_v2 WHERE case_key=%s AND remote_host IS NOT NULL
                    AND remote_host NOT LIKE '%%:%%' AND remote_host != ''
                    GROUP BY remote_host""", (case_key,))
                for host, ts in cur.fetchall():
                    if host and _IP_RE.match(host) and not _PRIV_RE.match(host):
                        new_iocs.append(('public_ip', host, host.lower(), 'event_logs_v2', ts))
                    # Also capture IP from payload (RDPClient EID 1102)
                cur.execute("""SELECT DISTINCT payload->>'PayloadData1', MIN(event_ts)
                    FROM event_logs_v2 WHERE case_key=%s AND event_id=1102
                    AND channel ILIKE '%%RDPClient%%' AND payload->>'PayloadData1' IS NOT NULL
                    GROUP BY payload->>'PayloadData1'""", (case_key,))
                for pd1, ts in cur.fetchall():
                    if pd1:
                        m = _IP_RE.search(pd1)
                        if m and not _PRIV_RE.match(m.group(1)):
                            new_iocs.append(('public_ip', m.group(1), m.group(1).lower(), 'event_logs_v2/RDPClient', ts))
                # SHA1 hashes from suspicious program_exec_v2 (exclude system files)
                _SYS_EXE_SKIP = {'dismhost.exe','dism.exe','svchost.exe','lsass.exe',
                                  'csrss.exe','winlogon.exe','services.exe','smss.exe',
                                  'conhost.exe','werfault.exe','searchindexer.exe',
                                  'trustedinstaller.exe','tiworker.exe','msiexec.exe'}
                cur.execute("""SELECT DISTINCT hash_sha1, lower(regexp_replace(executable_name,'.*[/\\\\]','')), MIN(event_ts)
                    FROM program_exec_v2 WHERE case_key=%s AND hash_sha1 IS NOT NULL AND hash_sha1 != ''
                    AND (full_path ILIKE '%%Public%%' OR full_path ILIKE '%%Roaming%%'
                         OR (full_path ILIKE '%%Temp%%' AND executable_name NOT ILIKE '%%dismhost%%')
                         OR full_path ILIKE '%%ProgramData%%')
                    AND full_path NOT ILIKE '%%Package Cache%%'
                    AND """ + _own_sql_not("coalesce(full_path,'')||' '||coalesce(executable_name,'')") + """
                    GROUP BY hash_sha1, executable_name""", (case_key,))
                for sha1, exe_name, ts in cur.fetchall():
                    _en = (exe_name or '').strip()
                    if _en in _SYS_EXE_SKIP:
                        continue
                    if _own_is_own(_en, ts=ts, case_key=case_key):
                        continue
                    # skip legit installers/redistributables (vcredist, InstallShield temp _is*.exe)
                    # — they are on every Windows box and create false cross-case IOC links.
                    if ('vcredist' in _en or 'vc_redist' in _en or _en.startswith('_is')
                            or _en in ('setup.exe','install.exe','unins000.exe')):
                        continue
                    new_iocs.append(('hash_sha1', sha1, sha1.lower(), 'sql_program_exec', ts))
                # Tool names from case_trigger_hits_v2
                cur.execute("""SELECT lower(trigger), coalesce(snippet,''), event_ts
                    FROM case_trigger_hits_v2 WHERE case_key=%s""", (case_key,))
                # a hit on our own footprint (the collector's Sigma rule files, its staging
                # folder) or made after the collection started names no attacker tool
                try:
                    from analysis.own_footprint import collect_started_at as _csa
                    _cst = _csa(case_key)
                except Exception:
                    _cst = None
                _trig_rows = sorted({(t,) for t, sn, ts in cur.fetchall()
                                     if t and not _own_is_own(sn)
                                     and not (_cst is not None and ts is not None and ts >= _cst - timedelta(minutes=10))})
                # 7za is a generic archiver and the one our collector ships in its staging folder.
                # A trigger naming it becomes an IOC only when the archiver was seen somewhere
                # that is NOT our footprint (path/name row in program_exec or the filesystem).
                cur.execute("""SELECT count(*) FROM (
                        SELECT full_path AS p, executable_name AS n, event_ts AS t FROM program_exec_v2
                         WHERE case_key=%s AND lower(coalesce(executable_name,'')||coalesce(full_path,'')) LIKE '%%7za%%'
                        UNION ALL
                        SELECT parent_path, file_name, event_ts FROM filesystem_v2
                         WHERE case_key=%s AND lower(file_name) LIKE '7za%%' AND action='MFT') s
                    WHERE """ + _own_sql_not("coalesce(s.p,'')||' '||coalesce(s.n,'')"), (case_key, case_key))
                _r = cur.fetchone()
                _7za_foreign = bool(_r and _r[0])
                for (trig,) in _trig_rows:
                    # sorted(): the loop breaks on the first match, so with a trigger
                    # naming two tools the set order decided which IOC got STORED.
                    # Latent today (0 of 23 matching triggers over 10 cases are
                    # ambiguous), but a wrong IOC in the database outlives the run.
                    for tool in sorted(_TOOL_RE):
                        if tool in trig:
                            if tool == '7za' and not _7za_foreign:
                                break
                            new_iocs.append(('tool_name', tool, tool, 'case_trigger_hits_v2', None))
                            break
                # User accounts created (EID 4720)
                cur.execute("""SELECT DISTINCT target_user, MIN(event_ts)
                    FROM event_logs_v2 WHERE case_key=%s AND event_id=4720 AND target_user IS NOT NULL
                    GROUP BY target_user""", (case_key,))
                for user, ts in cur.fetchall():
                    if user and user.lower() not in ('system', 'administrator'):
                        new_iocs.append(('user_account', user, user.lower(), 'event_logs_v2/EID4720', ts))

                # RAT / remote-access / tunnel tools that were EXECUTED (P3: detector-found
                # tools -> IOCs, e.g. RustDesk). Log-grounded exact values from Amcache/Prefetch.
                _RAT_SQL = (r'anydesk|teamviewer|rustdesk|meshagent|meshcentral|romviewer|romserver|'
                            r'rdpwrap|rdpwinst|litemanager|rutserv|screenconnect|splashtop|ammyy|'
                            r'radmin|ultravnc|ngrok|\yfrpc\y|cloudflared|localtonet|psexec|nltest|mimikatz')
                cur.execute("""SELECT DISTINCT lower(executable_name), MIN(event_ts)
                    FROM program_exec_v2 WHERE case_key=%s
                    AND (coalesce(executable_name,'') ~* %s OR coalesce(full_path,'') ~* %s)
                    AND """ + _own_sql_not("coalesce(full_path,'')||' '||coalesce(executable_name,'')") + """
                    GROUP BY 1""", (case_key, _RAT_SQL, _RAT_SQL))
                import re as _re_rat
                # canonical RAT names so the SAME tool matches across cases even when stored
                # as a full path (was: full path verbatim -> cross-case links silently missed).
                _RAT_CANON = [('anydesk','anydesk'),('teamviewer','teamviewer'),('rustdesk','rustdesk'),
                    ('meshagent','meshagent'),('meshcentral','meshagent'),('romviewer','litemanager'),
                    ('romserver','litemanager'),('litemanager','litemanager'),('rutserv','rms'),
                    ('rdpwrap','rdpwrapper'),('rdpwinst','rdpwrapper'),('screenconnect','screenconnect'),
                    ('splashtop','splashtop'),('ammyy','ammyy'),('radmin','radmin'),('ultravnc','ultravnc'),
                    ('ngrok','ngrok'),('frpc','frp'),('cloudflared','cloudflared'),('localtonet','localtonet'),
                    ('psexec','psexec'),('nltest','nltest'),('mimikatz','mimikatz')]
                for tool, ts in cur.fetchall():
                    if not tool:
                        continue
                    _tl = tool.lower()
                    _basename = _re_rat.sub(r'.*[/\\\\]', '', _tl)          # strip path
                    _canon = next((c for pat, c in _RAT_CANON if pat in _tl), _basename.replace('.exe', ''))
                    # value = readable basename, norm = canonical (cross-case key)
                    new_iocs.append(('tool_name', _basename or _tl, _canon, 'threat_detect/program_exec', ts))

                # Accounts added to privileged groups (P2: EID 4728/4732 group-adds)
                cur.execute("""SELECT DISTINCT coalesce(target_user, payload->>'MemberSid'), MIN(event_ts)
                    FROM event_logs_v2 WHERE case_key=%s AND event_id IN (4728,4732) AND channel='Security'
                    GROUP BY 1""", (case_key,))
                for user, ts in cur.fetchall():
                    if user and user.lower() not in ('system', 'administrator', '-'):
                        new_iocs.append(('user_account', user, user.lower(), 'event_logs_v2/EID4728_4732', ts))

                # Defender malware detections (EID 1116/1117): Threat Name + Path. Works WITHOUT
                # program_exec (fast-mode) — this is how AsyncRAT/Trojan names become IOCs + cross-case.
                cur.execute("""SELECT DISTINCT payload->>'Threat Name', payload->>'Path', MIN(event_ts)
                    FROM event_logs_v2 WHERE case_key=%s AND event_id IN (1116,1117)
                      AND coalesce(payload->>'Threat Name','') != ''
                    GROUP BY 1,2""", (case_key,))
                for tname, tpath, ts in cur.fetchall():
                    if tname and tname.strip():
                        new_iocs.append(('malware_name', tname.strip()[:120], tname.strip().lower()[:120],
                                         'defender_EID1116', ts))
                    if tpath:
                        import re as _re_p
                        # take the first concrete file path out of the Defender Path string
                        _m = _re_p.search(r'([a-zA-Z]:\\\\[^;|\n]+?\\.[a-zA-Z0-9]{2,4})', tpath)
                        if _m:
                            _fp = _m.group(1).strip()
                            if 'ad_driver' not in _fp.lower() and 'dell_forensic' not in _fp.lower():
                                new_iocs.append(('file_path', _fp[:200], _fp.lower()[:200], 'defender_EID1116', ts))

                # ── ATTACKER HOST over RDP (FIXED to this parser's schema, 2026-07-13) ──
                # This parser stores «WorkstationName (IP)» in the remote_host COLUMN (NOT payload),
                # and logon_type is BLANK — so the old payload->>'WorkstationName' logic captured
                # NOTHING. Two real signals from 4624/4625/4778 logons, excluding the victim's own host:
                #  (a) loopback source (::1 / 127.0.0.1) = RDP tunneled in via ngrok/rdpwrap → the
                #      workstation name leaks the attacker's machine (STRONG cross-case fingerprint,
                #      e.g. case_53 seen in multiple cases). Legit LAN PCs use real 192.168/fe80.
                #  (b) a PUBLIC source IP = direct external RDP → attacker host + attacker source IP.
                cur.execute("""SELECT lower(computer) FROM event_logs_v2
                    WHERE case_key=%s AND coalesce(computer,'')<>'' GROUP BY 1 ORDER BY count(*) DESC LIMIT 1""",
                    (case_key,))
                _vr = cur.fetchone()
                _victim = (_vr[0] if _vr and _vr[0] else '')
                _sys_wks = {'', '-', 'local', 'workgroup', 'localhost', 'window manager',
                            'font driver host', 'nt authority', _victim}
                # (a) loopback-tunnelled RDP workstation
                cur.execute("""SELECT split_part(remote_host, ' (', 1) AS wks, MIN(event_ts)
                    FROM event_logs_v2
                    WHERE case_key=%s AND event_id IN (4624,4625,4778)
                      AND (remote_host LIKE '%%(::1)%%' OR remote_host LIKE '%%(127.0.0.1)%%')
                    GROUP BY 1""", (case_key,))
                for wks, ts in cur.fetchall():
                    w = (wks or '').strip()
                    if not w or w.lower() in _sys_wks or len(w) < 3:
                        continue
                    new_iocs.append(('attacker_host', w[:80], w.lower()[:80],
                                     'event_logs_v2/RDP_tunnel_workstation', ts, 0.9))
                    new_iocs.append(('technique', 'RDP через loopback-тунель (ngrok/rdpwrap) з машини ' + w[:50],
                                     'rdp_loopback_tunnel', 'event_logs_v2/RDP_loopback', ts, 0.8))
                # (b) direct external RDP: workstation + PUBLIC source IP
                cur.execute("""SELECT split_part(remote_host,' (',1) AS wks,
                                      rtrim(split_part(remote_host,'(',2),')') AS ip, MIN(event_ts)
                    FROM event_logs_v2
                    WHERE case_key=%s AND event_id IN (4624,4625,4778)
                      AND remote_host ~ '\\([0-9]{1,3}(\\.[0-9]{1,3}){3}\\)'
                    GROUP BY 1,2""", (case_key,))
                for wks, ip, ts in cur.fetchall():
                    ip = (ip or '').strip()
                    if not _valid_pub_ip(ip):
                        continue
                    new_iocs.append(('public_ip', ip, ip, 'event_logs_v2/RDP_source', ts, 0.85))
                    w = (wks or '').strip()
                    if w and w.lower() not in _sys_wks and len(w) >= 3:
                        new_iocs.append(('attacker_host', w[:80], w.lower()[:80],
                                         'event_logs_v2/RDP_source_pubip', ts, 0.85))

                # T1-D: attacker account from disk profiles (C:\Users\<name>) — a STABLE cross-case
                # identifier (the actor reuses the same alias, e.g. 'case_59') that survives IP/token
                # rotation and works even when the case has NO report / no 4720 event. Precision:
                # drive-rooted profile only, victim + default accounts + package-folder noise dropped.
                _ACCT_DENY = {'user', 'users', 'public', 'default', 'defaultuser0', 'default user',
                              'all users', 'administrator', 'admin', 'guest', 'wdagutilityaccount',
                              'defaultapppool', 'localservice', 'networkservice', 'systemprofile',
                              'tempadmin', 'account unknown', _victim}
                try:
                    cur.execute("""SELECT DISTINCT lower(parent_path) FROM filesystem_v2
                        WHERE case_key=%s AND lower(parent_path) LIKE '%%users%%'""", (case_key,))
                    _seen_acct = set()
                    for (_pp,) in cur.fetchall():
                        _ma = _re_ioc.search(r'[\\/]users[\\/]+([^\\/]+)', _pp or '')  # KAPE paths are .\Users\<name> (no drive)
                        if not _ma:
                            continue
                        _u = _ma.group(1).strip()
                        if (_u and _u not in _ACCT_DENY and 2 < len(_u) <= 20 and _u not in _seen_acct
                                and not _u.endswith('$') and '.' not in _u and ' ' not in _u
                                and _re_ioc.fullmatch(r'[a-z0-9][a-z0-9_.\-]*', _u)
                                and not _re_ioc.search(r'_[a-z]{4,}', _u)):
                            _seen_acct.add(_u)
                            new_iocs.append(('user_account', _u, _u, 'filesystem_profile', None, 0.5))
                except Exception as _e_acct:
                    _log.warning(f"[extract_iocs] account profiles: {_e_acct}")

                # Remote-access / tunnel infrastructure DOMAINS from browser provenance
                # (zone MOTW host + visited url host). Precision-first: ONLY attack-infra
                # hosts (ngrok/RMS/AnyDesk/tunnel), NOT general browsing — dumping every
                # domain would drown cross-case intersection in gov.ua/telegram/music noise
                # (verified: blanket .ru catches wallpaper/mp3 browsing, not IOCs).
                # ioc_norm = registrable domain so subdomains (bin.equinox.io / cdn.equinox.io)
                # collapse to one cross-case key (equinox.io => ngrok delivery infra).
                _DOMAIN_INFRA_RE = (r'equinox\.io|ngrok|anydesk|teamviewer|rustdesk|assistant\.group|'
                                    r'getscreen|ammyy|radmin|litemanager|rutserv|remoteutilities|'
                                    r'screenconnect|splashtop|meshcentral|meshagent|cloudflared|'
                                    r'localtonet|localhost\.run|trycloudflare|serveo\.net|pagekite|'
                                    r'portmap\.io|dwservice|iperius|gotohttp')
                cur.execute("""
                    WITH hosts AS (
                      SELECT lower(regexp_replace(zone_identifier_host_url,'^https?://([^/:]+).*$','\\1')) host, min(event_ts) ts
                        FROM browser_provenance_v1 WHERE case_key=%s AND zone_identifier_host_url ~* '^https?://' GROUP BY 1
                      UNION ALL
                      SELECT lower(regexp_replace(url,'^https?://([^/:]+).*$','\\1')) host, min(event_ts) ts
                        FROM browser_provenance_v1 WHERE case_key=%s AND url ~* '^https?://' GROUP BY 1
                    )
                    SELECT host,
                      regexp_replace(host,'^.*?([a-z0-9-]+\\.[a-z]{2,})$','\\1') AS reg, min(ts)
                    FROM hosts WHERE host ~ '\\.' AND host ~* %s GROUP BY 1,2
                """, (case_key, case_key, _DOMAIN_INFRA_RE))
                for _h, _reg, _ts in cur.fetchall():
                    if _h and _reg:
                        new_iocs.append(('domain', _h, _reg.lower(), 'browser_provenance/infra', _ts))

                # Public remote_ip of infra hosts only (precision-first: browsing
                # remote_ips are 99% benign CDN/google — take ONLY rows whose host
                # matches the attack-infra regex above).
                cur.execute("""SELECT DISTINCT remote_ip, MIN(event_ts)
                    FROM browser_provenance_v1 WHERE case_key=%s
                      AND remote_ip ~ '^\\d{1,3}(\\.\\d{1,3}){3}$'
                      AND coalesce(zone_identifier_host_url,'')||' '||coalesce(url,'')||' '||coalesce(domain,'') ~* %s
                    GROUP BY 1""", (case_key, _DOMAIN_INFRA_RE))
                for _rip, _ts in cur.fetchall():
                    if _rip and not _PRIV_RE.match(_rip):
                        new_iocs.append(('public_ip', _rip, _rip, 'browser_provenance/infra_ip', _ts))

                # Initial-access delivery URL/domain: reuse the deterministic
                # infection-point winner from reports.reshape (same source the
                # report's 🎯 section renders) — the delivery host is the single
                # highest-value domain IOC a case has (e.g. swisstransfer link).
                try:
                    from reports.reshape import _initial_access_struct, _incident_window
                    _iw_s = _incident_window(case_key)[0]
                    _w = (_initial_access_struct(case_key, _iw_s) or {}).get('winner') or {}
                    _wu = (_w.get('url') or '').strip()
                    _m_h = _re_ioc.match(r'^https?://([^/:]+)', _wu.lower())
                    if _m_h:
                        _h = _m_h.group(1)
                        _p = _h.rstrip('.').split('.')
                        # registrable domain; keep 3 labels for ccTLD SLDs (com.ua etc.)
                        _n = 3 if (len(_p) > 2 and _p[-2] in
                                   ('com', 'net', 'org', 'gov', 'edu', 'co', 'in', 'ac', 'mil')
                                   and len(_p[-1]) == 2) else 2
                        _reg = '.'.join(_p[-_n:]) if len(_p) > _n else _h
                        new_iocs.append(('domain', _h, _reg, 'initial_access', _w.get('dl_ts')))
                        new_iocs.append(('url', _wu[:200], _wu.lower()[:200], 'initial_access', _w.get('dl_ts')))
                except Exception as _e_ia:
                    _log.warning(f"[extract_iocs] initial_access IOC skip: {_e_ia}")

                # ── BLOCK 3: new services (EID 7045) ImagePath — attacker service exe.
                # Anti-noise: write only if the path is user-writable OR the basename is a
                # known RAT (System32/Program Files/WinSxS = legit vendor updaters).
                _UW_RE = _re_ioc.compile(r'\\(temp|appdata|programdata|users\\public|downloads|roaming)\\', _re_ioc.I)
                # legit software/AV/forensic tools that also live in user-writable dirs
                _BENIGN_SVC_RE = _re_ioc.compile(
                    r'windows defender|mpksldrv|microsoft\\edgeupdate|\\microsoft\\|onedrive|'
                    r'ad_driver|accessdata|ftk|dell_forensic|cellebrite|kape|eztools|magnet|axiom|'
                    r'\\google\\|\\mozilla\\|\\adobe\\|\\nvidia\\|\\intel\\|packages\\|amcache', _re_ioc.I)
                try:
                    cur.execute("""SELECT DISTINCT payload->>'ImagePath', MIN(event_ts)
                        FROM event_logs_v2 WHERE case_key=%s AND event_id=7045
                          AND coalesce(payload->>'ImagePath','') != '' GROUP BY 1""", (case_key,))
                    for _img, _ts in cur.fetchall():
                        if not _img:
                            continue
                        _p = _re_ioc.sub(r'^"([^"]+)".*$', r'\1', _img.strip())      # strip quotes+args
                        _p = _re_ioc.split(r'\s+(?:-|/)', _p, 1)[0].strip().strip('"')
                        _bn = _p.replace('/', '\\').rsplit('\\', 1)[-1].lower()
                        if _BENIGN_SVC_RE.search(_p):
                            continue  # Defender/forensic/vendor service — not attacker
                        _uw = bool(_UW_RE.search(_p))
                        _rat = any(_t in _p.lower() for _t in (
                            'anydesk', 'rustdesk', 'ngrok', 'rdpwrap', 'rdpwinst', 'mimikatz', 'psexec',
                            'teamviewer', 'meshagent', 'litemanager', 'rutserv', 'screenconnect',
                            'splashtop', 'radmin', 'ammyy', 'ultravnc', 'cloudflared', 'localtonet'))
                        if _uw or _rat:
                            _add('file_path', _p, _p.lower(), 'service_7045', _ts, 0.75)
                            if _bn:
                                _add('file_name', _bn, _bn, 'service_7045', _ts, 0.7)
                except Exception as _e3:
                    _log.warning(f"[extract_iocs] block3 7045: {_e3}")

                # ── BLOCK 1+2: C2 from PowerShell ScriptBlock (4104) + command lines —
                # download cradles / LOLBin fetchers + base64 -EncodedCommand payloads.
                _CRADLE = (r'downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|\biex\b|'
                           r'net\.webclient|start-bitstransfer|invoke-restmethod|\birm\b|system\.net\.http')
                _LOLBIN = (r'certutil.{0,40}-urlcache|certutil.{0,40}-f\s|bitsadmin.{0,20}/transfer|'
                           r'mshta\s+https?|regsvr32.{0,30}/i:http|rundll32.{0,30}http|\bcurl\s+https?|'
                           r'\bwget\s+https?|msiexec.{0,20}https?')
                _ENC = (r'-e(nc|ncodedcommand)?\s+|frombase64string')
                _B64 = _re_ioc.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
                # T1-B: Defender exclusion path (Add/Set-MpPreference -ExclusionPath) = stable T1562.001 fingerprint
                _MPEXCL = _re_ioc.compile(r'(?i)(?:Add|Set)-MpPreference[^\r\n]{0,80}?ExclusionPath[ =]+([A-Za-z]:\\[^\s;"\'\r\n]*)')
                import base64 as _b64m
                try:
                    # T1-A: read the attacker's FULL command from classic PowerShell EID 600 (HostApplication=)
                    # + EID 400/403 + 4104 ScriptBlock + command_line. 600's command_line is ALWAYS empty and it
                    # isn't 4104, so these attacker cradles/Defender-tamper commands were 100% unread before.
                    # DISTINCT (600 repeats the same command thousands of times).
                    _txt_expr = ("coalesce(payload->>'ScriptBlockText','')||' '||coalesce(command_line,'')||' '||"
                                 "regexp_replace(coalesce(payload->>'PayloadData1',''),'^HostApplication=','')")
                    cur.execute("SELECT DISTINCT " + _txt_expr +
                                " FROM event_logs_v2 WHERE case_key=%s"
                                "   AND (event_id IN (4104,600,400,403) OR coalesce(command_line,'')<>'')"
                                "   AND (" + _txt_expr + ") ~* %s"
                                " LIMIT 4000", (case_key, _CRADLE + '|' + _LOLBIN + '|' + _ENC + '|mppreference'))
                    _rows = cur.fetchall()
                    _b64_seen = 0
                    for (_txt,) in _rows:
                        if not _txt:
                            continue
                        _u, _d, _i = _extract_net(_txt)
                        for _url in list(_u)[:10]:
                            _add('url', _url, _url, 'ps_c2', None, 0.8)
                        for _dm in list(_d)[:10]:
                            _add('domain', _dm, _reg_dom(_dm), 'ps_c2', None, 0.8)
                        for _ip in list(_i)[:10]:
                            _add('public_ip', _ip, _ip, 'ps_c2', None, 0.8)
                        # T1-B: Defender ExclusionPath → stable technique fingerprint (survives IP/token rotation)
                        for _mp in _MPEXCL.finditer(_txt):
                            _pth = _mp.group(1).strip().rstrip('\\')
                            if _pth and not _BENIGN_SVC_RE.search(_pth):
                                _add('technique', 'Defender ExclusionPath: ' + _pth[:120],
                                     'defender_exclusion:' + _pth.lower(), 'ps_defender_tamper', None, 0.8)
                                _add('technique', 'Вимкнення захисту Windows Defender (Add-MpPreference ExclusionPath)',
                                     't1562_001_defender_exclusion', 'ps_defender_tamper', None, 0.7)
                        # base64 payloads → decode → net indicators
                        if _b64_seen < 20 and _re_ioc.search(_ENC, _txt, _re_ioc.I):
                            for _blob in _B64.findall(_txt)[:5]:
                                if _b64_seen >= 20:
                                    break
                                _b64_seen += 1
                                try:
                                    _raw = _b64m.b64decode(_blob + '=' * (-len(_blob) % 4))
                                    _dec = _raw.decode('utf-16le', 'ignore')
                                    if _dec.count('\x00') > len(_dec) * 0.3 or len(_dec) < 8:
                                        _dec = _raw.decode('latin-1', 'ignore')
                                except Exception:
                                    continue
                                _bu, _bd, _bi = _extract_net(_dec)
                                for _url in list(_bu)[:6]:
                                    _add('url', _url, _url, 'ps_b64_decoded', None, 0.8)
                                for _dm in list(_bd)[:6]:
                                    _add('domain', _dm, _reg_dom(_dm), 'ps_b64_decoded', None, 0.8)
                                for _ip in list(_bi)[:6]:
                                    _add('public_ip', _ip, _ip, 'ps_b64_decoded', None, 0.8)
                except Exception as _e12:
                    _log.warning(f"[extract_iocs] block1+2 ps-c2: {_e12}")

                # ── Delivery URL of a PROVEN download->open->install chain ────────────
                # The domain extractor above is reputation-first: it only keeps hosts that
                # match the attack-infrastructure regex. That is right for browsing noise,
                # but it threw away the single most valuable indicator in the case_42
                # case - the attacker used Backblaze B2 and cutt.ly, both perfectly
                # legitimate services. What made that URL an indicator was not its domain
                # but the chain: the file was downloaded, the user opened it, and an
                # installer appeared minutes later.
                #
                # So: when the chain is proven, the URL and its domain become indicators
                # regardless of reputation. These are what let two cases be linked - the
                # same shortener or the same storage bucket across reports is the thread
                # that builds the attacker's portrait.
                try:
                    cur.execute("""
                        SELECT d.event_ts, d.file_name,
                               substring(coalesce(d.payload::text,'') from 'HostUrl=([^\\s"\\\\]+)'),
                               substring(coalesce(d.payload::text,'') from 'ReferrerUrl=([^\\s"\\\\]+)')
                        FROM filesystem_v2 d
                        WHERE d.case_key=%s AND d.event_ts IS NOT NULL
                          AND coalesce(d.payload::text,'') ~* 'hosturl=|referrerurl='
                          AND lower(d.file_name) ~ '\\.(zip|rar|7z|exe|msi|scr|js|vbs|ps1|bat|cmd|hta|iso|img|docm|xlsm)(:zone\\.identifier)?$'
                          AND EXISTS (
                              SELECT 1 FROM filesystem_v2 r
                              WHERE r.case_key=d.case_key
                                AND lower(coalesce(r.parent_path,'')) ~ 'recent'
                                AND lower(r.file_name) = lower(split_part(d.file_name, ':', 1)) || '.lnk'
                                AND r.event_ts BETWEEN d.event_ts AND d.event_ts + interval '10 minutes')
                          AND (EXISTS (
                              SELECT 1 FROM event_logs_v2 s
                              WHERE s.case_key=d.case_key AND s.event_id=7045
                                AND coalesce(s.channel,'')='System'
                                AND s.event_ts BETWEEN d.event_ts AND d.event_ts + interval '30 minutes')
                            OR EXISTS (
                              SELECT 1 FROM filesystem_v2 m
                              WHERE m.case_key=d.case_key
                                AND lower(coalesce(m.parent_path,'')) ~ 'programdata'
                                AND lower(m.file_name) ~ '\\.(msi|exe)$'
                                AND m.event_ts BETWEEN d.event_ts AND d.event_ts + interval '30 minutes'))
                        ORDER BY d.event_ts LIMIT 10""", (case_key,))
                    for _dts, _dfn, _dhost, _dref in cur.fetchall():
                        _fn = str(_dfn or '').split(':')[0]
                        if _fn:
                            new_iocs.append(('file_name', _fn, _fn.lower(),
                                             'delivery_chain/zone_identifier', _dts, 0.95))
                        _urls = []
                        for _u in (_dhost, _dref):
                            _u = str(_u or '').strip()
                            if not _u.lower().startswith('http'):
                                continue
                            _real, _wrapped = _unwrap_mail_link(_u)
                            if _real:
                                # keep the decoded destination, drop the provider wrapper
                                _urls.append(_real)
                            elif not _wrapped:
                                _urls.append(_u)
                        for _u in _urls:
                            new_iocs.append(('url', _u[:500], _u.lower()[:500],
                                             'delivery_chain/zone_identifier', _dts, 0.95))
                            _m_d = _re_ioc.match(r'^https?://([^/:]+)', _u.lower())
                            if _m_d:
                                _hst = _m_d.group(1).rstrip('.')
                                _pp = _hst.split('.')
                                _nn = 3 if (len(_pp) > 2 and _pp[-2] in
                                            ('com', 'net', 'org', 'gov', 'edu', 'co', 'in', 'ac', 'mil')) else 2
                                _reg = '.'.join(_pp[-_nn:]) if len(_pp) >= _nn else _hst
                                new_iocs.append(('domain', _hst, _reg,
                                                 'delivery_chain/zone_identifier', _dts, 0.95))
                except Exception as _edl:
                    _log.warning(f"[extract_iocs] delivery chain: {_edl}")
                # Upsert into case_iocs (tuples are 5- or 6-element; conf defaults 0.9)
                for _row in new_iocs:
                    ioc_type, ioc_val, ioc_norm, src, ts = _row[:5]
                    conf = _row[5] if len(_row) > 5 else 0.9
                    try:
                        cur.execute("""INSERT INTO case_iocs(case_key,ioc_type,ioc_value,ioc_norm,source_table,event_ts,confidence)
                            VALUES(%s,%s,%s,%s,%s,%s,%s)
                            ON CONFLICT(case_key,ioc_type,ioc_norm) DO NOTHING""",
                            (case_key, ioc_type, ioc_val, ioc_norm, src, ts, conf))
                    except Exception:
                        pass

                # Recompute ioc_overlap for this case vs all others
                cur.execute("SELECT DISTINCT case_key FROM case_iocs WHERE case_key!=%s", (case_key,))
                other_cases = [r[0] for r in cur.fetchall()]
                for other in other_cases:
                    cur.execute("""SELECT a.ioc_type, a.ioc_norm, a.event_ts, b.event_ts
                        FROM case_iocs a JOIN case_iocs b
                        ON a.ioc_type=b.ioc_type AND a.ioc_norm=b.ioc_norm
                        WHERE a.case_key=%s AND b.case_key=%s
                        AND a.ioc_norm NOT IN ('powershell','anydesk','rdp wrapper','rdpwrapper','ngrok','7za',
                            'certutil','bitsadmin','mshta','rundll32','regsvr32','schtasks','wmic','sc',
                            'cmd','cmd.exe','powershell.exe','svchost','svchost.exe','rundll32.exe')""",
                        (case_key, other))
                    for ioc_type, ioc_norm, ts_a, ts_b in cur.fetchall():
                        first = min(t for t in [ts_a, ts_b] if t) if any([ts_a, ts_b]) else None
                        last = max(t for t in [ts_a, ts_b] if t) if any([ts_a, ts_b]) else None
                        ca, cb_k = sorted([case_key, other])
                        try:
                            cur.execute("""INSERT INTO ioc_overlap(case_a,case_b,ioc_type,ioc_norm,first_seen,last_seen)
                                VALUES(%s,%s,%s,%s,%s,%s)
                                ON CONFLICT(case_a,case_b,ioc_type,ioc_norm) DO UPDATE
                                SET last_seen=EXCLUDED.last_seen""",
                                (ca, cb_k, ioc_type, ioc_norm, first, last))
                        except Exception:
                            pass
    except Exception as e:
        _log.error(f"[extract_iocs] {case_key}: {e}")


