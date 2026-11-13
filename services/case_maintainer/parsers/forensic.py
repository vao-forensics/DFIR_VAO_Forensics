"""Forensic artifact parsers — ZIP ingestion, CSV/JSON parsing, batch flush."""
import os
import re, json, csv, io, re as _re, zipfile, logging
import psycopg2
from psycopg2.extras import Json, execute_values


class _NulSafeJson(Json):
    """jsonb rejects U+0000 anywhere in the document; the collector's CSVs carry NULs in
    values and (UTF-16 files) in keys, and one refused row used to abort the whole ingest."""
    def dumps(self, obj):
        return json.dumps(obj, ensure_ascii=False, default=str).replace(chr(92) + 'u0000', '')


Json = _NulSafeJson
from glob import glob
from datetime import datetime, timezone
from core.config import PG_DSN, CASE_LIB
from core.db import _parse_ts
try:
    from analysis.system_profile import _upsert_system_profile_v1
except Exception:
    _upsert_system_profile_v1 = None

# KAPE Prefetch/Amcache CSV rows can have fields > the 128KB default -> raise it
# so a single huge field never aborts a whole file (BACKLOG: capstone caught PECmd).
try:
    csv.field_size_limit(16 * 1024 * 1024)
except Exception:
    pass
_log = logging.getLogger('app')

def _pick(d, keys):
    for k in keys:
        v = d.get(k)
        if v is not None and str(v).strip() != '':
            return v
    return None


# U+00A0-U+00BF is included on purpose: under CP1251 the Ukrainian letters і ї є ґ
# live there (0xB3 -> і, 0xBF -> ї, 0xBA -> є, 0xB4 -> ґ), so a run that starts at
# U+00C0 leaves them unrepaired — `квитанц³ÿ` instead of `квитанція`.
_MOJI_RUN_RE = re.compile(r'[\u00a0-\u00ff]{3,}')


def _demojibake(s):
    """CP1251 text that an upstream tool decoded as Latin-1, restored.

    The KAPE-side CSV writers hand us `Ðàáî÷èé` where the artefact said `Рабочий`. The
    conversion is exact, so it is undone here rather than in every consumer. Applied only
    when the string carries a run of Latin-1 supplement characters AND the round trip
    yields real Cyrillic, so Latin text with a stray accent is never touched.
    """
    if not s or not _MOJI_RUN_RE.search(s):
        return s
    fixed = None
    # CP1252 first: the upstream tool decoded 0x80-0x9F as CP1252, so a CP1251 apostrophe
    # (0x92) arrives as U+2019 — a character Latin-1 cannot encode, which used to make the
    # repair give up on 4650 rows.
    for enc in ('cp1252', 'latin-1'):
        try:
            fixed = s.encode(enc, 'strict').decode('cp1251', 'strict')
            break
        except Exception:
            continue
    if fixed is None:
        return s
    cyr = 0
    for ch in fixed:
        if '\u0400' <= ch <= '\u04ff':
            cyr += 1
            if cyr >= 3:
                return fixed
    return s


def _clean_row(d):
    out = {}
    for k, v in (d or {}).items():
        if isinstance(k, str) and '\x00' in k:
            k = k.replace('\x00', '')
        if isinstance(v, str):
            # NUL stripping plus the CP1251/Latin-1 repair — see _demojibake. Doing it
            # here covers every mapper, since they all pass through this function.
            out[k] = _demojibake(v.replace('\x00', ''))
        else:
            out[k] = v
    return out


# EIDs whose full detail lives ONLY in EvtxECmd's raw `Payload` JSON blob (EventData),
# NOT in the truncated PayloadData1-6 columns. For these we parse the blob and lift the
# named fields into payload so the analyst/LLM actually sees threat names, script text,
# service image paths, etc. Everything else keeps the lean PayloadData-only mapping.
_HIGH_VALUE_EIDS = {
    1006, 1007, 1008, 1009, 1015, 1116, 1117, 1118, 1119,  # Defender malware detections
    5001, 5007, 5010, 5012,                                 # Defender config/tamper
    4103, 4104,                                             # PowerShell module/scriptblock
    4688,                                                   # process creation
    7045, 7040,                                             # service install / start-type change
    4720, 4722, 4724, 4726, 4728, 4732, 4738, 4756,        # account & group changes
    4698, 4699, 4702,                                       # scheduled tasks
    1149,                                                   # RDP auth
    21, 22, 23, 24, 25, 39, 40,                             # TS LocalSessionManager: User, SessionID, Address
    106, 140, 141, 200, 201,                                # TaskScheduler operational: TaskName, UserContext
}
# small EIDs collide across providers: lift them only from the channel they belong to
_CHANNEL_SCOPED_EIDS = {21: 'terminalservices', 22: 'terminalservices', 23: 'terminalservices', 24: 'terminalservices',
                        25: 'terminalservices', 39: 'terminalservices', 40: 'terminalservices',
                        106: 'taskscheduler', 140: 'taskscheduler', 141: 'taskscheduler', 200: 'taskscheduler', 201: 'taskscheduler'}
# per-field length caps (script text needs room; everything else stays small)
_EVTDATA_LONG_KEYS = {'scriptblocktext', 'commandline', 'imagepath', 'newvalue', 'oldvalue'}


def _flatten_eventdata(raw):
    """Parse an EvtxECmd 'Payload' JSON string → {FieldName: text}.

    EvtxECmd emits ``{"EventData":{"Data":[{"@Name":"X","#text":"Y"}, ...]}}`` (or a
    single dict, or bare strings). Returns a flat dict of the named fields; pure and
    exception-safe (bad/absent blob → empty dict)."""
    try:
        obj = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        return {}
    if not isinstance(obj, dict):
        return {}
    out = {}
    container = obj.get('EventData') or obj.get('UserData') or {}
    # UserData.EventXML{User,SessionID,Address} (TerminalServices) — one nested dict level
    if isinstance(container, dict) and 'Data' not in container:
        _inner = [v for v in container.values() if isinstance(v, dict)]
        if len(_inner) == 1 and all(not isinstance(x, (dict, list)) for x in _inner[0].values()):
            return {str(k).lstrip('@#'): str(v) for k, v in _inner[0].items() if v not in (None, '')}
    if not isinstance(container, dict):
        return {}
    data = container.get('Data')
    if isinstance(data, dict) and '@Name' in data:
        data = [data]
    if isinstance(data, dict):
        data = [data]
    if isinstance(data, list):
        for i, item in enumerate(data):
            if isinstance(item, dict):
                name = item.get('@Name') or item.get('Name')
                text = item.get('#text')
                if name is not None and text is not None:
                    out[str(name)] = str(text)
                elif text is not None:
                    out[f'Data{i}'] = str(text)
            elif isinstance(item, str):
                out[f'Data{i}'] = item
    elif isinstance(data, str):
        out['Data'] = data
    # UserData/other single-level named children (e.g. TaskScheduler EventData)
    for k, v in container.items():
        if k == 'Data':
            continue
        if isinstance(v, (str, int, float)):
            out.setdefault(str(k), str(v))
    return out


_KAPE_FOLDERS = frozenset((
    'motw', 'live', 'communications', 'eventlogs', 'accountusage', 'remoteaccess',
    'forensictimeliner', 'webbrowsers', 'filesystem', 'programexecution',
    'srumdatabase', 'filedeletion', 'filefolderaccess', 'registry', 'iocs',
    'sumdatabase', 'sqldatabases',
))


def _kape_folder(parts):
    """The KAPE folder a file belongs to, tolerating a wrapper directory.

    Archives packed as `<case name>/EventLogs/x.csv` used to classify by the case name.
    Returns the first segment that is a real KAPE folder, else the old parts[0].
    """
    for p in parts[:-1]:
        if p in _KAPE_FOLDERS:
            return p
    return parts[0] if len(parts) > 1 else ''


def is_motw_csv(rel_path):
    """True if ``rel_path`` is a MOTW / :Zone.Identifier collector CSV.

    Recognised: any CSV under a ``motw/`` folder, or a ``*zone_identifier*`` /
    ``*motw*`` CSV under the existing ``webbrowsers/`` folder. Module-level and
    pure so the classify routing decision is unit-testable.
    """
    parts = str(rel_path).lower().replace('\\', '/').split('/')
    folder = parts[0] if len(parts) > 1 else ''
    name = parts[-1]
    if not name.endswith('.csv'):
        return False
    if folder == 'motw':
        return True
    if folder == 'webbrowsers' and ('zone_identifier' in name or 'zoneidentifier' in name or 'motw' in name):
        return True
    return False


def _motw_pick(row, keys):
    """Case-insensitive, whitespace-tolerant column lookup for MOTW CSV rows."""
    norm = {(str(k).strip().lower() if k is not None else ''): v for k, v in (row or {}).items()}
    for k in keys:
        v = norm.get(k.lower())
        if v is not None and str(v).strip() != '':
            return str(v).strip()
    return ''


def motw_row_to_fields(row):
    """Map one MOTW / :Zone.Identifier collector CSV row to filesystem_v2 fields.

    This is the module-level, pure transform behind the nested ``map_motw`` mapper,
    exposed so ``test_motw_parse.py`` can exercise the exact production logic.

    Expected (case-insensitive) collector columns:
      Path / File / FullPath  — full path of the downloaded file (the host file the ADS hangs off)
      ZoneId / Zone           — MOTW zone number (3 = Internet, 4 = Restricted)
      HostUrl                 — direct download URL (where the file came from)
      ReferrerUrl             — page the download was initiated from
      Timestamp / Created     — (optional) when the ADS / file was written

    Returns ``(file_name, extension, parent_path, zone_id_text, ts_raw)`` or
    ``None`` when the row carries no provenance (no HostUrl and no ReferrerUrl) —
    mirroring the ``map_fs_mft`` guard so empty ADS rows are not stored.

    ``zone_id_text`` reconstructs the raw :Zone.Identifier ADS body so the data is
    queryable by the EXISTING consumers, which read
    ``filesystem_v2.payload->>'zone_id'`` with regex ``HostUrl=([^\\r\\n]+)`` /
    ``ReferrerUrl=([^\\r\\n]+)`` and filter on ``extension='identifier'``.
    Generic — no case-specific values.
    """
    full = _motw_pick(row, ['Path', 'File', 'FullPath', 'FilePath', 'TargetPath'])
    zone = _motw_pick(row, ['ZoneId', 'Zone', 'ZoneIdValue'])
    host = _motw_pick(row, ['HostUrl', 'Host'])
    ref = _motw_pick(row, ['ReferrerUrl', 'Referrer'])
    ts_raw = _motw_pick(row, ['Timestamp', 'TimeStamp', 'Created', 'CreationTime', 'LastWriteTime'])

    if not host and not ref:
        return None  # no provenance to mine — skip (mirror map_fs_mft ZoneIdContents guard)

    norm_path = full.replace('\\', '/').rstrip('/')
    base = norm_path.split('/')[-1] if norm_path else ''
    parent = norm_path.rsplit('/', 1)[0] if '/' in norm_path else ''
    # file_name keeps the real extension + ':Zone.Identifier' suffix so the consumers'
    # suspicious-archive ordering regex (\.exe|\.zip…) matches and ':Zone.Identifier'
    # stripping displays cleanly — exactly like MFTECmd-native ADS rows.
    file_name = (base + ':Zone.Identifier') if base else 'Zone.Identifier'
    extension = 'identifier'  # load-bearing: consumers filter WHERE extension='identifier'

    lines = ['[ZoneTransfer]']
    if zone:
        lines.append('ZoneId=' + zone)
    if host:
        lines.append('HostUrl=' + host)
    if ref:
        lines.append('ReferrerUrl=' + ref)
    zone_id_text = '\r\n'.join(lines)

    return (file_name, extension, parent or None, zone_id_text, ts_raw or None)


def is_hindsight_file(rel_path):
    """True if ``rel_path`` is a Hindsight (ObsidianForensics) JSONL export.

    Hindsight's ``Hindsight_output.jsonl`` lands in the KAPE ``WebBrowsers`` folder
    next to the per-browser CSVs. Recognised: any ``*hindsight*.jsonl`` under the
    ``webbrowsers/`` folder. Module-level + pure so the routing decision is
    unit-testable. ADDITIVE — ``.jsonl`` is invisible to every existing collection
    (csv/json/thor/loki/regripper), so existing browser/MOTW routing is untouched.
    """
    parts = str(rel_path).lower().replace('\\', '/').split('/')
    folder = parts[0] if len(parts) > 1 else ''
    name = parts[-1]
    if folder != 'webbrowsers':
        return False
    if 'hindsight' not in name:
        return False
    return name.endswith('.jsonl')


def _hpick(obj, keys):
    """Case-insensitive, whitespace-tolerant key lookup for a Hindsight JSON record.

    Hindsight field names vary across versions / export formats (``row_type`` vs
    ``type``, ``host_key`` vs ``host``, ``full_path`` vs ``target_path`` …), so every
    field is resolved through an alias list — mirroring ``_motw_pick``.
    """
    norm = {(str(k).strip().lower() if k is not None else ''): v for k, v in (obj or {}).items()}
    for k in keys:
        v = norm.get(k.lower())
        if v is not None and str(v).strip() != '':
            return v
    return None


_HS_URL_RE = _re.compile(r'https?://[^\s"\'<>]+')


def hindsight_record_to_fallback(obj):
    """Map one Hindsight JSONL record to a ``(parser_family, payload)`` pair.

    Pure transform behind the Hindsight ingest pass, exposed module-level so
    ``test_hindsight_parse.py`` exercises the EXACT production logic. The payload
    keys are chosen to match what the bot's EXISTING browser consumers already read
    from ``raw_fallback_v2`` (so no new consumer code is needed):

      ``browser_downloads`` →  url, target_path, current_path, filename, end_time,
                               received_bytes, total_bytes, referrer
        (consumed by agent_tools.py get_browser_downloads/get_browser_activity which
         read payload->>'url' / 'target_path' / 'current_path' / 'filename' /
         'end_time' / 'total_bytes' / 'received_bytes')
      ``browser_history``   →  url, title, last_visit_time, visit_count
      ``browser_misc``      →  host, url, name  (chat.py filters payload ? 'host')

    Routing by the record's type field (``row_type`` / ``type``), tolerant of the
    value variants Hindsight emits: ``url``, ``download``, ``cookie (accessed)`` /
    ``cookie (created)``. Returns ``None`` for unsupported types or rows with no
    useful data (never raised). Generic — no case-specific values.
    """
    if not isinstance(obj, dict):
        return None
    rtype = str(_hpick(obj, ['type', 'row_type', 'rowtype', 'record_type']) or '').strip().lower()
    if not rtype:
        return None
    url = _hpick(obj, ['url', 'URL'])

    # --- download → browser_downloads ------------------------------------------
    if 'download' in rtype:
        target = _hpick(obj, ['target_path', 'full_path', 'current_path', 'value', 'target path', 'path'])
        referrer = _hpick(obj, ['referrer', 'from', 'from_url', 'referring_url', 'tab_url'])
        interp = _hpick(obj, ['interpretation'])
        if not referrer and interp:  # Hindsight often records provenance in interpretation text
            m = _HS_URL_RE.search(str(interp))
            if m:
                referrer = m.group(0)
        rbytes = _hpick(obj, ['received_bytes', 'received bytes', 'bytes', 'size'])
        tbytes = _hpick(obj, ['total_bytes', 'total bytes'])
        end_ts = _hpick(obj, ['end_time', 'timestamp', 'start_time', 'datetime', 'date', 'time'])
        if not url and not target:
            return None  # nothing useful to mine
        payload = {}
        if url:
            payload['url'] = str(url)
        if target:
            tp = str(target)
            payload['target_path'] = tp
            payload['current_path'] = tp
            payload['filename'] = tp.replace('\\', '/').rstrip('/').split('/')[-1]
        if referrer:
            payload['referrer'] = str(referrer)
        if rbytes:
            payload['received_bytes'] = str(rbytes)
        if tbytes:
            payload['total_bytes'] = str(tbytes)
        if end_ts:
            ets = str(end_ts)
            payload['end_time'] = ets
            payload['start_time'] = ets  # chat.py / agent_tools.py read start_time too
        if interp:
            payload['interpretation'] = str(interp)[:500]
        return ('browser_downloads', payload)

    # --- cookie → browser_misc -------------------------------------------------
    if 'cookie' in rtype:
        host = _hpick(obj, ['host', 'host_key', 'domain'])
        name = _hpick(obj, ['name', 'cookie_name', 'key'])
        ts = _hpick(obj, ['timestamp', 'creation_utc', 'last_access_utc', 'datetime', 'date'])
        if not host and url:  # derive a host so the chat.py `payload ? 'host'` consumer sees it
            try:
                host = str(url).split('//', 1)[-1].split('/', 1)[0]
            except Exception:
                host = None
        if not host and not name:
            return None
        payload = {}
        if host:
            payload['host'] = str(host)
        if url:
            payload['url'] = str(url)
        if name:
            payload['name'] = str(name)
        if ts:
            payload['last_visit_time'] = str(ts)
        return ('browser_misc', payload)

    # --- visit / url → browser_history -----------------------------------------
    if 'url' in rtype or 'visit' in rtype or 'history' in rtype:
        if not url:
            return None
        title = _hpick(obj, ['title', 'name'])
        ts = _hpick(obj, ['timestamp', 'last_visit_time', 'visit_time', 'datetime', 'date', 'time'])
        vcount = _hpick(obj, ['visit_count', 'visits', 'visit count'])
        interp = _hpick(obj, ['interpretation'])
        payload = {'url': str(url)}
        if title:
            payload['title'] = str(title)
        if ts:
            payload['last_visit_time'] = str(ts)
        if vcount:
            payload['visit_count'] = str(vcount)
        if interp:
            payload['interpretation'] = str(interp)[:500]
        return ('browser_history', payload)

    return None  # unsupported type (autofill, local storage, …) — skip gracefully


# === registry-hive ASEP helper (inserted before _ensure_minimal_ingest_from_zip) ===
_REG_SOFTWARE_ASEP = [
    r'\Microsoft\Windows\CurrentVersion\Run',
    r'\Microsoft\Windows\CurrentVersion\RunOnce',
    r'\Microsoft\Windows\CurrentVersion\RunServices',
    r'\Microsoft\Windows\CurrentVersion\RunServicesOnce',
    r'\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    r'\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    r'\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    r'\Microsoft\Windows NT\CurrentVersion\Winlogon',
    r'\Microsoft\Windows NT\CurrentVersion\Windows',
]
_REG_NTUSER_ASEP = [
    r'\Software\Microsoft\Windows\CurrentVersion\Run',
    r'\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    r'\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    r'\Software\Microsoft\Windows NT\CurrentVersion\Windows',
]
_REG_IFEO = r'\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
_REG_SVC_PATHS = [r'\ControlSet001\Services', r'\ControlSet002\Services', r'\CurrentControlSet\Services']
_REG_WINLOGON_KEEP = ('shell', 'userinit', 'taskman', 'appsetup', 'vmapplet', 'system')
_REG_SVC_STD_RE = _re.compile(
    r'(system32|syswow64|\\windows\\|program files|windows defender|servicing|'
    r'\\systemroot\\|microsoft\.net|\\framework)', _re.I)
_REG_SEP = chr(92)  # backslash


def _reg_val(v):
    if isinstance(v, dict):
        return v.get('name'), v.get('value')
    return getattr(v, 'name', None), getattr(v, 'value', None)


def _parse_registry_hives(zf, raw_names, case_key):
    """Parse _raw/registry SOFTWARE/SYSTEM/NTUSER hives for autostart/persistence keys.
    Returns raw_fallback_v2 rows (parser_family='registry') that detect_threats #16 + the LLM mine."""
    try:
        import tempfile as _tf
        from regipy.registry import RegistryHive as _RH
    except Exception:
        return []
    rows = []

    def _emit(kind, key_path, name, data, src):
        txt = (str(key_path) + _REG_SEP + str(name or '') + ' = ' + str(data or ''))[:1200]
        rows.append((case_key, 'registry', src,
                     Json({'artifact': 'registry_asep', 'kind': kind, 'key_path': str(key_path),
                           'value_name': str(name or ''), 'value_data': str(data or '')[:800], 'text': txt})))

    def _hive_path(b):
        tf = _tf.NamedTemporaryFile(delete=False, suffix='.hive')
        tf.write(b)
        tf.close()
        return tf.name

    for n in raw_names:
        base = n.replace(_REG_SEP, '/').rsplit('/', 1)[-1].upper()
        try:
            hb = zf.read(n)
        except Exception:
            continue
        if not hb:
            continue
        is_soft = (base == 'SOFTWARE')
        is_ntuser = base.startswith('NTUSER')
        is_system = (base == 'SYSTEM')
        is_usrclass = base.startswith('USRCLASS')
        if not (is_soft or is_ntuser or is_system or is_usrclass):
            continue
        path = _hive_path(hb)
        if is_ntuser or is_usrclass:
            # per-user activity: what was opened, typed, run, mounted, RDP'd to
            try:
                from parsers.reg_user_activity import parse_user_hive
                for _p in parse_user_hive(path, 'ntuser' if is_ntuser else 'usrclass', n):
                    rows.append((case_key, 'registry', n, Json(_p)))
            except Exception:
                pass
        try:
            hive = _RH(path)
            if is_soft or is_ntuser:
                for kp in (_REG_SOFTWARE_ASEP if is_soft else _REG_NTUSER_ASEP):
                    try:
                        key = hive.get_key(kp)
                    except Exception:
                        continue
                    is_winlogon = 'winlogon' in kp.lower()
                    try:
                        for v in key.get_values():
                            nm, dv = _reg_val(v)
                            if dv in (None, '') and not is_winlogon:
                                continue
                            if is_winlogon and str(nm or '').lower() not in _REG_WINLOGON_KEEP:
                                continue
                            _emit('winlogon' if is_winlogon else 'run', kp, nm, dv, n)
                    except Exception:
                        pass
                if is_soft:
                    try:
                        ifeo = hive.get_key(_REG_IFEO)
                        for sk in ifeo.iter_subkeys():
                            for v in sk.get_values():
                                nm, dv = _reg_val(v)
                                if str(nm or '').lower() in ('debugger', 'globalflag', 'monitorprocess'):
                                    _emit('ifeo', 'IFEO' + _REG_SEP + str(sk.name), nm, dv, n)
                    except Exception:
                        pass
            elif is_system:
                for cs in _REG_SVC_PATHS:
                    try:
                        key = hive.get_key(cs)
                    except Exception:
                        continue
                    for sk in key.iter_subkeys():
                        try:
                            ip = ''
                            for v in sk.get_values():
                                nm, dv = _reg_val(v)
                                if nm == 'ImagePath':
                                    ip = str(dv or '')
                        except Exception:
                            continue
                        if ip and not _REG_SVC_STD_RE.search(ip):
                            _emit('service', cs + _REG_SEP + str(sk.name), 'ImagePath', ip, n)
                    break
        except Exception:
            pass
        finally:
            try:
                os.unlink(path)
            except Exception:
                pass
    return rows



# --- header-signature fallback (name-based routing first; this only sees what it missed) ---
# (kind, required lower-cased column names). Ordered most-specific first.
_HEADER_SIGNATURES = [
    ('fs_usn',               {'updatesequencenumber', 'updatereasons'}),
    ('fs_mft',               {'entrynumber', 'sequencenumber', 'parentpath', 'filename', 'inuse'}),
    ('event',                {'eventid', 'channel', 'provider', 'timecreated'}),
    ('pe_prefetch',          {'executablename', 'runcount', 'lastrun'}),
    ('fb_prefetch_timeline', {'runtime', 'executablename'}),
    ('pe_shimcache',         {'controlset', 'cacheentryposition', 'path'}),
    ('pe_amcache_prog',      {'programid', 'programname_name'}),
    ('pe_amcache',           {'fullpath', 'sha1', 'filekeylastwritetimestamp'}),
    ('srum_netusage',        {'exeinfo', 'bytesreceived', 'bytessent'}),
    ('srum_netconn',         {'exeinfo', 'connectstarttime'}),
    ('srum_appres',          {'exeinfo', 'foregroundcycletime'}),
    ('fb_jumplists',         {'appid', 'appiddescription'}),
    ('fb_lnk',               {'targetcreated', 'localpath', 'sourcefile'}),
    ('fb_recyclebin',        {'deletedon', 'filesize', 'filename'}),
    ('fb_registry',          {'hivepath', 'keypath', 'valuename'}),
    ('hayabusa_alert',       {'ruletitle', 'level', 'computer'}),
]


def sniff_kind_by_header(header_line):
    """Map a CSV header line to a router kind by its column set, or None when no signature fits."""
    if not header_line:
        return None
    cols = set()
    for c in str(header_line).lstrip('\ufeff').strip().split(','):
        c = c.strip().strip('"').strip().lower()
        if c:
            cols.add(c)
    if len(cols) < 2:
        return None
    for kind, need in _HEADER_SIGNATURES:
        if need <= cols:
            return kind
    return None


def _sniff_member_kind(zf, rel_path):
    """Read the first line of a zip member and route it by header; None on any failure."""
    try:
        with zf.open(rel_path, 'r') as bf:
            head = bf.read(8192)
        line = head.decode('utf-8-sig', 'ignore').split('\n', 1)[0].split('\r', 1)[0]
        return sniff_kind_by_header(line)
    except Exception:
        return None


_LOGON_TYPE_RE = _re.compile(r'LogonType\s*[:=]?\s*(\d{1,2})\b')


_LOGON_TYPE_WORDS = (
    ('remote interactive', '10'), ('rdp', '10'), ('cached', '11'), ('unlock', '7'), ('cleartext', '8'),
    ('new credentials', '9'), ('network', '3'), ('batch', '4'), ('service', '5'), ('console', '2'), ('interactive', '2'),
)


def logon_type_of(row):
    """LogonType from a column when present (descriptive words from older EvtxECmd maps are mapped
    to the numeric type), else from EvtxECmd PayloadData1..6 («LogonType 10»)."""
    v = _pick(row, ['LogonType', 'Logon Type'])
    if v not in (None, ''):
        vs = str(v).strip()
        if vs.isdigit():
            return vs
        low = vs.lower()
        for word, num in _LOGON_TYPE_WORDS:
            if word in low:
                return num
        return vs
    for k in ('PayloadData2', 'PayloadData1', 'PayloadData3', 'PayloadData4', 'PayloadData5', 'PayloadData6'):
        m = _LOGON_TYPE_RE.search(str(row.get(k) or ''))
        if m:
            return m.group(1)
    return None


def _ensure_minimal_ingest_from_zip(case_key, st=None):
    # ensure case exists (FK target)
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("INSERT INTO cases(case_key, case_name) VALUES(%s,%s) ON CONFLICT (case_key) DO NOTHING", (case_key, case_key.replace('_',' ')))
            conn.commit()

    zips = sorted(glob(os.path.join(CASE_LIB, case_key, 'uploads', 'logs', '*.zip')))
    if not zips:
        return {'ok': False, 'error': 'logs zip not found'}
    zip_path = zips[-1]

    # CRASH-SAFE MARKER: open an ingest_jobs row = 'running'. If the container is
    # restarted mid-ingest, this row stays 'running' with finished_at NULL → the
    # coverage self-check treats the case as INCOMPLETE (no silent partial ingest).
    _ingest_job_id = None
    try:
        with psycopg2.connect(PG_DSN) as _jc:
            _jc.autocommit = True
            with _jc.cursor() as _jcur:
                _jcur.execute("UPDATE ingest_jobs SET status='superseded' WHERE case_key=%s AND status='running'", (case_key,))
                _jcur.execute("""INSERT INTO ingest_jobs(case_key, source_zip_path, status, started_at)
                    VALUES(%s,%s,'running',now()) RETURNING job_id""", (case_key, zip_path))
                _ingest_job_id = _jcur.fetchone()[0]
    except Exception:
        _ingest_job_id = None

    BATCH = int(os.getenv('BOOTSTRAP_BATCH_SIZE', '2000'))

    # Folder-aware classification. Folder names from KAPE are static even though
    # file names change (timestamps prefix). Route by folder + filename suffix.
    # Supports both default KAPE output and extended KAPE with Hayabusa/THOR/LOKI/
    # ForensicTimeliner/logparser/RECmd batches/browser forensics.
    def classify(rel_path):
        parts = rel_path.lower().replace('\\', '/').split('/')
        folder = _kape_folder(parts)
        name = parts[-1]

        # MOTW / :Zone.Identifier provenance (webbrowsers/ or motw/ folder) →
        # filesystem_v2 (extension='identifier') so existing HostUrl/ReferrerUrl
        # consumers mine it. Checked first so it pre-empts browser suffix rules.
        if is_motw_csv(rel_path):
            return 'fs_motw'

        # --- the collector's own analytic outputs (see INTEGRATION_CONTRACT.md) ---
        # These are finished lead lists, not raw artefacts, so each gets its own family
        # instead of being swallowed by a generic fallback.
        if name == 'autoruns.csv':
            # persistence entry points (SysInternals Autorunsc, LIVE+FULL only)
            return 'fb_autoruns'
        if name == 'ads_streams.csv':
            # non-standard alternate data streams on the target disk (collector v4.9+); the
            # stream bytes sit beside it in ads/NNNN.bin and are read by the ADS pass below
            return 'fb_ads_streams'
        if len(parts) > 1 and parts[-2] == 'ads' and re.match(r'^\d{4}\.bin$', name):
            return None
        if name == 'encrypted_files.csv':
            # dormant encryption on the TARGET disk: containers, encrypted archives/docs.
            # Produced for BOTH live and mounted-image runs since collector v2.3.
            return 'fb_encrypted_files'
        if name == 'execution_findings.csv':
            # our own ShimCache/Amcache/Prefetch analysis; every row carries when_kind,
            # so the report can say whether a timestamp is a real execution
            return 'fb_execution_findings'
        if name == '_collector_footprint.csv':
            # what the collector itself touched, declared so the next examiner can
            # subtract it instead of following it
            return 'fb_collector_footprint'
        if name in ('suspicious_files.txt', 'suspicious_files.csv'):
            # The collector writes the .txt form (vao_collect_all.ps1); the .csv name was
            # here first and never appeared in an archive. Both go to the same family so
            # the finding survives whichever the collector emits.
            return 'fb_suspicious_files'

        if name == 'execution_findings.txt':
            # Skipped deliberately: execution_findings.csv sits beside it with the same
            # findings and is ingested above. Two copies would double-count them.
            return None

        if name == 'hashes.csv':
            # Read by its own pass (file_hashes + offline reputation). The root catch-all
            # below would store it a second time as fb_other_root.
            return None

        if name == 'filesystem_tree.txt':
            # A full directory listing of the examined drive - tens of megabytes of text.
            # It belongs in a file the analyst can open, not as a million rows nobody
            # queries. Kept in the case library; see the case assets endpoint.
            return None

        if name == 'suspicious_files.csv':
            # machine-readable twin of suspicious_files.txt: 13 MFT-based signals
            return 'fb_suspicious_files'
        if name == 'encryption_status.csv':
            # ACTIVE disk encryption of the machine the collector ran on (LIVE only)
            return 'fb_encryption_status'

        # --- collector v4.0 (native C#) artefacts, INTEGRATION_CONTRACT.md §6 ---
        if name == 'environment_restrictions.csv':
            # what the target machine blocks: cmd.exe, .ps1 files (GPO), PowerShell
            # language mode, antivirus. Evidence in itself — a disabled cmd.exe that
            # the administrator says he never disabled was disabled by someone.
            return 'fb_environment'
        if name == 'collection_gaps.csv':
            # every step that did NOT run, and why. Without it a half-collected
            # archive reads as a complete one.
            return 'fb_collection_gaps'
        if name == 'defender_exclusions.csv':
            # Defender exclusions as tampering evidence. Matched BEFORE the
            # folder=='live' rule, which would otherwise bury it in fb_live_network.
            return 'fb_defender_exclusions'
        if name == 'ram_capture.csv':
            # manifest of the memory capture (tool, size, hash) or the honest reason
            # there is none. Lives in memory/ of the output archive.
            return 'fb_ram_capture'
        if name == 'encryption_status_examiner.csv':
            # the EXAMINER's own workstation in image mode. Deliberately dropped:
            # it must never reach the case conclusions.
            return None

        if folder == 'live':
            # live network snapshot (collector live mode): netstat/dns CSV ->
            # raw_fallback_v2 so the existing network/RDP/firewall/ngrok miners pick
            # it up. TXT files (hosts/firewall/arp/ipconfig) -> live-network TXT pass.
            if name.endswith('.csv'):
                return 'fb_live_network'
            return None

        if folder == 'communications':
            # email + messenger extraction produced by the collector's «Комунікації»
            # step -> communications_v1 (identifiers + conversations). See [[comms-extraction]].
            if name.endswith('.csv'):
                return 'communications'
            return None

        if folder == 'eventlogs':
            if 'evtxecmd_output.csv' in name:
                return 'event'
            # Hayabusa full event feed → alert table only (no event_logs_v2 insert)
            if 'hayabusa_events_offline' in name and name.endswith('.csv'):
                return 'hayabusa_alert'
            # Hayabusa logon summary CSVs → fallback (summary statistics)
            if 'hayabusa_logon_summary' in name and name.endswith('.csv'):
                return 'fb_hayabusa_summary'
            # Focused detection CSVs from Hayabusa/chainsaw-style reports + sigma
            if any(x in name for x in [
                'account_tampering', 'lateral_movement', 'login_attacks',
                'rdp_attacks', 'rdp_events', 'service_installation',
                'powershell_script', 'antivirus', 'sigma.csv',
                'log_tampering.csv',
                'applocker', 'credential_access', 'defense_evasion',
                'service_tampering', 'microsoft_rasvpn',
            ]):
                return 'dfir_alert'
            # Microsoft RDS events → fallback
            if 'microsoft_rds' in name and name.endswith('.csv'):
                return 'fb_rds_events'
            # hayabusa_event_statistics.csv → skip (aggregate counts, not events)
            if name.endswith('.csv') and 'event_statistics' not in name:
                return 'fb_other_eventlogs'
            return None

        if folder == 'accountusage':
            # logparser logon/logoff CSV → event_logs_v2
            if name.endswith('.csv'):
                return 'logon_logoff'
            return None

        if folder == 'remoteaccess':
            if 'rdp' in name and name.endswith('.csv'):
                return 'rdp_usage'
            if 'smb' in name and name.endswith('.csv'):
                return 'smb_logon'
            return None

        if folder == 'forensictimeliner':
            if name.endswith('.csv'):
                return 'fb_forensictimeline'
            return None

        if folder == 'webbrowsers':
            if 'history' in name and name.endswith('.csv'):
                return 'fb_browser_history'
            if 'downloads' in name and name.endswith('.csv'):
                return 'fb_browser_downloads'
            if 'searches' in name and name.endswith('.csv'):
                return 'fb_browser_searches'
            if name.endswith('.csv'):
                return 'fb_browser_misc'
            return None

        if folder == 'filesystem':
            if 'mftecmd_$mft_output.csv' in name:
                return 'fs_mft'
            if 'mftecmd_$j_output.csv' in name:
                return 'fs_usn'
            # $Boot and $SDS not useful for DFIR analysis
            return None

        # BAM/DAM: the Background Activity Moderator records a REAL last-run time per
        # user SID. RECmd writes it as *_BamDam_*.csv, usually into the Registry folder,
        # so match by NAME and before the folder rules.
        if 'bamdam' in name and name.endswith('.csv'):
            return 'pe_bam'

        if folder == 'programexecution':
            if 'pecmd_output_timeline' in name and name.endswith('.csv'):
                return 'fb_prefetch_timeline'
            if 'pecmd_output.csv' in name and 'timeline' not in name:
                return 'pe_prefetch'
            if 'amcache_associatedfileentries' in name:
                return 'pe_amcache'
            if 'amcache_unassociatedfileentries' in name:
                return 'pe_amcache'
            if 'amcache_programentries' in name:
                return 'pe_amcache_prog'
            if 'appcompatcache' in name:
                return 'pe_shimcache'
            if 'amcache_shortcuts' in name:
                return 'pe_amcache'
            # DriveBinaries: driver binaries w/ SHA1 (BYOVD evidence) -> raw_fallback
            if 'drivebinaries' in name and name.endswith('.csv'):
                return 'fb_amcache_drivers'
            # Skip: DeviceContainers, DevicePnps, DriverPackages — hardware noise
            return None

        if folder == 'srumdatabase':
            if 'networkconnections_output.csv' in name:
                return 'srum_netconn'
            if 'networkusages_output.csv' in name:
                return 'srum_netusage'
            if 'appresourceuseinfo_output.csv' in name:
                return 'srum_appres'
            if 'apptimelineprovider_output.csv' in name:
                return 'fb_srum_timeline'
            # Other SRUM tables (EnergyUsage, PushNotifications, vfuprov) — skip
            return None

        if folder == 'filedeletion':
            if 'rbcmd_output.csv' in name:
                return 'fb_recyclebin'
            return None

        if folder == 'filefolderaccess':
            if 'lecmd_output.csv' in name:
                return 'fb_lnk'
            if 'automaticdestinations.csv' in name:
                return 'fb_jumplists'
            if 'customdestinations.csv' in name:
                return 'fb_jumplists'
            if name.endswith('_ntuser.csv') or name.endswith('_usrclass.csv'):
                return 'fb_shellbags'
            if '_activity.csv' in name and 'packageids' not in name and 'operations' not in name:
                return 'fb_win_activity'
            if '_activity' in name and ('operations' in name or 'packageids' in name) and name.endswith('.csv'):
                return 'fb_win_activity_ops'
            return None

        # ShimCache (AppCompatCache from the SYSTEM hive) is written by RECmd into the
        # Registry folder on some layouts; matched by NAME before the folder rule, like BAM,
        # or the folder rule would file it as generic registry rows.
        if 'appcompatcache' in name and name.endswith('.csv'):
            return 'pe_shimcache'

        if folder == 'registry':
            # RECmd batch CSV output — any CSV in registry folder
            if name.endswith('.csv'):
                return 'fb_registry'
            # reg_hunter NDJSON — handled in separate JSON pass
            return None

        if folder == 'iocs':
            # THOR files_md5s.csv: md5,path,size (no header)
            if ('files_md5s' in name or 'thor_files' in name) and name.endswith('.csv'):
                return 'thor_md5'
            # THOR/LOKI text/html outputs handled in separate text pass
            return None

        # SumECmd output (KAPE SUMDatabase) - User Access Logging tables.
        # No dedicated schema yet -> route CSVs into raw_fallback_v2 via the
        # existing fb_* path so nothing is silently dropped (BACKLOG #27).
        if folder == 'sumdatabase':
            if name.endswith('.csv'):
                stem = name[:-4].split('_')[-1] or 'table'
                return 'fb_sum_' + stem
            return None

        # SQLECmd output (KAPE SQLDatabases) - parsed app SQLite DBs.
        if folder == 'sqldatabases':
            if name.endswith('.csv'):
                stem = name[:-4].split('_')[-1] or 'table'
                return 'fb_sql_' + stem
            return None

        # FILENAME FALLBACK (KAPE-layout robustness): a standard EZ-Tools output in an
        # UNRECOGNISED folder (raw KAPE !EZParser uses WebBrowser/SRUM/Registry/
        # FileFolderAccess vs the collector's webbrowsers/srumdatabase/...) is routed by
        # its STABLE filename to the right structured family, so ANY KAPE layout indexes
        # correctly instead of dropping to the generic raw fallback. Known folders already
        # returned above, so this only sees non-standard layouts.
        if name.endswith('.csv'):
            if 'mftecmd_$mft_output' in name: return 'fs_mft'
            if 'mftecmd_$j_output' in name: return 'fs_usn'
            if 'evtxecmd_output' in name: return 'event'
            if 'hayabusa_events_offline' in name: return 'hayabusa_alert'
            if 'pecmd_output_timeline' in name: return 'fb_prefetch_timeline'
            if 'pecmd_output' in name and 'timeline' not in name: return 'pe_prefetch'
            if 'appcompatcache' in name: return 'pe_shimcache'
            if 'amcache' in name and 'programentries' in name: return 'pe_amcache_prog'
            if ('amcache_associatedfileentries' in name or 'amcache_unassociatedfileentries' in name
                    or 'amcache_shortcuts' in name): return 'pe_amcache'
            if 'networkusages_output' in name: return 'srum_netusage'
            if 'networkconnections_output' in name: return 'srum_netconn'
            if 'appresourceuseinfo_output' in name: return 'srum_appres'
            if 'apptimelineprovider_output' in name: return 'fb_srum_timeline'
            if 'rbcmd_output' in name: return 'fb_recyclebin'
            if 'lecmd_output' in name: return 'fb_lnk'
            if 'automaticdestinations' in name or 'customdestinations' in name: return 'fb_jumplists'
            if 'recmd_' in name: return 'fb_registry'
            if 'history' in name: return 'fb_browser_history'
            if 'downloads' in name: return 'fb_browser_downloads'
            if 'searches' in name: return 'fb_browser_searches'

        # CATCH-ALL: a CSV in a non-root, UNRECOGNIZED folder -> raw_fallback so
        # non-standard / new log types are never silently dropped (LLM still mines
        # them). Known folders' own `return None` already exited classify above, so
        # intentional skips are unaffected. KAPE run metadata is excluded.
        # A CSV at the archive ROOT (folder == '') is caught too: the collector writes its
        # newest outputs there first (collection_gaps.csv, suspicious_files.csv), and an
        # output the bot has not been taught yet must still become searchable rows.
        if name.endswith('.csv'):
            _junk = ('consolelog', 'copylog', 'skiplog', '_log.csv', 'sha1')
            if not any(j in name for j in _junk):
                _fam = ''.join(c if c.isalnum() else '_' for c in folder)[:24] or 'root'
                return 'fb_other_' + _fam
        return None

    def classify_json(rel_path):
        """Classify JSON files for the separate NDJSON processing pass."""
        parts = rel_path.lower().replace('\\', '/').split('/')
        folder = _kape_folder(parts)
        name = parts[-1]
        if folder == 'registry' and name.startswith('reg_hunter_') and name.endswith('.json'):
            return 'reg_hunter'
        return None

    # -----------------------------------------------------------------------
    # Mapper functions — one per artifact type, filtered payload (no garbage)
    # -----------------------------------------------------------------------

    # EventLogs: EvtxECmd output
    # Garbage columns excluded from payload: ChunkNumber, HiddenRecord, Keywords,
    # ExtraDataOffset, Payload (full JSON blob — too large)
    _EVT_PAYLOAD_KEYS = {
        'Level', 'MapDescription', 'UserId', 'RecordNumber',
        'PayloadData1', 'PayloadData2', 'PayloadData3',
        'PayloadData4', 'PayloadData5', 'PayloadData6',
        'ProcessId', 'ThreadId',
    }

    def map_event(row, src):
        row = _clean_row(dict(row))
        eid = _pick(row, ['EventId', 'Event ID', 'EventID', 'Id'])
        try:
            eid = int(str(eid).strip()) if eid is not None else None
        except Exception:
            eid = None
        # Extract source file basename from full KAPE path (Windows backslashes)
        sf_raw = str(row.get('SourceFile') or '')
        sf = sf_raw.replace('\\', '/').split('/')[-1] if sf_raw else src
        # Payload: lean PayloadData fields by default; for high-value EIDs also lift the
        # full named fields out of the raw `Payload` blob (threat names, script text, ...).
        payload = {k: row[k] for k in _EVT_PAYLOAD_KEYS if row.get(k)}
        _cmdline = _pick(row, ['CommandLine', 'Command line', 'PayloadData4', 'PayloadData8', 'Message'])
        ed = {}
        _lift = eid in _HIGH_VALUE_EIDS
        if _lift and eid in _CHANNEL_SCOPED_EIDS:
            _chan = (str(row.get('Channel') or '') + ' ' + str(row.get('Provider') or '') + ' ' + sf).lower()
            _lift = _CHANNEL_SCOPED_EIDS[eid] in _chan
        if _lift and row.get('Payload'):
            ed = _flatten_eventdata(row.get('Payload'))
            for _k, _v in ed.items():
                if not _v:
                    continue
                _cap = 6000 if _k.lower() in _EVTDATA_LONG_KEYS else 1200
                if _k in payload:
                    # same name as an EvtxECmd column (ProcessId, ThreadId...): EvtxECmd's value is
                    # the logging process (4688: always 4 = System), EventData's is the real one
                    if str(payload[_k]) != str(_v):
                        payload['ed_' + _k] = _v[:_cap]
                    continue
                payload[_k] = _v[:_cap]
            # surface the real actionable text into the command_line column so
            # keyword/cmdline detectors (PowerShell obfuscation, cred-dump, service
            # image paths) can actually match on it — previously always empty here.
            if not _cmdline:
                _cmdline = (ed.get('ScriptBlockText') or ed.get('CommandLine')
                            or ed.get('ImagePath') or ed.get('Application') or None)
                if _cmdline:
                    _cmdline = str(_cmdline)[:6000]
        return (
            case_key,
            eid,
            _parse_ts(_pick(row, ['TimeCreated', 'TimeCreatedUtc', 'Timestamp', 'EventTime', 'DateTime'])),
            _pick(row, ['Channel', 'LogName']),
            _pick(row, ['Provider', 'ProviderName', 'Source']),
            _pick(row, ['Computer', 'ComputerName', 'Hostname']),
            (_pick(row, ['RemoteHost', 'IpAddress', 'SourceIP', 'WorkstationName'])
             or ed.get('Address') or ed.get('IpAddress') or ed.get('SourceNetworkAddress') or ed.get('ClientAddress') or None),
            (_pick(row, ['UserName', 'TargetUserName', 'User', 'AccountName'])
             or ed.get('User') or ed.get('TargetUserName') or ed.get('UserName') or ed.get('UserContext') or None),
            logon_type_of(row),
            _pick(row, ['ExecutableInfo', 'Image', 'NewProcessName', 'ProcessName']),
            _cmdline,
            Json(payload),
            sf,
        )

    def map_alert(row, src, tool_hint='kape'):
        row = _clean_row(dict(row))
        sev = str(_pick(row, ['Level', 'level', 'Severity', 'severity', 'risk', 'Risk']) or '').strip().lower() or 'medium'
        rule = str(_pick(row, ['RuleTitle', 'Rule Name', 'Rule', 'rule', 'Title', 'title']) or '').strip()
        details = str(_pick(row, ['Message', 'Details', 'details', 'Description', 'CommandLine']) or '')[:2000]
        ioc = str(_pick(row, ['IoC', 'IOC', 'Indicator', 'Value', 'TargetFileName', 'FilePath']) or '').strip()
        comp = str(_pick(row, ['Computer', 'ComputerName', 'Hostname']) or '').strip()
        user = str(_pick(row, ['User', 'UserName', 'TargetUserName']) or '').strip()
        ts = _parse_ts(_pick(row, ['Timestamp', 'TimeCreated', 'DateTime', 'EventTime']))
        return (
            case_key, tool_hint, sev or None, rule or None, ts,
            comp or None, user or None, ioc or None, details or None,
            src, Json({'level': row.get('Level'), 'channel': row.get('Channel')}),
        )

    # MFT ($MFT) — columns: FileName, Extension, ParentPath, Created0x10,
    #   LastModified0x10, LastAccess0x10, FileSize, IsDirectory, InUse, SiFlags, ZoneIdContents
    # Garbage: all SequenceNumber, ReferenceCount, UpdateSequenceNumber, LogfileSequenceNumber,
    #   SecurityId, ObjectIdFileDroid, LoggedUtilStream, Created0x30/LastModified0x30 (FN timestamps)
    def map_fs_mft(row, src):
        row = _clean_row(dict(row))
        fn = str(row.get('FileName') or '')
        ext = str(row.get('Extension') or '').lstrip('.').lower()
        parent = str(row.get('ParentPath') or '')
        ts = _parse_ts(row.get('Created0x10'))
        payload = {}
        if row.get('FileSize'): payload['file_size'] = row['FileSize']
        if row.get('InUse'): payload['in_use'] = row['InUse']
        if row.get('IsDirectory'): payload['is_dir'] = row['IsDirectory']
        if row.get('SiFlags'): payload['si_flags'] = row['SiFlags']
        if row.get('LastModified0x10'): payload['last_modified'] = row['LastModified0x10']
        if row.get('LastAccess0x10'): payload['last_access'] = row['LastAccess0x10']
        if row.get('ZoneIdContents'): payload['zone_id'] = row['ZoneIdContents']
        if row.get('EntryNumber'): payload['entry'] = row['EntryNumber']
        _t = lambda k: str(row.get(k) or '').strip().lower() == 'true'
        if _t('SI<FN'):
            # $STANDARD_INFORMATION earlier than $FILE_NAME = classic timestomp; keep the FN times
            payload['si_lt_fn'] = True
            if row.get('Created0x30'): payload['created_fn'] = row['Created0x30']
            if row.get('LastModified0x30'): payload['modified_fn'] = row['LastModified0x30']
        if _t('uSecZeros'): payload['usec_zeros'] = True
        if _t('Copied'): payload['copied'] = True
        if _t('HasAds'): payload['has_ads'] = True
        if _t('IsAds'): payload['is_ads'] = True
        return (case_key, ts, fn or None, ext or None, parent or None, 'MFT', src, Json(payload))

    # USN Journal ($J) — columns: Name, Extension, ParentPath, UpdateTimestamp,
    #   UpdateReasons, FileAttributes
    def map_fs_usn(row, src):
        row = _clean_row(dict(row))
        fn = str(row.get('Name') or '')
        ext = str(row.get('Extension') or '').lstrip('.').lower()
        parent = str(row.get('ParentPath') or '')
        ts = _parse_ts(row.get('UpdateTimestamp'))
        action = str(row.get('UpdateReasons') or 'USN')
        payload = {}
        if row.get('FileAttributes'): payload['file_attrs'] = row['FileAttributes']
        if row.get('EntryNumber'): payload['entry_number'] = row['EntryNumber']
        return (case_key, ts, fn or None, ext or None, parent or None, action, src, Json(payload))

    # MOTW / :Zone.Identifier collector CSV → filesystem_v2 (extension='identifier').
    # Feeds the SAME storage the zone_identifier consumers already mine
    # (payload->>'zone_id' regex HostUrl=/ReferrerUrl=). See motw_row_to_fields().
    def map_motw(row, src):
        fields = motw_row_to_fields(_clean_row(dict(row)))
        if not fields:
            return None
        file_name, ext, parent, zone_id_text, ts_raw = fields
        ts = _parse_ts(ts_raw) if ts_raw else None
        return (case_key, ts, file_name, ext, parent, 'MOTW', src, Json({'zone_id': zone_id_text}))

    # Prefetch (PECmd) — columns: ExecutableName, Hash, RunCount, LastRun,
    #   PreviousRun0..6, SourceFilename
    def map_pe_prefetch(row, src):
        row = _clean_row(dict(row))
        exe = str(row.get('ExecutableName') or '')
        ts = _parse_ts(row.get('LastRun'))
        prev = [str(row[f'PreviousRun{i}']) for i in range(7)
                if row.get(f'PreviousRun{i}') and str(row[f'PreviousRun{i}']).strip()]
        payload = {}
        if row.get('RunCount'): payload['run_count'] = row['RunCount']
        if prev: payload['prev_runs'] = prev
        if row.get('Hash'): payload['pf_hash'] = row['Hash']
        loaded = str(row.get('FilesLoaded') or '')
        full = None
        if loaded and exe:
            for _f in loaded.split(','):
                _f = _f.strip()
                if _f.lower().endswith('\\' + exe.lower()):
                    full = _f
                    break
        if loaded: payload['files_loaded'] = loaded[:4000]
        if row.get('Directories'): payload['dirs_n'] = len(str(row['Directories']).split(','))
        if row.get('Volume0Serial'): payload['vol_serial'] = row['Volume0Serial']
        if row.get('Volume0Name'): payload['vol_name'] = row['Volume0Name']
        return (case_key, ts, exe or None, full, None, src, Json(payload))

    # Amcache AssociatedFileEntries — SHA1, FullPath, Name, LinkDate,
    #   FileKeyLastWriteTimestamp, ApplicationName, ProductName, Size, Version
    def map_pe_amcache(row, src):
        row = _clean_row(dict(row))
        full_path = str(row.get('FullPath') or row.get('Path') or '')
        exe = os.path.basename(full_path) if full_path else str(row.get('Name') or '')
        sha1 = str(row.get('SHA1') or '')
        sha1 = sha1 if len(sha1) == 40 else None
        ts = _parse_ts(row.get('FileKeyLastWriteTimestamp') or row.get('LinkDate'))
        payload = {}
        if row.get('ApplicationName'): payload['app_name'] = row['ApplicationName']
        if row.get('ProductName'): payload['product'] = row['ProductName']
        if row.get('Size'): payload['size'] = row['Size']
        if row.get('Version'): payload['version'] = row['Version']
        if row.get('LinkDate'): payload['link_date'] = row['LinkDate']
        return (case_key, ts, exe or None, full_path or None, sha1, src, Json(payload))

    # Amcache ProgramEntries — Name, RootDirPath, KeyLastWriteTimestamp,
    #   Publisher, Version, InstallDate, UninstallString, Type
    def map_pe_amcache_prog(row, src):
        row = _clean_row(dict(row))
        name = str(row.get('Name') or '')
        root = str(row.get('RootDirPath') or '')
        ts = _parse_ts(row.get('KeyLastWriteTimestamp') or row.get('InstallDate'))
        payload = {}
        if row.get('Publisher'): payload['publisher'] = row['Publisher']
        if row.get('Version'): payload['version'] = row['Version']
        if row.get('InstallDate'): payload['install_date'] = row['InstallDate']
        if row.get('Type'): payload['type'] = row['Type']
        if row.get('UninstallString'): payload['uninstall'] = row['UninstallString']
        return (case_key, ts, name or None, root or None, None, src, Json(payload))

    # BAM/DAM — Program, BatchKeyPath (…\UserSettings\<SID>), ExecutionTime
    # Unlike ShimCache this IS an execution time, so it lands in program_exec_v2 with the
    # source preserved; the report labels it accordingly.
    def map_pe_bam(row, src):
        row = _clean_row(dict(row))
        prog = str(row.get('Program') or row.get('BatchValueName') or '')
        if not prog:
            return None
        # \Device\HarddiskVolume3\Windows\... -> \Windows\... (volume letter unknown
        # offline; keeping the raw form in payload so nothing is lost)
        norm = re.sub(r'^\\Device\\HarddiskVolume\d+', '', prog)
        # executable_name here carries the FULL path ON PURPOSE: every other
        # program_exec_v2 mapper (amcache/shimcache) ends up storing the whole windows
        # path in this column, and 29 consumer sites filter by FOLDER. A bare basename
        # would hide 'program files (x86)\teamviewer\tv_w32.exe' (the word teamviewer
        # lives only in the folder) and shrink the grouping keys. BAM must match them.
        exe = norm or prog
        ts = _parse_ts(row.get('ExecutionTime'))
        sid = ''
        m = re.search(r'UserSettings[\\/](S-1-[0-9-]+)', str(row.get('BatchKeyPath') or ''))
        if m:
            sid = m.group(1)
        payload = {'artifact': 'bam', 'when_kind': 'execution(bam)', 'raw_program': prog}
        if sid:
            payload['user_sid'] = sid
        return (case_key, ts, exe or None, norm or prog, None, src, Json(payload))

    # AppCompatCache (Shimcache) — Path, LastModifiedTimeUTC, Executed, CacheEntryPosition
    def map_pe_shimcache(row, src):
        row = _clean_row(dict(row))
        full_path = str(row.get('Path') or '')
        exe = os.path.basename(full_path) if full_path else ''
        ts = _parse_ts(row.get('LastModifiedTimeUTC'))
        payload = {}
        if row.get('CacheEntryPosition'): payload['cache_pos'] = row['CacheEntryPosition']
        if row.get('Executed'): payload['executed'] = row['Executed']
        if row.get('ControlSet'): payload['control_set'] = row['ControlSet']
        return (case_key, ts, exe or None, full_path or None, None, src, Json(payload))

    # SRUM NetworkConnections — Timestamp, ExeInfo, UserName, ConnectedTime,
    #   ConnectStartTime, InterfaceType, ProfileName
    def map_srum_netconn(row, src):
        row = _clean_row(dict(row))
        ts = _parse_ts(row.get('Timestamp'))
        exe = str(row.get('ExeInfo') or '')
        user = str(row.get('UserName') or '')
        if not ts and not exe and not user:
            return None
        payload = {}
        if row.get('ConnectedTime'): payload['connected_time'] = row['ConnectedTime']
        if row.get('ConnectStartTime'): payload['connect_start'] = row['ConnectStartTime']
        if row.get('InterfaceType'): payload['iface_type'] = row['InterfaceType']
        if row.get('ProfileName'): payload['profile'] = row['ProfileName']
        return (case_key, ts, user or None, exe or None, src, Json(payload))

    # SRUM NetworkUsages — Timestamp, ExeInfo, UserName, BytesReceived, BytesSent,
    #   InterfaceType, ProfileName
    def map_srum_netusage(row, src):
        row = _clean_row(dict(row))
        ts = _parse_ts(row.get('Timestamp'))
        exe = str(row.get('ExeInfo') or '')
        user = str(row.get('UserName') or '')
        if not exe and not user:
            return None
        payload = {}
        if row.get('BytesReceived'): payload['bytes_rx'] = row['BytesReceived']
        if row.get('BytesSent'): payload['bytes_tx'] = row['BytesSent']
        if row.get('InterfaceType'): payload['iface_type'] = row['InterfaceType']
        if row.get('ProfileName'): payload['profile'] = row['ProfileName']
        return (case_key, ts, user or None, exe or None, src, Json(payload))

    # SRUM AppResourceUseInfo — Timestamp, ExeInfo, UserName, Background/ForegroundBytes*
    def map_srum_appres(row, src):
        row = _clean_row(dict(row))
        ts = _parse_ts(row.get('Timestamp'))
        exe = str(row.get('ExeInfo') or '')
        user = str(row.get('UserName') or '')
        if not exe and not user:
            return None
        payload = {}
        for k, pk in [('BackgroundBytesRead','bg_read'), ('BackgroundBytesWritten','bg_write'),
                      ('ForegroundBytesRead','fg_read'), ('ForegroundBytesWritten','fg_write'),
                      ('FaceTime','face_time')]:
            if row.get(k): payload[pk] = row[k]
        return (case_key, ts, user or None, exe or None, src, Json(payload))

    # Fallback — raw_fallback_v2: strip KAPE path prefix from SourceFile, keep useful columns
    _FB_SKIP_COLS = {'SourceFile'}  # full KAPE path, useless

    def map_fallback(row, src, parser_family):
        row = _clean_row(dict(row))
        payload = {k: v for k, v in row.items()
                   if k not in _FB_SKIP_COLS and v is not None and str(v).strip() != ''}
        return (case_key, parser_family, src, Json(payload))

    # AccountUsage: logparser Logon-Logoff → event_logs_v2
    # Columns: Date, EventID, Description, Username, Domain, CredentialsUsed,
    #          LogonID, SessionName, LogonType, Status, SubStatus, AuthPackage
    def map_logon_logoff(row, src):
        row = _clean_row(dict(row))
        eid = _pick(row, ['EventID', 'EventId', 'Event ID'])
        try: eid = int(str(eid).strip()) if eid else None
        except Exception: eid = None
        ts = _parse_ts(_pick(row, ['Date', 'Timestamp', 'DateTime']))
        user = str(row.get('Username') or row.get('UserName') or '').strip()
        logon_type = str(row.get('LogonType') or row.get('Logon Type') or '').strip()
        payload = {}
        for k in ('Domain', 'CredentialsUsed', 'LogonID', 'SessionName', 'Status', 'SubStatus', 'AuthPackage', 'Description'):
            if row.get(k): payload[k.lower()] = row[k]
        return (case_key, eid, ts, 'Security', 'logparser', None, None,
                user or None, logon_type or None, None,
                str(row.get('Description') or '')[:500] or None, Json(payload), src)

    # RemoteAccess: logparser RDP-Usage → event_logs_v2
    # Columns: Date, SourceName, EventID, User, Description, SessionID, SourceSessionID, ReasonCode, SourceIP
    def map_rdp_usage(row, src):
        row = _clean_row(dict(row))
        eid = _pick(row, ['EventID', 'EventId', 'Event ID'])
        try: eid = int(str(eid).strip()) if eid else None
        except Exception: eid = None
        ts = _parse_ts(row.get('Date'))
        user = str(row.get('User') or '').strip()
        src_ip = str(row.get('SourceIP') or '').strip()
        payload = {}
        for k in ('SourceName', 'SessionID', 'SourceSessionID', 'ReasonCode', 'Description'):
            if row.get(k): payload[k.lower()] = row[k]
        return (case_key, eid, ts, 'Microsoft-Windows-TerminalServices-RemoteConnectionManager',
                'logparser', None, src_ip or None, user or None, None, None,
                str(row.get('Description') or '')[:500] or None, Json(payload), src)

    # RemoteAccess: logparser SMBServer-Anonymous-Logon → event_logs_v2
    # Columns: Date, EventID, Description, UserName, ClientName
    def map_smb_logon(row, src):
        row = _clean_row(dict(row))
        eid = _pick(row, ['EventID', 'EventId', 'Event ID'])
        try: eid = int(str(eid).strip()) if eid else None
        except Exception: eid = None
        ts = _parse_ts(row.get('Date'))
        user = str(row.get('UserName') or '').strip()
        client = str(row.get('ClientName') or '').strip()
        payload = {'description': str(row.get('Description') or '')[:300]}
        return (case_key, eid, ts, 'Microsoft-Windows-SMBServer',
                'logparser', None, client or None, user or None, None, None,
                str(row.get('Description') or '')[:500] or None, Json(payload), src)

    # EventLogs: Hayabusa full events → tool_alerts_v2 only
    # Columns: Timestamp, RuleTitle, Level, Computer, Channel, EventID, RecordID, Details, ExtraFieldInfo
    def map_hayabusa_alert(row, src):
        row = _clean_row(dict(row))
        sev = str(row.get('Level') or 'medium').strip().lower()
        rule = str(row.get('RuleTitle') or '').strip()
        if not rule:
            return None
        ts = _parse_ts(row.get('Timestamp'))
        comp = str(row.get('Computer') or '').strip()
        details = str(row.get('Details') or row.get('ExtraFieldInfo') or '')[:2000]
        eid = str(row.get('EventID') or '').strip()
        payload = {}
        if row.get('Channel'): payload['channel'] = row['Channel']
        if row.get('RecordID'): payload['record_id'] = row['RecordID']
        if row.get('ExtraFieldInfo'): payload['extra'] = str(row['ExtraFieldInfo'])[:500]
        return (case_key, 'hayabusa', sev or None, rule or None, ts,
                comp or None, None, eid or None, details or None, src, Json(payload))

    # EventLogs: focused detection CSVs (account_tampering, lateral_movement, etc.)
    # Columns: timestamp, detections, path, Event ID, Record ID, Computer, User, [extra]
    def map_dfir_alert(row, src):
        row = _clean_row(dict(row))
        rule = str(row.get('detections') or row.get('Detections') or '').strip()
        if not rule:
            rule = os.path.splitext(src)[0]  # use filename as rule hint
        ts = _parse_ts(_pick(row, ['timestamp', 'Timestamp', 'DateTime']))
        comp = str(_pick(row, ['Computer', 'ComputerName', 'Hostname']) or '').strip()
        user = str(_pick(row, ['User', 'UserName', 'Username']) or '').strip()
        # Build ioc_value from the most specific field available
        ioc = str(_pick(row, ['Service Name', 'Service File Name', 'IP Address', 'SourceIP',
                               'Member SID', 'User SID', 'path']) or '').strip()
        details_parts = []
        for k in ('Event ID', 'EventID', 'Channel', 'Information', 'Service Type',
                  'Service Start Type', 'Service Account', 'Logon Type', 'count', 'path'):
            if row.get(k):
                details_parts.append(f'{k}={row[k]}')
        details = '; '.join(details_parts)[:2000]
        sev = 'medium'
        # Escalate severity for known high-impact rule categories
        rl = rule.lower()
        if any(x in rl for x in ['tamper', 'lateral', 'rdp_attack', 'login_attack', 'service_install']):
            sev = 'high'
        return (case_key, 'dfir_report', sev, rule or None, ts,
                comp or None, user or None, ioc or None, details or None, src, Json({}))

    # reg_hunter NDJSON line → tool_alerts_v2
    def map_reg_hunter(obj, src):
        tags = obj.get('tags') or []
        if not tags:
            return None
        rule = ', '.join(str(t) for t in tags)
        ts = _parse_ts(obj.get('timestamp') or obj.get('last_write_time'))
        comp = str(obj.get('device_name') or '').strip()
        key_path = str(obj.get('registry_key') or '').strip()
        value = str(obj.get('registry_value') or '')[:500]
        details = f"key={key_path} value_name={obj.get('registry_value_name','')} value={value[:200]}"
        payload = {}
        for k in ('registry_hive', 'registry_type', 'device_type', 'device_domain', 'error'):
            if obj.get(k): payload[k] = obj[k]
        return (case_key, 'reg_hunter', 'medium', rule, ts,
                comp or None, None, key_path[:500] or None, details[:2000], src, Json(payload))

    # THOR files_md5s.csv: no header, format md5,filepath,filesize
    def map_thor_md5(row, src):
        md5 = str(row.get('f0') or '').strip().lower()
        fpath = str(row.get('f1') or '').strip()
        fsize = str(row.get('f2') or '').strip()
        if len(md5) != 32 or not fpath:
            return None
        fname = fpath.split('\\')[-1].split('/')[-1]
        payload = {'md5': md5, 'path': fpath, 'size': fsize, 'file_name': fname}
        return (case_key, 'thor_file_hashes', src, Json(payload))

    # -----------------------------------------------------------------------
    inserted = {'event_rows': 0, 'fs_rows': 0, 'pe_rows': 0,
                'srum_rows': 0, 'fb_rows': 0, 'alert_rows': 0}
    errors = []

    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            if st:
                st.update({'stage': 'ingest_db_prepare', 'progress': 12})
            cur.execute("DELETE FROM event_logs_v2 WHERE case_key=%s", (case_key,))
            cur.execute("DELETE FROM filesystem_v2 WHERE case_key=%s", (case_key,))
            cur.execute("DELETE FROM program_exec_v2 WHERE case_key=%s", (case_key,))
            cur.execute("DELETE FROM srum_v2 WHERE case_key=%s", (case_key,))
            cur.execute("DELETE FROM raw_fallback_v2 WHERE case_key=%s", (case_key,))
            cur.execute("DELETE FROM tool_alerts_v2 WHERE case_key=%s", (case_key,))
            # communications_v1 may not exist yet on older DBs → guard so re-ingest
            # (idempotent) doesn't fail when the comms table hasn't been created.
            try:
                cur.execute("DELETE FROM communications_v1 WHERE case_key=%s", (case_key,))
            except Exception:
                conn.rollback()
            conn.commit()

            # Last-resort net for an archive that reached the library WITHOUT passing the
            # upload gate - copied in over SSH, restored from a backup, re-ingested from an
            # old path. The gate normally decrypts, so this is a no-op on every ordinary
            # run; without it such an archive would parse as 'nothing forensic inside'.
            try:
                from analysis import archive_crypto as _ac
                _ac.maybe_decrypt_in_place(zip_path)
            except Exception as _ace:
                errors.append('archive_crypto: %s' % repr(_ace)[:200])

            with zipfile.ZipFile(zip_path, 'r') as zf:
                all_names = zf.namelist()
                _sizes = {zi.filename: zi.file_size for zi in zf.infolist() if not zi.is_dir()}
                _utf16_csvs = []
                csv_entries = [n for n in all_names if n.lower().endswith('.csv')]
                json_entries = [n for n in all_names
                                if n.lower().endswith('.json') and classify_json(n)]
                # THOR TXT, LOKI LOG, RegRipper TXT
                thor_entries = [n for n in all_names
                                if _kape_folder(n.lower().replace('\\','/').split('/')) == 'iocs'
                                and n.lower().endswith('.txt')
                                and 'thor' in n.lower()]
                loki_entries = [n for n in all_names
                                if _kape_folder(n.lower().replace('\\','/').split('/')) == 'iocs'
                                and n.lower().endswith('.log')
                                and 'loki' in n.lower()]
                deepblue_entries = [n for n in all_names
                                    if _kape_folder(n.lower().replace(chr(92), '/').split('/')) == 'eventlogs'
                                    and '/deepblue/' in n.lower().replace(chr(92), '/')
                                    and n.lower().endswith('.txt')]
                detections_entries = [n for n in all_names
                                      if _kape_folder(n.lower().replace(chr(92), '/').split('/')) == 'eventlogs'
                                      and n.lower().endswith('detections.json')]
                regripper_entries = [n for n in all_names
                                     if _kape_folder(n.lower().replace('\\','/').split('/')) == 'registry'
                                     and n.lower().endswith('.txt')
                                     and 'regripper' in n.lower()]
                # ADDITIVE: live network snapshot TXT (hosts/firewall/arp/ipconfig)
                # from the collector's live mode -> raw_fallback_v2 'live_network'.
                live_txt_entries = [n for n in all_names
                                    if _kape_folder(n.lower().replace('\\','/').split('/')) == 'live'
                                    and n.lower().endswith('.txt')]
                # ADDITIVE: the collector's OWN declaration (_collector_self.txt, root of
                # the archive). Two lines: the work root and the toolkit temp folder, both
                # of which the collector excluded from Defender itself. Read so the report
                # can subtract exactly those and stop accusing our own tool of tampering.
                self_decl_entries = [n for n in all_names
                                     if n.lower().replace(chr(92), '/').split('/')[-1]
                                     == '_collector_self.txt']
                # ADDITIVE: the collector's shortlist of suspicious binaries, written
                # at the ROOT of the archive as TXT (vao_collect_all.ps1). Every other
                # TXT family is picked up by folder; this one has no folder.
                susp_entries = [n for n in all_names
                                if n.lower().replace(chr(92), '/').split('/')[-1]
                                == 'suspicious_files.txt']
                # ADDITIVE: Hindsight (ObsidianForensics) JSONL browser export
                hindsight_entries = [n for n in all_names if is_hindsight_file(n)]
                total = max(1, len(csv_entries) + len(json_entries)
                            + len(thor_entries) + len(loki_entries)
                            + len(regripper_entries) + len(hindsight_entries)
                            + len(deepblue_entries) + len(detections_entries))

                # COVERAGE: what became of every entry in the archive. The bot reads what
                # it was taught to read; a file nobody taught it about used to vanish
                # without a trace, and a "no threats" verdict looked the same over a
                # half-read archive as over a full one. rel_path -> (family, rows, status, note)
                _cov = {}

                def _cov_mark(rel, family, rows, status, note=''):
                    _cov[rel] = (family, rows, status, (note or '')[:200])

                # --- CSV pass ---
                for i, rel_path in enumerate(csv_entries, 1):
                    kind = classify(rel_path)
                    # name told nothing (or only a folder): let the header decide
                    if (not kind or str(kind).startswith('fb_other_')) and rel_path.lower().endswith('.csv'):
                        _hk = _sniff_member_kind(zf, rel_path)
                        if _hk:
                            kind = _hk
                    if not kind:
                        _cov_mark(rel_path, None, 0, _skip_status(rel_path))
                        continue
                    base = os.path.basename(rel_path)
                    if st:
                        st.update({'stage': f'ingest {i}/{total} {base[:40]}',
                                   'progress': min(68, 15 + int(i * 53 / total))})
                    try:
                        with zf.open(rel_path, 'r') as bf:
                            tf = _open_csv_text(zf, rel_path, bf)
                            if str(getattr(tf, 'encoding', '')).lower().startswith('utf-16'):
                                _utf16_csvs.append(rel_path)
                            # THOR md5 CSV has no header row
                            if kind == 'thor_md5':
                                reader = csv.DictReader(tf, fieldnames=['f0', 'f1', 'f2'])
                            else:
                                reader = csv.DictReader(tf)
                            batch = []
                            alert_batch = []
                            _nrows = 0

                            for row in reader:
                                _nrows += 1
                                rec = None
                                if kind == 'event':
                                    batch.append(map_event(row, base))
                                elif kind == 'event_alert':
                                    batch.append(map_event(row, base))
                                    tool_hint = ('sigma' if 'sigma' in base.lower()
                                                 else 'hayabusa' if 'hayabusa' in base.lower()
                                                 else 'log_tampering')
                                    alert_batch.append(map_alert(row, base, tool_hint))
                                elif kind == 'hayabusa_alert':
                                    rec = map_hayabusa_alert(row, base)
                                    if rec: alert_batch.append(rec)
                                elif kind == 'dfir_alert':
                                    rec = map_dfir_alert(row, base)
                                    if rec: alert_batch.append(rec)
                                elif kind == 'logon_logoff':
                                    batch.append(map_logon_logoff(row, base))
                                elif kind == 'rdp_usage':
                                    batch.append(map_rdp_usage(row, base))
                                elif kind == 'smb_logon':
                                    batch.append(map_smb_logon(row, base))
                                elif kind == 'fs_mft':
                                    fn = str(row.get('FileName') or '').strip()
                                    if not fn:
                                        continue
                                    batch.append(map_fs_mft(row, base))
                                elif kind == 'fs_usn':
                                    fn = str(row.get('Name') or '').strip()
                                    if not fn:
                                        continue
                                    batch.append(map_fs_usn(row, base))
                                elif kind == 'fs_motw':
                                    rec = map_motw(row, base)
                                    if rec: batch.append(rec)
                                elif kind == 'pe_prefetch':
                                    batch.append(map_pe_prefetch(row, base))
                                elif kind == 'pe_amcache':
                                    batch.append(map_pe_amcache(row, base))
                                elif kind == 'pe_amcache_prog':
                                    batch.append(map_pe_amcache_prog(row, base))
                                elif kind == 'pe_shimcache':
                                    batch.append(map_pe_shimcache(row, base))
                                elif kind == 'pe_bam':
                                    _r = map_pe_bam(row, base)
                                    if _r:
                                        batch.append(_r)
                                elif kind == 'srum_netconn':
                                    rec = map_srum_netconn(row, base)
                                    if rec: batch.append(rec)
                                elif kind == 'srum_netusage':
                                    rec = map_srum_netusage(row, base)
                                    if rec: batch.append(rec)
                                elif kind == 'srum_appres':
                                    rec = map_srum_appres(row, base)
                                    if rec: batch.append(rec)
                                elif kind == 'communications':
                                    _r = _clean_row(dict(row))
                                    _plat = (str(_pick(_r, ['platform', 'Platform', 'app', 'App']) or '').lower())[:40]
                                    _txt = _pick(_r, ['message_text', 'message', 'Message', 'text', 'Text', 'body', 'Body'])
                                    _src = str(_pick(_r, ['source_artifact', 'source', 'artifact', 'SourceFile']) or base)[:400]
                                    if _plat or _txt:
                                        batch.append((
                                            case_key, _plat or 'unknown',
                                            (str(_pick(_r, ['source_kind', 'kind', 'SourceKind']) or 'unknown'))[:20],
                                            _pick(_r, ['self_account', 'self', 'owner', 'SelfAccount', 'account']),
                                            _pick(_r, ['contact_id', 'peer_id', 'peer', 'ContactId']),
                                            _pick(_r, ['contact_name', 'contact', 'peer_name', 'ContactName', 'name']),
                                            (str(_pick(_r, ['direction', 'dir', 'Direction']) or 'unknown'))[:10],
                                            _parse_ts(_pick(_r, ['msg_ts', 'timestamp', 'Timestamp', 'ts', 'date', 'DateTime', 'time'])),
                                            _txt,
                                            _pick(_r, ['thread_id', 'thread', 'chat_id', 'ThreadId', 'conversation']),
                                            _pick(_r, ['attachment', 'attachments', 'file', 'Attachment', 'media']),
                                            _src,
                                            (str(_pick(_r, ['confidence', 'conf', 'Confidence']) or 'medium'))[:10],
                                            Json(_r) if _r else None,
                                        ))
                                elif kind == 'thor_md5':
                                    rec = map_thor_md5(row, base)
                                    if rec: batch.append(rec)
                                elif kind.startswith('fb_'):
                                    parser_family = kind[3:]  # strip 'fb_'
                                    batch.append(map_fallback(row, base, parser_family))

                                if len(batch) >= BATCH:
                                    _flush_batch(cur, conn, kind, case_key, batch, alert_batch, inserted)
                                    batch = []
                                    alert_batch = []
                                elif len(alert_batch) >= BATCH:
                                    _flush_batch(cur, conn, kind, case_key, batch, alert_batch, inserted)
                                    batch = []
                                    alert_batch = []

                            if batch or alert_batch:
                                _flush_batch(cur, conn, kind, case_key, batch, alert_batch, inserted)
                        _cov_mark(rel_path, kind, _nrows, 'consumed' if _nrows else 'empty')
                    except Exception as e:
                        errors.append(f'{base}: {e}')
                        _cov_mark(rel_path, kind, 0, 'rejected', str(e).splitlines()[0] if str(e) else 'error')
                        _reset_txn(conn)
                        continue

                # --- Prefetch rescue: raw .pf when no PECmd output was consumed ---
                # (PECmd < 2026.5 refuses Prefetch v31 / Windows 11 24H2+; the collector cannot
                #  re-run .NET here, but the raw .pf ship in *_input.zip — parse them natively)
                try:
                    _pe_pf = sum(int(v[1] or 0) for v in _cov.values() if v and v[0] == 'pe_prefetch' and v[2] == 'consumed')
                    if not _pe_pf:
                        from parsers.prefetch_rescue import rescue_rows as _pf_rescue
                        _pf_pe, _pf_tl, _pf_src, _pf_failed = _pf_rescue(zip_path, zf)
                        if _pf_pe:
                            batch = [map_pe_prefetch(r, 'PYPECmd_Output.csv') for r in _pf_pe]
                            _flush_batch(cur, conn, 'pe_prefetch', case_key, batch, [], inserted)
                            _cov_mark('(raw .pf <- %s)' % _pf_src, 'pe_prefetch', len(batch), 'consumed',
                                      'PECmd output absent; %d .pf parsed natively (prefetch_py v17-31), %d failed' % (len(batch), _pf_failed))
                            batch = [map_fallback(r, 'PYPECmd_Output_Timeline.csv', 'prefetch_timeline') for r in _pf_tl]
                            if batch:
                                _flush_batch(cur, conn, 'fb_prefetch_timeline', case_key, batch, [], inserted)
                            batch = []
                except Exception as e:
                    errors.append('prefetch_rescue: %s' % str(e)[:160])
                    _reset_txn(conn)

                # --- NDJSON pass (reg_hunter files) ---
                for j, rel_path in enumerate(json_entries, len(csv_entries) + 1):
                    jkind = classify_json(rel_path)
                    base = os.path.basename(rel_path)
                    if st:
                        st.update({'stage': f'ingest json {base[:40]}',
                                   'progress': min(70, 15 + int(j * 55 / total))})
                    try:
                        with zf.open(rel_path, 'r') as bf:
                            raw = bf.read().decode('utf-8', errors='ignore').replace('\x00', '')
                        alert_batch = []
                        for line in raw.splitlines():
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                obj = json.loads(line)
                            except Exception:
                                continue
                            if jkind == 'reg_hunter':
                                rec = map_reg_hunter(obj, base)
                                if rec:
                                    alert_batch.append(rec)
                            if len(alert_batch) >= BATCH:
                                if alert_batch:
                                    _em(cur, """
                                        INSERT INTO tool_alerts_v2(case_key,tool,severity,rule,event_ts,computer,
                                            user_name,ioc_value,details,source_file,payload)
                                        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                                    """, alert_batch)
                                    inserted['alert_rows'] += len(alert_batch)
                                    conn.commit()
                                    alert_batch = []
                        if alert_batch:
                            _em(cur, """
                                INSERT INTO tool_alerts_v2(case_key,tool,severity,rule,event_ts,computer,
                                    user_name,ioc_value,details,source_file,payload)
                                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                            """, alert_batch)
                            inserted['alert_rows'] += len(alert_batch)
                            conn.commit()
                    except Exception as e:
                        errors.append(f'{base}: {e}')
                        _reset_txn(conn)
                        continue

                # --- THOR TXT pass ---
                for rel_path in thor_entries:
                    base = os.path.basename(rel_path)
                    try:
                        with zf.open(rel_path, 'r') as bf:
                            raw = bf.read().decode('utf-8', errors='ignore').replace('\x00', '')
                        alert_batch = []
                        # THOR TXT format: lines with [ALERT], [WARNING], [NOTICE], [INFO]
                        # Pattern: DATE TIME HOSTNAME LEVEL MODULE - RULE - MESSAGE
                        import re as _re
                        thor_line_re = _re.compile(
                            r'(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d+)?)'
                            r'.*?\b(ALERT|WARNING|NOTICE|INFO)\b'
                            r'.*?MODULE:\s*([^\s,]+)'
                            r'.*?MESSAGE:\s*(.+)',
                            _re.IGNORECASE
                        )
                        # Simpler fallback: scan for ALERT/WARNING lines
                        sev_map = {'ALERT': 'critical', 'WARNING': 'high',
                                   'NOTICE': 'medium', 'INFO': 'low'}
                        for line in raw.splitlines():
                            line = line.strip()
                            if not line:
                                continue
                            # Extract severity
                            sev = None
                            for tok in ('ALERT', 'WARNING', 'NOTICE'):
                                if tok in line.upper():
                                    sev = sev_map[tok]
                                    break
                            if not sev:
                                continue
                            # Extract timestamp
                            ts_m = _re.search(r'\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}', line)
                            ts = ts_m.group(0).replace(' ', 'T') if ts_m else None
                            # Extract rule / detection name
                            rule_m = (_re.search(r'(?:RULE|REASON|MATCH|DETECTION)[:\s]+([^\s,;|]{3,80})', line, _re.I)
                                      or _re.search(r'(?:Threat|Name)[:\s]+([^\s,;|]{3,80})', line, _re.I))
                            rule = rule_m.group(1)[:200] if rule_m else 'thor_detection'
                            # Extract IOC value (file path, hash, etc.)
                            ioc_m = (_re.search(r'(?:FILE|PATH|HASH|SHA\d*|MD5)[:\s]+([^\s,;|]{4,300})', line, _re.I)
                                     or _re.search(r'([A-Za-z]:\\[^\s,;|]{4,200})', line))
                            ioc = ioc_m.group(1)[:500] if ioc_m else None
                            # Computer name
                            comp_m = _re.search(r'(?:HOSTNAME|COMPUTER)[:\s]+([A-Z0-9_-]{3,30})', line, _re.I)
                            comp = comp_m.group(1) if comp_m else None
                            details = line[:2000]
                            alert_batch.append((
                                case_key, 'thor', sev, rule[:200], ts,
                                comp, None, ioc, details, base, Json({'raw': line[:500]})
                            ))
                            if len(alert_batch) >= BATCH:
                                _em(cur, """
                                    INSERT INTO tool_alerts_v2(case_key,tool,severity,rule,event_ts,
                                        computer,user_name,ioc_value,details,source_file,payload)
                                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                                """, alert_batch)
                                inserted['alert_rows'] += len(alert_batch)
                                conn.commit()
                                alert_batch = []
                        if alert_batch:
                            _em(cur, """
                                INSERT INTO tool_alerts_v2(case_key,tool,severity,rule,event_ts,
                                    computer,user_name,ioc_value,details,source_file,payload)
                                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                            """, alert_batch)
                            inserted['alert_rows'] += len(alert_batch)
                            conn.commit()
                    except Exception as e:
                        errors.append(f'thor:{base}: {e}')

                # --- LOKI LOG pass ---
                for rel_path in loki_entries:
                    base = os.path.basename(rel_path)
                    try:
                        with zf.open(rel_path, 'r') as bf:
                            raw = bf.read().decode('utf-8', errors='ignore').replace('\x00', '')
                        alert_batch = []
                        import re as _re
                        sev_map = {'ALERT': 'critical', 'WARNING': 'high', 'NOTICE': 'medium'}
                        for line in raw.splitlines():
                            line = line.strip()
                            if not line:
                                continue
                            sev = None
                            for tok in ('ALERT', 'WARNING', 'NOTICE'):
                                if tok in line.upper():
                                    sev = sev_map[tok]
                                    break
                            if not sev:
                                continue
                            ts_m = _re.search(r'\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}', line)
                            ts = ts_m.group(0).replace(' ', 'T') if ts_m else None
                            rule_m = _re.search(r'(?:REASON|RULE|MATCH|DESCRIPTION)[:\s]+([^\|]{3,150})', line, _re.I)
                            rule = (rule_m.group(1).strip()[:200] if rule_m else 'loki_detection')
                            ioc_m = _re.search(r'FILE:\s*([^\|,\n]{4,300})', line, _re.I)
                            ioc = ioc_m.group(1).strip()[:500] if ioc_m else None
                            comp_m = _re.search(r'(?:HOSTNAME|COMPUTER)[:\s]+([A-Z0-9_-]{3,30})', line, _re.I)
                            comp = comp_m.group(1) if comp_m else None
                            alert_batch.append((
                                case_key, 'loki', sev, rule, ts,
                                comp, None, ioc, line[:2000], base, Json({'raw': line[:500]})
                            ))
                            if len(alert_batch) >= BATCH:
                                _em(cur, """
                                    INSERT INTO tool_alerts_v2(case_key,tool,severity,rule,event_ts,
                                        computer,user_name,ioc_value,details,source_file,payload)
                                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                                """, alert_batch)
                                inserted['alert_rows'] += len(alert_batch)
                                conn.commit()
                                alert_batch = []
                        if alert_batch:
                            _em(cur, """
                                INSERT INTO tool_alerts_v2(case_key,tool,severity,rule,event_ts,
                                    computer,user_name,ioc_value,details,source_file,payload)
                                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                            """, alert_batch)
                            inserted['alert_rows'] += len(alert_batch)
                            conn.commit()
                    except Exception as e:
                        errors.append(f'loki:{base}: {e}')

                # --- DeepblueCLI TXT pass (eventlogs/Deepblue/*.evtx.txt, UTF-16) ---
                for rel_path in deepblue_entries:
                    base = os.path.basename(rel_path)
                    try:
                        import re as _re
                        from datetime import datetime as _dbdt
                        with zf.open(rel_path, 'r') as bf:
                            raw_b = bf.read()
                        if raw_b[:2] in (b'\xff\xfe', b'\xfe\xff') or raw_b[:1000].count(b'\x00') > 100:
                            raw = raw_b.decode('utf-16', errors='ignore')
                        else:
                            raw = raw_b.decode('utf-8', errors='ignore')
                        raw = raw.replace(chr(0), '')

                        def _db_flush(rec):
                            if not rec.get('message') and not rec.get('results'):
                                return None
                            ts = None
                            dt_raw = (rec.get('date') or '').strip()
                            for fmt in ('%m/%d/%Y %I:%M:%S %p', '%d.%m.%Y %H:%M:%S', '%Y-%m-%d %H:%M:%S'):
                                try:
                                    ts = _dbdt.strptime(dt_raw, fmt).isoformat()
                                    break
                                except Exception:
                                    continue
                            rule = (rec.get('message') or 'deepblue_detection')[:200]
                            details = ('; '.join(k + ': ' + v for k, v in rec.items()
                                                 if v and not k.startswith('_')))[:2000]
                            ioc_m = _re.search(r'([A-Za-z]:[\\/][^\s,;|]{4,200}|[\w.-]{3,80}\.(?:exe|ps1|dll|bat))',
                                               rec.get('results') or '')
                            return (case_key, 'deepbluecli', 'medium', rule, ts,
                                    None, None, (ioc_m.group(1)[:500] if ioc_m else None),
                                    details, base,
                                    Json({'record': {k: v[:400] for k, v in rec.items() if not k.startswith('_')}}))

                        alert_batch = []
                        cur_rec = {}
                        for line in raw.splitlines():
                            m = _re.match(r'^(Date|Log|EventID|Message|Results|Command|Decoded)\s*:\s*(.*)$',
                                          line.strip(), _re.I)
                            if not m:
                                lk = cur_rec.get('_last')
                                if lk and line.strip():
                                    cur_rec[lk] = ((cur_rec.get(lk) or '') + ' ' + line.strip())[:4000]
                                continue
                            key = m.group(1).lower()
                            if key == 'date' and cur_rec:
                                row = _db_flush(cur_rec)
                                if row:
                                    alert_batch.append(row)
                                cur_rec = {}
                            cur_rec[key] = m.group(2).strip()
                            cur_rec['_last'] = key
                        if cur_rec:
                            row = _db_flush(cur_rec)
                            if row:
                                alert_batch.append(row)
                        for i0 in range(0, len(alert_batch), BATCH):
                            _em(cur, """
                                INSERT INTO tool_alerts_v2(case_key,tool,severity,rule,event_ts,
                                    computer,user_name,ioc_value,details,source_file,payload)
                                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                            """, alert_batch[i0:i0 + BATCH])
                            inserted['alert_rows'] += len(alert_batch[i0:i0 + BATCH])
                            conn.commit()
                    except Exception as e:
                        errors.append(f'deepblue:{base}: {e}')

                # --- Chainsaw Detections.json pass (eventlogs/*Detections.json) ---
                for rel_path in detections_entries:
                    base = os.path.basename(rel_path)
                    try:
                        import json as _json
                        with zf.open(rel_path, 'r') as bf:
                            raw_b = bf.read()
                        try:
                            data = _json.loads(raw_b.decode('utf-8', errors='ignore'))
                        except Exception:
                            data = []
                        if isinstance(data, dict):
                            data = data.get('detections') or data.get('hits') or [data]
                        _sevmap = {'critical': 'critical', 'high': 'high', 'medium': 'medium',
                                   'low': 'low', 'informational': 'low', 'info': 'low'}
                        alert_batch = []
                        for item in (data or []):
                            if not isinstance(item, dict):
                                continue
                            rule = str(item.get('title') or item.get('name') or item.get('rule')
                                       or 'sigma_detection')[:200]
                            sev = _sevmap.get(str(item.get('rule_level') or item.get('level') or '').lower(),
                                              'medium')
                            matches = item.get('matches') or []
                            total_cnt = int(item.get('count') or len(matches) or 1)
                            if not matches:
                                ts = str(item.get('timestamp') or '').strip() or None
                                details = _json.dumps(item, ensure_ascii=False, default=str)[:2000]
                                alert_batch.append((case_key, 'sigma_json', sev, rule, ts,
                                                    None, None, None, details, base,
                                                    Json({'raw': details[:800], 'count': total_cnt})))
                                continue
                            for mt in matches[:50]:
                                if not isinstance(mt, dict):
                                    continue
                                ts = str(mt.get('SystemTime') or mt.get('timestamp') or '').strip() or None
                                comp = str(mt.get('Computer') or '')[:60] or None
                                ioc = str(mt.get('Path') or mt.get('Image') or mt.get('CommandLine')
                                          or '')[:500] or None
                                details = (rule + ' | ' + _json.dumps(
                                    {k: v for k, v in mt.items()
                                     if k in ('EventID', 'Channel', 'Path', 'Image', 'CommandLine',
                                              'ProductName', 'CategoryName', 'User', 'TargetUserName',
                                              'ServiceName', 'ProcessName', 'ThreatName')},
                                    ensure_ascii=False, default=str))[:2000]
                                alert_batch.append((case_key, 'sigma_json', sev, rule, ts,
                                                    comp, None, ioc, details, base,
                                                    Json({'match': {k: str(v)[:300] for k, v in mt.items()},
                                                          'rule_total': total_cnt})))
                        for i0 in range(0, len(alert_batch), BATCH):
                            _em(cur, """
                                INSERT INTO tool_alerts_v2(case_key,tool,severity,rule,event_ts,
                                    computer,user_name,ioc_value,details,source_file,payload)
                                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                            """, alert_batch[i0:i0 + BATCH])
                            inserted['alert_rows'] += len(alert_batch[i0:i0 + BATCH])
                            conn.commit()
                    except Exception as e:
                        errors.append(f'detections:{base}: {e}')

                # --- RegRipper TXT pass → raw_fallback_v2 ---
                for rel_path in regripper_entries:
                    base = os.path.basename(rel_path)
                    # Determine hive type from filename
                    hive = 'unknown'
                    bl = base.lower()
                    for h in ('ntuser', 'software', 'system', 'sam', 'security', 'usrclass'):
                        if h in bl:
                            hive = h
                            break
                    try:
                        with zf.open(rel_path, 'r') as bf:
                            raw_bytes = bf.read()
                        # RegRipper output is often UTF-16LE (BOM \xff\xfe or \xff\xfe)
                        if raw_bytes[:2] in (b'\xff\xfe', b'\xfe\xff'):
                            raw = raw_bytes.decode('utf-16', errors='ignore').replace('\x00', '')
                        elif b'\x00' in raw_bytes[:200]:
                            raw = raw_bytes.decode('utf-16-le', errors='ignore').replace('\x00', '')
                        else:
                            raw = raw_bytes.decode('utf-8', errors='ignore')
                        import re as _re
                        fb_batch = []
                        # RegRipper output: plugin blocks separated by blank lines
                        # Each block starts with "pluginname v.X.X" then key/value lines
                        current_plugin = None
                        current_lines = []

                        def flush_plugin(plugin, lines, hive, base, case_key):
                            if not plugin or not lines:
                                return None
                            text = '\n'.join(lines).strip().replace('\x00', '')
                            if not text or len(text) < 10:
                                return None
                            payload_dict = {'plugin': plugin, 'hive': hive, 'text': text[:15000]}
                            # (case_key, parser_family, source_file, payload)
                            return (case_key, 'regripper_' + hive, base, Json(payload_dict))

                        # raw_fallback_v2 insert signature:
                        # (case_key, file_id, row_ts, computer, user_name, action,
                        #  file_name, parent_path, url, raw_text, parser_family, event_id, payload)
                        plugin_header_re = _re.compile(
                            r'^([a-z_][a-z0-9_]{2,40})\s+v\.\d', _re.I)

                        for line in raw.splitlines():
                            m = plugin_header_re.match(line)
                            if m:
                                # flush previous plugin
                                rec = flush_plugin(current_plugin, current_lines, hive, base, case_key)
                                if rec:
                                    fb_batch.append(rec)
                                current_plugin = m.group(1)
                                current_lines = [line]
                            elif current_plugin is not None:
                                current_lines.append(line)

                            if len(fb_batch) >= BATCH:
                                _em(cur, """
                                    INSERT INTO raw_fallback_v2(case_key,parser_family,source_file,payload)
                                    VALUES(%s,%s,%s,%s)
                                """, fb_batch)
                                inserted['fb_rows'] += len(fb_batch)
                                conn.commit()
                                fb_batch = []

                        # flush last plugin
                        rec = flush_plugin(current_plugin, current_lines, hive, base, case_key)
                        if rec:
                            fb_batch.append(rec)
                        if fb_batch:
                            _em(cur, """
                                INSERT INTO raw_fallback_v2(case_key,parser_family,source_file,payload)
                                VALUES(%s,%s,%s,%s)
                            """, fb_batch)
                            inserted['fb_rows'] += len(fb_batch)
                            conn.commit()
                    except Exception as e:
                        errors.append(f'regripper:{base}: {e}')

                # --- live network TXT pass -> raw_fallback_v2 ('live_network') ---
                # hosts/firewall/arp/ipconfig are STATE (no per-event ts); stored so the
                # network/RDP/firewall miners + LLM timeline can use them (firewall allow
                # 3389, hosts-file tampering, active C2 connections at collection time).
                for rel_path in live_txt_entries:
                    base = os.path.basename(rel_path)
                    kind = base.lower().rsplit('.', 1)[0]
                    try:
                        with zf.open(rel_path, 'r') as bf:
                            raw = bf.read().decode('utf-8', errors='ignore').replace('\x00', '')
                        fb_batch = []
                        if kind in ('hosts', 'arp'):
                            for line in raw.splitlines():
                                s = line.strip()
                                if not s or s.startswith('#'):
                                    continue
                                fb_batch.append((case_key, 'live_network', base,
                                                 Json({'kind': kind, 'line': s[:500]})))
                        else:
                            txt = raw.strip()
                            if txt:
                                for off in range(0, min(len(txt), 60000), 8000):
                                    fb_batch.append((case_key, 'live_network', base,
                                                     Json({'kind': kind, 'text': txt[off:off + 8000]})))
                        for off in range(0, len(fb_batch), BATCH):
                            _em(cur, """
                                INSERT INTO raw_fallback_v2(case_key,parser_family,source_file,payload)
                                VALUES(%s,%s,%s,%s)
                            """, fb_batch[off:off + BATCH])
                        inserted['fb_rows'] += len(fb_batch)
                        conn.commit()
                    except Exception as e:
                        errors.append(f'live_network:{base}: {e}')

                # --- collector self-declaration pass -> raw_fallback_v2 ('collector_self') ---
                # Comment lines start with '#'; every other non-empty line is one path.
                # Stored verbatim (payload {'path': ...}); normalization and the narrow
                # matching rules live in analysis/collector_self.py.
                for rel_path in susp_entries:
                    base = os.path.basename(rel_path.replace(chr(92), '/'))
                    try:
                        with zf.open(rel_path, 'r') as bf:
                            raw = bf.read().decode('utf-8-sig', errors='ignore').replace(chr(0), '')
                        seen_susp, fb_batch = set(), []
                        for line in raw.splitlines():
                            t = line.strip().strip(chr(34)).strip()
                            if not t or t.startswith('#'):
                                continue
                            k = t.lower()
                            if k in seen_susp:
                                continue
                            seen_susp.add(k)
                            fb_batch.append((case_key, 'suspicious_files', base,
                                             Json({'path': t[:400]})))
                        if fb_batch:
                            cur.execute("DELETE FROM raw_fallback_v2 WHERE case_key=%s "
                                        "AND parser_family='suspicious_files'", (case_key,))
                            execute_values(cur, "INSERT INTO raw_fallback_v2 "
                                                "(case_key, parser_family, source_file, payload) "
                                                "VALUES %s", fb_batch, page_size=500)
                            inserted['fb_rows'] += len(fb_batch)
                    except Exception as _se:
                        _log.error('[ingest] suspicious_files.txt failed: %s', repr(_se)[:140])

                for rel_path in self_decl_entries:
                    base = os.path.basename(rel_path.replace(chr(92), '/'))
                    try:
                        with zf.open(rel_path, 'r') as bf:
                            raw = bf.read().decode('utf-8-sig', errors='ignore').replace(chr(0), '')
                        seen_self, fb_batch, meta_batch = set(), [], []
                        seen_meta = set()
                        for line in raw.splitlines():
                            t = line.strip().strip(chr(34)).strip()
                            if t.startswith('#'):
                                # Collector v4.5+ declares its identity in the comments:
                                # "# collector_version 4.5", "# collector_started ...",
                                # "# collector_started_utc ...", "# collector_host ...".
                                # Older builds write none of them, and an archive with no
                                # version is one made before the Prefetch/ShimCache rescue
                                # existed - the report has to say so instead of treating a
                                # half-blind case as a complete one (INTEGRATION_CONTRACT
                                # section 2; case case_08, 2026-09-07).
                                try:
                                    from analysis.collector_self import parse_self_meta
                                    mk, mv = parse_self_meta(t)
                                except Exception:
                                    mk, mv = '', ''
                                # only the collector's own keys - a prose comment line
                                # ("# paths THIS collector added...") must not become data
                                if mk and mv and mk not in seen_meta:
                                    seen_meta.add(mk)
                                    meta_batch.append((case_key, 'collector_self_meta', base,
                                                       Json({'key': mk, 'value': mv[:200]})))
                                continue
                            if not t:
                                continue
                            k = t.lower()
                            if k in seen_self:
                                continue
                            seen_self.add(k)
                            fb_batch.append((case_key, 'collector_self', base,
                                             Json({'path': t[:400]})))
                        if fb_batch or meta_batch:
                            cur.execute("""
                                DELETE FROM raw_fallback_v2
                                 WHERE case_key=%s
                                   AND parser_family IN ('collector_self','collector_self_meta')
                            """, (case_key,))
                        if fb_batch:
                            _em(cur, """
                                INSERT INTO raw_fallback_v2(case_key,parser_family,source_file,payload)
                                VALUES(%s,%s,%s,%s)
                            """, fb_batch)
                            inserted['fb_rows'] += len(fb_batch)
                        if meta_batch:
                            _em(cur, """
                                INSERT INTO raw_fallback_v2(case_key,parser_family,source_file,payload)
                                VALUES(%s,%s,%s,%s)
                            """, meta_batch)
                            inserted['fb_rows'] += len(meta_batch)
                        if fb_batch or meta_batch:
                            conn.commit()
                    except Exception as e:
                        errors.append('collector_self:' + base + ': ' + str(e))

                # --- Hindsight JSONL pass → raw_fallback_v2 (browser_* families) ---
                # ADDITIVE: ObsidianForensics_Hindsight FULL-mode export. Stored into the
                # SAME raw_fallback_v2 / parser_family storage the bot already mines for
                # fb_browser_history / fb_browser_downloads, so assemblers.py /
                # agent_tools.py browser queries pick it up with zero new consumer code.
                for rel_path in hindsight_entries:
                    base = os.path.basename(rel_path)
                    try:
                        with zf.open(rel_path, 'r') as bf:
                            raw = bf.read().decode('utf-8', errors='ignore').replace('\x00', '')
                        fb_batch = []
                        for line in raw.splitlines():
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                obj = json.loads(line)
                            except Exception:
                                continue  # tolerate non-JSON / partial lines
                            try:
                                rec = hindsight_record_to_fallback(obj)
                            except Exception:
                                rec = None  # never crash ingestion on a single bad record
                            if not rec:
                                continue
                            parser_family, payload = rec
                            fb_batch.append((case_key, parser_family, base, Json(payload)))
                            if len(fb_batch) >= BATCH:
                                _em(cur, """
                                    INSERT INTO raw_fallback_v2(case_key,parser_family,source_file,payload)
                                    VALUES(%s,%s,%s,%s)
                                """, fb_batch)
                                inserted['fb_rows'] += len(fb_batch)
                                conn.commit()
                                fb_batch = []
                        if fb_batch:
                            _em(cur, """
                                INSERT INTO raw_fallback_v2(case_key,parser_family,source_file,payload)
                                VALUES(%s,%s,%s,%s)
                            """, fb_batch)
                            inserted['fb_rows'] += len(fb_batch)
                            conn.commit()
                    except Exception as e:
                        errors.append(f'hindsight:{base}: {e}')

                # BROWSER_SQLITE_PASS (ADDITIVE): raw Chrome/Edge 'History' &
                # Firefox 'places.sqlite' from a STANDARD KAPE collection (Targets
                # only, no Hindsight module). Emits the SAME (parser_family,payload)
                # tuples as the Hindsight pass into raw_fallback_v2, so existing
                # browser consumers pick it up. GATED on 'no hindsight_entries' so
                # collector-EXE cases (which already have Hindsight JSONL) are NOT
                # double-counted.
                if not hindsight_entries:
                    try:
                        from parsers.browser_sqlite import is_browser_history_file as _bh_is, parse_file as _bh_parse
                    except Exception:
                        _bh_is = None
                    if _bh_is is not None:
                        import tempfile as _bh_tf, shutil as _bh_sh
                        _bh_list = [(n, _bh_is(n)) for n in all_names]
                        _bh_list = [(n, k) for n, k in _bh_list if k]
                        for _bh_rel, _bh_kind in _bh_list:
                            _bh_base = os.path.basename(_bh_rel)
                            _bh_td = None
                            try:
                                _bh_td = _bh_tf.mkdtemp(prefix='bhist_')
                                _bh_main = os.path.join(_bh_td, _bh_base or 'History')
                                with zf.open(_bh_rel, 'r') as _s, open(_bh_main, 'wb') as _d:
                                    _bh_sh.copyfileobj(_s, _d)
                                for _sib in (_bh_rel + '-wal', _bh_rel + '-shm'):
                                    if _sib in all_names:
                                        with zf.open(_sib, 'r') as _s2, open(os.path.join(_bh_td, os.path.basename(_sib)), 'wb') as _d2:
                                            _bh_sh.copyfileobj(_s2, _d2)
                                _bh_recs = _bh_parse(_bh_main, _bh_kind) or []
                                _bh_batch = [(case_key, _fam, _bh_base, Json(_pl)) for _fam, _pl in _bh_recs]
                                for _bi in range(0, len(_bh_batch), BATCH):
                                    _em(cur, """
                                        INSERT INTO raw_fallback_v2(case_key,parser_family,source_file,payload)
                                        VALUES(%s,%s,%s,%s)
                                    """, _bh_batch[_bi:_bi + BATCH])
                                    conn.commit()
                                inserted['fb_rows'] += len(_bh_batch)
                            except Exception as _bh_e:
                                errors.append('browser_sqlite:%s: %s' % (_bh_base, _bh_e))
                            finally:
                                if _bh_td:
                                    _bh_sh.rmtree(_bh_td, ignore_errors=True)

                # --- _raw/browsers pass: our own vao_parser_browser over the RAW browser
                # databases the collector ships in the OUTPUT archive (_raw/browsers/...).
                # Runs ALONGSIDE NirSoft/Hindsight - their file names never match ours, so
                # nothing is double counted - and adds what they cannot give: the full
                # download URL chain, decoded visit transitions and resolved referrers.
                # Each DB is extracted with its -wal/-shm sidecars or the newest history
                # (the part that matters most) would be invisible.
                try:
                    from parsers.vao_browser import parse_from_zip as _vb_parse
                except Exception:
                    _vb_parse = None
                if _vb_parse is not None:
                    try:
                        _vb_recs, _vb_errs = _vb_parse(zf, all_names)
                        _vb_batch = [(case_key, _vf,
                                      (_vp.get('source_file') or 'vao_parser_browser'), Json(_vp))
                                     for _vf, _vp in _vb_recs]
                        for _vi in range(0, len(_vb_batch), BATCH):
                            _em(cur, """
                                INSERT INTO raw_fallback_v2(case_key,parser_family,source_file,payload)
                                VALUES(%s,%s,%s,%s)
                            """, _vb_batch[_vi:_vi + BATCH])
                            conn.commit()
                        inserted['fb_rows'] += len(_vb_batch)
                        for _ve in _vb_errs[:5]:
                            errors.append('vao_browser:' + _ve)
                    except Exception as _vb_e:
                        errors.append('vao_browser: %s' % _vb_e)

                # Browser EXTENSIONS - the quietest foothold there is: reads every page,
                # survives a password change, has no process and appears in no execution
                # artefact. The collector started forwarding Preferences / extensions.json
                # on 2026-08-22; before that the question had no source at all.
                try:
                    from parsers.browser_extensions import parse_from_zip as _bx_parse
                except Exception:
                    _bx_parse = None
                if _bx_parse is not None:
                    try:
                        _bx_recs, _bx_errs = _bx_parse(zf, all_names)
                        _bx_batch = [(case_key, _bf,
                                      (_bp.get('source_file') or 'browser_extensions'), Json(_bp))
                                     for _bf, _bp in _bx_recs]
                        for _bi in range(0, len(_bx_batch), BATCH):
                            _em(cur, """
                                INSERT INTO raw_fallback_v2(case_key,parser_family,source_file,payload)
                                VALUES(%s,%s,%s,%s)
                            """, _bx_batch[_bi:_bi + BATCH])
                            conn.commit()
                        inserted['fb_rows'] += len(_bx_batch)
                        for _be in _bx_errs[:5]:
                            errors.append('browser_extensions:' + _be)
                    except Exception as _bx_e:
                        errors.append('browser_extensions: %s' % _bx_e)

                # --- hashes.csv pass: the collector hashed exactly the files its MFT
                # sweep flagged. Store them, then check OFFLINE reputation databases.
                # Offline on purpose: an online lookup would disclose to a third party
                # which case is being worked on (owner's decision 2026-08-08).
                try:
                    _hs_rel = next((n for n in all_names
                                    if n.lower().replace(chr(92), '/').endswith('hashes.csv')), None)
                except Exception:
                    _hs_rel = None
                if _hs_rel:
                    try:
                        import csv as _hs_csv, io as _hs_io
                        with zf.open(_hs_rel, 'r') as _hf:
                            _hs_rows = list(_hs_csv.DictReader(
                                _hs_io.TextIOWrapper(_hf, encoding='utf-8', errors='replace')))
                        _hs_batch = [(case_key, 'file_hashes', 'hashes.csv', Json(_r))
                                     for _r in _hs_rows]
                        for _hi in range(0, len(_hs_batch), BATCH):
                            _em(cur, """
                                INSERT INTO raw_fallback_v2(case_key,parser_family,source_file,payload)
                                VALUES(%s,%s,%s,%s)
                            """, _hs_batch[_hi:_hi + BATCH])
                            conn.commit()
                        inserted['fb_rows'] += len(_hs_batch)

                        try:
                            from analysis.hash_lookup import lookup_rows as _hs_lookup
                        except Exception:
                            _hs_lookup = None
                        if _hs_lookup is not None and _hs_rows:
                            _hs_res = _hs_lookup(_hs_rows)
                            _al = []
                            for _b in _hs_res.get('bad') or []:
                                _al.append((case_key, 'malwarebazaar', 'critical',
                                            'known malware hash (offline MalwareBazaar set)',
                                            None, None, _b.get('sha256'),
                                            'file: %s' % (_b.get('path') or '')[:400],
                                            'hashes.csv', Json(_b)))
                            for _ai in range(0, len(_al), BATCH):
                                _em(cur, """
                                    INSERT INTO tool_alerts_v2(case_key,tool,severity,rule,computer,
                                        user_name,ioc_value,details,source_file,payload)
                                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                                """, _al[_ai:_ai + BATCH])
                                conn.commit()
                            inserted['alert_rows'] = inserted.get('alert_rows', 0) + len(_al)
                    except Exception as _hs_e:
                        errors.append('hashes_csv: %s' % _hs_e)

                # --- Autoruns triage: filter untrusted+enabled persistence, then rank
                # against the vanilla Windows baseline (Study Course method, automated).
                try:
                    _ar_rel = next((n for n in all_names
                                    if n.lower().replace(chr(92), '/').endswith('autoruns.csv')), None)
                except Exception:
                    _ar_rel = None
                if _ar_rel:
                    try:
                        import csv as _ar_csv, io as _ar_io
                        with zf.open(_ar_rel, 'r') as _af:
                            _ar_rows = list(_ar_csv.DictReader(
                                _ar_io.TextIOWrapper(_af, encoding='utf-8-sig', errors='replace')))
                        from analysis.autoruns_triage import triage as _ar_triage
                        _ar_res = _ar_triage(_ar_rows)
                        _ar_alerts = []
                        for _h in (_ar_res.get('high') or []):
                            _ar_alerts.append((
                                case_key, 'autoruns', 'high',
                                'suspicious persistence entry',
                                None, None, (_h.get('image_path') or '')[:400],
                                '; '.join(_h.get('reasons') or [])[:900],
                                'Autoruns.csv', Json(_h)))
                        for _ai in range(0, len(_ar_alerts), BATCH):
                            _em(cur, """
                                INSERT INTO tool_alerts_v2(case_key,tool,severity,rule,computer,
                                    user_name,ioc_value,details,source_file,payload)
                                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                            """, _ar_alerts[_ai:_ai + BATCH])
                            conn.commit()
                        inserted['alert_rows'] = inserted.get('alert_rows', 0) + len(_ar_alerts)
                    except Exception as _ar_e:
                        errors.append('autoruns_triage: %s' % _ar_e)

                # --- ADS pass: what is INSIDE the non-standard streams (collector v4.9+) ---
                # $MFT gives only the stream name and size; the collector saves up to 1 MB of
                # each stream as ads/NNNN.bin. One alert per stream, kind + printable preview.
                try:
                    _ads_rel = next((n for n in all_names
                                     if n.lower().replace(chr(92), '/').rsplit('/', 1)[-1] == 'ads_streams.csv'), None)
                except Exception:
                    _ads_rel = None
                if _ads_rel:
                    try:
                        import csv as _ads_csv, io as _ads_io
                        from analysis.ads_content import analyse as _ads_analyse
                        _ads_base = _ads_rel[:len(_ads_rel) - len('ads_streams.csv')]
                        _ads_names = {n.replace(chr(92), '/').lower(): n for n in all_names}
                        with zf.open(_ads_rel, 'r') as _af:
                            _ads_rows = list(_ads_csv.DictReader(
                                _ads_io.TextIOWrapper(_af, encoding='utf-8-sig', errors='replace')))

                        def _ads_read(rel):
                            key = (_ads_base + rel).replace(chr(92), '/').lower()
                            if key not in _ads_names:
                                return None
                            with zf.open(_ads_names[key], 'r') as _bf:
                                return _bf.read(1048577)

                        _ads_al = []
                        for _h in _ads_analyse(_ads_rows, _ads_read):
                            _ads_al.append((
                                case_key, 'ads', _h['severity'],
                                'hidden NTFS stream: %s' % _h['kind'],
                                None, None, ('%s:%s' % (_h['path'], _h['stream']))[:400],
                                ('%s; %d B; %s' % (_h['kind_label'], _h['size'], _h['preview']))[:900],
                                'ads_streams.csv', Json(_h)))
                        for _ai in range(0, len(_ads_al), BATCH):
                            _em(cur, """
                                INSERT INTO tool_alerts_v2(case_key,tool,severity,rule,computer,
                                    user_name,ioc_value,details,source_file,payload)
                                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                            """, _ads_al[_ai:_ai + BATCH])
                            conn.commit()
                        inserted['alert_rows'] = inserted.get('alert_rows', 0) + len(_ads_al)
                    except Exception as _ads_e:
                        errors.append('ads_content: %s' % _ads_e)

                # --- _raw/registry NTLM pass: offline SAM+SYSTEM -> sidecar -> tool_alerts_v2 ---
                try:
                    raw_names = [n for n in all_names if '_raw/registry/' in n.lower().replace('\\', '/')]
                    def _find_hive(suffix):
                        for n in raw_names:
                            if n.replace('\\', '/').lower().rsplit('/', 1)[-1] == suffix:
                                return n
                        return None
                    sam_n = _find_hive('sam'); sys_n = _find_hive('system')
                    if sam_n and sys_n:
                        import urllib.request as _ur, uuid as _uuid
                        sam_b = zf.read(sam_n); sys_b = zf.read(sys_n)
                        SIDE = os.getenv('DFIR_TOOLS_SIDECAR_URL', 'http://tools-sidecar:8799').rstrip('/')
                        bnd = '----ntlm' + _uuid.uuid4().hex
                        def _part(name, fn, data):
                            return (('--%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\n'
                                     'Content-Type: application/octet-stream\r\n\r\n' % (bnd, name, fn)).encode()
                                    + data + b'\r\n')
                        body = _part('sam', 'SAM', sam_b) + _part('system', 'SYSTEM', sys_b) + ('--%s--\r\n' % bnd).encode()
                        req = _ur.Request(SIDE + '/forensic/ntlm', data=body,
                                          headers={'Content-Type': 'multipart/form-data; boundary=%s' % bnd})
                        resp = json.loads(_ur.urlopen(req, timeout=120).read().decode())
                        accounts = resp.get('accounts') or []
                        EMPTY_NT = '31d6cfe0d16ae931b73c59d7e0c089c0'  # blank-password NT hash
                        arows = []
                        for a in accounts:
                            nt = str(a.get('nt') or ''); user = str(a.get('username') or '')
                            has_pw = bool(nt) and nt.lower() != EMPTY_NT
                            # our own offline hash recovery: information for the account table, never an
                            # attack signal (the report once called it an attacker running secretsdump)
                            sev = 'info'
                            arows.append((case_key, 'impacket-secretsdump', sev,
                                          'local NTLM hash recovered from offline SAM/SYSTEM',
                                          None, user or None, nt or None,
                                          ('rid=%s nt=%s%s' % (a.get('rid'), nt, '' if has_pw else ' (blank pw)'))[:500],
                                          '_raw/registry', Json({'rid': a.get('rid'), 'nt': nt, 'lm': a.get('lm'), 'blank_pw': (not has_pw)})))
                        if arows:
                            _em(cur, 
                                "INSERT INTO tool_alerts_v2(case_key,tool,severity,rule,computer,user_name,ioc_value,details,source_file,payload)"
                                " VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", arows)
                            inserted['alert_rows'] += len(arows)
                            conn.commit()
                        # password reuse: same non-blank NT hash on >=2 accounts = lateral-movement enabler
                        _byhash = {}
                        for a in accounts:
                            _nt = str(a.get('nt') or '').lower()
                            if _nt and _nt != EMPTY_NT:
                                _byhash.setdefault(_nt, []).append(str(a.get('username') or '?'))
                        rrows = []
                        for _h, _us in _byhash.items():
                            if len(_us) >= 2:
                                rrows.append((case_key, 'impacket-secretsdump', 'medium',
                                              'password reuse: identical NT hash across local accounts',
                                              None, (', '.join(_us))[:200], _h,
                                              ('accounts share the same password: ' + ', '.join(_us))[:500],
                                              '_raw/registry', Json({'nt': _h, 'accounts': _us})))
                        if rrows:
                            _em(cur, 
                                "INSERT INTO tool_alerts_v2(case_key,tool,severity,rule,computer,user_name,ioc_value,details,source_file,payload)"
                                " VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", rrows)
                            inserted['alert_rows'] += len(rrows)
                            conn.commit()
                except Exception as e:
                    try: conn.rollback()
                    except Exception: pass
                    errors.append('raw_ntlm: ' + str(e)[:200])

                # --- _raw/registry ASEP hive pass: SOFTWARE/SYSTEM/NTUSER autostarts -> raw_fallback_v2 ---
                try:
                    _raw_reg = [n for n in all_names if '_raw/registry/' in n.lower().replace(chr(92), '/')]
                    _reg_rows = _parse_registry_hives(zf, _raw_reg, case_key)
                    for _i0 in range(0, len(_reg_rows), BATCH):
                        _em(cur, 
                            "INSERT INTO raw_fallback_v2(case_key,parser_family,source_file,payload)"
                            " VALUES(%s,%s,%s,%s)", _reg_rows[_i0:_i0 + BATCH])
                        inserted['fb_rows'] += len(_reg_rows[_i0:_i0 + BATCH])
                        conn.commit()
                except Exception as e:
                    try: conn.rollback()
                    except Exception: pass
                    errors.append('reg_hives: ' + str(e)[:200])

                # --- _raw/rdpcache pass: RDP bitmap cache -> sidecar -> tool_alert ---
                # Accept BOTH the legacy .bmc (bcache*.bmc, pre-Win7) AND the modern
                # persistent bitmap cache Cache####.bin (Win8+/10/11 mstsc) — real
                # machines almost always have .bin, so filtering .bmc-only silently
                # recovered nothing. bmc-tools autodetects the container by header.
                try:
                    bmc_names = [n for n in all_names
                                 if '_raw/rdpcache/' in n.lower().replace('\\', '/')
                                 and (n.lower().endswith('.bmc') or n.lower().endswith('.bin'))]
                    if bmc_names:
                        import urllib.request as _ur2, uuid as _uuid2
                        SIDE2 = os.getenv('DFIR_TOOLS_SIDECAR_URL', 'http://tools-sidecar:8799').rstrip('/')
                        bnd2 = '----rd' + _uuid2.uuid4().hex
                        body2 = b''
                        for _i, _bn in enumerate(bmc_names[:50]):
                            _dat = zf.read(_bn)
                            _fn = os.path.basename(_bn.replace('\\', '/'))
                            body2 += (('--%s\r\nContent-Disposition: form-data; name="bmc%d"; filename="%s"\r\n'
                                       'Content-Type: application/octet-stream\r\n\r\n' % (bnd2, _i, _fn)).encode()
                                      + _dat + b'\r\n')
                        body2 += ('--%s--\r\n' % bnd2).encode()
                        _rq2 = _ur2.Request(SIDE2 + '/forensic/rdpcache', data=body2,
                                            headers={'Content-Type': 'multipart/form-data; boundary=%s' % bnd2})
                        _rj = json.loads(_ur2.urlopen(_rq2, timeout=240).read().decode())
                        _tc = int(_rj.get('tile_count') or 0)
                        if _tc > 0:
                            # PERSIST the reconstructed RDP screen collage — this is the
                            # whole point of RDP-cache forensics (you see what the attacker
                            # did on screen). Previously collage_b64 was returned then thrown
                            # away (only has_collage:bool survived). Save it under the case so
                            # the report/delivery layer can attach it.
                            _collage_rel = None
                            _cb64 = _rj.get('collage_b64')
                            if _cb64:
                                try:
                                    import base64 as _b64
                                    _art_dir = os.path.join(CASE_LIB, case_key, 'artifacts')
                                    os.makedirs(_art_dir, exist_ok=True)
                                    _collage_path = os.path.join(_art_dir, 'rdp_screen_cache.png')
                                    with open(_collage_path, 'wb') as _cf:
                                        _cf.write(_b64.b64decode(_cb64))
                                    _collage_rel = 'artifacts/rdp_screen_cache.png'
                                except Exception as _ce:
                                    errors.append('rdpcache_save: ' + str(_ce)[:120])
                            cur.execute(
                                "INSERT INTO tool_alerts_v2(case_key,tool,severity,rule,computer,user_name,ioc_value,details,source_file,payload)"
                                " VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                                (case_key, 'bmc-tools', 'med',
                                 'RDP bitmap cache reconstructed (RDP session screen fragments)',
                                 None, None, None,
                                 ('%d RDP cache tiles recovered from %d cache file(s) - visuals of the RDP session%s'
                                  % (_tc, len(bmc_names),
                                     ' (screen collage saved)' if _collage_rel else ''))[:500],
                                 '_raw/rdpcache', Json({'tile_count': _tc, 'bmc_files': len(bmc_names),
                                                        'has_collage': bool(_cb64),
                                                        'collage_path': _collage_rel})))
                            inserted['alert_rows'] += 1
                            conn.commit()
                except Exception as e:
                    try: conn.rollback()
                    except Exception: pass
                    errors.append('rdpcache: ' + str(e)[:200])

    # Refresh system profile from regripper text files (available in extended KAPE archive)
    try:
        _upsert_system_profile_v1(case_key)
    except Exception:
        try: conn.rollback()
        except: pass
        pass

    # COVERAGE: every archive entry the CSV pass did not mark is judged here. The TXT/JSON/
    # raw passes take whole name lists, so membership in a list means the pass saw the
    # file; the rest is either a deliberate skip (named in _skip_status) or a file the bot
    # was never taught - the one kind that must be visible in the report.
    _cov_summary = {}
    try:
        _pass_lists = (
            ('reg_hunter', locals().get('json_entries') or []),
            ('thor', locals().get('thor_entries') or []),
            ('loki', locals().get('loki_entries') or []),
            ('regripper', locals().get('regripper_entries') or []),
            ('live_network', locals().get('live_txt_entries') or []),
            ('collector_self', locals().get('self_decl_entries') or []),
            ('suspicious_files', locals().get('susp_entries') or []),
            ('hindsight', locals().get('hindsight_entries') or []),
            ('deepblue', locals().get('deepblue_entries') or []),
            ('chainsaw', locals().get('detections_entries') or []),
        )
        _cov_all = dict(locals().get('_cov') or {})
        for _n in (locals().get('all_names') or []):
            if _n.endswith('/') or _n in _cov_all:
                continue
            _fam = None
            for _pn, _lst in _pass_lists:
                if _n in _lst:
                    _fam = _pn
                    break
            if _fam is None:
                _fam = _raw_pass_family(_n)
            if _fam:
                _cov_all[_n] = (_fam, None, 'consumed', '')
            else:
                _cov_all[_n] = (None, 0, _skip_status(_n), '')
        _cov_summary = _persist_coverage(case_key, _ingest_job_id, _cov_all,
                                         locals().get('_sizes') or {},
                                         locals().get('_utf16_csvs') or [], errors)
    except Exception as _ce:
        errors.append('coverage: %s' % str(_ce)[:160])

    # mark the ingest job DONE (reaching here = the full loop completed)
    if _ingest_job_id is not None:
        try:
            with psycopg2.connect(PG_DSN) as _jc:
                _jc.autocommit = True
                with _jc.cursor() as _jcur:
                    _parsed = sum(int(v or 0) for v in inserted.values())
                    _jcur.execute("""UPDATE ingest_jobs SET status='done', finished_at=now(),
                        parsed_files=%s, errors_json=%s::jsonb WHERE job_id=%s""",
                        (_parsed, json.dumps(errors[:50]) if errors else '[]', _ingest_job_id))
                    try:
                        _jcur.execute("ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS coverage_json jsonb")
                        _jcur.execute("UPDATE ingest_jobs SET coverage_json=%s::jsonb WHERE job_id=%s",
                                      (json.dumps(_cov_summary or {}, ensure_ascii=False, default=str), _ingest_job_id))
                    except Exception:
                        pass
        except Exception:
            pass

    return {
        'ok': True,
        'zip': os.path.basename(zip_path),
        'event_rows': inserted['event_rows'],
        'fs_rows': inserted['fs_rows'],
        'pe_rows': inserted['pe_rows'],
        'srum_rows': inserted['srum_rows'],
        'fb_rows': inserted['fb_rows'],
        'alert_rows': inserted['alert_rows'],
        'errors': errors,
    }


def _em(cur, sql, rows):
    """executemany replacement: use execute_values (multi-row INSERT) for simple
    'INSERT ... VALUES(%s,%s,...)' templates; fall back to executemany otherwise.
    ~10-50x faster on bulk ingest; identical rows inserted."""
    if not rows:
        return
    m = _re.search(r'VALUES\s*\(\s*(?:%s\s*,\s*)*%s\s*\)', sql, _re.I)
    if m and 'ON CONFLICT' not in sql.upper() and 'RETURNING' not in sql.upper():
        newsql = sql[:m.start()] + 'VALUES %s' + sql[m.end():]
        execute_values(cur, newsql, rows, page_size=1000)
        return
    cur.executemany(sql, rows)


def _open_csv_text(zf, rel_path, bf):
    """Text stream for a CSV inside the archive, honouring a UTF-16 BOM.

    MPLog_*.csv from the collector is UTF-16LE; read as UTF-8 every key came out as
    't\x00i\x00m\x00e', jsonb refused the payload and (2026-09-02) the failed statement
    took the whole ingest with it.
    """
    with zf.open(rel_path, 'r') as probe:
        head = probe.read(2)
    enc = 'utf-16' if head in (b'\xff\xfe', b'\xfe\xff') else 'utf-8-sig'
    return io.TextIOWrapper(bf, encoding=enc, errors='ignore', newline='')


def _reset_txn(conn):
    """After a failed statement the connection may sit in an aborted transaction; clear it."""
    try:
        conn.rollback()
    except Exception:
        pass


# Files the ingest leaves alone ON PURPOSE. Everything else that lands in no pass is an
# UNKNOWN artefact and is reported as such - that is the whole point of the coverage table.
_SKIP_BY_DESIGN = (
    ('execution_findings.txt', 'twin of execution_findings.csv'),
    ('/ads/0', 'stream contents: read by the ADS pass'),
    ('filesystem_tree.txt', 'kept as a case asset, not rows'),
    ('encryption_status_examiner.csv', 'examiner workstation, never case evidence'),
    ('$boot_output.csv', 'not useful for DFIR'),
    ('$sds_output.csv', 'not useful for DFIR'),
    ('amcache_devicecontainers', 'hardware noise'),
    ('amcache_devicepnps', 'hardware noise'),
    ('amcache_driverpackages', 'hardware noise'),
    ('energyusage_output', 'SRUM table without forensic value'),
    ('pushnotifications_output', 'SRUM table without forensic value'),
    ('vfuprov_output', 'SRUM table without forensic value'),
    ('hayabusa_event_statistics', 'aggregate counts, not events'),
    ('consolelog', 'KAPE run log'), ('copylog', 'KAPE run log'), ('skiplog', 'KAPE run log'),
    ('-journal', 'SQLite journal sidecar'), ('-wal', 'SQLite sidecar'), ('-shm', 'SQLite sidecar'),
    ('favicons', 'browser icon cache'), ('top sites', 'browser cache'), ('web data', 'browser autofill store'),
    ('cookies', 'browser cookies (not parsed)'), ('login data', 'credential store (not parsed)'),
    ('_raw/minidump/', 'crash dumps: listed, not parsed'),
    ('_raw/registry/', 'hive consumed by the NTLM/ASEP/sysinfo passes'),
    ('_raw/rdpcache/', 'consumed by the RDP bitmap-cache pass'),
    ('hashes.csv', 'consumed by the hashes pass'),
)


def _skip_status(rel_path):
    """'skipped:<reason>' for a file the ingest ignores by design, else 'unconsumed'."""
    low = '/' + (rel_path or '').replace(chr(92), '/').lower()
    for pat, why in _SKIP_BY_DESIGN:
        if pat in low:
            return 'skipped:' + why
    return 'unconsumed'


def _raw_pass_family(rel_path):
    """Family of the raw-artefact pass that reads this entry, or None."""
    low = (rel_path or '').replace(chr(92), '/').lower()
    base = low.rsplit('/', 1)[-1]
    if '_raw/browsers/' in low:
        if base.endswith('history') or base.endswith('places.sqlite'):
            return 'vao_browser'
        if base.endswith('preferences') or base.endswith('extensions.json'):
            return 'browser_extensions'
        if base.endswith('bookmarks') or base.endswith('shortcuts'):
            return 'vao_browser'
        return None
    if '_raw/registry/' in low:
        return 'raw_hives'
    if '_raw/rdpcache/' in low:
        return 'rdpcache'
    if base == 'hashes.csv':
        return 'file_hashes'
    if base in ('_collector_footprint.txt', '_collector_self.txt'):
        return 'collector_self'
    return None


def _persist_coverage(case_key, job_id, cov, sizes, utf16_csvs, errors):
    """Write dfir_ingest_coverage_v1 rows for this job and return the summary dict."""
    by_status = {}
    by_folder = {}
    unconsumed = []
    for rel, (fam, rows, status, note) in cov.items():
        key = status.split(':', 1)[0]
        by_status[key] = by_status.get(key, 0) + 1
        folder = rel.replace(chr(92), '/').split('/')[0] if '/' in rel.replace(chr(92), '/') else '(root)'
        d = by_folder.setdefault(folder, {'files': 0, 'consumed': 0, 'unconsumed': 0, 'rejected': 0})
        d['files'] += 1
        if key in d:
            d[key] += 1
        if key == 'unconsumed':
            unconsumed.append({'path': rel, 'size': int(sizes.get(rel) or 0)})
    unconsumed.sort(key=lambda x: -x['size'])
    summary = {
        'files_total': len(cov),
        'consumed': by_status.get('consumed', 0),
        'empty': by_status.get('empty', 0),
        'unconsumed': by_status.get('unconsumed', 0),
        'rejected': by_status.get('rejected', 0),
        'skipped_by_design': by_status.get('skipped', 0),
        'utf16_csvs': len(utf16_csvs or []),
        'first_error': (errors[0][:200] if errors else None),
        'unconsumed_top': unconsumed[:25],
        'by_folder': by_folder,
    }
    if psycopg2 is None:
        return summary
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS public.dfir_ingest_coverage_v1 (
                              id bigserial PRIMARY KEY,
                              case_key text NOT NULL,
                              job_id bigint,
                              rel_path text NOT NULL,
                              family text,
                              rows integer,
                              status text NOT NULL,
                              note text,
                              size_bytes bigint,
                              ingested_at timestamptz DEFAULT now())""")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_ingest_cov_case ON public.dfir_ingest_coverage_v1(case_key)")
            cur.execute("DELETE FROM public.dfir_ingest_coverage_v1 WHERE case_key=%s", (case_key,))
            batch = [(case_key, job_id, rel, fam, rows, status, note, int(sizes.get(rel) or 0))
                     for rel, (fam, rows, status, note) in cov.items()]
            for i in range(0, len(batch), 500):
                execute_values(cur, """INSERT INTO public.dfir_ingest_coverage_v1
                    (case_key, job_id, rel_path, family, rows, status, note, size_bytes) VALUES %s""",
                    batch[i:i + 500])
    return summary


def _flush_batch(cur, conn, kind, case_key, batch, alert_batch, inserted):
    """Flush a batch of rows to the appropriate table based on artifact kind."""
    # Alert-only kinds (batch contains nothing, alerts go to tool_alerts_v2)
    if kind in ('hayabusa_alert', 'dfir_alert'):
        if alert_batch:
            _em(cur, """
                INSERT INTO tool_alerts_v2(case_key,tool,severity,rule,event_ts,computer,
                    user_name,ioc_value,details,source_file,payload)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, alert_batch)
            inserted['alert_rows'] += len(alert_batch)
        conn.commit()
        return

    if not batch:
        # Still flush any alert_batch that may have accumulated
        if alert_batch:
            _em(cur, """
                INSERT INTO tool_alerts_v2(case_key,tool,severity,rule,event_ts,computer,
                    user_name,ioc_value,details,source_file,payload)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, alert_batch)
            inserted['alert_rows'] += len(alert_batch)
            conn.commit()
        return

    if kind in ('event', 'event_alert', 'logon_logoff', 'rdp_usage', 'smb_logon'):
        _em(cur, """
            INSERT INTO event_logs_v2(case_key,event_id,event_ts,channel,provider,computer,
                remote_host,target_user,logon_type,process_name,command_line,payload,source_file)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, batch)
        inserted['event_rows'] += len(batch)
        if alert_batch:
            _em(cur, """
                INSERT INTO tool_alerts_v2(case_key,tool,severity,rule,event_ts,computer,
                    user_name,ioc_value,details,source_file,payload)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, alert_batch)
            inserted['alert_rows'] += len(alert_batch)
    elif kind in ('fs_mft', 'fs_usn', 'fs_motw'):
        _em(cur, """
            INSERT INTO filesystem_v2(case_key,event_ts,file_name,extension,parent_path,
                action,source_file,payload)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
        """, batch)
        inserted['fs_rows'] += len(batch)
    elif kind in ('pe_prefetch', 'pe_amcache', 'pe_amcache_prog', 'pe_shimcache', 'pe_bam'):
        _em(cur, """
            INSERT INTO program_exec_v2(case_key,event_ts,executable_name,full_path,
                hash_sha1,source_file,payload)
            VALUES(%s,%s,%s,%s,%s,%s,%s)
        """, batch)
        inserted['pe_rows'] += len(batch)
    elif kind in ('srum_netconn', 'srum_netusage', 'srum_appres'):
        _em(cur, """
            INSERT INTO srum_v2(case_key,event_ts,username,exe_info,source_file,payload)
            VALUES(%s,%s,%s,%s,%s,%s)
        """, batch)
        inserted['srum_rows'] += len(batch)
    elif kind == 'communications':
        cur.execute("""CREATE TABLE IF NOT EXISTS public.communications_v1 (
            row_id bigserial PRIMARY KEY, case_key text NOT NULL, platform text,
            source_kind text, self_account text, contact_id text, contact_name text,
            direction text, msg_ts timestamptz, message_text text, thread_id text,
            attachment text, source_artifact text, confidence text, payload jsonb,
            created_at timestamptz DEFAULT now())""")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_comms_ck ON public.communications_v1(case_key)")
        _em(cur, """
            INSERT INTO communications_v1(case_key,platform,source_kind,self_account,
                contact_id,contact_name,direction,msg_ts,message_text,thread_id,
                attachment,source_artifact,confidence,payload)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, batch)
        inserted['comms_rows'] = inserted.get('comms_rows', 0) + len(batch)
    elif kind == 'thor_md5':
        _em(cur, """
            INSERT INTO raw_fallback_v2(case_key,parser_family,source_file,payload)
            VALUES(%s,%s,%s,%s)
        """, batch)
        inserted['fb_rows'] += len(batch)
    elif kind.startswith('fb_'):
        _em(cur, """
            INSERT INTO raw_fallback_v2(case_key,parser_family,source_file,payload)
            VALUES(%s,%s,%s,%s)
        """, batch)
        inserted['fb_rows'] += len(batch)
    conn.commit()


