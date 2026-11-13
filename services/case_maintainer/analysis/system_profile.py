"""System profile: registry-based host fingerprinting."""
import json, logging, os, re, psycopg2
from datetime import datetime, timezone
from core.config import PG_DSN, CASE_LIB
from reports.claims import _safe_case_folder

_log = logging.getLogger('app')

def _ensure_system_profile_table():
    sql = """
    CREATE TABLE IF NOT EXISTS public.system_profile_v1 (
      case_key text PRIMARY KEY,
      computer_name text,
      hostname text,
      os_name text,
      build text,
      install_date_utc text,
      timezone text,
      utc_offset text,
      last_shutdown_utc text,
      users_json jsonb,
      source_kind text,
      updated_at timestamptz default now()
    );
    """
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(sql)


def _registry_system_profile(case_key):
    out = {
        'computer_name': None, 'hostname': None, 'os_name': None, 'build': None,
        'install_date_utc': None, 'timezone': None, 'utc_offset': None, 'last_shutdown_utc': None,
        'users': []
    }
    logs_dir = os.path.join(CASE_LIB, _safe_case_folder(case_key), 'uploads', 'logs')
    zip_path = os.path.join(logs_dir, f'{case_key}_kape_output.zip')
    if not os.path.isfile(zip_path):
        import glob as _glob
        candidates = _glob.glob(os.path.join(logs_dir, '*.zip'))
        zip_path = candidates[0] if candidates else zip_path
    if not os.path.isfile(zip_path):
        return out

    import zipfile, re

    def _read_txt(inner):
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                raw = zf.read(inner)
            try:
                return raw.decode('utf-16le', errors='ignore')
            except Exception:
                return raw.decode('utf-8', errors='ignore')
        except Exception:
            return ''

    system_txt = _read_txt('Registry/regripper-system.txt')
    software_txt = _read_txt('Registry/regripper-software.txt')
    sam_txt = _read_txt('Registry/regripper-sam.txt')

    # system keys
    m = re.search(r'ComputerName\s*=\s*([^\r\n]+)', system_txt)
    if m: out['computer_name'] = m.group(1).strip()
    m = re.search(r'TCP/IP Hostname\s*=\s*([^\r\n]+)', system_txt)
    if m: out['hostname'] = m.group(1).strip()
    m = re.search(r'ShutdownTime\s*:\s*([^\r\n]+)', system_txt)
    if m: out['last_shutdown_utc'] = m.group(1).strip()
    m = re.search(r'TimeZoneKeyName\s*[-=>: ]+\s*([^\r\n]+)', system_txt)
    if m: out['timezone'] = m.group(1).strip()
    m = re.search(r'Bias\s*[-=>: ]+\s*(-?\d+)\s*\((-?\d+)\s*hours\)', system_txt)
    if m:
        # Windows bias semantics: -120 means UTC+02:00
        hh = int(m.group(2)) * -1
        out['utc_offset'] = f"UTC{hh:+03d}:00"

    # software keys
    m = re.search(r'ProductName\s+([^\r\n]+)', software_txt)
    if m: out['os_name'] = m.group(1).strip()
    m = re.search(r'BuildLabEx\s+([^\r\n]+)', software_txt)
    if m:
        b = m.group(1).strip()
        out['build'] = b.split('.')[0] if b else None
    m = re.search(r'InstallDate\s+([^\r\n]+)', software_txt)
    if m: out['install_date_utc'] = m.group(1).strip()

    # SAM users
    users = []
    for block in re.split(r'Username\s*:\s*', sam_txt):
        block = block.strip()
        if not block:
            continue
        uname_raw = block.splitlines()[0].strip()
        # normalize to readable "Name [RID]" when possible
        mname = re.search(r'([A-Za-z0-9_.-]+\s*\[\d+\])', uname_raw)
        uname = mname.group(1).strip() if mname else uname_raw
        if (not uname) or ('samparse' in uname.lower()):
            continue
        u = {'username': uname, 'sid': None, 'created_utc': None, 'last_login_utc': None, 'disabled': False}
        msid = re.search(r'SID\s*:\s*([^\r\n]+)', block)
        if msid:
            u['sid'] = msid.group(1).strip()
            if u['sid'].endswith('-500'):
                u['username'] = 'Administrator [500]'
            elif u['sid'].endswith('-501'):
                u['username'] = 'Guest [501]'
        mcr = re.search(r'Account Created\s*:\s*([^\r\n]+)', block)
        if mcr: u['created_utc'] = mcr.group(1).strip()
        mll = re.search(r'Last Login Date\s*:\s*([^\r\n]+)', block)
        if mll: u['last_login_utc'] = mll.group(1).strip()
        if 'Account Disabled' in block:
            u['disabled'] = True
        users.append(u)
    # dedup usernames
    ded=[]; seen=set()
    for u in users:
        k=u['username'].lower()
        if k in seen:
            continue
        seen.add(k); ded.append(u)
    out['users'] = ded[:20]

    # FAST fallback: no regripper text (FAST collection) -> derive OS from the _raw
    # SOFTWARE/SYSTEM hives via the tools-sidecar (impacket), users from recovered
    # NTLM accounts. Additive: only fills fields the regripper pass left empty.
    if not out.get('os_name') or not out.get('users'):
        if not out.get('os_name'):
            try:
                import urllib.request as _ur, uuid as _uuid
                with zipfile.ZipFile(zip_path, 'r') as _zf:
                    _names = _zf.namelist()
                    def _findhive(nm):
                        for _n in _names:
                            _p = _n.replace('\\', '/').lower()
                            if '_raw/registry/' in _p and _p.rsplit('/', 1)[-1] == nm:
                                return _zf.read(_n)
                        return None
                    _sw = _findhive('software'); _sy = _findhive('system')
                if _sw:
                    _SIDE = os.getenv('DFIR_TOOLS_SIDECAR_URL', 'http://tools-sidecar:8799').rstrip('/')
                    _bnd = '----si' + _uuid.uuid4().hex
                    def _part(nm, fn, dat):
                        return (('--%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\n'
                                 'Content-Type: application/octet-stream\r\n\r\n' % (_bnd, nm, fn)).encode()
                                + dat + b'\r\n')
                    _body = _part('software', 'SOFTWARE', _sw)
                    if _sy:
                        _body += _part('system', 'SYSTEM', _sy)
                    _body += ('--%s--\r\n' % _bnd).encode()
                    _rq = _ur.Request(_SIDE + '/forensic/sysinfo', data=_body,
                                      headers={'Content-Type': 'multipart/form-data; boundary=%s' % _bnd})
                    _si = (json.loads(_ur.urlopen(_rq, timeout=180).read().decode()).get('sysinfo') or {})
                    if _si.get('os_name'):
                        _osn = str(_si['os_name'])
                        if _si.get('display_version'):
                            _osn += ' ' + str(_si['display_version'])
                        out['os_name'] = _osn
                    out['build'] = out.get('build') or _si.get('build')
                    out['computer_name'] = out.get('computer_name') or _si.get('computer_name')
                    if _si.get('install_date') and not out.get('install_date_utc'):
                        try:
                            out['install_date_utc'] = datetime.fromtimestamp(
                                int(_si['install_date']), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
                        except Exception:
                            pass
            except Exception:
                pass
        if not out.get('users'):
            try:
                with psycopg2.connect(PG_DSN) as _c:
                    with _c.cursor() as _cur:
                        _cur.execute(
                            "SELECT DISTINCT user_name FROM tool_alerts_v2 WHERE case_key=%s "
                            "AND tool='impacket-secretsdump' AND user_name IS NOT NULL "
                            "AND rule LIKE 'local NTLM%%'", (case_key,))
                        out['users'] = [{'username': _r[0], 'sid': None, 'created_utc': None,
                                         'last_login_utc': None, 'disabled': False}
                                        for _r in _cur.fetchall()][:20]
            except Exception:
                pass

    return out


def _system_profile_enricher_v1(case_key, base):
    out = dict(base or {})
    out.setdefault('users', [])
    out.setdefault('profiles_on_disk', [])
    out.setdefault('local_accounts', [])
    out.setdefault('incident_users', [])
    out.setdefault('related_hosts', [])
    out.setdefault('ips', [])

    def _is_machine_or_service_user(u):
        s = str(u or '').strip().lower()
        if not s:
            return True
        if s.endswith('$'):
            return True
        bad_prefix = ['system', 'local service', 'network service', 'dwm-', 'umfd-']
        bad_exact = {'guest [501]', 'defaultaccount [503]', 'wdagutilityaccount [504]', 'defaultaccount', 'wdagutilityaccount'}
        if s in bad_exact:
            return True
        return any(s.startswith(x) for x in bad_prefix)

    def _norm_user(u):
        s = str(u or '').strip()
        if not s:
            return None
        if '\\' in s:
            s = s.split('\\')[-1]
        if '@' in s and s.count('@') == 1:
            s = s.split('@')[0]
        return s.strip() or None

    def _uniq(seq, key=lambda x: str(x).lower()):
        seen = set(); out = []
        for x in seq:
            if x is None:
                continue
            k = key(x)
            if not k or k in seen:
                continue
            seen.add(k); out.append(x)
        return out

    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            # host/time basics
            cur.execute("""
                SELECT min(event_ts), max(event_ts)
                FROM event_logs_v2
                WHERE case_key=%s
            """, (case_key,))
            _w = cur.fetchone() or (None, None)

            # users from event logs (incident-relevant)
            incident_users = []
            try:
                cur.execute("""
                    SELECT DISTINCT COALESCE(NULLIF(target_user,''), NULLIF(subject_user,''))
                    FROM event_logs_v2
                    WHERE case_key=%s
                    LIMIT 400
                """, (case_key,))
                for (u,) in cur.fetchall():
                    nu = _norm_user(u)
                    if not nu:
                        continue
                    if _is_machine_or_service_user(nu):
                        continue
                    incident_users.append(nu)
            except Exception:
                try: conn.rollback()
                except: pass
                pass

            # profile paths on disk
            profiles = []
            try:
                cur.execute("""
                    SELECT DISTINCT lower(coalesce(parent_path,''))
                    FROM filesystem_v2
                    WHERE case_key=%s AND lower(coalesce(parent_path,'')) LIKE 'c:\\\\users\\\\%%'
                    LIMIT 500
                """, (case_key,))
                for (p,) in cur.fetchall():
                    pp = str(p or '')
                    m = re.search(r'c:\\users\\([^\\/]+)', pp)
                    if not m:
                        continue
                    user = _norm_user(m.group(1))
                    if not user:
                        continue
                    if _is_machine_or_service_user(user):
                        continue
                    profiles.append(user)
            except Exception:
                try: conn.rollback()
                except: pass
                pass

            # remote hosts + IPs
            # A bare (\d{1,3}\.){3}\d{1,3} also matches inside a longer number, so
            # "Microsoft.AV1VideoExtension_2024.401.617.0" yielded the "address"
            # 024.401.617.0. Require non-digit/non-dot boundaries and a valid octet
            # range — the same rules reports/render.py::_ip_ok already applies.
            ips = []
            related_hosts = []
            # ORDER BY 1 sorted the peers as STRINGS, and the caller then printed the first
            # six. On case_66 that handed the client six brute-force scanners from the
            # collection day (9/9/6/6 events, all 2026-08-13 08:4x) and hid 82.207.114.163
            # with 305 events over six months. Rank by how many events the peer actually
            # produced, and remember the true total so the caller can say 6 of 36.
            try:
                cur.execute("""
                    SELECT coalesce(remote_host,''), count(*) AS n
                    FROM event_logs_v2
                    WHERE case_key=%s AND coalesce(remote_host,'') <> ''
                    GROUP BY 1
                    ORDER BY n DESC, 1
                    LIMIT 1200
                """, (case_key,))
                _ip_n = {}
                for (rh, _n) in cur.fetchall():
                    s = str(rh or '').strip()
                    if not s:
                        continue
                    for ip in _extract_ipv4(s):
                        _ip_n[ip] = _ip_n.get(ip, 0) + int(_n or 0)
                    # host-like labels
                    if any(ch.isalpha() for ch in s) and len(s) <= 128:
                        related_hosts.append(s)
                ips = [_i for _i, _c in sorted(_ip_n.items(), key=lambda kv: (-kv[1], kv[0]))]
                ips_total = len(_ip_n)
            except Exception:
                try: conn.rollback()
                except: pass
                pass

            # THOR writes its syslog header as "<hostname>/<ip> THOR: ...", and that ip
            # is THIS machine's own address — the only source in the library that knows
            # it. Everything else this table offers as a dotted quad is a version.
            host_ips = []
            try:
                cur.execute("""
                    SELECT DISTINCT left(coalesce(details,''),200)
                    FROM tool_alerts_v2
                    WHERE case_key=%s
                      AND coalesce(details,'')
                          ~* '[/][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3} +thor:'
                    ORDER BY 1
                    LIMIT 200
                """, (case_key,))
                for (dt,) in cur.fetchall():
                    for m in _THOR_HOST_RX.finditer(str(dt or '')):
                        for ip in _extract_ipv4(m.group(2)):
                            host_ips.append(ip)
            except Exception:
                try: conn.rollback()
                except: pass
                pass

    reg_users = []
    for u in (out.get('users') or []):
        if isinstance(u, dict):
            uu = _norm_user(u.get('username'))
            if uu and not _is_machine_or_service_user(uu):
                reg_users.append({'username': uu, 'sid': u.get('sid'), 'created_utc': u.get('created_utc'), 'last_login_utc': u.get('last_login_utc'), 'disabled': bool(u.get('disabled'))})

    out['users'] = _uniq(reg_users, key=lambda x: str((x or {}).get('username') or '').lower())[:30]
    out['local_accounts'] = [u.get('username') for u in out['users'] if isinstance(u, dict) and u.get('username')][:20]
    out['incident_users'] = _uniq([_norm_user(x) for x in incident_users], key=lambda x: str(x).lower())[:20]
    out['profiles_on_disk'] = _uniq([_norm_user(x) for x in profiles], key=lambda x: str(x).lower())[:20]
    out['ips'] = _uniq(ips, key=lambda x: str(x))[:20]
    try:
        out['ips_total'] = int(ips_total)
    except Exception:
        out['ips_total'] = len(out['ips'])
    try:
        out['host_ips'] = _uniq(host_ips, key=lambda x: str(x))[:4]
    except Exception:
        out['host_ips'] = []
    out['related_hosts'] = _uniq(related_hosts, key=lambda x: str(x).lower())[:20]

    # choose primary hostname
    primary = out.get('computer_name') or out.get('hostname')
    if not primary:
        # pick first non-ip host token
        for h in out['related_hosts']:
            if re.match(r'^((?:\d{1,3}\.){3}\d{1,3})(:\d+)?$', str(h)):
                continue
            primary = h
            break
    out['computer_name'] = primary or out.get('computer_name')
    out['hostname'] = out.get('hostname') or primary

    return out


def _os_name_for_build(name, build):
    """Windows 11 keeps ProductName = 'Windows 10 ...' in the SOFTWARE hive (Microsoft never
    changed the value); a build of 22000 or later is the fact that decides."""
    try:
        b = int(str(build or '').split('.')[0])
    except ValueError:
        return name
    if name and b >= 22000 and 'windows 10' in name.lower():
        return name.replace('Windows 10', 'Windows 11').replace('windows 10', 'Windows 11')
    return name


def _upsert_system_profile_v1(case_key):
    _ensure_system_profile_table()
    reg = _registry_system_profile(case_key)
    reg = _system_profile_enricher_v1(case_key, reg)
    reg['os_name'] = _os_name_for_build(reg.get('os_name'), reg.get('build'))
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO public.system_profile_v1 (
                  case_key, computer_name, hostname, os_name, build,
                  install_date_utc, timezone, utc_offset, last_shutdown_utc,
                  users_json, source_kind, updated_at
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,now())
                ON CONFLICT (case_key) DO UPDATE SET
                  computer_name=EXCLUDED.computer_name,
                  hostname=EXCLUDED.hostname,
                  os_name=EXCLUDED.os_name,
                  build=EXCLUDED.build,
                  install_date_utc=EXCLUDED.install_date_utc,
                  timezone=EXCLUDED.timezone,
                  utc_offset=EXCLUDED.utc_offset,
                  last_shutdown_utc=EXCLUDED.last_shutdown_utc,
                  users_json=EXCLUDED.users_json,
                  source_kind=EXCLUDED.source_kind,
                  updated_at=now()
            """, (
                case_key,
                reg.get('computer_name'), reg.get('hostname'), reg.get('os_name'), reg.get('build'),
                reg.get('install_date_utc'), reg.get('timezone'), reg.get('utc_offset'), reg.get('last_shutdown_utc'),
                json.dumps(reg, ensure_ascii=False),
                'system_profile_enricher_v1'
            ))
    return reg



_IPV4_RX = re.compile(r'(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])')
_THOR_HOST_RX = re.compile(r'([A-Za-z0-9_.-]+)/((?:\d{1,3}\.){3}\d{1,3})\s+thor:', re.I)


def _extract_ipv4(text):
    """Every syntactically valid, non-loopback IPv4 in `text`, in order.

    Boundaries matter: without them the pattern happily reads 024.401.617.0 out of a
    WindowsApps package version. Octet range and leading-zero rules mirror
    reports/render.py::_ip_ok so the two renderers cannot disagree about what an
    address is.
    """
    out = []
    for m in _IPV4_RX.finditer(str(text or '')):
        cand = m.group(1)
        parts = cand.split('.')
        if any(len(p) > 1 and p.startswith('0') for p in parts):
            continue
        try:
            nums = [int(p) for p in parts]
        except Exception:
            continue
        if not all(0 <= n <= 255 for n in nums):
            continue
        if nums[0] == 127 or nums in ([0, 0, 0, 0], [255, 255, 255, 255]):
            continue
        if not any(n != 0 for n in nums):
            continue
        out.append(cand)
    return out

def _get_system_profile_v1(case_key):
    try:
        _ensure_system_profile_table()
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT computer_name, hostname, os_name, build, install_date_utc,
                           timezone, utc_offset, last_shutdown_utc, users_json
                    FROM public.system_profile_v1
                    WHERE case_key=%s
                    LIMIT 1
                """, (case_key,))
                r = cur.fetchone()
                if r:
                    uj = r[8]
                    if isinstance(uj, dict):
                        out = dict(uj)
                        out['computer_name'] = out.get('computer_name') or r[0]
                        out['hostname'] = out.get('hostname') or r[1]
                        out['os_name'] = out.get('os_name') or r[2]
                        out['build'] = out.get('build') or r[3]
                        out['install_date_utc'] = out.get('install_date_utc') or r[4]
                        out['timezone'] = out.get('timezone') or r[5]
                        out['utc_offset'] = out.get('utc_offset') or r[6]
                        out['last_shutdown_utc'] = out.get('last_shutdown_utc') or r[7]
                        out.setdefault('users', [])
                        out.setdefault('profiles_on_disk', [])
                        out.setdefault('local_accounts', [])
                        out.setdefault('incident_users', [])
                        out.setdefault('ips', [])
                        out.setdefault('host_ips', [])
                        out.setdefault('related_hosts', [])
                        return out
                    return {
                        'computer_name': r[0], 'hostname': r[1], 'os_name': r[2], 'build': r[3],
                        'install_date_utc': r[4], 'timezone': r[5], 'utc_offset': r[6], 'last_shutdown_utc': r[7],
                        'users': uj if isinstance(uj, list) else [],
                        'profiles_on_disk': [], 'local_accounts': [], 'incident_users': [], 'ips': [], 'related_hosts': []
                    }
    except Exception:
        try: conn.rollback()
        except: pass
        pass
    return _upsert_system_profile_v1(case_key)


