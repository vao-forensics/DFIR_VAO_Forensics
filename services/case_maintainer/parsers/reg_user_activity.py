"""Per-user activity from NTUSER.DAT / UsrClass.dat hives.

Added 2026-08-01. The collector now ships these hives in `_raw/registry`, and the bot
parses them here instead of bundling a parser into the collector EXE — so new extraction
logic can be applied to archives that were collected long ago.

What it recovers (the investigative gold that CSV triage output does not carry):
  recent_doc   - files the user opened (RecentDocs, per extension)
  typed_path   - paths typed into the Explorer address bar
  run_mru      - commands run via Win+R
  user_assist  - GUI program executions with run count and last-run time
  mount_point  - mounted volumes / mapped network shares (USB and lateral movement)
  rdp_target   - servers this machine connected OUT to over RDP
  open_save    - files touched through Open/Save dialogs
  office_mru   - recently opened Office documents
  shellbag     - folders browsed in Explorer (from UsrClass.dat)

Values inside these keys are mostly binary PIDLs; the readable part is a UTF-16LE string,
so names are recovered with a scanner rather than a full PIDL parser.
"""
import codecs
import datetime
import re
import struct

_MIN_STR = 4
# Only characters a real Windows file/folder name uses here: Latin, Cyrillic, digits and
# punctuation. Without this, the scanner reads binary PIDL padding as CJK "names".
_SANE = re.compile(r'^[A-Za-z0-9 ._\-()\[\]{}~!@#$%^&+=,;\'`\\/:Ѐ-ӿ]+$')


def _utf16_strings(data, min_len=_MIN_STR):
    """Readable UTF-16LE strings inside a binary PIDL blob."""
    if not isinstance(data, (bytes, bytearray)):
        return []
    out, buf = [], []
    i = 0
    while i + 1 < len(data):
        ch = data[i] | (data[i + 1] << 8)
        c = chr(ch)
        if 0x20 <= ch <= 0x04FF and _SANE.match(c):
            buf.append(c)
        else:
            if len(buf) >= min_len:
                out.append(''.join(buf))
            buf = []
        i += 2
    if len(buf) >= min_len:
        out.append(''.join(buf))
    res = []
    for s in (x.strip() for x in out):
        # a name must carry real letters/digits, not just punctuation runs
        if len(s) >= min_len and _SANE.match(s) and re.search(r'[A-Za-z0-9Ѐ-ӿ]{3}', s):
            res.append(s)
    return res


def _best_name(data):
    """The most filename-looking string in a PIDL blob."""
    cands = _utf16_strings(data)
    if not cands:
        return None
    with_ext = [s for s in cands if re.search(r'\.[A-Za-z0-9]{1,6}$', s)]
    pool = with_ext or cands
    return max(pool, key=len)


def _filetime(raw):
    """Windows FILETIME (100ns since 1601) -> ISO string, or None."""
    try:
        if raw <= 0 or raw > 0x7FFFFFFFFFFFFFFF:
            return None
        ts = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=raw / 10)
        if 1990 < ts.year < 2100:
            return ts.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        pass
    return None


def _vals(key):
    try:
        return list(key.get_values())
    except Exception:
        return []


def _vname(v):
    return getattr(v, 'name', None) or (v.get('name') if isinstance(v, dict) else None) or ''


def _vdata(v):
    if isinstance(v, dict):
        return v.get('value')
    return getattr(v, 'value', None)


def _subkeys(key):
    try:
        return list(key.iter_subkeys())
    except Exception:
        return []


def _get(hive, path):
    try:
        return hive.get_key(path)
    except Exception:
        return None


# ------------------------------------------------------------------ NTUSER ---

_EXPLORER = r'\Software\Microsoft\Windows\CurrentVersion\Explorer'


def _recent_docs(hive, emit):
    root = _get(hive, _EXPLORER + r'\RecentDocs')
    if not root:
        return
    for key in [root] + _subkeys(root):
        ext = getattr(key, 'name', '') or ''
        if len(ext) > 12 and not ext.startswith('.'):
            continue                        # junk subkey name (a stray URL, not an extension)
        for v in _vals(key):
            if _vname(v).lower() in ('mrulistex', ''):
                continue
            name = _best_name(_vdata(v))
            if name:
                emit('recent_doc', key.path if hasattr(key, 'path') else _EXPLORER, name,
                     {'extension': ext if ext.startswith('.') else ''})


def _typed_paths(hive, emit):
    key = _get(hive, _EXPLORER + r'\TypedPaths')
    for v in _vals(key) if key else []:
        d = _vdata(v)
        if isinstance(d, str) and d.strip():
            emit('typed_path', _EXPLORER + r'\TypedPaths', d.strip(), {'slot': _vname(v)})


def _run_mru(hive, emit):
    key = _get(hive, _EXPLORER + r'\RunMRU')
    for v in _vals(key) if key else []:
        if _vname(v).lower() == 'mrulist':
            continue
        d = _vdata(v)
        if isinstance(d, str) and d.strip():
            emit('run_mru', _EXPLORER + r'\RunMRU', d.split('\\1')[0].strip(),
                 {'slot': _vname(v)})


def _user_assist(hive, emit):
    root = _get(hive, _EXPLORER + r'\UserAssist')
    for guid in _subkeys(root) if root else []:
        # walk to the GUID's own Count subkey - regipy paths on a nested key object are
        # not reliably absolute, so descend instead of re-looking-up by path
        count = None
        for sk in _subkeys(guid):
            if (getattr(sk, 'name', '') or '').lower() == 'count':
                count = sk
                break
        for v in _vals(count) if count else []:
            name = codecs.decode(_vname(v), 'rot_13')
            if not name:
                continue
            runs, last = None, None
            d = _vdata(v)
            if isinstance(d, (bytes, bytearray)) and len(d) >= 68:
                try:
                    runs = struct.unpack('<I', d[4:8])[0]
                    last = _filetime(struct.unpack('<Q', d[60:68])[0])
                except Exception:
                    pass
            emit('user_assist', r'%s\UserAssist' % _EXPLORER, name,
                 {'run_count': runs, 'last_run': last})


def _mount_points(hive, emit):
    root = _get(hive, _EXPLORER + r'\MountPoints2')
    for sk in _subkeys(root) if root else []:
        nm = getattr(sk, 'name', '')
        if not nm:
            continue
        kind = 'network share' if nm.startswith('##') else (
            'drive letter' if len(nm) <= 2 else 'volume GUID')
        emit('mount_point', _EXPLORER + r'\MountPoints2',
             nm.replace('#', chr(92)) if nm.startswith('##') else nm, {'mount_kind': kind})


def _rdp_targets(hive, emit):
    base = r'\Software\Microsoft\Terminal Server Client'
    servers = _get(hive, base + r'\Servers')
    for sk in _subkeys(servers) if servers else []:
        user = None
        for v in _vals(sk):
            if _vname(v).lower().startswith('usernamehint'):
                user = _vdata(v)
        emit('rdp_target', base + r'\Servers', getattr(sk, 'name', ''), {'username_hint': user})
    default = _get(hive, base + r'\Default')
    for v in _vals(default) if default else []:
        d = _vdata(v)
        if isinstance(d, str) and d.strip():
            emit('rdp_target', base + r'\Default', d.strip(), {'slot': _vname(v)})


def _open_save(hive, emit):
    for sub in ('OpenSavePidlMRU', 'LastVisitedPidlMRU'):
        root = _get(hive, _EXPLORER + r'\ComDlg32' + '\\' + sub)
        if not root:
            continue
        for key in [root] + _subkeys(root):
            for v in _vals(key):
                if _vname(v).lower() == 'mrulistex':
                    continue
                name = _best_name(_vdata(v))
                if name:
                    emit('open_save', _EXPLORER + r'\ComDlg32' + '\\' + sub, name,
                         {'dialog': sub, 'group': getattr(key, 'name', '')})


def _office_mru(hive, emit):
    office = _get(hive, r'\Software\Microsoft\Office')
    for ver in _subkeys(office) if office else []:
        for app in _subkeys(ver):
            mru = _get(hive, (app.path if hasattr(app, 'path') else '') + r'\File MRU')
            for v in _vals(mru) if mru else []:
                d = _vdata(v)
                if isinstance(d, str) and '*' in d:
                    emit('office_mru', r'\Software\Microsoft\Office', d.split('*')[-1],
                         {'app': getattr(app, 'name', ''), 'version': getattr(ver, 'name', '')})


# --------------------------------------------------------------- UsrClass ---

def _shellbags(hive, emit, limit=400):
    root = _get(hive, r'\Local Settings\Software\Microsoft\Windows\Shell\BagMRU')
    if not root:
        return
    seen, stack, n = set(), [root], 0
    while stack and n < limit:
        key = stack.pop()
        for v in _vals(key):
            if _vname(v).lower() in ('mrulistex', 'nodeslots', 'nodeslot'):
                continue
            name = _best_name(_vdata(v))
            if name and name not in seen and len(name) > 2:
                seen.add(name)
                n += 1
                emit('shellbag', r'\...\Shell\BagMRU', name, {})
        stack.extend(_subkeys(key))


_NTUSER_PARSERS = (_recent_docs, _typed_paths, _run_mru, _user_assist, _mount_points,
                   _rdp_targets, _open_save, _office_mru)


def parse_user_hive(path, kind, source_file=''):
    """Parse one NTUSER.DAT ('ntuser') or UsrClass.dat ('usrclass') hive.
    Returns payload dicts; never raises."""
    rows = []

    def emit(sub, key_path, item, extra):
        p = {'artifact': 'user_activity', 'kind': sub, 'key_path': str(key_path),
             'item': str(item)[:500], 'source_file': source_file,
             'text': '%s: %s' % (sub, str(item)[:400])}
        p.update({k: v for k, v in (extra or {}).items() if v not in (None, '')})
        rows.append(p)

    try:
        from regipy.registry import RegistryHive
        hive = RegistryHive(path)
    except Exception:
        return rows
    parsers = _NTUSER_PARSERS if kind == 'ntuser' else (_shellbags,)
    for fn in parsers:
        try:
            fn(hive, emit)
        except Exception:
            continue
    return rows
