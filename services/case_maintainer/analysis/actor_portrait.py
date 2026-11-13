# -*- coding: utf-8 -*-
"""Actor portrait: which cases were done by the same person, and on what evidence.

`ioc_overlap` already joins cases on any shared indicator, and that is why it was not
useful: measured across the seventeen cases, the top link was `tool_name: rdpwrap` with
29 pairs over 7 cases. Two investigators both finding RDP Wrapper says nothing about who
was behind the keyboard - it is a public tool. The same is true of `mimikatz`,
`teamviewer`, and of `technique: rdp_loopback_tunnel`.

The links that DO identify a person were buried underneath:

    attacker_host  case_53   -> case_47_case_59, case_58_NGROK, case_58_phishing
    user_account   case_59             -> the same three
    hash_sha1      five shared SHA1  -> three cases each

So indicators are graded, and only identity-grade ones build a portrait:

  IDENTITY  the attacker's own machine name, a binary hash, their email, AnyDesk ID,
            their IP, a specific delivery URL. Two cases sharing one of these were
            touched by the same hands or the same build.
  SUPPORT   an account name, a domain, a file name. Corroborates an identity link;
            alone it is suggestive, not proof - `case_59` is a plausible name for anyone
            to pick.
  CONTEXT   tool names and techniques. Never an identity. Kept for reading, never for
            linking.

A portrait needs at least one IDENTITY link. Everything else only strengthens one that
already exists.
"""
import logging

import psycopg2

from core.config import PG_DSN

_log = logging.getLogger('app')

IDENTITY = ('attacker_host', 'hash_sha1', 'hash_md5', 'hash_sha256',
            'email', 'anydesk_id', 'public_ip', 'url')
SUPPORT = ('user_account', 'domain', 'file_name', 'file_path', 'malware_name')
CONTEXT = ('tool_name', 'technique', 'mitre')

# Hosting, tunnelling and update infrastructure that turns up in unrelated cases.
# equinox.io is ngrok's own CDN; two victims both being tunnelled through ngrok is a
# statement about the tool, not about the person using it.
GENERIC_VALUES = {
    'equinox.io', 'bin.equinox.io', 'microsoft.net', 'microsoft.com', 'windows.net',
    'google.com', 'googleapis.com', 'gstatic.com', 'live.com', 'office.com',
    'digicert.com', 'verisign.com', 'akamai.net', 'cloudflare.com', 'amazonaws.com',
    'github.com', 'githubusercontent.com', '127.0.0.1', '0.0.0.0', 'localhost',
    '8.8.8.8', '1.1.1.1',
}

LABELS = {
    'attacker_host': 'робоча станція зловмисника',
    'hash_sha1': 'той самий бінарник (SHA1)',
    'hash_md5': 'той самий бінарник (MD5)',
    'hash_sha256': 'той самий бінарник (SHA256)',
    'email': 'поштова адреса',
    'anydesk_id': 'ID AnyDesk',
    'public_ip': 'зовнішня IP-адреса',
    'url': 'адреса завантаження',
    'user_account': 'обліковий запис',
    'domain': 'домен',
    'file_name': 'імʼя файлу',
    'file_path': 'шлях до файлу',
    'malware_name': 'назва шкідливого ПЗ',
}



# Labels that mean "software many people have", not "somebody's implant".
PUA_LABEL_RX = 'hacktool|pua|riskware|not-a-virus|unwanted|adware|keygen|autokms|kmsauto'

_verdict_cache = {}


def _is_compromised(case_key, conn):
    """True when the deterministic layer rated this case high or critical."""
    if case_key in _verdict_cache:
        return _verdict_cache[case_key]
    ok = False
    try:
        from analysis.threat_detect import detect_threats
        dets = detect_threats(case_key, conn) or []
        items = (dets.get('detections') if isinstance(dets, dict) else dets) or []
        ok = any(str((d or {}).get('severity', '')).lower() in ('high', 'critical')
                 for d in items if isinstance(d, dict))
    except Exception as e:
        _log.error('[portrait] verdict lookup failed for %s: %s' % (case_key, e))
    _verdict_cache[case_key] = ok
    return ok


_pua_cache = {}


def _pua_hashes(conn):
    """Hashes whose indicator is labelled as a public tool rather than an implant."""
    key = id(conn)
    if key in _pua_cache:
        return _pua_cache[key]
    out = set()
    try:
        with conn.cursor() as cur:
            cur.execute("""SELECT DISTINCT a.ioc_norm
                           FROM public.case_iocs a
                           JOIN public.case_iocs b ON b.case_key = a.case_key
                          WHERE a.ioc_type IN ('hash_sha1','hash_md5','hash_sha256')
                            AND b.ioc_type = 'malware_name'
                            AND lower(b.ioc_value) ~ %s""", (PUA_LABEL_RX,))
            out = {r[0] for r in cur.fetchall() if r and r[0]}
    except Exception as e:
        _log.error('[portrait] pua lookup failed: %s' % e)
    _pua_cache[key] = out
    return out


# A binary present in more cases than this is ordinary software, not somebody's tool.
MAX_CASES_FOR_IDENTITY = 3

_rarity_cache = {}


def _hash_rarity(conn):
    """{hash_norm: how many cases carry it} - computed once per connection."""
    key = id(conn)
    if key in _rarity_cache:
        return _rarity_cache[key]
    out = {}
    try:
        with conn.cursor() as cur:
            cur.execute("""SELECT ioc_norm, count(DISTINCT case_key)
                           FROM public.case_iocs
                           WHERE ioc_type IN ('hash_sha1','hash_md5','hash_sha256')
                           GROUP BY 1""")
            out = {r[0]: int(r[1]) for r in cur.fetchall() if r and r[0]}
    except Exception as e:
        _log.error('[portrait] rarity lookup failed: %s' % e)
    _rarity_cache[key] = out
    return out


_VENDOR_PATH_RX = (r'([/\\\\]windows[/\\\\]|windows defender|program files( [(]x86[)])?[/\\\\](microsoft|windows|common files)'
                   r'|programdata[/\\\\]microsoft|windowsapps|[/\\\\]winsxs[/\\\\])')
_vendor_cache = {}


def _vendor_hashes(conn):
    """Hashes of binaries that live in OS / Defender / Microsoft folders in ANY case. Two
    cases sharing MsMpEng.exe were linked as «той самий бінарник» (case_50 -> case_42,
    02.10.2026); the report itself filed both hashes under «довідково, не індикатори»."""
    key = id(conn)
    if key in _vendor_cache:
        return _vendor_cache[key]
    out = set()
    try:
        with conn.cursor() as cur:
            cur.execute("""SELECT DISTINCT lower(hash_sha1) FROM public.program_exec_v2
                           WHERE coalesce(hash_sha1,'') <> ''
                             AND (lower(coalesce(full_path,'')) ~ %s
                                  OR lower(coalesce(executable_name,'')) ~ '^(msmpeng|mpcmdrun|nissrv|mpdefendercoreservice|smartscreen)[.]exe$')""",
                        (_VENDOR_PATH_RX,))
            out = {r[0] for r in cur.fetchall() if r and r[0]}
    except Exception as e:
        _log.error('[portrait] vendor hash lookup failed: %s' % e)
    _vendor_cache[key] = out
    return out


def _grade(ioc_type, ioc_norm, rarity=None, vendor=None):
    v = str(ioc_norm or '').strip().lower()
    if ioc_type in ('hash_sha1', 'hash_md5', 'hash_sha256') and vendor and v in vendor:
        return None          # an OS / Defender binary, present on every Windows box
    if not v or v in GENERIC_VALUES:
        return None
    if any(v.endswith('.' + g) or v == g for g in GENERIC_VALUES):
        return None
    if ioc_type in ('hash_sha1', 'hash_md5', 'hash_sha256'):
        n = (rarity or {}).get(v)
        if n is not None and n > MAX_CASES_FOR_IDENTITY:
            return None          # common software, not an actor's tool
        return 'identity'
    if ioc_type in IDENTITY:
        return 'identity'
    if ioc_type in SUPPORT:
        return 'support'
    return None      # CONTEXT never links


def links_for(case_key, conn=None):
    """Graded links from this case to others: {other_case: {'identity': [...], 'support': [...]}}"""
    own = conn is None
    if own:
        conn = psycopg2.connect(PG_DSN)
        conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT CASE WHEN case_a = %s THEN case_b ELSE case_a END AS other,
                       ioc_type, ioc_norm
                FROM public.ioc_overlap
                WHERE case_a = %s OR case_b = %s""", (case_key, case_key, case_key))
            rows = cur.fetchall()
    except Exception as e:
        _log.error('[portrait] links_for failed: %s' % e)
        if own:
            try:
                conn.close()
            except Exception:
                pass
        return {}

    out = {}
    try:
        _rar = _hash_rarity(conn) if conn else {}
        _pua = _pua_hashes(conn) if conn else set()
        _vend = _vendor_hashes(conn) if conn else set()
        _self_ok = _is_compromised(case_key, conn) if conn else True
    except Exception:
        _rar, _pua, _self_ok = {}, set(), True
    if not _self_ok:
        if own:
            try:
                conn.close()
            except Exception:
                pass
        return {}          # a clean machine has no actor to share
    for other, t, v in rows:
        if not other or other == case_key:
            continue
        if str(v).strip().lower() in _pua:
            continue
        g = _grade(t, v, _rar, _vend)
        if not g:
            continue
        slot = out.setdefault(other, {'identity': [], 'support': []})
        item = (t, str(v)[:120])
        if item not in slot[g]:
            slot[g].append(item)
    # a portrait needs a hard link, and the other side must be compromised too
    keep = {}
    for k, v in out.items():
        if not v['identity']:
            continue
        try:
            if conn and not _is_compromised(k, conn):
                continue
        except Exception:
            pass
        keep[k] = v
    if own:
        try:
            conn.close()
        except Exception:
            pass
    return keep


def portrait_section(case_key, conn=None):
    """Report block naming the other cases the same actor appears in. [] when none."""
    try:
        linked = links_for(case_key, conn=conn)
    except Exception:
        return []
    if not linked:
        return []

    order = sorted(linked.items(), key=lambda kv: (-len(kv[1]['identity']), kv[0]))
    out = ['## 🕵 ТОЙ САМИЙ ЗЛОВМИСНИК — ПЕРЕТИН З ІНШИМИ СПРАВАМИ', '']
    out.append('_Звʼязок будується лише на індикаторах, що вказують на конкретну особу або '
               'конкретний файл: імʼя машини зловмисника, хеш бінарника, пошта, ID віддаленого '
               'доступу, адреса. Спільний публічний інструмент (rdpwrap, mimikatz, AnyDesk) '
               'звʼязком НЕ вважається — ним користуються всі._')
    out.append('')
    for other, ev in order:
        out.append('**%s**' % other.replace('_', ' '))
        for t, v in ev['identity'][:6]:
            out.append('- 🔗 %s: `%s`' % (LABELS.get(t, t), v))
        for t, v in ev['support'][:4]:
            out.append('  - додатково: %s `%s`' % (LABELS.get(t, t), v))
        out.append('')
    return out


def clusters(conn=None):
    """All actor clusters in the database: [[case, case, ...], ...] joined by identity links."""
    own = conn is None
    if own:
        conn = psycopg2.connect(PG_DSN)
        conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT DISTINCT case_a FROM public.ioc_overlap")
            cases = [r[0] for r in cur.fetchall() if r and r[0]]
            parent = {c: c for c in cases}

            def find(x):
                while parent.get(x, x) != x:
                    parent[x] = parent.get(parent[x], parent[x])
                    x = parent[x]
                return x

            for c in cases:
                for other in links_for(c, conn=conn):
                    if other not in parent:
                        parent[other] = other
                    ra, rb = find(c), find(other)
                    if ra != rb:
                        parent[rb] = ra
        groups = {}
        for c in list(parent):
            groups.setdefault(find(c), set()).add(c)
        return [sorted(g) for g in groups.values() if len(g) > 1]
    except Exception as e:
        _log.error('[portrait] clusters failed: %s' % e)
        return []
    finally:
        if own:
            try:
                conn.close()
            except Exception:
                pass
