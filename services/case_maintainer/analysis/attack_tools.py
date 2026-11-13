# -*- coding: utf-8 -*-
"""Attacker tooling, by category — one place, so every consumer agrees.

Why this file exists: detection used several ad-hoc regexes (_TOOL_RE, _RAT,
_COMBO_TOOL_RE, _IA_POSTEXP_RE), each grown for a different purpose and each missing tools
the others had. The owner supplied a BAM extract showing seventeen NirSoft credential
recoverers executed from one folder in eighteen seconds — of those seventeen, the previous
patterns knew four.

Two ideas here:

1. A CATEGORY dictionary, not a per-case IOC list. `pspv.exe` matters because it is a
   password recoverer, not because it appeared in one case.
2. Categories make a structural rule possible: several tools OF THE SAME CATEGORY run from
   ONE folder is a toolkit sweep, which is different from an administrator having a single
   utility. That rule keeps working when the files are renamed, because the operator
   usually renames none of them and only needs to be caught once.

Names are matched as whole-ish tokens against the executable name and full path.
"""

# ── credential access ────────────────────────────────────────────────────────────────
# The NirSoft recovery suite in full (the owner's BAM list), plus the classic dumpers.
CREDENTIAL_THEFT = [
    # NirSoft password recoverers — the exact set seen executed as a chain
    'pspv', 'webbrowserpassview', 'mailpv', 'pstpassword', 'rdpv', 'vncpassview',
    'routerpassview', 'mspass', 'iepv', 'operapassview', 'dialupass', 'passwordfox',
    'chromepass', 'bulletspassview', 'wirelesskeyview', 'sniffpass', 'netpass',
    'netpass64', 'wnetwatcher', 'credentialsfileview', 'vaultpasswordview',
    'encryptedregview', 'protected storage passview', 'passwordfox64',
    # dumpers / extractors
    'mimikatz', 'mimilib', 'lazagne', 'secretsdump', 'procdump', 'nanodump', 'dumpert',
    'sharpdump', 'safetykatz', 'pypykatz', 'lsassy', 'hashdump', 'gsecdump', 'wce',
    'creddump', 'quarkspwdump', 'ntdsutil', 'esentutl', 'sharpchrome', 'seatbelt',
    'donpapi', 'dpapi', 'sessiongopher',
]

# ── discovery / reconnaissance ───────────────────────────────────────────────────────
RECON = [
    'netscan', 'advanced_port_scanner', 'advanced_ip_scanner', 'softperfect',
    'angryip', 'nmap', 'zenmap', 'masscan', 'fping', 'nbtscan', 'adfind', 'adexplorer',
    'sharphound', 'bloodhound', 'azurehound', 'pingcastle', 'snaffler', 'seatbelt',
    'winpeas', 'privesccheck', 'powerup', 'watson', 'sherlock',
]

# ── lateral movement / execution ─────────────────────────────────────────────────────
LATERAL = [
    'psexec', 'paexec', 'psexesvc', 'wmiexec', 'smbexec', 'atexec', 'dcomexec',
    'crackmapexec', 'netexec', 'impacket', 'evil-winrm', 'rubeus', 'kerbrute',
    'godpotato', 'juicypotato', 'roguepotato', 'printspoofer', 'sweetpotato',
]

# ── remote access / tunnelling (dual-use: legitimate on many machines) ───────────────
REMOTE_ACCESS = [
    'anydesk', 'teamviewer', 'rustdesk', 'meshagent', 'meshcentral', 'romviewer',
    'romserver', 'romfusclient', 'rdpwrap', 'rdpwinst', 'tektonit', 'rutserv',
    'litemanager', 'atera', 'screenconnect', 'connectwise', 'splashtop', 'dwagent',
    'supremo', 'ammyy', 'radmin', 'ultravnc', 'tightvnc', 'realvnc', 'gotomypc',
    'logmein', 'anyviewer', 'todesk', 'sunlogin',
]
# Mainstream VPN clients are deliberately absent: openvpn, wireguard, tailscale and
# zerotier are standard corporate software and listing them produced hits on three clean
# cases. What stays are the tools whose purpose is to expose an internal host outward.
TUNNEL = [
    'ngrok', 'frpc', 'frps', 'chisel', 'cloudflared', 'localtonet', 'playit',
    'stunnel', 'iodine', 'dnscat', 'gost.exe', 'revsocks',
]

# ── defence evasion ──────────────────────────────────────────────────────────────────
DEFENSE_EVASION = [
    'defendercontrol', 'defender control', 'dcontrol', 'nsudo', 'processhacker',
    'pchunter', 'gmer', 'kdmapper', 'gdrv', 'rtcore64', 'dbutil_2_3', 'mhyprot',
    'truesight', 'zemana', 'aswarpot', 'backstab', 'hrsword', 'antispy',
    'killav', 'avkill',
]
# Short driver names that match inside legitimate ones (gdrv inside magdrv.sys — the
# Magnet RAM Capture driver, i.e. OUR tool). Matched with boundaries, never as substrings.
BOUNDED_TOKENS = ('gdrv', 'wce', 'gost.exe', 'rms', 'vnc', 'frpc', 'frps',
                  # more substring traps found on real cases: gmer inside regmerge,
                  # eraser inside trackeraser, cipher inside agent_cipher_caas
                  'gmer', 'eraser', 'wget', 'curl', 'nmap')

# ── destruction / anti-recovery ──────────────────────────────────────────────────────
DESTRUCTION = [
    'vssadmin', 'wbadmin', 'bcdedit', 'reagentc', 'cipher.exe', 'sdelete', 'eraser',
    'diskpart', 'format.com', 'shadowcopyview',
]

# ── staging / exfiltration ───────────────────────────────────────────────────────────
# curl and wget ship with Windows now, so they are not indicators by themselves.
EXFIL = [
    'rclone', 'megasync', 'megacmd', 'filezilla', 'winscp', 'psftp', 'aria2c',
    'megatools', 'freefilesync',
]

CATEGORIES = {
    'крадіжка облікових даних': CREDENTIAL_THEFT,
    'розвідка мережі та AD': RECON,
    'латеральний рух': LATERAL,
    'віддалений доступ': REMOTE_ACCESS,
    'тунелювання': TUNNEL,
    'обхід захисту': DEFENSE_EVASION,
    'знищення можливості відновлення': DESTRUCTION,
    'виведення даних': EXFIL,
}

# Categories whose mere presence is suspicious on an ordinary workstation. Remote access
# is excluded on purpose: accountants legitimately run AnyDesk for years, and treating it
# as an attack was a real false positive on the case_58 and bank cases.
HIGH_SIGNAL_CATEGORIES = (
    'крадіжка облікових даних', 'латеральний рух', 'обхід захисту',
    'розвідка мережі та AD',
)


def _rx(names):
    """Regex alternation for Postgres, escaping the dots in file names."""
    return '|'.join(n.replace('.', '[.]').replace(' ', '.') for n in names)


def category_regex(category):
    return _rx(CATEGORIES[category])


def all_tools_regex():
    out = []
    for names in CATEGORIES.values():
        out.extend(names)
    return _rx(sorted(set(out)))


import re as _re

# examiner/collector tooling must never be classified as attacker tooling
_EXAMINER_RE = _re.compile(
    r'vao_dfir_collector_marker|vao_triage|'
    r'magnet|magdrv|winpmem|dumpit|ftk|encase|x-ways|autopsy|belkasoft|axiom|'
    r'kape|gkape|dfirtriage|cellebrite|oxygen', _re.I)


def categorize(text):
    """Which categories a path/name belongs to.

    Substring match, except for BOUNDED_TOKENS, which are short enough to appear inside
    unrelated names — `gdrv` lives inside `magdrv.sys`, the Magnet RAM Capture driver.
    Examiner tooling is excluded outright."""
    t = str(text or '').lower()
    if _EXAMINER_RE.search(t):
        return []
    hits = []
    for cat, names in CATEGORIES.items():
        for n in names:
            if n in BOUNDED_TOKENS:
                if _re.search(r'(^|[^a-z0-9])' + _re.escape(n) + r'([^a-z0-9]|$)', t):
                    hits.append(cat)
                    break
            elif n in t:
                hits.append(cat)
                break
    return hits
