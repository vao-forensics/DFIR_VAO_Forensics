# -*- coding: utf-8 -*-
"""Deterministic THREAT-DETECTION layer for the DFIR bot.

The report engine used to dump a raw event timeline + LLM hedging, so it MISSED
obvious attacks (a real Babuk ransomware case — 3614 `.babyk` files + ransom notes
+ 588 log-clears + RDP intrusion — came back "Висновок: unknown"). This module runs
deterministic SQL SIGNATURES over the structured tables and returns CONCRETE,
grounded findings (family, counts, samples) that lead the verdict — generalisable
across ransomware / RDP intrusion / log tampering / defense evasion / cred access /
suspicious execution, and HEURISTIC catch for unknown families.

`detect_threats(case_key, conn)` -> list[dict]: each {severity, category, mitre,
title, detail, count, samples[]}. Pure reads; no LLM; safe to run on any case.
"""
import re
import logging
from datetime import datetime, timedelta, timezone

_log = logging.getLogger('app')

# The pipeline's own footprint on the target (collector staging folder, dfp_ probes,
# vao_collector, our tools after the collector started). Twice on one case the report
# described our own work as the attack; every query below that names executables or
# paths subtracts this first. See analysis/own_footprint.py.
try:
    from analysis.own_footprint import is_own as _is_own, sql_not_own as _sql_not_own, collect_started_at as _collect_started_at
except Exception:  # pragma: no cover - the module ships with the service
    def _is_own(text, ts=None, case_key=None, conn=None, declared=None):
        return False

    def _sql_not_own(col):
        return 'TRUE'

    def _collect_started_at(case_key, conn=None):
        return None


# ── Provenance, timestamp kind, collection-day cut (12-case review 2026-09-06) ─────────
# FIX_QUEUE §0: every event/IOC names the file in the archive it came from and the record
# in it, so an investigator confirms the fact in 30 s. №7/№12: a ShimCache "last modified"
# or an $MFT created-time is when a file EXISTED, not when it ran - three cases carried
# rdpwinst «2017-12-27 19:20:08» to the second and two carried ngrok «2026-02-12 21:52:20»,
# PE/archive stamps that were read as launches and anchored CRITICAL combinations. №10:
# everything after the collector started is the response, not the attack.
def _exe_from_imagepath(val):
    """`"C:\\Program Files\\X\\rutserv.exe" -service` -> `rutserv.exe`."""
    t = str(val or '').strip()
    if t.startswith('"'):
        t = t[1:].split('"', 1)[0]
    else:
        t = t.split(' -')[0].split(' /')[0].strip()
    t = t.replace('/', chr(92)).rstrip('"').strip()
    return (t.split(chr(92))[-1] or t)[:120]


_PRESENCE_SRC_RX = re.compile(r'appcompatcache|shimcache|\$mft_output|_mft_output', re.I)
_ANCHOR_ORDER_SQL = "CASE WHEN source_file ILIKE '%%AppCompatCache%%' THEN 1 ELSE 0 END"
_ANCHOR_WINDOW = timedelta(days=30)
_PRESENCE_LABEL = 'файл існував раніше (мітка PE/архіву)'
_FAR_FUTURE = datetime(9999, 1, 1, tzinfo=timezone.utc)
_prov_cache = {}


def ts_kind(source_file, source=''):
    """'anchor' for timestamps that date an action (Prefetch run, BAM, Amcache first-seen,
    $J FileCreate, event-log records, alert CSVs); 'presence' for ShimCache and $MFT stamps."""
    sf = str(source_file or '')
    if sf:
        return 'presence' if _PRESENCE_SRC_RX.search(sf) else 'anchor'
    s = str(source or '')
    if re.search(r'appcompatcache|shimcache', s, re.I) or (re.search(r'\$mft', s, re.I) and not re.search(r'\$j', s, re.I)):
        return 'presence'
    return 'anchor'


def _rel_paths(case_key, cur):
    """{basename_lower: rel_path, '__evtx__': [rel_paths of EvtxECmd outputs]} from the
    ingest coverage table; empty on cases ingested before the table existed."""
    if case_key in _prov_cache:
        return _prov_cache[case_key]
    m = {'__evtx__': []}
    try:
        cur.execute("SELECT rel_path FROM dfir_ingest_coverage_v1 WHERE case_key=%s AND coalesce(rel_path,'')<>''", (case_key,))
        for (rp,) in cur.fetchall() or []:
            base = rp.replace(chr(92), '/').rsplit('/', 1)[-1].lower()
            m.setdefault(base, rp)
            if 'evtxecmd_output' in base:
                m['__evtx__'].append(rp)
    except Exception:
        try:
            cur.connection.rollback()
        except Exception:
            pass
    _prov_cache[case_key] = m
    return m


def provenance(case_key, source_file, record=None, cur=None):
    """'<archive path> · <source file> · RecordNumber N' (events), '… · entry N' ($J rows),
    or '<archive path> · <source file>' ($MFT / Amcache / Prefetch rows). Falls back to
    '<source file> · …' when the coverage table has no row for the case, '' when even the
    source file is unknown."""
    sf = str(source_file or '').strip()
    if not sf:
        return ''
    rp = ''
    if cur is not None and case_key:
        m = _rel_paths(case_key, cur)
        low = sf.replace(chr(92), '/').rsplit('/', 1)[-1].lower()
        if low.endswith('.evtx'):
            rp = ' | '.join(m.get('__evtx__') or [])
        else:
            rp = m.get(low, '')
    parts = [p for p in (rp, sf) if p]
    rec = str(record or '').strip()
    if rec and rec.lower() not in ('none', 'null'):
        parts.append(('RecordNumber %s' if sf.lower().endswith('.evtx') or not re.search(r'\$j', sf, re.I) else 'entry %s') % rec)
    return ' · '.join(parts)


def _as_dt(t):
    if t is None or hasattr(t, 'hour'):
        return t
    try:
        return datetime.fromisoformat(str(t)[:19].replace('T', ' '))
    except Exception:
        return None


def os_name_fallback(case_key, cur):
    """OS name for the report when system_profile has none (FIX_QUEUE №8, 7 of 12 cases).
    Sources in order: system_profile_v1.os_name; System 6009 payload; Kernel-General 12
    version fields; WindowsUpdateClient «Windows 10/11 Version 22H2»; a weak mention in any
    System-channel payload (labelled). Returns None when nothing names it - never guesses."""
    try:
        cur.execute("SELECT os_name, build FROM system_profile_v1 WHERE case_key=%s", (case_key,))
        r = cur.fetchone()
        if r and (r[0] or '').strip():
            return ('%s (build %s)' % (r[0].strip(), r[1]) if r[1] and str(r[1]) not in r[0] else r[0].strip())
    except Exception:
        try: cur.connection.rollback()
        except Exception: pass
    probes = [
        ("SELECT payload::text FROM event_logs_v2 WHERE case_key=%s AND event_id=6009 AND channel='System' "
         "AND payload::text ~ 'PayloadData' ORDER BY event_ts DESC LIMIT 1",
         r'"PayloadData1":\s*"([^"]{2,60})"', 'System 6009'),
        ("SELECT payload::text FROM event_logs_v2 WHERE case_key=%s AND event_id=12 AND provider ILIKE '%%Kernel-General%%' "
         "AND payload::text ~* 'MajorVersion|BuildVersion' ORDER BY event_ts DESC LIMIT 1",
         r'(?:MajorVersion|Major)[^0-9]{0,6}(\d+)[^0-9]{0,40}(?:MinorVersion|Minor)[^0-9]{0,6}(\d+)[^0-9]{0,40}(?:BuildVersion|Build)[^0-9]{0,6}(\d+)', 'Kernel-General 12'),
        # event_id first (indexed): 20-24 s per case without it; these are all the IDs that provider has in the DB
        ("SELECT payload::text FROM event_logs_v2 WHERE case_key=%s AND event_id IN (19,20,26,41,43,44) "
         "AND provider ILIKE '%%WindowsUpdateClient%%' "
         "AND payload::text ~* 'Windows (10|11|Server 20[0-9]{2})[^\"]{0,40}(Version|верс)' ORDER BY event_ts DESC LIMIT 1",
         r'(Windows (?:10|11|Server 20\d\d)[^",]{0,30}(?:Version|верс[іи][яї])\s*[0-9A-Z]{3,6})', 'WindowsUpdateClient'),
        ("SELECT payload::text FROM event_logs_v2 WHERE case_key=%s AND channel='System' "
         "AND payload::text ~ 'Windows (10|11|Server 20[0-9]{2})' ORDER BY event_ts DESC LIMIT 1",
         r'(Windows (?:10|11|Server 20\d\d)(?: (?:Pro|Home|Enterprise|Education|LTSC|Datacenter|Standard)[A-Za-z ]{0,20})?)', 'згадкою у System-журналі, без видання/збірки'),
    ]
    for sql, rx, label in probes:
        try:
            cur.execute(sql, (case_key,))
            r = cur.fetchone()
        except Exception:
            try: cur.connection.rollback()
            except Exception: pass
            continue
        if not r or not r[0]:
            continue
        m = re.search(rx, r[0], re.I)
        if not m:
            continue
        if label == 'Kernel-General 12':
            return 'Windows %s.%s build %s (за %s)' % (m.group(1), m.group(2), m.group(3), label)
        return '%s (за %s)' % (m.group(1).strip(), label)
    return None

# ── Known ransomware encrypted-file extensions (family → ext) ───────────────
RANSOM_EXT = {
    'babyk': 'Babuk', 'babuk': 'Babuk', 'lockbit': 'LockBit', 'abcd': 'LockBit',
    'conti': 'Conti', 'ryk': 'Ryuk', 'ryuk': 'Ryuk', 'sodinokibi': 'REvil',
    'revil': 'REvil', 'hive': 'Hive', 'phobos': 'Phobos', 'eking': 'Phobos',
    'devos': 'Phobos', 'dharma': 'Dharma', 'wallet': 'Dharma', 'java': 'Dharma',
    'crab': 'GandCrab', 'gdcb': 'GandCrab', 'krab': 'GandCrab', 'wncry': 'WannaCry',
    'wcry': 'WannaCry', 'locky': 'Locky', 'zepto': 'Locky', 'cerber': 'Cerber',
    'cryptolocker': 'CryptoLocker',
    'blackcat': 'BlackCat', 'alphv': 'BlackCat', 'royal': 'Royal',
    'play': 'PLAY', 'basta': 'BlackBasta', 'cactus': 'Cactus', 'akira': 'Akira',
    'powerrank': 'Akira', 'nochi': 'Akira', 'mallox': 'Mallox', 'mlox': 'Mallox',
    'rhysida': 'Rhysida', 'medusa': 'Medusa', 'mkp': 'Makop', 'makop': 'Makop',
    'qlocker': 'Qlocker', 'deadbolt': 'DeadBolt', 'stop': 'STOP/Djvu',
    'djvu': 'STOP/Djvu', 'lockfile': 'LockFile', 'venus': 'Venus', 'snatch': 'Snatch',
    'avos': 'AvosLocker', 'avoslinux': 'AvosLocker', 'nokoyawa': 'Nokoyawa',
    '8base': '8Base', 'wormhole': 'WormHole',
}
# standard extensions that are NEVER ransomware (suppress heuristic false positives)
_BENIGN_EXT = {
    'exe','dll','sys','log','log1','log2','txt','xml','ini','dat','tmp','manifest',
    'cdxml','adml','admx','ps1xml','psd1','psm1','html','htm','css','js','json','png',
    'jpg','jpeg','gif','ico','svg','mui','cat','inf','pnf','etl','evtx','pf','db','mof',
    'config','xsd','xsl','rll','nls','ttf','cab','msi','dll','node','pri','winmd','resx',
    'pdb','lib','h','c','cpp','cs','py','pyc','bat','cmd','vbs','reg','lnk','url','wim',
    'edb','jrs','chk','jfm','bin','rsp','pem','cer','crt','key','pfx','store','default',
    'mum','cdf-ms','appx','msix','aspx','asmx','sdb','blf','regtrans-ms','dmp','wer',
    'man','msc','theme','gadget','library-ms','search-ms','contact','group','ico',
    'fon','clb','imd','idx','dll','tlb','ocx','drv','scr','cpl','ax','acm','efi','ime',
}
# A ransom note name must contain a SPECIFIC ransom phrase — a bare "readme.txt"
# (every software ships one) MUST NOT match.
def _ip_shaped(v):
    """True only for a real IPv4/IPv6 address; rejects «LogonId: 0x…», process names, '-', etc."""
    v = str(v or '').strip()
    if not v or v in ('-', '::1', '127.0.0.1'):
        return False
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', v):
        return True
    # IPv6: hex groups and colons only (LogonId 0x… and tunnel markers ::%N are excluded)
    if ':' in v and '%' not in v and 'x' not in v.lower() and re.match(r'^[0-9a-f:]+$', v.lower()):
        return True
    return False



def _ip_of(v):
    """Address from a remote_host value. EvtxECmd writes 4624 sources as «WORKSTATION (10.0.0.5)»,
    which _ip_shaped() rejects as a whole - 86 RDP type-10 logons with an address were lost that way."""
    v = str(v or '').strip()
    m = re.match(r'^.*\(([^()]*)\)\s*$', v)
    if m:
        v = m.group(1).strip()
    return v if _ip_shaped(v) else ''


_PS_BOILER_SQL = "lower(coalesce(command_line,'')) !~ 'copyright.{0,30}microsoft|import-localizeddata|bindingvariable|inboxime|bagmru|shellregroot|get-localizedstring|localizationstring|#\\s*common utility functions'"
RANSOM_NOTE_RE = re.compile(
    r'(how[ _-]?to[ _-]?(restore|recover|decrypt)|'
    r'(restore|recover|decrypt)[ _-]?(my|your)[ _-]?files|'
    r'your[ _-]?files[ _-]?(are|have|were)[ _-]?(been[ _-]?)?(encrypt|lock)|'
    r'files[ _-]?(are[ _-]?)?encrypted|'
    r'(decrypt|restore|recover)[ _-]?(instruction|info|note|guide)|'
    r'!!![ _-]?(read|restore|recover|decrypt)|'
    r'(read[ _-]?me)[ _-]?(to[ _-]?decrypt|ransom|now!)|'
    r'^_+readme(_txt)?\.txt$|'
    r'(unlock|recover)[ _-]?(my|your)[ _-]?(files|data)|'
    r'@[\w.-]+\.onion|how[ _-]?recovery)', re.I)


# ── Allowlists to suppress FALSE POSITIVES ──────────────────────────────────
# (1) Benign vendor/OS service names — a triage of a corporate host is full of
# legit driver/agent service installs (Cisco Secure Client, VMware, Dell, Apple,
# Realtek, Google updater, USB drivers...). Without this every EID 7045 from those
# inflates a fake "persistence" finding. A random-named malware service still
# does NOT match this list, so it is still flagged. POSIX regex (PG ~*).
_BENIGN_SVC_RE = (
    r'cisco|anyconnect|\yacsock\y|\yancrcl\y|\ycscnvmpt\y|\yciscosam\y|orbital|'
    r'vmware|\yvmnet|\yvmx86\y|\yvmci\y|vsock|hcmon|'
    r'dell |supportassist|apple mobile|realtek|'
    r'google( ?updat)|googleupdater|usbdk|libusb|wudfwpdmtp|biontdrv|virtual wifi|'
    r'microsoft|windows defender|onedrive|edgeupdate|\ymsedge|nvidia|intel\(r\)|'
    r'\ywdm_usb\y|\ywdf\y|miniport|'
    # enterprise agents commonly seen on corporate hosts (EDR/MDM/VPN/posture) —
    # legit deployments, not attacker persistence. Random-named malware still fails these.
    r'\yiseexecservice\y|\yinteltacd\y|\yintel |wazuh|\ysms process event|\yccmexec\y|configmgr|'
    r'dell data vault|dell client management|\yduo |\yesif|\yciscosam\y|umbrella|'
    r'network visibility|posture agent|trusted peer|crashplan|crowdstrike|\ycsagent\y|'
    r'sentinelone|carbonblack|tanium|zscaler|forticlient|globalprotect|'
    r'teamviewer|lenovo|hewlett-packard|synaptics|'
    # benign enterprise software often mis-flagged as "persistence services" (7045):
    # SCCM, Google/Apple updaters, AV vendors, and Defender's OWN dynamic-signature
    # services (MpKsl<hash>) — these are NOT attacker persistence.
    r'sms agent host|ccmsetup|ccmexec|configuration manager|\ygupdate|google.?updat|bonjour|'
    r'\yadobe|\yeset\y|kaspersky|\ympksl|url.?scanner|brother|\ybryn|dropbox|'
    r'windows search|onedrive|\ynvidia|\yamd\y|logitech|elan|goodix|nahimic|killer|'
    r'google chrome elevation|googlechrome|mozilla|firefox|waves audio|filesynchelper|filesync|'
    r'epson|canon|\yhp\b|xerox|\ywsd\y|usb.?scanner|usb.?сканера|scanner service|печат|принтер|'
    r'\ynpcap\y|npf\b|packet driver|wireshark|\yn-?able|acronis|veeam|\ymsi\y|asus|gigabyte|'
    r'edge.?update|microsoft edge|\yfax\y|blizzard|steam|epic online|riot|'
    r'bluetooth|office source engine|immunet|\yglpi|trufos|bitdefender|eamon|\yavast\y|avg |'
    r'mcafee|sophos|malwarebytes|webroot|\yf-secure|trend.?micro|comodo|wiman|usb video|'
    r'\yipf_|acpi|\ywdm\y|realtek|\yhid\y|\ywpn|\ysense\y|windefend|securityhealth|'
    r'\yeelam|\yehdrv|\yepfw|\yeamon|\yekrn|\yacx\b|\ywpd\b|apple.+filter|pri-driver|'
    r'audio|bthhf|\ywcifs|volsnap|storqosflt|\ywof\b|'
    # enterprise EDR/VPN/mgmt suites + built-in Windows per-user service instances
    # (AarSvc_4a3f1, CDPUserSvc_xxxxx, OneSyncSvc_xxxxx …) that flood 7045/services.
    r'cisco|anyconnect|\bamp\b|vmware|\yduo\y|wazuh|glpi|codemeter|libreoffice|'
    r'aarsvc|cdpusersvc|onesyncsvc|cbdhsvc|wpnuserservice|captureservice|messagingservice|'
    r'devicesflowusersvc|printworkflowusersvc|unistoresvc|userdatasvc|bluetoothuserservice|'
    r'consentuxusersvc|webthreatdef|penservice|udkusersvc|p9rdrservice|clipboarduser|'
    r'credentialenrollment|deviceassociationbroker|accessdata|ftk imager|ftk_|\yftk\y|\ykape\y|eztools|mftecmd|pecmd|recmd|rbcmd|lecmd|sbecmd|amcacheparser|appcompatcache|srumecmd|evtxecmd|jlecmd|wxtcmd|rlacmd|magnet axiom|axiom process|magnetforensics|autopsy|x-?ways|encase|cellebrite|belkasoft|griffeye|\ynuix\y|arsenal image|virtual disk mount|_[0-9a-f]{4,5}$'
)
# (2) Forensic-examiner environment paths — the collection was taken on/with an
# analyst's tooling (AccessData/FTK, KAPE, EZ Tools, X-Ways, Autopsy, the
# For_Dump_Event_logs work dir...). Programs executed from these paths are the
# EXAMINER's, not the attacker's, and must not be reported as attacker tooling.
# Our own collector stamps every PowerShell script it runs with this token, so the
# script text that lands in EID 4104 can be attributed instead of read as an
# unattributed script. See Modules\!DFIRbot\*.ps1 banners.
_COLLECTOR_MARKER = 'VAO_DFIR_COLLECTOR_MARKER'

# Our own collector's fingerprints in a command line or a service name. Narrower on
# purpose than _EXAMINER_PATH_RE (which contains bare 'dfir' and 'magnet'): this one
# only matches strings the VAO collector itself writes, so an attacker who happens to
# mention a forensic product is still flagged. Measured over all 11 library cases:
# it removes 19 command lines, all on case_66, and zero rows anywhere else.
_OWN_COLLECTOR_RE = (
    r'vao_dfir_collector_marker|vao_triage|vao_collect_all|dfir_triage|'
    r'dfirtriage_[0-9a-f]{6,}|kape_triage|magnetramcapture|for_dump_event|'
    r'[\\/]kape[\\/]|!dfirbot'
)
_OWN_COLLECTOR_RX = re.compile(_OWN_COLLECTOR_RE, re.I)

# A 4104 script block is SOURCE, not a command: comments, help blocks and module bodies
# carry every cmdlet name there is. Strip comments; drop blocks that are module/profile
# source (help headers, alias tables, WinUtil tweak engines) - on case_67 they produced
# "24 lateral movements" and "22 obfuscations" on a gaming PC.
_PS_BLOCK_COMMENT_RX = re.compile(r'<#.*?#>', re.S)
_PS_LINE_COMMENT_RX = re.compile(r'(^|[\r\n,])\s*#[^\r\n]*')
_PS_SOURCE_RX = re.compile(
    r'\.synopsis|\.description\b|export-modulemember|cmdletbinding\(|# implicit remoting module|'
    r'\$sync\.configs|tweaks\.json|winutil|caller validation to ensure|'
    r'set-alias -name \w+ -value|new-alias -name \w+ -value|getcommand\(.microsoft\.powershell', re.I)


def _ps_effective(cmd):
    """The part of a command line / script block that can be judged as an ACTION."""
    if not cmd:
        return ''
    if len(cmd) > 200 and _PS_SOURCE_RX.search(cmd):
        return ''
    if '#' in cmd:
        cmd = _PS_BLOCK_COMMENT_RX.sub(' ', cmd)
        cmd = _PS_LINE_COMMENT_RX.sub(lambda m: m.group(1), cmd)
    return cmd

_EXAMINER_PATH_RE = (
    r'accessdata|forensic tools|\yftk\y|x-?ways|autopsy|\bkape\b|\\kape|eztools|'
    r'ez tools|magnet|axiom|for_dump_event|griffeye|\ynuix\y|encase|cellebrite|'
    r'oxygen forensic|oxydetective|oxyprocess|\bufed\b|physical analyzer|ufed4pc|belkasoft|griffeye|\bdar\.exe|\\tools\\|forensic_tools|dfir'
)


# Services whose crash (7031/7034) or stop is a fact the analyst needs dated: ESET died at
# 07:36 on the morning a wiper ran at 10:10 (3-4-19-1N, 2026-09-02).
AV_SERVICE_RX = ('ekrn|eset|windefend|msmpsvc|msmpeng|wdnissvc|mssense|sense[.]exe|avp[.]exe|kaspersky|sophos|'
                 'savservice|mcafee|mfe[a-z]|bdservicehost|bitdefender|avast|avgsvc|norton|symantec|ccsvchst|'
                 'crowdstrike|csfalcon|sentinel|cylance|ntrtscan|tmbmsrv|malwarebytes|mbam')


def _q(cur, sql, params):
    try:
        cur.execute(sql, params)
        return cur.fetchall()
    except Exception:
        try:
            cur.connection.rollback()
        except Exception:
            pass
        return []


def _clean_cmd_sample(sample, rx=None):
    """Strip EDR/integrity-level noise prefixes and show the matched region, not the
    noisy start of command_line. Fixes ugly threat-section examples like
    'mandatory label: security_mandatory_system_rid ...' / 'process (if real-time
    detection): unknown behavior:_process: ...'."""
    t = re.sub(r'mandatory label:\s*security_mandatory_\w+_rid\s*', '', sample, flags=re.I)
    t = re.sub(r'process \(if real-time detection\):\s*unknown behavior:_process:\s*', '', t, flags=re.I)
    t = re.sub(r'\s+', ' ', t).strip()
    if rx is not None:
        m = rx.search(t)
        if m:
            st = max(0, m.start() - 25)
            return t[st:st + 90]
    return t[:90]


# --- FP-hardening constants (2026-08-01) ---
# A real autostart key path, not just the substring "run" (the word "running" in
# Uninstall-key product metadata produced hundreds of FPs on clean machines).
_REG_ASEP_KEY_RE = r'(currentversion..{0,2}run(once)?|winlogon|image file execution options|appinit_dlls)'
# ...whose value points at a user-writable path or a script/LOLBin.
_REG_ASEP_VAL_RE = r'([a-z]:.{0,90}(\\|/)(temp|appdata|programdata|public|downloads)(\\|/)|powershell|[.](vbs|ps1|bat|cmd|js|hta|scr)\b|rundll32|mshta|regsvr32)'
# Vendor autoruns that legitimately sit under AppData/ProgramData or use rundll32.
_BENIGN_AUTORUN_RE = r'(onedrive|bingwallpaper|microsoftedge|edgeupdate|googleupdate|google drive|dropbox|megasync|yandex|opera|vivaldi|brave|chrome|firefox|telegram|viber|whatsapp|signal|discord|slack|zoom|teams|skype|steam|epicgames|spotify|logilda|logitech|realtek|nvidia|intel|amd |adobe|acrobat|java|jusched|msmpeng|mpcmdrun|windows defender|securityhealth|dismhost|onenote|office|ccleaner|piriform|eset|egui|kaspersky|avast|avg |dr.web|drweb|bitdefender|websigner|dbo soft|ezvit|medoc|anydesk|teamviewer)'
# WMI persistence = a consumer that RUNS something; Windows ships benign ones everywhere.
_WMI_CONSUMER_RE = r'(commandlineeventconsumer|activescripteventconsumer|scriptingengine|scripttext|commandlinetemplate)'
_WMI_BENIGN_CONSUMER_RE = r'(scm event log|bvtconsumer|bvtfilter|ntevent log|forwardedeventconsumer)'

# A ransom note is dropped into EVERY folder the malware encrypted, so the same name
# repeats across hundreds of directories. That repetition is the signal; the phrase
# list above stays as the name-only path for the classic families.
_NOTE_VOCAB_RE = re.compile(
    r'(recover|restore|decrypt|unlock|encrypt|ransom|readme|read[_ -]?me|how[ _-]?to)', re.I)
_NOTE_EXT_RE = re.compile(r'\.(txt|hta|html|htm|rtf|url)$', re.I)
# our own toolkit ships README/recovery-named rule files; match WHOLE path segments,
# never a substring (a bare Contains has produced four separate false-positive bugs)
_TOOLKIT_SEG_RE = re.compile(
    r'[\\/](kape|modules|targets|rules|hayabusa|zircolite|sigma|thor|thor-lite|loki|'
    r'chainsaw|dfir|dfir_triage|dfirbot)[\\/]', re.I)
# Extensions that mass-appear on a healthy Windows box; used only to skip candidates
# when picking the encrypted extension out of the note directories.
_NOT_ENCRYPTED_EXT = {
    'dll', 'mui', 'exe', 'sys', 'cat', 'mum', 'manifest', 'txt', 'log', 'log1', 'log2',
    'xml', 'ini', 'dat', 'tmp', 'json', 'js', 'png', 'jpg', 'jpeg', 'gif', 'ico', 'html',
    'htm', 'css', 'inf', 'pnf', 'etl', 'evtx', 'pf', 'db', 'mof', 'lnk', 'url', 'pri',
    'rtf', 'lock', 'ldb', 'old', 'bak', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt',
    'pptx', 'zip', 'rar', '7z', 'msi', 'cab', 'ps1xml', 'psd1', 'psm1', 'resjson',
    'config', 'pdb', 'wer', 'dmp', 'mun', 'data', 'patch', 'pac', 'identifier',
    # formats shipped by our own collector toolkit — never evidence of encryption
    'yml', 'yms', 'yaml', 'mkape', 'tkape', 'md', 'tsv', 'sigma', 'rule', 'ioc',
}
# Same vocabulary as _NOTE_VOCAB_RE, expressed for Postgres so the GROUP BY only ever
# aggregates candidate names instead of every file name in the case.
_NOTE_SQL_VOCAB = ('(recover|restore|decrypt|unlock|encrypt|ransom|readme|read[_ -]?me'
                   '|how[ _-]?to).*\\.(txt|hta|html|htm|rtf|url)$')
# One scan serves both the phrase path and the repetition path: same table, same kind of
# name. Union of the two old vocabularies, extensions included.
_NOTE_SQL_UNION = ('(recover|restore|decrypt|unlock|encrypt|ransom|readme|read[_ -]?me'
                   '|how.{0,4}to|!!!).*\\.(txt|hta|html|htm|rtf|url)$')


_INSTALLED_SW_RE = re.compile(r'[\\/](program files|program files \\(x86\\)|windows|'
                              r'programdata\\\\package cache|winsxs)[\\\\/]', re.I)


def _repeated_note_hits(cur, case_key, _q, name_rows):
    """Ransom notes found by REPETITION across directories, not by phrase.

    Returns [(file_name, dirs, files)] sorted by directory count. Two exclusions, both
    added after a regression run produced false criticals on clean cases: our own
    toolkit folders (whole-segment match), and files that live inside installed
    software, where a per-language `howtoscan.html` or a gadget `readme.txt` naturally
    repeats across tens of directories."""
    rows = [r for r in (name_rows or []) if r[1] >= 25]
    rows.sort(key=lambda r: -r[1])
    rows = rows[:60]
    _q(cur, "SET statement_timeout='20000'", ())
    out = []
    for fn, dirs, files in rows:
        fn = fn or ''
        if not (_NOTE_VOCAB_RE.search(fn) and _NOTE_EXT_RE.search(fn)):
            continue
        paths = [(r[0] or '') for r in _q(cur, """SELECT parent_path FROM filesystem_v2
                                                  WHERE case_key=%s AND file_name=%s
                                                  LIMIT 25""", (case_key, fn))]
        norm = [p.replace(chr(92), '/') + '/' for p in paths]
        if norm and all(_TOOLKIT_SEG_RE.search(p) for p in norm):
            continue
        # a note dropped by malware lands in data folders; a readme that ships with a
        # product lives under Program Files / Windows
        if norm and sum(1 for p in norm if _INSTALLED_SW_RE.search(p)) > len(norm) * 0.4:
            continue
        out.append((fn, dirs, files))
    _q(cur, "SET statement_timeout='0'", ())
    return out


def _encrypted_ext_in_note_dirs(cur, case_key, note_name, _q):
    """The extension that dominates the directories the ransom note was dropped in.

    Dictionary-free by design: whatever the family renames files to, it is the thing
    sitting next to its own note. Returns (ext, files_with_ext, dirs) or None."""
    _q(cur, "SET statement_timeout='20000'", ())
    dirs_rows = _q(cur, """SELECT DISTINCT parent_path FROM filesystem_v2
                           WHERE case_key=%s AND file_name=%s AND parent_path IS NOT NULL
                           LIMIT 300""", (case_key, note_name))
    note_dirs = [r[0] for r in dirs_rows]
    if not note_dirs:
        _q(cur, "SET statement_timeout='0'", ())
        return None
    rows = _q(cur, """
        SELECT lower(regexp_replace(file_name, '^.*\\.', '')) AS ext,
               count(*) AS files, count(DISTINCT parent_path) AS dirs
        FROM filesystem_v2
        WHERE case_key=%s AND parent_path = ANY(%s)
          AND file_name ~ '\\.[A-Za-z0-9]{3,12}$'
        GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 12""", (case_key, note_dirs))
    _q(cur, "SET statement_timeout='0'", ())
    for ext, files, dirs in rows:
        if ext and ext not in _NOT_ENCRYPTED_EXT and len(ext) >= 3 and not ext.isdigit() \
                and files >= 20:
            return (ext, files, dirs)
    return None


# Activation cracks, keygens and bundled "potentially unwanted" installers. Detecting
# these means the person at the keyboard installed something, not that somebody broke in.
_PUA_NAME_RE = re.compile(
    r'hacktool|autokms|kmsauto|kms.?activator|winactivator|activator|offact|keygen|'
    r'crack|riskware|puabundler|pua:|unwanted|softcnapp|presenoker', re.I)


def _self_inflicted_pua(cur, case_key, _q):
    """Piracy tooling with no sign of anyone else being on the machine.

    Returns dict(total, pua, others) when the picture holds, else None. Requires the
    piracy share to dominate AND every external-access signal to be absent, so a real
    intrusion that also happens to touch a KMS tool is never swallowed.
    """
    det = _q(cur, """SELECT coalesce(payload->>'PayloadData1', payload->>'ThreatName','') t,
                            count(*)
                     FROM event_logs_v2 WHERE case_key=%s AND event_id IN (1116,1117,1006,1015)
                     GROUP BY 1""", (case_key,))
    det = [(t, n) for t, n in det if 'malware name' in (t or '').lower()
           or 'threat' in (t or '').lower()]
    total = sum(n for _, n in det)
    if not total:
        return None
    pua = sum(n for t, n in det if _PUA_NAME_RE.search(t or ''))
    if pua < total * 0.6:
        return None
    for sql in (
        """SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id=4624
           AND substring(payload->>'PayloadData2' from 'LogonType[ ]*([0-9]+)')='10'""",
        "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id IN (4720,4732,4728)",
        """SELECT count(*) FROM program_exec_v2 WHERE case_key=%s
           AND lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) ~
               'ngrok|rdpwinst|rdpwrap|psexec|mimikatz|chisel|frpc|meterpreter|cobalt'""",
    ):
        r = _q(cur, sql, (case_key,))
        if r and r[0][0]:
            return None
    others = sorted(set(t.split(':', 1)[-1].strip() for t, _n in det
                        if not _PUA_NAME_RE.search(t or '')))
    return {'total': total, 'pua': pua, 'others': others}




def _note_scan(cur, case_key, _qf):
    """One filesystem scan, everything the ransom-note logic needs.

    Returns (note_hits, rep_notes, rep_top, rep_co). Extracted verbatim from
    detect_threats so that the report renderer can reuse the SAME dictionary-free
    derivation -- repetition across directories plus a co-located unknown
    extension -- instead of carrying its own phrase list."""
    _q = _qf
    # ── ransom notes FIRST (specific phrases only; a bare README must NOT match) ──
    # ONE scan for note-shaped names; both paths below read these rows
    name_rows = _q(cur, """SELECT file_name, count(DISTINCT parent_path) AS dirs, count(*) AS files
                           FROM filesystem_v2
                           WHERE case_key=%s AND coalesce(file_name,'') <> ''
                             AND lower(file_name) ~ %s
                           GROUP BY 1 ORDER BY 3 DESC, 1 LIMIT 200""",
                        (case_key, _NOTE_SQL_UNION))
    note_hits = [(fn, files) for fn, _dirs, files in name_rows
                 if RANSOM_NOTE_RE.search(fn or '')]
    # a note-shaped name that lives ONLY in vendor/system folders is an application's readme
    # (FurMark ships «_readme.txt» in Program Files) — it must not carry a CRITICAL verdict
    _kept = []
    for _fn, _files in note_hits:
        _r = _q(cur, """SELECT count(DISTINCT parent_path) FROM filesystem_v2
                        WHERE case_key=%s AND lower(file_name)=lower(%s)
                          AND lower(coalesce(parent_path,'')) !~ %s""",
                (case_key, _fn, r'(program files|programdata|windowsapps|[/\\]windows[/\\]|\$recycle|appdata[/\\]local[/\\]packages)'))
        if _r and _r[0] and _r[0][0]:
            _kept.append((_fn, _files))
    note_hits = _kept
    # second, independent path: the same note name repeated across many directories
    rep_notes = _repeated_note_hits(cur, case_key, _q, name_rows)
    # A repeated name is only a ransom note if the directories it repeats through also
    # hold files with an unknown, non-system extension — i.e. the encrypted files. This
    # is what separates «RecoveryHelp.txt» (4287 dirs, next to 6074 .vricpe files) from
    # a printer's «howtoscan.html» (35 dirs, next to nothing but .html).
    rep_top, rep_co = None, None
    for fn, dirs, files in rep_notes[:3]:
        _co = _encrypted_ext_in_note_dirs(cur, case_key, fn, _q)
        if _co:
            rep_top, rep_co = (fn, dirs, files), _co
            break
    if rep_top and rep_top[0] not in set(fn for fn, _ in note_hits):
        note_hits.append((rep_top[0], rep_top[2]))
    return note_hits, rep_notes, rep_top, rep_co


def ransom_note_names(cur, case_key, _qf=None):
    """The ransom-note file names for a case, or [] on a clean one.

    The renderer needs only the names, to read their write times; it must not
    have to know how they were derived."""
    _n, _rep, _top, _co = _note_scan(cur, case_key, _qf or _q)
    names = [fn for fn, _f in _n if fn]
    if _top and _top[0] not in names:
        names.append(_top[0])
    return names


_ATTACK_TOOL_RE = ('mimikatz|psexec|cobalt|advanced.?ip|advanced.?port|netscan|ngrok|pinggy|'
                   'rclone|megasync|process.?hacker|\\ygmer\\y|pchunter|defendercontrol|\\ynssm\\y|'
                   'rdpwrap|lazagne|secretsdump|winpeas|adfind|nltest|bloodhound|sharphound')


def _detect_threats_raw(case_key, conn):
    """Return a ranked list of concrete threat findings for the case."""
    cur = conn.cursor()
    findings = []

    def add(sev, cat, mitre, title, detail, count=0, samples=None, events=None, iocs=None):
        # FINDING SCHEMA (2026-09-04). `samples` are display strings; the report builders
        # need structure, so a finding may also carry:
        #   events: [{'ts': datetime|str, 'label': str, 'source': str, 'artifact': str}]
        #           - what happened, when, from which artefact; the chronology is their union
        #   iocs:   [{'type': 'file'|'path'|'task'|'gpo'|'hash'|'domain'|'ip'|'service'|'user',
        #             'value': str, 'role': str, 'source': str}]
        #           - the IOC section is their union; nothing else is an IOC by default
        #   Since 2026-09-06 every event also carries file (source_file in the archive),
        #   record (RecordNumber / $J entry), prov (formatted provenance string or ''),
        #   kind ('anchor' = dates an action; 'presence' = ShimCache/$MFT stamp = the file
        #   existed, or an anchor-class stamp more than 30 days away from the other legs).
        #   Presence legs are labelled, sorted after the anchors and left out of the
        #   finding's `window` [first anchor, last anchor]; the chain/CRITICAL logic and the
        #   report must not date a phase by them. IOCs carry file/record/prov the same way.
        # ts as text: the result builder json-dumps findings (a datetime broke the whole
        # narrative on 2026-09-04); the renderers parse ISO text back with _ev_ts
        _evs = []
        for _e in (events or []):
            _e = dict(_e or {})
            _dt = _as_dt(_e.get('ts'))
            _e['ts'] = (_dt.isoformat(sep=' ') if _dt is not None else (str(_e.get('ts')) if _e.get('ts') else None))
            _e.setdefault('label', '')
            _e.setdefault('source', '')
            _e.setdefault('artifact', '')
            _e['file'] = str(_e.get('file') or '')
            _e['record'] = '' if _e.get('record') in (None, '', 'None') else str(_e.get('record'))
            if not _e.get('prov'):
                _e['prov'] = provenance(case_key, _e['file'], _e['record'], cur)
            if _e.get('kind') not in ('anchor', 'presence'):
                _e['kind'] = ts_kind(_e['file'], _e.get('source'))
            _e['_dt'] = _dt
            _evs.append(_e)
        # an anchor-class stamp far away from the other anchors of the same finding is not a
        # leg of this chain (rdpwinst 2017 next to a 2026 tunnel): median of the anchors ±30 d
        _anch = [e for e in _evs if e['kind'] == 'anchor' and e['_dt'] is not None]
        if len(_anch) >= 2:
            _sorted = sorted(e['_dt'] for e in _anch)
            _med = _sorted[len(_sorted) // 2]
            for e in _anch:
                try:
                    if abs(e['_dt'] - _med) > _ANCHOR_WINDOW:
                        e['kind'] = 'presence'
                except Exception:
                    continue
        _win = [e['_dt'] for e in _evs if e['kind'] == 'anchor' and e['_dt'] is not None]
        for e in _evs:
            if e['kind'] == 'presence' and _PRESENCE_LABEL not in (e.get('label') or ''):
                e['label'] = '%s: %s' % (_PRESENCE_LABEL, e.get('label') or '')
        _evs.sort(key=lambda e: (0 if e['kind'] == 'anchor' else 1, e.get('ts') or '9999'))
        for e in _evs:
            e.pop('_dt', None)
        _ios = []
        for _i in (iocs or []):
            _i = dict(_i or {})
            _i['file'] = str(_i.get('file') or '')
            _i['record'] = '' if _i.get('record') in (None, '', 'None') else str(_i.get('record'))
            if not _i.get('prov'):
                _i['prov'] = provenance(case_key, _i['file'], _i['record'], cur)
            _ios.append(_i)
        findings.append({'severity': sev, 'category': cat, 'mitre': mitre,
                         'title': title, 'detail': detail, 'count': count,
                         'samples': (samples or [])[:6],
                         'events': _evs, 'iocs': _ios,
                         'window': ([min(_win).isoformat(sep=' '), max(_win).isoformat(sep=' ')] if _win else None)})

    # Collection-day cut (FIX_QUEUE №10): the collector's own PowerShell (464×4104 on DVB),
    # MagnetRAM/FTK drivers, the examiner's RDP session and the 5379 burst at capture time
    # are the response. Every query below that counts or lists events, executions or
    # services stops 10 minutes before the collection started; what was cut is reported
    # once, as counts, in the «Дії реагування/збору» line at the end.
    _cut_at = _collect_started_at(case_key, conn)
    _cut_ts = (_cut_at - timedelta(minutes=10)) if _cut_at else _FAR_FUTURE
    _CUT = " AND coalesce(event_ts < %s, true) "

    pua_self = _self_inflicted_pua(cur, case_key, _q)

    # ransom notes FIRST. The scan itself lives in _note_scan() because the report
    # renderer anchors its incident window on the same note names, and a second copy
    # of the vocabulary there would drift away from this one.
    note_hits, rep_notes, rep_top, rep_co = _note_scan(cur, case_key, _q)

    # ── 1) RANSOMWARE — encrypted extensions ──
    ext_rows = _q(cur, """
        SELECT lower(regexp_replace(file_name, '^.*\\.', '')) AS ext, count(*) c
        FROM filesystem_v2 WHERE case_key=%s AND file_name ~ '\\.[A-Za-z0-9]{2,12}$'
        GROUP BY 1 HAVING count(*) >= 25 ORDER BY 2 DESC, 1""", (case_key,))
    ransom_hit = None
    for ext, cnt in ext_rows:
        if ext and ext in RANSOM_EXT and cnt >= 25:        # KNOWN family extension = strong
            fam = RANSOM_EXT[ext]
            locs = _q(cur, """SELECT parent_path, count(*) FROM filesystem_v2 WHERE case_key=%s
                              AND lower(file_name) LIKE %s GROUP BY 1 ORDER BY 2 DESC LIMIT 6""",
                      (case_key, '%.' + ext))
            add('critical', 'Ransomware', 'T1486',
                'Шифрування файлів (ransomware: %s)' % fam,
                'Розширення «.%s» (сімейство %s) на %d файлах — масове шифрування.' % (ext, fam, cnt),
                cnt, [f'{p} ({n})' for p, n in locs])
            ransom_hit = (fam, ext, cnt)
            break
    # unknown family ONLY if corroborated by a REAL ransom note (kills .mum/.cdf-ms FPs)
    if not ransom_hit and rep_top:
        # anchor on the directories the note was dropped in — that is where the
        # encrypted files are, whatever the family decided to call them
        co = rep_co
        if co:
            ext, cnt, dirs = co
            total = _q(cur, """SELECT count(*) FROM filesystem_v2 WHERE case_key=%s
                                AND lower(file_name) ~ %s""",
                       (case_key, r'\.' + re.escape(ext) + '$'))
            all_cnt = total[0][0] if total else cnt
            locs = _q(cur, """SELECT parent_path, count(*) FROM filesystem_v2
                               WHERE case_key=%s AND lower(file_name) LIKE %s
                               GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 6""",
                      (case_key, '%.' + ext))
            add('critical', 'Ransomware', 'T1486',
                'Шифрування файлів (сімейство не визначене)',
                'Файли з розширенням «.%s» — %d шт., у тому числі %d у %d теках, де лежить '
                'записка «%s». Заміна розширення разом із запискою в тих самих теках = '
                'масове шифрування.' % (ext, all_cnt, cnt, dirs, rep_top[0]),
                all_cnt, ['%s (%d)' % (p, n) for p, n in locs])
            findings[-1]['facts'] = {'ext': ext, 'files': all_cnt,
                                     'note': rep_top[0], 'note_dirs': rep_top[1]}
            ransom_hit = ('unknown', ext, all_cnt)
    if not ransom_hit and note_hits:
        for ext, cnt in ext_rows:
            if not ext or ext in _BENIGN_EXT or ext in _NOT_ENCRYPTED_EXT:
                continue
            if cnt < 100 or len(ext) < 3 or ext.isdigit():
                continue
            # if the files with this extension live in our own toolkit folders, it is
            # our collector we are looking at, not the victim's data
            _sm = _q(cur, """SELECT parent_path FROM filesystem_v2 WHERE case_key=%s
                             AND lower(file_name) LIKE %s LIMIT 20""",
                     (case_key, '%.' + ext))
            _paths = [(r[0] or '').replace(chr(92), '/') + '/' for r in _sm]
            if _paths and sum(1 for p in _paths if _TOOLKIT_SEG_RE.search(p)) >= len(_paths) * 0.7:
                continue
            if True:
                add('high', 'Ransomware', 'T1486',
                    'Підозра на шифрування (невідоме сімейство)',
                    'Нестандартне розширення «.%s» на %d файлах + наявна записка викупу — імовірне шифрування.' % (ext, cnt),
                    cnt)
                ransom_hit = ('unknown', ext, cnt)
                break

    # ── 1b) when did the encryption run? (last_modified of the encrypted files; creation
    #        times are the ORIGINAL files' and can span years — case_66 2007→2026) ──
    try:
        if ransom_hit:
            _rext = ransom_hit[1]
            _tm = _q(cur, """SELECT min(m), max(m), count(*), (array_agg(source_file ORDER BY m))[1]
                             FROM (SELECT ((payload->>'last_modified')::timestamp AT TIME ZONE 'UTC') AS m, source_file
                                   FROM filesystem_v2 WHERE case_key=%s AND lower(file_name) LIKE %s
                                     AND coalesce(payload->>'last_modified','') ~ '^20[0-9]{2}-') t""",
                      (case_key, '%.' + _rext)) or []
            _pk = _q(cur, """SELECT date_trunc('hour', ((payload->>'last_modified')::timestamp AT TIME ZONE 'UTC')) h, count(*)
                             FROM filesystem_v2 WHERE case_key=%s AND lower(file_name) LIKE %s
                               AND coalesce(payload->>'last_modified','') ~ '^20[0-9]{2}-'
                             GROUP BY 1 ORDER BY 2 DESC LIMIT 1""", (case_key, '%.' + _rext)) or []
            if _tm and _tm[0] and _tm[0][0]:
                _t0, _t1, _n, _sf = _tm[0]
                _evs = [{'ts': _t0, 'label': 'початок шифрування: перший файл «.%s» змінено' % _rext,
                         'source': 'filesystem_v2 (MFT last_modified)', 'artifact': _sf or '', 'kind': 'anchor'}]
                if _pk and _pk[0] and _pk[0][0]:
                    _evs.append({'ts': _pk[0][0], 'label': 'пік шифрування: %d файлів за годину' % int(_pk[0][1] or 0),
                                 'source': 'filesystem_v2 (MFT last_modified)', 'artifact': _sf or '', 'kind': 'anchor'})
                _evs.append({'ts': _t1, 'label': 'кінець шифрування: останній із %d файлів «.%s»' % (int(_n or 0), _rext),
                             'source': 'filesystem_v2 (MFT last_modified)', 'artifact': _sf or '', 'kind': 'anchor'})
                for _f in findings:
                    if _f.get('category') == 'Ransomware' and 'ифруван' in str(_f.get('title') or '') and not _f.get('events'):
                        _f['events'] = _evs
                        try:
                            _f['window'] = [_t0.isoformat(sep=' '), _t1.isoformat(sep=' ')]
                        except Exception:
                            pass
                        _f['detail'] = (str(_f.get('detail') or '').rstrip() +
                                        ' Шифрування тривало з %s до %s (за last_modified %d файлів).'
                                        % (str(_t0)[:16], str(_t1)[:16], int(_n or 0)))
    except Exception:
        pass

    # ── 2) Ransom note finding (only for specific ransom-note names) ──
    if note_hits:
        top = note_hits[0]
        _dirs = dict((fn, d) for fn, d, _f in rep_notes)
        _d = _dirs.get(top[0])
        # the first and last drop of each note name, with the $J entry / $MFT row it comes from
        _note_ev, _note_io = [], []
        for _fn, _n in note_hits[:4]:
            for _t0, _t1, _cnt, _pp, _sf, _rn in (_q(cur, """SELECT min(event_ts), max(event_ts), count(*),
                                                              max(nullif(parent_path,'')),
                                                              (array_agg(source_file ORDER BY event_ts, (CASE WHEN source_file ILIKE '%%$J%%' THEN 0 ELSE 1 END)))[1],
                                                              (array_agg(payload->>'entry_number' ORDER BY event_ts, (CASE WHEN source_file ILIKE '%%$J%%' THEN 0 ELSE 1 END)))[1]
                                                       FROM filesystem_v2 WHERE case_key=%s AND lower(file_name)=lower(%s) AND event_ts IS NOT NULL""" + _CUT, (case_key, _fn, _cut_ts)) or []):
                if _t0:
                    _note_ev.append({'ts': _t0, 'label': 'перша поява записки викупу %s (усього %d до %s)' % (_fn, _cnt, str(_t1)[:16]), 'source': 'filesystem_v2 ($J/$MFT)',
                                     'artifact': (_pp or '')[:160], 'file': _sf, 'record': _rn})
                _note_io.append({'type': 'file', 'value': _fn, 'role': 'записка з вимогою викупу', 'source': 'filesystem_v2', 'file': _sf, 'record': _rn})
        add('critical', 'Ransomware', 'T1486',
            'Записка з вимогою викупу',
            'Файл-записка «%s» виявлений у %d розташуваннях%s — підтверджує ransomware.'
            % (top[0], sum(n for _, n in note_hits),
               (' (%d різних тек — записку розкладено в кожну зашифровану теку)' % _d) if _d else ''),
            sum(n for _, n in note_hits), [f'{fn} ({n})' for fn, n in note_hits], events=_note_ev, iocs=_note_io)
        findings[-1]['facts'] = {'note': top[0], 'note_dirs': _d}

    # ── 2b) destruction of recovery options (T1490) ──
    # Anchor on vssadmin/wbadmin: those exist to delete shadow copies and backups.
    # bcdedit and reagentc alone also run during legitimate servicing — measured on a
    # clean case in this very database — so they only ESCALATE, they never fire alone.
    # source_file decides what the timestamp means: Prefetch/Amcache record a real
    # execution, AppCompatCache/ShimCache records the file's own mtime.
    # count(*) would count ROWS, and a row is not an observation: AppCompatCacheParser emits
    # the cache from BOTH control sets (ControlSet001/002), so every entry legitimately appears
    # twice - and twice again when the case holds two registry exports. That is how a single
    # observation printed as "vssadmin (4)". The rows stay (two control sets are two independent
    # witnesses); what changes is the counting: DISTINCT (exe, path, ts) over the whole case, not
    # per source_file - a per-file DISTINCT would still sum 1+1=2 across the two exports.
    # A NULL event_ts collapses to one observation: they cannot be told apart, and over-counting
    # is exactly the defect being fixed.
    kill_rows = _q(cur, """SELECT lower(coalesce(exe,'')), has_real, count(*), max(ts)
                           FROM (SELECT executable_name AS exe, full_path AS fp, event_ts AS ts,
                                        bool_or(coalesce(source_file,'') !~* 'appcompat|shimcache')
                                            AS has_real
                                 FROM program_exec_v2 WHERE case_key=%s
                                 AND lower(coalesce(executable_name,'')) ~
                                     'vssadmin|wbadmin|bcdedit|reagentc|wmic'
                                 GROUP BY 1, 2, 3) o
                           GROUP BY 1, 2""", (case_key,))
    _tools = {}
    _shim_only = {}
    for name, _has_real, n, last in kill_rows:
        base = (name or '').replace(chr(92), '/').rsplit('/', 1)[-1]
        _is_shim = not _has_real
        for t in ('vssadmin', 'wbadmin', 'bcdedit', 'reagentc', 'wmic'):
            if t in base:
                _prev = _tools.get(t, (0, None))
                _tools[t] = (_prev[0] + n, last if (_prev[1] is None or (last and last > _prev[1])) else _prev[1])
                _d = _shim_only.setdefault(t, {'shim': 0, 'real': 0})
                _d['shim' if _is_shim else 'real'] += n
    _anchor = [t for t in ('vssadmin', 'wbadmin') if t in _tools]
    _escal = [t for t in ('bcdedit', 'reagentc', 'wmic') if t in _tools]
    if _anchor:
        _all = _anchor + _escal
        _real_rows = sum(_shim_only.get(t, {}).get('real', 0) for t in _all)
        if _real_rows:
            add('critical' if _escal else 'high', 'Знищення резервних копій', 'T1490',
                'Знищення можливості відновлення',
                'Запускались: %s. Це стандартний крок шифрувальника перед шифруванням — '
                'видалити тіньові копії та резервні копії, щоб файли не можна було відкотити. '
                'Прапорці запуску в Prefetch/Amcache не зберігаються, тому підтверджено сам '
                'факт запуску, а не аргументи.'
                % ', '.join('%s (%d)' % (t, _tools[t][0]) for t in _all),
                sum(_tools[t][0] for t in _all),
                ['%s — останній запуск %s' % (t, _tools[t][1]) for t in _all])
            findings[-1]['facts'] = {'kill_tools': _all}
        else:
            # ShimCache only. vssadmin.exe / wbadmin.exe / wmic.exe ship with every
            # Windows, so their presence proves nothing; the timestamps here are the
            # binaries' build dates. Say that instead of calling it a launch.
            add('medium', 'Знищення резервних копій', 'T1490',
                'Засоби знищення резервних копій присутні (ЗА ShimCache — не доказ запуску)',
                'У ShimCache/AppCompatCache є записи про %s. ShimCache зберігає час '
                'ЗМІНИ ФАЙЛУ, а не час запуску, і ці утиліти входять до складу Windows — '
                'тому сам факт запуску НЕ доведений. Щоб довести видалення тіньових копій, '
                'потрібні Prefetch/Amcache, командні рядки (4688/4104) або журнал VSS.'
                % ', '.join('%s (%d)' % (t, _tools[t][0]) for t in _all),
                sum(_tools[t][0] for t in _all),
                ['%s — час файлу за ShimCache %s' % (t, _tools[t][1]) for t in _all])
            findings[-1]['facts'] = {'kill_tools': _all, 'shimcache_only': True}

    if pua_self:
        _oth = ('; серед детекцій є не-піратські: %s' % ', '.join(pua_self['others'][:4])) \
            if pua_self['others'] else ''
        add('medium', 'Самозаподіяне (піратське ПЗ)', 'T1588',
            'Ознак стороннього втручання не виявлено — картина відповідає піратському ПЗ',
            'З %d детекцій антивіруса %d — це засоби активації/зламу (HackTool, keygen, '
            'activator). При цьому немає жодного входу по RDP, жодного створеного облікового '
            'запису і жодного інструмента віддаленого доступу чи тунелю. Найімовірніше, '
            'користувач сам встановлював піратське ПЗ і сам вимкнув захист, щоб воно '
            'запрацювало%s.' % (pua_self['total'], pua_self['pua'], _oth),
            pua_self['pua'],
            (['УВАГА: %s — це вже справжня загроза, її треба прибрати незалежно від '
              'походження' % o for o in pua_self['others'][:3]] or None))

    # ── 3) Log tampering (1102 security / 104 system cleared) ──
    # CHANNEL-GUARDED: 1102 only counts on the Security log (audit log cleared);
    # 104 only when provider is Eventlog. Without this, EID 1102 on unrelated
    # channels (e.g. ShellCommon-StartLayoutPopulation) produced huge false counts.
    _LOGCLR_SQL = "((event_id=1102 AND channel='Security') OR (event_id=104 AND channel IN ('System','Security') AND coalesce(provider,'') ILIKE '%%Eventlog%%'))"
    lt = _q(cur, "SELECT event_id, count(*) FROM event_logs_v2 WHERE case_key=%s AND " + _LOGCLR_SQL + _CUT + " GROUP BY 1", (case_key, _cut_ts))
    lt_total = sum(n for _, n in lt)
    if lt_total >= 3:
        _lt_rows = _q(cur, """SELECT event_ts, event_id, channel, coalesce(payload->>'PayloadData1',''), source_file, payload->>'RecordNumber'
                              FROM event_logs_v2 WHERE case_key=%s AND """ + _LOGCLR_SQL + _CUT + """
                              ORDER BY event_ts LIMIT 10""", (case_key, _cut_ts)) or []
        add('high', 'Анти-форензика', 'T1070.001',
            'Очищення журналів подій',
            'Зафіксовано %d подій очищення Windows-журналів (EID 1102/104) — приховування слідів.' % lt_total,
            lt_total,
            events=[{'ts': r[0], 'label': 'очищено журнал (EID %s%s)' % (r[1], (': ' + r[3][:60]) if r[3] else ''),
                     'source': 'event_logs_v2/%s' % (r[2] or ''), 'artifact': r[2] or '', 'file': r[4], 'record': r[5]} for r in _lt_rows if r[0]])

    # ── 4) RDP intrusion (logon_type often NULL after EvtxECmd → use multiple signals) ──
    # Every RDP counter is signed by its source (FIX_QUEUE №18): case_43 read «RDP-доступ:
    # 220 ознак» from hayabusa «RDP Logon» rows built on LocalSessionManager 21/25, which
    # fire for console logons too (SrcIP: LOCAL) - the DB had 0×1149 and 0×type-10. Without
    # a 1149 or a 4624 type 10 the host had no RDP session and the line says so.
    _T10_SQL = "(logon_type ILIKE '%%remote interactive%%' OR logon_type ILIKE '%%RDP%%' OR logon_type='10' OR substring(payload->>'PayloadData2' from 'LogonType[ ]*([0-9]+)')='10')"
    _r = _q(cur, "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id=1149 AND channel ILIKE '%%TerminalServices%%'" + _CUT, (case_key, _cut_ts))
    _rdp_1149 = int(_r[0][0] or 0) if _r else 0
    _r = _q(cur, "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id=4624 AND " + _T10_SQL + _CUT, (case_key, _cut_ts))
    _rdp_t10 = int(_r[0][0] or 0) if _r else 0
    # 4778 is also fast-user-switching and a console session coming back from the lock
    # screen (ClientAddress LOCAL) - case_43 had 220 of those and no RDP at all
    _r = _q(cur, "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id=4778 AND channel='Security' AND coalesce(payload->>'ClientAddress', payload->>'PayloadData3', '') !~* '^(local|127[.]0[.]0[.]1|::1|-)?$'" + _CUT, (case_key, _cut_ts))
    _rdp_4778 = int(_r[0][0] or 0) if _r else 0
    _r = _q(cur, "SELECT count(*) FROM tool_alerts_v2 WHERE case_key=%s AND lower(coalesce(rule,'')) ~ 'rdp session connect|rds.{0,4}session logon|remote desktop' "
                 "AND lower(coalesce(details,'')) !~ 'srcip: *(local|локал|127[.]0[.]0[.]1|::1|-)'" + _CUT, (case_key, _cut_ts))
    _rdp_alerts = int(_r[0][0] or 0) if _r else 0
    _rdp_core = _rdp_1149 + _rdp_t10
    rdp_n = _rdp_core + _rdp_4778 + _rdp_alerts
    _rdp_src = 'джерела лічильника: 1149=%d, 4624 type 10=%d, 4778=%d, детекції hayabusa/DeepBlue=%d' % (_rdp_1149, _rdp_t10, _rdp_4778, _rdp_alerts)
    if rdp_n >= 10 and _rdp_core >= 1:
        _rdp_rows = _q(cur, """SELECT min(event_ts), max(event_ts), count(*), coalesce(nullif(payload->>'TargetUserName',''), target_user, '?'),
                                      coalesce(nullif(remote_host,''), payload->>'IpAddress', payload->>'Address', payload->>'SourceNetworkAddress', ''),
                                      (array_agg(source_file ORDER BY event_ts))[1], (array_agg(payload->>'RecordNumber' ORDER BY event_ts))[1]
                               FROM event_logs_v2 WHERE case_key=%s
                               AND ((event_id=1149 AND channel ILIKE '%%TerminalServices%%')
                                    OR (event_id=4624 AND """ + _T10_SQL + """))""" + _CUT + """
                               GROUP BY 4, 5 ORDER BY 3 DESC LIMIT 8""", (case_key, _cut_ts)) or []
        _rdp_iocs = []
        for _t0, _t1, _n, _u, _ip, _sf, _rn in _rdp_rows:
            _ip = _ip_of(_ip)   # «WORKSTATION (ip)» -> ip; LogonId / process name / other text -> ''
            if _ip and _ip not in ('-', '::1', '127.0.0.1') and not _ip.startswith('fe80'):
                _rdp_iocs.append({'type': 'ip', 'value': _ip, 'role': 'джерело RDP-входу (%d сесій, %s)' % (_n, _u), 'source': 'event_logs_v2 4624/1149', 'file': _sf, 'record': _rn})
            if _u and _u not in ('?', '-') and not _u.endswith('$'):
                _rdp_iocs.append({'type': 'user', 'value': _u, 'role': 'акаунт RDP-входів (%d)' % _n, 'source': 'event_logs_v2 4624/1149', 'file': _sf, 'record': _rn})
        add('high', 'Доступ (RDP)', 'T1021.001',
            'RDP-доступ до хоста',
            'Виявлено %d ознак RDP-сесій (вхід/підключення/реконект) — ймовірний вектор доступу/латерального руху; %s.' % (rdp_n, _rdp_src), rdp_n,
            events=[{'ts': r[0], 'label': 'перший RDP-вхід %s%s (%d сесій до %s)' % (r[3], (' з ' + _ip_of(r[4])) if _ip_of(r[4]) else '', r[2], str(r[1])[:16]),
                     'source': 'event_logs_v2 4624/1149', 'artifact': 'Security/TerminalServices', 'file': r[5], 'record': r[6]} for r in _rdp_rows if r[0]],
            iocs=_rdp_iocs[:12])
    elif rdp_n >= 10:
        add('low', 'Доступ (не підтверджено)', 'T1021.001',
            'Сесійні події RDS без RDP-підключень',
            'Детектори позначили %d подій «RDP Logon/Session» (LocalSessionManager 21/25 та 4778 — вони фіксуються і для консольних входів), '
            'але у журналах 0 подій 1149 (TerminalServices) і 0 входів 4624 type 10 — RDP-доступ до хоста НЕ підтверджено; %s.' % (rdp_n, _rdp_src), rdp_n)
    # The only place the RDP source address survives EvtxECmd is 1149 (remote_host); 4624
    # IpAddress is empty on all 12 cases, so "type 10 from a public address" fired 0/12 by
    # construction. Public sources become IOCs; a localhost source (::%16777216 / 127.0.0.1 /
    # ::1) means the RDP session came through a tunnel or an RDP-wrapper on the box itself.
    _src = _q(cur, """SELECT coalesce(remote_host,''), count(*), min(event_ts), max(event_ts),
                             (array_agg(source_file ORDER BY event_ts))[1], (array_agg(payload->>'RecordNumber' ORDER BY event_ts))[1]
                      FROM event_logs_v2
                      WHERE case_key=%s AND event_id=1149 AND channel ILIKE '%%TerminalServices%%'""" + _CUT + """
                      GROUP BY 1 ORDER BY 2 DESC LIMIT 20""", (case_key, _cut_ts)) or []
    _src4624 = _q(cur, """SELECT coalesce(remote_host,''), count(*), min(event_ts), max(event_ts),
                             (array_agg(source_file ORDER BY event_ts))[1], (array_agg(payload->>'RecordNumber' ORDER BY event_ts))[1]
                      FROM event_logs_v2
                      WHERE case_key=%s AND event_id=4624 AND """ + _T10_SQL + _CUT + """
                      GROUP BY 1 ORDER BY 2 DESC LIMIT 20""", (case_key, _cut_ts)) or []
    _seen = {str(r[0]).strip() for r in _src}
    for _h, _n, _t0, _t1, _sf, _rn in _src4624:
        _a = _ip_of(_h)
        if _a and _a not in _seen and _a not in ('127.0.0.1', '::1'):
            _seen.add(_a)
            _src.append((_a, _n, _t0, _t1, _sf, _rn))
    _pub, _loc = [], []
    for _h, _n, _t0, _t1, _sf, _rn in _src:
        _hs = str(_h or '').strip()
        if not _hs or _hs == '-':
            continue
        if _hs in ('127.0.0.1', '::1') or _hs.startswith('::%') or _hs.lower().startswith('localhost'):
            _loc.append((_hs, _n, _t0, _t1, _sf, _rn))
        elif not re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|fe80|fd)', _hs, re.I):
            _pub.append((_hs, _n, _t0, _t1, _sf, _rn))
    if _pub:
        # attach the sources to the RDP finding when it exists, else record them on their own
        _rdp_f = next((f for f in findings if f.get('title') == 'RDP-доступ до хоста'), None)
        _pub_iocs = [{'type': 'ip', 'value': h, 'role': 'зовнішнє джерело RDP-підключень (%d, %s..%s)' % (n, str(t0)[:10], str(t1)[:10]), 'source': 'TerminalServices 1149 / Security 4624 type 10',
                      'file': sf, 'record': rn, 'prov': provenance(case_key, sf, rn, cur)} for h, n, t0, t1, sf, rn in _pub[:10]]
        _pub_ev = [{'ts': t0.isoformat(sep=' ') if hasattr(t0, 'isoformat') else str(t0), 'label': 'перше RDP-підключення з %s (усього %d)' % (h, n), 'source': 'TerminalServices 1149', 'artifact': h,
                    'file': sf, 'record': rn or '', 'prov': provenance(case_key, sf, rn, cur), 'kind': 'anchor'} for h, n, t0, t1, sf, rn in _pub[:6] if t0]
        if _rdp_f is not None:
            _rdp_f['iocs'] = (_rdp_f.get('iocs') or []) + _pub_iocs
            _rdp_f['events'] = (_rdp_f.get('events') or []) + _pub_ev
        else:
            add('high', 'Доступ (RDP)', 'T1133',
                'RDP-підключення із зовнішніх адрес',
                'Зафіксовано %d RDP-підключень (EID 1149 / 4624 type 10) з %d публічних адрес: %s.' % (sum(x[1] for x in _pub), len(_pub), ', '.join(x[0] for x in _pub[:6])),
                sum(x[1] for x in _pub), [x[0] for x in _pub[:6]], events=_pub_ev, iocs=_pub_iocs)
    _loc_n = sum(x[1] for x in _loc)
    if _loc_n >= 3:
        add('high', 'Доступ (RDP через тунель)', 'T1090',
            'RDP через локальний тунель / RDP-wrapper',
            'Зафіксовано %d RDP-підключень (EID 1149) з локальної адреси (%s) — сесія прийшла через тунель (ngrok/frp/SSH) або RDP-wrapper на самій машині, '
            'а не з мережі; зовнішньої адреси у журналі бути не може. Шукай тунельний клієнт та його конфіг.'
            % (_loc_n, ', '.join(x[0] for x in _loc[:3])), _loc_n, ['%s ×%d (%s..%s)' % (h, n, str(t0)[:10], str(t1)[:10]) for h, n, t0, t1, _, _ in _loc[:4]],
            events=[{'ts': t0, 'label': 'перше RDP-підключення з localhost %s (усього %d до %s)' % (h, n, str(t1)[:16]), 'source': 'TerminalServices 1149', 'artifact': h,
                     'file': sf, 'record': rn} for h, n, t0, t1, sf, rn in _loc if t0],
            iocs=[{'type': 'ip', 'value': h, 'role': 'локальна адреса RDP-підключень через тунель/RDP-wrapper (%d)' % n, 'source': 'TerminalServices 1149', 'file': sf, 'record': rn} for h, n, t0, t1, sf, rn in _loc[:3]])
    bf = _q(cur, "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id=4625" + _CUT, (case_key, _cut_ts))
    bf_n = bf[0][0] if bf else 0
    if bf_n >= 50:
        add('medium', 'Доступ', 'T1110',
            'Підбір паролів (failed logons)',
            'Зафіксовано %d невдалих входів (EID 4625) — можливий брутфорс.' % bf_n, bf_n)

    # ── 5) Defense evasion (firewall / service kills / Defender) ──
    fw = _q(cur, "SELECT count(*) FROM tool_alerts_v2 WHERE case_key=%s AND lower(coalesce(rule,'')) ~ 'firewall'" + _CUT, (case_key, _cut_ts))
    fw_n = fw[0][0] if fw else 0
    if fw_n >= 5:
        # 31 rule changes on a workstation were installers and updaters (the Hayabusa rows name
        # GoogleUpdater as ModifyingApplication) and the report called them "preparing a C2
        # channel". Evasion needs a reason: a rule written by a program outside the vendor
        # trees, or the "uncommon new rule" signature repeating.
        _fw_odd = _q(cur, """SELECT count(*), min(event_ts), max(event_ts),
                                    (array_agg(source_file ORDER BY event_ts))[1], (array_agg(payload->>'record_id' ORDER BY event_ts))[1]
                             FROM tool_alerts_v2 WHERE case_key=%s
                             AND lower(coalesce(rule,'')) ~ 'firewall'
                             AND coalesce(details,'') ~* 'ModifyingApplication: [a-z]:'
                             AND coalesce(details,'') !~* 'ModifyingApplication: [a-z]:[^¦]*(program files|systemtemp|system32|windowsapps|programdata\\\\microsoft)'""" + _CUT, (case_key, _cut_ts))
        _fw_unc = _q(cur, """SELECT count(*) FROM tool_alerts_v2 WHERE case_key=%s
                             AND lower(coalesce(rule,'')) ~ 'uncommon new firewall rule'""" + _CUT, (case_key, _cut_ts))
        _fw_odd_n = int(_fw_odd[0][0] or 0) if _fw_odd else 0
        _fw_unc_n = int(_fw_unc[0][0] or 0) if _fw_unc else 0
        if _fw_odd_n >= 1 or _fw_unc_n >= 3:
            add('medium', 'Захист обходили', 'T1562.004',
                'Зміни правил брандмауера',
                'Виявлено %d подій зміни правил Windows Firewall, з них %d від програм поза вендорськими теками і %d нетипових нових правил — перевір, чи це підготовка каналу.' % (fw_n, _fw_odd_n, _fw_unc_n), fw_n,
                events=[{'ts': _fw_odd[0][1], 'label': 'перша зміна правила брандмауера програмою поза вендорськими теками',
                         'source': 'tool_alerts_v2/hayabusa', 'artifact': 'Microsoft-Windows-Windows Firewall With Advanced Security',
                         'file': _fw_odd[0][3], 'record': _fw_odd[0][4]}] if (_fw_odd and _fw_odd[0][1]) else None)
        else:
            add('low', 'Захист (інформаційно)', 'T1562.004',
                'Зміни правил брандмауера інсталяторами/оновлювачами',
                'Виявлено %d подій зміни правил Windows Firewall, усі від програм у вендорських теках (оновлювачі/інсталятори) — звичайна активність, не евазія.' % fw_n, fw_n)
    # Defender DISABLE / tamper — 5001 RTP off, 5010 AM off, 5012 AV off (NOT 5007 = benign config change)
    # PROVIDER-GUARDED: EID 5001 also exists under Cisco Secure Client / NcdAutoSetup,
    # which are NOT Defender. Require the Windows Defender provider.
    ddis = _q(cur, "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id IN (5001,5010,5012) AND coalesce(provider,'') ILIKE '%%Windows Defender%%'" + _CUT, (case_key, _cut_ts))
    ddis_n = ddis[0][0] if ddis else 0
    if ddis_n >= 1:
        _dd_rows = _q(cur, """SELECT event_ts, event_id, source_file, payload->>'RecordNumber' FROM event_logs_v2 WHERE case_key=%s AND event_id IN (5001,5010,5012)
                              AND coalesce(provider,'') ILIKE '%%Windows Defender%%'""" + _CUT + """ ORDER BY event_ts LIMIT 8""", (case_key, _cut_ts)) or []
        # Who switched it off? A third-party antivirus arriving in the same days turns
        # Defender off by design (kyiv: McAfee), a pirated activator is the user's own hand
        # (case_56), and only a switch-off next to malware/tool activity is the attacker's.
        # judged per switch-off event, not by the oldest one: case_55 had a 2022 switch-off
        # and the one that matters on 2026-04-06, between AsyncRAT (04-02) and Crack (04-07)
        _dd_sev, _dd_why = 'medium', ' Поруч немає детекцій чи інструментів атаки — перевірити, чи не вимкнув користувач або сторонній антивірус.'
        _avinst = []
        for _dd_ts, _dd_eid, _dd_sf, _dd_rn in _dd_rows:
            if _dd_ts is None or pua_self:     # the activator's own detections are "near" by definition
                continue
            _near = _q(cur, """SELECT (SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id IN (1116,1117)
                                       AND coalesce(provider,'') ILIKE '%%Windows Defender%%' AND event_ts BETWEEN %s - interval '7 days' AND %s + interval '7 days')
                                    + (SELECT count(*) FROM program_exec_v2 WHERE case_key=%s AND event_ts BETWEEN %s - interval '7 days' AND %s + interval '7 days'
                                       AND lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) ~ %s)""",
                       (case_key, _dd_ts, _dd_ts, case_key, _dd_ts, _dd_ts, _ATTACK_TOOL_RE)) or []
            if _near and _near[0][0]:
                _dd_sev, _dd_why = 'high', ''
                break
            if not _avinst:
                _avinst = _q(cur, """SELECT coalesce(payload->>'PayloadData1',''), event_ts FROM event_logs_v2 WHERE case_key=%s AND event_id=7045
                                     AND event_ts BETWEEN %s - interval '3 days' AND %s + interval '3 days'
                                     AND payload::text ~* 'mcafee|eset|kaspersky|avast|avg |bitdefender|norton|symantec|sophos|malwarebytes|reason security|360 total|dr[.]web|drweb|panda|trend micro|f-secure|webroot|crowdstrike|sentinel'
                                     ORDER BY event_ts LIMIT 3""", (case_key, _dd_ts, _dd_ts)) or []
        if _dd_sev != 'high':
            if pua_self:
                _dd_sev, _dd_why = 'medium', ' Детекції поруч — піратські активатори; схоже на дії самого користувача.'
            elif _avinst:
                _dd_sev, _dd_why = 'low', ' У ті ж дні встановлено сторонній антивірус (%s) — Defender вимикається штатно.' % (_avinst[0][0] or '')[:60]
        add(_dd_sev, 'Захист обходили' if _dd_sev == 'high' else 'Захист (перевірити)', 'T1562.001',
            'Вимкнення Windows Defender',
            ('Зафіксовано %d подій вимкнення компонентів захисту Defender (EID 5001/5010/5012).' % ddis_n) + _dd_why, ddis_n,
            events=[{'ts': r[0], 'label': 'вимкнено компонент Defender (EID %s)' % r[1], 'source': 'Microsoft-Windows-Windows Defender/Operational',
                     'artifact': 'EID %s' % r[1], 'file': r[2], 'record': r[3]} for r in _dd_rows if r[0]])
    # Defender DETECTIONS — the AV actually flagged malware (confirmed infection + names)
    # PROVIDER-GUARDED: EID 1116/1117 collide with Microsoft-Windows-PushNotification-Platform
    # (benign). Require the Windows Defender provider so only real AV detections count.
    ddet = _q(cur, "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id IN (1116,1117) AND coalesce(provider,'') ILIKE '%%Windows Defender%%'" + _CUT, (case_key, _cut_ts))
    ddet_n = ddet[0][0] if ddet else 0
    # SPECIFIC threat names (Trojan:Win32/..., HackTool:..., Behavior:...) — EvtxECmd
    # dumps the full Defender detection into raw_fallback; the exact family/name is far
    # more useful to an analyst than the generic severity category in PayloadData.
    _threat_names = []
    try:
        _tn = _q(cur, r"""SELECT DISTINCT substring(payload::text from
                    '(?:Trojan|HackTool|Behavior|PUA|PUADlManager|PWS|Backdoor|Ransom|VirTool|Exploit|Worm|DoS|TrojanDownloader|TrojanSpy):Win(?:32|64)/[A-Za-z0-9._!]+')
                  FROM raw_fallback_v2 WHERE case_key=%s
                  AND payload::text ~ '(?:Trojan|HackTool|Behavior|Backdoor|Ransom|VirTool|Exploit|Worm|PWS|TrojanDownloader|TrojanSpy):Win(?:32|64)/'
                  ORDER BY 1 LIMIT 12""", (case_key,))
        _threat_names = sorted({r[0] for r in _tn if r and r[0]})
    except Exception:
        try: conn.rollback()
        except Exception: pass
        _threat_names = []
    if ddet_n >= 1 or _threat_names:
        if _threat_names:
            _detail = ('Windows Defender зафіксував %d детектів; конкретні загрози: %s.'
                       % (max(ddet_n, len(_threat_names)), ', '.join(_threat_names[:6])))
            _samples = _threat_names[:8]
        else:
            nm = _q(cur, """SELECT coalesce(payload->>'PayloadData2', payload->>'PayloadData1'), count(*)
                            FROM event_logs_v2 WHERE case_key=%s AND event_id IN (1116,1117)
                            AND coalesce(provider,'') ILIKE '%%Windows Defender%%'""" + _CUT + """
                            GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 6""", (case_key, _cut_ts))
            _detail = 'Windows Defender зафіксував %d детектів шкідливого ПЗ (EID 1116/1117) — підтверджене зараження.' % ddet_n
            _samples = [str(n0)[:70] for n0, _ in nm if n0]
        _det_rows = _q(cur, """SELECT min(event_ts), max(event_ts), count(*),
                                      (array_agg(source_file ORDER BY event_ts))[1], (array_agg(payload->>'RecordNumber' ORDER BY event_ts))[1]
                               FROM event_logs_v2 WHERE case_key=%s
                               AND event_id IN (1116,1117) AND coalesce(provider,'') ILIKE '%%Windows Defender%%'""" + _CUT, (case_key, _cut_ts)) or []
        _det_ev = []
        if _det_rows and _det_rows[0][0]:
            _det_ev.append({'ts': _det_rows[0][0], 'label': 'перша детекція Defender (усього %d до %s)' % (_det_rows[0][2], str(_det_rows[0][1])[:16]),
                            'source': 'Microsoft-Windows-Windows Defender/Operational 1116/1117', 'artifact': ', '.join(_threat_names[:3]),
                            'file': _det_rows[0][3], 'record': _det_rows[0][4]})
        # When the detections are the user's own activators (and nobody else was on the
        # machine - _self_inflicted_pua checked RDP/accounts/tools), this is hygiene, not
        # an intrusion; case_56 read "26 detections, confirmed infection" for KMSAuto.
        if pua_self:
            _detail = ('Детекції антивіруса — переважно засоби активації/зламу (%d з %d); '
                       'ознак стороннього доступу немає. %s' % (pua_self['pua'], pua_self['total'], _detail))
        add('medium' if pua_self else 'high', 'Самозаподіяне (піратське ПЗ)' if pua_self else 'Виявлене шкідливе ПЗ', 'T1204',
            'Детекції антивіруса: піратські активатори (самозараження)' if pua_self else 'Antivirus задетектив загрози',
            _detail, max(ddet_n, len(_threat_names)), _samples,
            events=_det_ev,
            iocs=[{'type': 'malware', 'value': n, 'role': 'назва загрози за Defender', 'source': 'Defender 1116/1117',
                   'file': (_det_rows[0][3] if _det_rows and _det_rows[0][0] else ''), 'record': (_det_rows[0][4] if _det_rows and _det_rows[0][0] else '')} for n in _threat_names[:8]])

    # ── 6) Suspicious / attacker tooling in program execution ──
    # first run = the earliest ANCHOR stamp (Prefetch/BAM/Amcache); a ShimCache row is only
    # used when nothing else dates the tool, and then it is labelled as presence
    tools = _q(cur, """SELECT executable_name, full_path,
                              coalesce(min(event_ts) FILTER (WHERE source_file NOT ILIKE '%%AppCompatCache%%'), min(event_ts)),
                              (array_agg(source_file ORDER BY """ + _ANCHOR_ORDER_SQL + """, event_ts))[1]
                       FROM program_exec_v2 WHERE case_key=%s
                       AND lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) ~ %s
                       AND coalesce(full_path,'') !~* %s
                       AND """ + _sql_not_own("coalesce(full_path,'')||' '||coalesce(executable_name,'')") + _CUT + """
                       GROUP BY 1, 2 ORDER BY 3 NULLS LAST, 1 LIMIT 12""",
                    (case_key, _ATTACK_TOOL_RE, _EXAMINER_PATH_RE, _cut_ts))
    tools = [t for t in (tools or []) if not _is_own((t[1] or '') + ' ' + (t[0] or ''), ts=t[2], case_key=case_key)]
    if tools:
        names = sorted({(t[0] or '').split('\\')[-1] for t in tools if t[0]})
        _tool_events = [{'ts': t[2], 'label': 'запуск інструмента %s' % (t[0] or '').split('\\')[-1],
                         'source': 'program_exec_v2', 'artifact': (t[1] or t[0] or '')[:160], 'file': t[3]} for t in tools if t[2]]
        _tool_iocs = [{'type': 'file', 'value': (t[0] or '').split('\\')[-1], 'role': 'інструмент атакувальника',
                       'source': 'program_exec_v2', 'file': t[3]} for t in tools if t[0]]
        # len(tools) is a SAMPLE size capped at 12, and rows double per control set - neither
        # is "how many times this was seen". Count distinct (exe, path, ts) instead; the
        # 12 sampled rows still feed the names.
        _tn = _q(cur, """SELECT count(*) FROM (
                             SELECT DISTINCT executable_name, full_path, event_ts
                             FROM program_exec_v2 WHERE case_key=%s
                             AND lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) ~ %s
                             AND coalesce(full_path,'') !~* %s""" + _CUT + """) o""",
                  (case_key, _ATTACK_TOOL_RE, _EXAMINER_PATH_RE, _cut_ts))
        _tn = int((_tn[0][0] if _tn else 0) or 0) or len(names)
        add('high', 'Інструменти атакувальника', 'T1588.002',
            'Хакерські/подвійного призначення інструменти',
            'У виконанні виявлено: %s.' % ', '.join(names[:10]), _tn, names,
            events=_tool_events[:12], iocs=_tool_iocs[:12])

    # ── 6b) Suspicious download sources / file-shares / tunnels (browser provenance) ──
    # Surfaces the DELIVERY/C2 URLs an analyst needs (SwissTransfer/pixeldrain phishing
    # payloads, bin.equinox ngrok download, anydesk/rustdesk installers) — these live in
    # browser history (browser_provenance_v1), not the event logs.
    _dl = []
    try:
        _dl = _q(cur, r"""SELECT DISTINCT domain, left(url, 120), coalesce(remote_ip::text,''),
                            to_char(event_ts,'YYYY-MM-DD HH24:MI')
                          FROM browser_provenance_v1 WHERE case_key=%s
                          AND url ~* '(swisstransfer|pixeldrain|dropmefiles|file\.io|transfer\.sh|mega\.nz|mediafire|anonfiles|gofile|bin\.equinox|\yngrok|pinggy|anydesk|rustdesk|tinyurl|bit\.ly|cutt\.ly|is\.gd|t\.me/)'
                          AND coalesce(domain,'') !~* 'google|microsoft|windows|mozilla|office'
                          ORDER BY 4, 1, 2, 3 LIMIT 15""", (case_key,))
    except Exception:
        try: conn.rollback()
        except Exception: pass
        _dl = []
    if _dl:
        def _host(_d, _u):
            if _d:
                return _d
            m = re.search(r'https?://([^/]+)', _u or '')
            return m.group(1) if m else (_u or '')[:40]
        _doms = sorted({_host(d, u) for d, u, _ip, _ts in _dl})
        _dsamp = [f"{_host(d, u)}: {u}" for d, u, _ip, _ts in _dl[:6]]
        add('high', 'Доставка / C2', 'T1105',
            'Підозрілі завантаження / файлообмінники / тунелі (браузер)',
            'Виявлено %d завантажень з підозрілих джерел: %s — ймовірна доставка payload / канал C2.'
            % (len(_dl), ', '.join(_doms[:8])), len(_dl), _dsamp)

    # ── 6c) Executable unpacked from an archive attachment (phishing by archive) ──
    # The delivery the reports kept inventing was in the data all along, unnamed:
    # case_58 `Лист ... ЕРА.exe` in Temp\Rar$, case_45 `Лист державним реєстраторам ДРАЦС.exe`
    # in Temp\Rar$ 2026-04-20 22:23 with ngrok the next morning, case_55 WinScan2PDF.exe.
    # A WinRAR/7-Zip temp folder holding ONE or TWO executables named like a document is
    # an opened attachment; a folder with a dozen (7zS<hex>\utils\...) is an installer.
    try:
        # «архів-вкладення» = the archiver's Rar$/7z/Temp1_ folders, a .zip/.rar path and
        # Outlook's Content.Outlook - not the browser cache (INetCache\IE) and never a
        # Windows.old tree: case_67's "phishing" was ReasonLabs installer stubs in the
        # previous OS's IE cache (FIX_QUEUE №14). The $J FileCreate row (anchor) is
        # preferred over the $MFT created-time (presence) for the same file.
        _ph = _q(cur, """SELECT coalesce(parent_path,''), file_name,
                                min(event_ts),
                                count(*) OVER (PARTITION BY coalesce(parent_path,'')),
                                (array_agg(source_file ORDER BY event_ts, (CASE WHEN source_file ILIKE '%%$J%%' THEN 0 ELSE 1 END)))[1],
                                (array_agg(payload->>'entry_number' ORDER BY event_ts, (CASE WHEN source_file ILIKE '%%$J%%' THEN 0 ELSE 1 END)))[1]
                         FROM filesystem_v2 WHERE case_key=%s AND event_ts IS NOT NULL
                           AND lower(file_name) ~ '[.](exe|scr|pif|com|js|jse|vbs|vbe|wsf|hta|bat|cmd|lnk|cpl|msi)$'
                           AND (parent_path ILIKE '%%Temp%%Rar$%%' OR parent_path ILIKE '%%Temp%%7z%%' OR parent_path ILIKE '%%.zip%%'
                                OR parent_path ILIKE '%%.rar%%' OR parent_path ILIKE '%%Content.Outlook%%'
                                OR parent_path ILIKE '%%Temp%%Temp1_%%'
                                -- «Видобути все» Провідника: Downloads/<імʼя архіву>/<файл>.exe; тека
                                -- названа за архівом і містить основу імені файла (case_50, 02.10.2026)
                                OR (parent_path ~* '[/\\\\]downloads[/\\\\][^/\\\\]+$'
                                    AND position(lower(regexp_replace(file_name, '\\.[^.]+$', '')) in lower(parent_path)) > 0))
                           AND parent_path NOT ILIKE '%%7zS%%' AND parent_path NOT ILIKE '%%DFIRTriage%%'
                           AND parent_path NOT ILIKE '%%Windows.old%%' AND parent_path NOT ILIKE '%%INetCache%%IE%%'
                           AND lower(coalesce(parent_path,'')) !~ 'pathunknown|wow64_|amd64_|x86_microsoft|msil_|windowsapps|program files|programdata[/\\\\](microsoft|package cache)|node_modules|site-packages|winsxs|driverstore|nvidia|intel|amd'
                           AND lower(file_name) !~ 'setup|install|dpinst|vcredist|unins|update|patch|winrar|7-zip|7zip'
                           """ + _CUT + """
                         GROUP BY 1, 2 ORDER BY 3 LIMIT 40""", (case_key, _cut_ts)) or []
    except Exception:
        try: conn.rollback()
        except Exception: pass
        _ph = []
    # the $MFT/$J may no longer hold the unpacked file (deleted with the temp folder) while
    # Prefetch/Amcache/ShimCache still hold its EXECUTION - case_58 `... ЕРА.exe` lived only there
    try:
        _ph_pe = _q(cur, """SELECT coalesce(full_path,''), executable_name,
                                   coalesce(min(event_ts) FILTER (WHERE source_file NOT ILIKE '%%AppCompatCache%%'), min(event_ts)), 1,
                                   (array_agg(source_file ORDER BY """ + _ANCHOR_ORDER_SQL + """, event_ts))[1], NULL
                            FROM program_exec_v2 WHERE case_key=%s AND event_ts IS NOT NULL
                              AND (full_path ~* '(temp[/\\\\]+rar\\$|temp[/\\\\]+7z|[.](zip|rar|7z)[/\\\\]|content[.]outlook|temp[/\\\\]+temp1_)'
                                   OR (full_path ~* 'downloads[/\\\\]+[^/\\\\]+[/\\\\]+[^/\\\\]+[.](exe|scr|com|bat|cmd|js|vbs|hta|msi)$'
                                       AND position(lower(regexp_replace(regexp_replace(full_path, '^.*[/\\\\]', ''), '\\.[^.]+$', ''))
                                                    in lower(regexp_replace(full_path, '[/\\\\][^/\\\\]+$', ''))) > 0))
                              AND full_path NOT ILIKE '%%7zS%%' AND full_path NOT ILIKE '%%DFIRTriage%%' AND full_path NOT ILIKE '%%Windows.old%%'
                              AND lower(coalesce(executable_name,'')||coalesce(full_path,'')) !~ 'setup|install|dpinst|vcredist|unins|update|patch|winrar|7-zip|7zip'
                              """ + _CUT + """
                            GROUP BY 1, 2 ORDER BY 3 LIMIT 20""", (case_key, _cut_ts)) or []
    except Exception:
        try: conn.rollback()
        except Exception: pass
        _ph_pe = []
    _seen_fn = {(str(r[1]) or '').lower() for r in _ph}
    for _fp, _en, _t0, _one, _sf, _rn in _ph_pe:
        _base = (_en or '').replace('/', chr(92)).rsplit(chr(92), 1)[-1]
        if _base.lower() in _seen_fn:
            continue
        _dir = _fp.replace('/', chr(92)).rsplit(chr(92), 1)[0] if chr(92) in _fp.replace('/', chr(92)) else _fp
        _ph.append((_dir, _base, _t0, 1, _sf, _rn))
    _ph_hits = []
    for _pp, _fn, _t0, _nfold, _sf, _rn in _ph:
        if _is_own(_pp + ' ' + _fn):
            continue
        if int(_nfold or 0) > 3:            # many executables in one temp folder = an installer
            continue
        _low = (_fn or '').lower()
        _doclike = bool(re.search(r'(\.(pdf|docx?|xlsx?|jpe?g|png|zip|asice|p7s)\.[a-z]{2,4}$)|лист|договір|договор|рахунок|акт\b|заяв|наказ|постанов|повістк|скарг|ухвал|запит|реєстр|invoice|scan|документ|платіж|платеж|ера\.exe', _low))
        # «Видобути все» into Downloads\<name>\ is how a lure is opened, but also how a printer
        # driver is unpacked (case_67: LBP2900_..._EN_7.exe): outside the archiver's own temp folders
        # only a document-like name counts
        if (not _doclike and re.search(r'[/\\]downloads[/\\]', (_pp or '').lower())
                and not re.search(r'temp|rar\$|7z|\.zip|\.rar|content\.outlook', (_pp or '').lower())):
            continue
        _ph_hits.append((_pp, _fn, _t0, _doclike, _sf, _rn))
    # the executions of those files (Prefetch/BAM/Amcache) - the anchors the RAT rule below
    # and the chain start from; the $J row only says when the file was written
    _ph_exec = []
    if _ph_hits:
        _ph_exec = _q(cur, """SELECT executable_name, full_path, min(event_ts), (array_agg(source_file ORDER BY event_ts))[1]
                              FROM program_exec_v2 WHERE case_key=%s AND event_ts IS NOT NULL
                                AND source_file NOT ILIKE '%%AppCompatCache%%'
                                AND lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) ~ %s
                                """ + _CUT + """ GROUP BY 1, 2 ORDER BY 3 LIMIT 12""",
                       (case_key, '|'.join(re.escape((h[1] or '').lower()) for h in _ph_hits[:8] if h[1]) or '^$', _cut_ts)) or []
    if _ph_hits:
        _doc_hits = [h for h in _ph_hits if h[3]]
        _sev = 'high' if _doc_hits else 'medium'
        _ev = [{'ts': h[2], 'label': 'розпаковано виконуваний файл з архіву/вкладення: %s' % h[1], 'source': 'filesystem_v2 ($MFT/$J)' if not (h[4] or '').lower().endswith('.csv') or 'mftecmd' in (h[4] or '').lower() else 'program_exec_v2',
                'artifact': (h[0] or '')[:160], 'file': h[4], 'record': h[5]} for h in _ph_hits[:8]]
        _ev += [{'ts': r[2], 'label': 'запущено виконуваний файл з архіву/вкладення: %s' % (r[0] or '').replace('/', chr(92)).rsplit(chr(92), 1)[-1],
                 'source': 'program_exec_v2', 'artifact': (r[1] or r[0] or '')[:160], 'file': r[3]} for r in _ph_exec if r[2]]
        _io = [{'type': 'file', 'value': h[1], 'role': 'виконуваний файл з архіву-вкладення (ймовірна доставка)', 'source': 'filesystem_v2', 'file': h[4], 'record': h[5]} for h in _ph_hits[:8]]
        _io += [{'type': 'path', 'value': (h[0] or '')[:200], 'role': 'тека розпакування архіву', 'source': 'filesystem_v2', 'file': h[4], 'record': h[5]} for h in _ph_hits[:4]]
        add(_sev, 'Доставка (фішинг)', 'T1566.001',
            'Виконуваний файл, розпакований з архіву-вкладення',
            ('У теці розпакування архіву (WinRAR/7-Zip/zip/Outlook або «Видобути все» у Завантаженнях) знайдено %d виконуваних файлів%s: %s. '
             'Це типова доставка через вкладення листа: перевірити лист/джерело архіву та що запускалось одразу після.'
             % (len(_ph_hits), ' з назвою під документ' if _doc_hits else '',
                ', '.join('%s (%s)' % (h[1], str(h[2])[:16]) for h in (_doc_hits or _ph_hits)[:4]))),
            len(_ph_hits), ['%s @ %s' % (h[1], h[0]) for h in _ph_hits[:6]], events=_ev, iocs=_io)

    # ── 7) Shadow copy / backup destruction (anti-recovery) ──
    # Anti-recovery — only REAL deletion (vssadmin/wbadmin/wmic DELETE, bcdedit recovery-off,
    # EID 524 backup-catalog-deleted). NOT EID 8224 (= benign VSS idle shutdown → was a FP).
    # PROVIDER-GUARDED: EID 524 = "backup catalog deleted" ONLY under provider
    # Microsoft-Windows-Backup. It collides with StorPort / DeviceManagement 524
    # (benign) which otherwise produced thousands of fake anti-recovery hits.
    vss = _q(cur, """SELECT count(*) FROM event_logs_v2 WHERE case_key=%s
                     AND ((coalesce(command_line,'')<>'' AND lower(coalesce(command_line,'')) ~
                          'vssadmin.{0,15}delete|wbadmin.{0,15}delete|wmic.{0,30}shadowcopy.{0,12}delete|delete.{0,10}(shadows|catalog)|bcdedit.{0,40}(recoveryenabled.{0,6}no|bootstatuspolicy.{0,6}ignore)'
                          )
                          OR (event_id=524 AND coalesce(provider,'') ILIKE '%%Backup%%'))""" + _CUT, (case_key, _cut_ts))
    vss_n = vss[0][0] if vss else 0
    if vss_n >= 1:
        _vss_rows = _q(cur, """SELECT event_ts, event_id, left(coalesce(command_line,''), 160), source_file, payload->>'RecordNumber' FROM event_logs_v2 WHERE case_key=%s
                     AND ((coalesce(command_line,'')<>'' AND lower(coalesce(command_line,'')) ~
                          'vssadmin.{0,15}delete|wbadmin.{0,15}delete|wmic.{0,30}shadowcopy.{0,12}delete|delete.{0,10}(shadows|catalog)|bcdedit.{0,40}(recoveryenabled.{0,6}no|bootstatuspolicy.{0,6}ignore)'
                          )
                          OR (event_id=524 AND coalesce(provider,'') ILIKE '%%Backup%%'))""" + _CUT + """
                     ORDER BY event_ts LIMIT 8""", (case_key, _cut_ts)) or []
        add('high', 'Анти-відновлення', 'T1490',
            'Видалення тіньових копій / бекапів',
            'Виявлено %d ознак знищення Shadow Copies/бекапів (vssadmin/wbadmin delete, bcdedit) — блокування відновлення.' % vss_n, vss_n,
            events=[{'ts': r[0], 'label': 'знищення тіньових копій/бекапів: %s' % (r[2] or 'EID %s' % r[1]),
                     'source': 'event_logs_v2 4688/524', 'artifact': r[2] or 'Microsoft-Windows-Backup 524', 'file': r[3], 'record': r[4]} for r in _vss_rows if r[0]])

    # ── 7b) Destructive WinPE / boot-image deployment (wiper) ──
    # 3-4-19-1N, 2026-09-02: an MSI arrived through the domain GPO SysVol cache
    # (WindowsRecoveryUpdate.msi 08:53), registered task \WindowsRecovery (106, 08:54), the task
    # ran TBWinPE.exe with a boot.wim (200/201, 10:10) and the machine went down (6008). There was
    # no 4688 and no Prefetch: the chain lives in $J, the TaskScheduler log and the System log,
    # so every leg is counted on its own and the finding needs three legs inside one day.
    _legs = {}
    _leg_prov = {}      # (leg, ts, label) -> (source_file, record) for the provenance of each event
    def _leg(name, rows):
        for r in rows or []:
            if r and r[0]:
                _lab = str(r[1] or '')[:80]
                _pv = (str(r[2] or '') if len(r) > 2 else '', str(r[3] or '') if len(r) > 3 and r[3] is not None else '')
                # the same file touched three times inside one second ($J FileCreate/DataExtend/Close)
                # is one leg, not three
                if any(_l == _lab and abs((_t - r[0]).total_seconds()) < 1 for _t, _l in _legs.get(name, []) if hasattr(_t, 'timestamp')) and (r[0], _lab) not in _legs.get(name, []):
                    continue
                if (r[0], _lab) in _legs.get(name, []):
                    # the same stamp from $MFT and $J: keep the row that names a record
                    if _pv[1] and not _leg_prov.get((name, r[0], _lab), ('', ''))[1]:
                        _leg_prov[(name, r[0], _lab)] = _pv
                    continue
                _legs.setdefault(name, []).append((r[0], _lab))
                _leg_prov[(name, r[0], _lab)] = _pv
    _J_FIRST = "(CASE WHEN source_file ILIKE '%%$J%%' THEN 0 ELSE 1 END)"
    # $J rows carry no parent_path: the $J FileCreate of a GPO-cached MSI is found by the
    # name the $MFT row gave it, so the leg is dated by the journal (anchor), not $MFT
    _GPO_J_SQL = ("(coalesce(parent_path,'')='' AND source_file ILIKE '%%$J%%' AND lower(file_name) IN "
                  "(SELECT lower(file_name) FROM filesystem_v2 WHERE case_key=%s AND lower(file_name) LIKE '%%.msi' AND parent_path ILIKE '%%GroupPolicy%%DataStore%%'))")
    _leg('gpo_msi', _q(cur, """SELECT min(event_ts), file_name,
                              (array_agg(source_file ORDER BY event_ts, """ + _J_FIRST + """))[1],
                              (array_agg(payload->>'entry_number' ORDER BY event_ts, """ + _J_FIRST + """))[1]
                       FROM filesystem_v2 WHERE case_key=%s
                       AND lower(file_name) LIKE '%%.msi' AND (parent_path ILIKE '%%GroupPolicy%%DataStore%%' OR """ + _GPO_J_SQL + """)""" + _CUT + """
                       GROUP BY 2 ORDER BY 1 LIMIT 5""", (case_key, case_key, _cut_ts)))
    # $J rows carry no parent_path while the $MFT row of the same file does: group by the
    # file name and take the longest path seen, so the label reads
    # "boot.wim @ .\Program Files (x86)\Microsoft\Windows Recovery Update", not "boot.wim @ ".
    # Every timestamp of the file stays its own row (the $J touch at 09:49 is the one that sits
    # inside the chain; the $MFT creation is timestomped to 2023), and the path comes from
    # whichever row of the same file has one (window over the file name).
    _leg('boot_image', _q(cur, """SELECT DISTINCT event_ts, file_name || ' @ ' || coalesce(max(nullif(parent_path,'')) OVER (PARTITION BY lower(file_name)), '(шлях не збережено)'),
                              source_file, payload->>'entry_number'
                       FROM filesystem_v2 WHERE case_key=%s
                       AND (lower(file_name) IN ('boot.wim','winpe.wim','wininitpe.exe') OR lower(file_name) LIKE '%%winpe%%.exe')
                       AND coalesce(parent_path,'') NOT ILIKE '%%Windows%%Boot%%' AND coalesce(parent_path,'') NOT ILIKE '%%WindowsRE%%'
                       AND coalesce(parent_path,'') NOT ILIKE '%%Windows Kits%%' AND coalesce(parent_path,'') NOT ILIKE '%%WinSxS%%'
                       AND coalesce(parent_path,'') NOT ILIKE '%%sources'
                       AND coalesce(parent_path,'') NOT ILIKE '%%servicing%%' AND coalesce(parent_path,'') NOT ILIKE '%%Package_for%%'
                       AND coalesce(parent_path,'') NOT ILIKE '%%PathUnknown%%'""" + _CUT + """
                       ORDER BY 1 LIMIT 12""", (case_key, _cut_ts)))
    _leg('bcdedit', (_q(cur, """SELECT event_ts, coalesce(process_name,''), source_file, payload->>'RecordNumber' FROM event_logs_v2 WHERE case_key=%s AND event_id=4688
                       AND (lower(coalesce(process_name,'')) LIKE '%%bcdedit.exe' OR lower(coalesce(command_line,'')) LIKE '%%bcdedit%%')""" + _CUT + """
                       ORDER BY 1 LIMIT 5""", (case_key, _cut_ts)) or [])
                    + (_q(cur, """SELECT event_ts, executable_name, source_file FROM program_exec_v2 WHERE case_key=%s
                       AND lower(coalesce(executable_name,'')) LIKE '%%bcdedit%%'""" + _CUT + """ ORDER BY 1 LIMIT 5""", (case_key, _cut_ts)) or []))
    _leg('pe_exec', _q(cur, """SELECT event_ts, executable_name, source_file FROM program_exec_v2 WHERE case_key=%s
                       AND (lower(coalesce(executable_name,'')) LIKE '%%winpe%%' OR lower(coalesce(full_path,'')) LIKE '%%winpe%%')""" + _CUT + """
                       ORDER BY 1 LIMIT 5""", (case_key, _cut_ts)))
    _leg('shutdown', _q(cur, """SELECT event_ts, event_id::text, source_file, payload->>'RecordNumber' FROM event_logs_v2 WHERE case_key=%s
                       AND event_id=6008 AND channel ILIKE '%%System%%'""" + _CUT + """ ORDER BY 1 DESC LIMIT 10""", (case_key, _cut_ts)))
    _leg('av_down', _q(cur, """SELECT event_ts, coalesce(payload->>'PayloadData1',''), source_file, payload->>'RecordNumber' FROM event_logs_v2 WHERE case_key=%s
                       AND event_id IN (7031,7034) AND channel ILIKE '%%System%%' AND payload::text ~* %s""" + _CUT + """
                       ORDER BY 1 LIMIT 10""", (case_key, AV_SERVICE_RX, _cut_ts)))
    # Task registrations are looked up around the other legs, not "the 20 oldest non-Microsoft
    # 106 rows of the case": a workstation registers hundreds (SoftLanding, OneDrive, updaters),
    # and the LIMIT used to keep \WindowsRecovery out of its own chain. Benign task families
    # are named out too, so the IOC list carries the wiper's task and not the OneDrive updater.
    _BENIGN_TASK_RX = ('softlanding|onedrive|google|adobe|mozilla|firefox|opera|brave|edge|npcap|intel|nvidia|amd|realtek|'
                       'dropbox|ccleaner|steam|epic|discord|viber|telegram|zoom|teams|skype|java|oracle|abbyy|eset|kaspersky|'
                       'avast|bitdefender|hp |dell|lenovo|asus|acer|samsung|logitech|xerox|canon|epson|brother|1c|medoc|eusign|'
                       'user_feed|customizeyourwindows|onedrive|edgeupdate|{[0-9a-f-]{36}}$')
    _anchor_pts = [t for k in ('gpo_msi', 'boot_image', 'bcdedit', 'pe_exec', 'shutdown', 'av_down') for t, _ in _legs.get(k, [])]
    if _anchor_pts:
        _leg('task_registered', _q(cur, """SELECT event_ts, coalesce(payload->>'PayloadData1',''), source_file, payload->>'RecordNumber' FROM event_logs_v2 WHERE case_key=%s
                           AND event_id=106 AND channel ILIKE '%%TaskScheduler%%'
                           AND coalesce(payload->>'PayloadData1','') NOT ILIKE '%%Microsoft%%'
                           AND coalesce(payload->>'PayloadData1','') !~* %s
                           AND event_ts BETWEEN %s - interval '24 hours' AND %s + interval '24 hours'""" + _CUT + """
                           ORDER BY 1 LIMIT 40""", (case_key, _BENIGN_TASK_RX, min(_anchor_pts), max(_anchor_pts), _cut_ts)))
    _strong = ('gpo_msi', 'boot_image', 'task_registered', 'bcdedit', 'pe_exec')
    _best = None
    for _name in _strong:
        for _ts, _ in _legs.get(_name, []):
            _near = {}
            for _n2, _rows in _legs.items():
                for _t2, _lab in _rows:
                    try:
                        _dh = abs((_t2 - _ts).total_seconds()) / 3600.0
                    except Exception:
                        continue
                    if _dh <= 24 and _n2 not in _near:
                        _near[_n2] = (_t2, _lab)
            _sc = (sum(1 for k in _near if k in _strong), len(_near))
            if _best is None or _sc > _best[0]:
                _best = (_sc, _ts, _near)
    if _best and _best[0][0] >= 2 and _best[0][1] >= 3:
        # labels are read by an investigator on the first screen of the report: plain words,
        # the artefact name where there is one, no event-id tails (the 6008 leg used to print
        # as «неочікуване вимкнення (6008): 6008»)
        _lbl = {'gpo_msi': 'MSI-пакет з доменної групової політики (SysVol)', 'boot_image': 'образ підмінного завантаження WinPE',
                'task_registered': 'створено заплановане завдання', 'bcdedit': 'зміна конфігурації завантаження (bcdedit)',
                'pe_exec': 'запуск WinPE-лоадера', 'shutdown': 'аварійне вимкнення компʼютера',
                'av_down': 'зупинилась служба антивірусу'}
        _bare = ('shutdown',)   # legs whose value is only an event id — print the label alone
        _samp = [('%s (%s)' % (_lbl.get(k, k), str(v[0])[:16])) if k in _bare else ('%s: %s (%s)' % (_lbl.get(k, k), v[1], str(v[0])[:16]))
                 for k, v in sorted(_best[2].items(), key=lambda kv: kv[1][0])]
        # Structured legs for the chronology and the IOC section: every artefact of the chain
        # with its own time and source, so the report can name the MSI, the task, the GPO and
        # the image path instead of a prose summary.
        _src_of = {'gpo_msi': 'filesystem_v2 ($J/$MFT)', 'boot_image': 'filesystem_v2 ($MFT/$J)',
                   'task_registered': 'TaskScheduler/Operational 106', 'bcdedit': 'event_logs_v2/program_exec_v2',
                   'pe_exec': 'program_exec_v2', 'shutdown': 'System 6008', 'av_down': 'System 7031/7034'}
        _w_events, _w_iocs, _w_seen = [], [], set()
        _t0 = _best[1]
        for _k, _rows in _legs.items():
            for _t2, _lab in _rows:
                try:
                    if abs((_t2 - _t0).total_seconds()) > 24 * 3600:
                        continue
                except Exception:
                    continue
                _pv = _leg_prov.get((_k, _t2, _lab), ('', ''))
                _w_events.append({'ts': _t2, 'label': (_lbl.get(_k, _k) if _k in _bare else '%s: %s' % (_lbl.get(_k, _k), _lab)),
                                  'source': _src_of.get(_k, _k), 'artifact': _lab, 'file': _pv[0], 'record': _pv[1]})
        _w_events.sort(key=lambda e: e['ts'])
        # the artefacts: every MSI/loader/image file of the chain with the path it was seen at
        for _fn, _pp, _ts, _sf, _rn in (_q(cur, """SELECT file_name, max(nullif(parent_path,'')), min(event_ts),
                                     (array_agg(source_file ORDER BY event_ts, """ + _J_FIRST + """))[1],
                                     (array_agg(payload->>'entry_number' ORDER BY event_ts, """ + _J_FIRST + """))[1]
                                     FROM filesystem_v2 WHERE case_key=%s
                                     AND ((lower(file_name) LIKE '%%.msi' AND (parent_path ILIKE '%%GroupPolicy%%DataStore%%' OR """ + _GPO_J_SQL + """))
                                          OR lower(file_name) IN ('boot.wim','winpe.wim','wininitpe.exe','tbwinpe.exe')
                                          OR lower(file_name) LIKE '%%winpe%%.exe')
                                     AND coalesce(parent_path,'') NOT ILIKE '%%Windows%%Boot%%' AND coalesce(parent_path,'') NOT ILIKE '%%WindowsRE%%'
                                     AND coalesce(parent_path,'') NOT ILIKE '%%Windows Kits%%' AND coalesce(parent_path,'') NOT ILIKE '%%WinSxS%%'
                                     AND coalesce(parent_path,'') NOT ILIKE '%%servicing%%' AND coalesce(parent_path,'') NOT ILIKE '%%Package_for%%'
                                     AND coalesce(parent_path,'') NOT ILIKE '%%PathUnknown%%'
                                     GROUP BY 1 ORDER BY 3 LIMIT 12""", (case_key, case_key)) or []):
            if _fn and _fn.lower() not in _w_seen:
                _w_seen.add(_fn.lower())
                _w_iocs.append({'type': 'file', 'value': _fn, 'role': 'MSI-лоадер з GPO' if _fn.lower().endswith('.msi') else 'WinPE-образ/лоадер wiper', 'source': 'filesystem_v2', 'file': _sf, 'record': _rn})
                if _pp:
                    _w_iocs.append({'type': 'path', 'value': _pp, 'role': 'розташування %s' % _fn, 'source': 'filesystem_v2', 'file': _sf, 'record': _rn})
        # a second MSI dropped next to the first one under the same name stem (WindowsRecovery.msi
        # in \Windows after WindowsRecoveryUpdate.msi in the GPO cache) belongs to the chain too
        for _fn, _pp in (_q(cur, """SELECT file_name, max(nullif(parent_path,'')) FROM filesystem_v2 WHERE case_key=%s
                                   AND lower(file_name) LIKE '%%.msi' AND parent_path NOT ILIKE '%%GroupPolicy%%'
                                   AND event_ts BETWEEN %s - interval '24 hours' AND %s + interval '24 hours'
                                   AND lower(file_name) IN (SELECT DISTINCT lower(regexp_replace(file_name, 'update', '', 'i')) FROM filesystem_v2
                                                            WHERE case_key=%s AND lower(file_name) LIKE '%%.msi' AND parent_path ILIKE '%%GroupPolicy%%DataStore%%')
                                   GROUP BY 1 LIMIT 4""", (case_key, _t0, _t0, case_key)) or []):
            if _fn and _fn.lower() not in _w_seen:
                _w_seen.add(_fn.lower())
                _w_iocs.append({'type': 'file', 'value': _fn, 'role': 'MSI wiper (копія поза кешем GPO)', 'source': 'filesystem_v2'})
                if _pp:
                    _w_iocs.append({'type': 'path', 'value': _pp, 'role': 'розташування %s' % _fn, 'source': 'filesystem_v2'})
        for _t2, _lab in _legs.get('task_registered', []):
            _tn = _lab.replace('Task:', '').strip()
            if _tn and ('task:' + _tn.lower()) not in _w_seen:
                _w_seen.add('task:' + _tn.lower())
                _pv = _leg_prov.get(('task_registered', _t2, _lab), ('', ''))
                _w_iocs.append({'type': 'task', 'value': _tn, 'role': 'завдання планувальника, що запускає wiper', 'source': 'TaskScheduler/Operational 106', 'file': _pv[0], 'record': _pv[1]})
        # the GPO that delivered it: its GUID shows up as a Microsoft\Windows\GroupPolicy\{GUID} task
        # registered in the same window, and as the SysVol folder the MSI was cached from
        for _g, _sf, _rn in (_q(cur, """SELECT substring(coalesce(payload->>'PayloadData1',''), '[{][0-9A-Fa-f-]{36}[}]'),
                                       (array_agg(source_file ORDER BY event_ts))[1], (array_agg(payload->>'RecordNumber' ORDER BY event_ts))[1]
                                FROM event_logs_v2
                                WHERE case_key=%s AND event_id IN (106,100,200) AND channel ILIKE '%%TaskScheduler%%'
                                AND coalesce(payload->>'PayloadData1','') ILIKE '%%GroupPolicy%%'
                                AND event_ts BETWEEN %s - interval '3 hours' AND %s + interval '3 hours' GROUP BY 1 LIMIT 3""", (case_key, _t0, _t0)) or []):
            if _g and ('gpo:' + _g.lower()) not in _w_seen:
                _w_seen.add('gpo:' + _g.lower())
                _w_iocs.append({'type': 'gpo', 'value': _g, 'role': 'GPO, застосована у вікні розгортання MSI (перевірити на контролері домену, яка з них несе пакет)', 'source': 'TaskScheduler/Operational', 'file': _sf, 'record': _rn})
        for _i in list(_w_iocs):
            if _i['type'] == 'path' and 'sysvol' in _i['value'].lower():
                _w_iocs.append({'type': 'path', 'value': _i['value'], 'role': 'SysVol-шлях доставки MSI (домен)', 'source': 'filesystem_v2'})
                break
        add('critical', 'Знищення', 'T1561',
            'Розгортання WinPE-образу для знищення системи (wiper)',
            'Ланцюг із %d ланок за одну добу навколо %s: %s. Це підготовка та запуск підставного середовища завантаження — '
            'типовий wiper через доменну GPO; шукай ту саму GPO/MSI на інших машинах домену.'
            % (_best[0][1], str(_best[1])[:16], '; '.join(_samp)), _best[0][1], _samp,
            events=_w_events[:24], iocs=_w_iocs[:24])

    # ── 7c) MSI delivered through the domain GPO (SysVol cache) ──
    # Software installation by group policy leaves the package in
    # System32\GroupPolicy\DataStore\<n>\SysVol\<domain>\Policies\{GUID}\... Selective (1 of 12
    # cases) and decisive when it fires: whoever pushed that MSI holds the domain. Reported on
    # its own so the entry point is named even when the wiper chain is incomplete.
    _gpo_msi = _q(cur, """SELECT file_name, max(nullif(parent_path,'')), min(event_ts), count(*),
                                 (array_agg(source_file ORDER BY event_ts, """ + _J_FIRST + """))[1],
                                 (array_agg(payload->>'entry_number' ORDER BY event_ts, """ + _J_FIRST + """))[1]
                          FROM filesystem_v2 WHERE case_key=%s
                          AND lower(file_name) LIKE '%%.msi' AND (parent_path ILIKE '%%GroupPolicy%%DataStore%%' OR """ + _GPO_J_SQL + """)""" + _CUT + """
                          GROUP BY 1 ORDER BY 3 LIMIT 8""", (case_key, case_key, _cut_ts)) or []
    if _gpo_msi:
        _gm_dom = ''
        for _fn, _pp, _ts, _n, _sf, _rn in _gpo_msi:
            _m = re.search(r'sysvol\\([^\\]+)', _pp or '', re.I)
            if _m:
                _gm_dom = _m.group(1)
                break
        add('high', 'Доставка (GPO)', 'T1484.001',
            'MSI-пакет, доставлений через доменну GPO',
            'У кеші групової політики (System32\\GroupPolicy\\DataStore) знайдено %d MSI-пакет(и)%s: %s. Пакет, розгорнутий політикою, '
            'встановлює той, хто керує доменом — перевір на контролері домену, хто і коли створив цю GPO, і які ще машини її отримали.'
            % (len(_gpo_msi), (' з домену %s' % _gm_dom) if _gm_dom else '', ', '.join(x[0] for x in _gpo_msi)),
            len(_gpo_msi), ['%s @ %s' % (x[0], (x[1] or '')[:90]) for x in _gpo_msi],
            events=[{'ts': x[2], 'label': 'MSI з GPO SysVol зʼявився у кеші політики: %s' % x[0], 'source': 'filesystem_v2 ($J/$MFT)', 'artifact': (x[1] or '')[:160], 'file': x[4], 'record': x[5]} for x in _gpo_msi if x[2]],
            iocs=[{'type': 'file', 'value': x[0], 'role': 'MSI, розгорнутий доменною GPO', 'source': 'filesystem_v2', 'file': x[4], 'record': x[5]} for x in _gpo_msi]
                 + [{'type': 'path', 'value': x[1], 'role': 'SysVol-шлях доставки (домен %s)' % (_gm_dom or '?'), 'source': 'filesystem_v2', 'file': x[4], 'record': x[5]} for x in _gpo_msi if x[1]][:2]
                 + ([{'type': 'domain', 'value': _gm_dom, 'role': 'домен, чия GPO принесла пакет', 'source': 'filesystem_v2'}] if _gm_dom else []))

    # ── 8) PowerShell heavy usage (execution) ──
    # count DISTINCT non-boilerplate script blocks: repeated benign Microsoft OS scriptblocks
    # (DVB: 608 events, 3 distinct, 0 non-boilerplate) are not «mass PowerShell payload».
    ps = _q(cur, "SELECT count(DISTINCT command_line) FROM event_logs_v2 WHERE case_key=%s AND event_id IN (4104,4103) "
                 "AND channel ILIKE '%%PowerShell%%' AND coalesce(command_line,'') <> '' AND " + _PS_BOILER_SQL + _CUT, (case_key, _cut_ts))
    ps_n = ps[0][0] if ps else 0
    if ps_n >= 30:
        _ps_rng = _q(cur, "SELECT min(event_ts), max(event_ts), date_trunc('day', event_ts)::date d, count(*), "
                          "(array_agg(source_file ORDER BY event_ts))[1], (array_agg(payload->>'RecordNumber' ORDER BY event_ts))[1] FROM event_logs_v2 "
                          "WHERE case_key=%s AND event_id IN (4104,4103) AND channel ILIKE '%%PowerShell%%' "
                          "AND " + _sql_not_own("coalesce(command_line,'')||' '||coalesce(payload::text,'')") + _CUT +
                          "GROUP BY 3 ORDER BY 4 DESC LIMIT 3", (case_key, _cut_ts)) or []
        add('medium', 'Виконання', 'T1059.001',
            'Масове використання PowerShell',
            'Зафіксовано %d РІЗНИХ PowerShell скрипт-блоків (EID 4104, без службових скриптів ОС) — імовірне виконання payload/скриптів.' % ps_n, ps_n,
            events=[{'ts': r[0], 'label': 'найактивніший день PowerShell (%d скрипт-блоків %s)' % (r[3], str(r[2])), 'source': 'PowerShell/Operational 4104', 'artifact': 'EID 4104',
                     'file': r[4], 'record': r[5]} for r in _ps_rng if r[0]])

    # ── 9) Persistence — new service / scheduled task ──
    # `!~* _OWN_COLLECTOR_RE` on BOTH the name and the ImagePath: our RAM capture
    # installs "MagnetRAMCapture Driver" from ...\\KAPE_TRIAGE\\cports-x64\\MRC*.tmp on
    # collection day, and it was the ONLY 7045 on the case_66 case — the report
    # called it attacker persistence and told the client to delete it.
    svc = _q(cur, "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id=7045 "
                  "AND coalesce(payload->>'PayloadData1', process_name, '') !~* %s "
                  "AND coalesce(payload->>'PayloadData1', '') || coalesce(payload->>'ImagePath', '') "
                  "|| coalesce(process_name, '') !~* %s" + _CUT,
             (case_key, _BENIGN_SVC_RE, _OWN_COLLECTOR_RE, _cut_ts))
    svc_n = svc[0][0] if svc else 0
    if svc_n >= 1:
        sn = _q(cur, """SELECT coalesce(payload->>'PayloadData1', process_name), count(*),
                               btrim(coalesce(nullif(payload->>'ImagePath',''), command_line, ''), '" '), min(event_ts),
                               (array_agg(source_file ORDER BY event_ts))[1], (array_agg(payload->>'RecordNumber' ORDER BY event_ts))[1]
                        FROM event_logs_v2 WHERE case_key=%s AND event_id=7045
                        AND coalesce(payload->>'PayloadData1', process_name, '') !~* %s
                        AND coalesce(payload->>'PayloadData1', '') || coalesce(payload->>'ImagePath', '')
                            || coalesce(process_name, '') !~* %s""" + _CUT + """
                        GROUP BY 1, 3 ORDER BY 2 DESC LIMIT 12""",
                 (case_key, _BENIGN_SVC_RE, _OWN_COLLECTOR_RE, _cut_ts))
        # A service whose binary lives where vendors install (Program Files, WindowsApps,
        # System32\drivers, DriverStore, Common Files) is a driver or an updater until proven
        # otherwise; "Intel(R) Graphics Software" and "ABBYY ... Licensing Service" became
        # "backdoor services" in a report once. Only a service with no path, or a path outside
        # those trees, stays a persistence candidate.
        _VENDOR_DIR_RX = re.compile(r'\\(program files( \(x86\))?|windowsapps|common files|programdata\\(microsoft|intel|nvidia|amd|google)|system32\\(drivers|driverstore)|windows\\system32\\[a-z0-9_]+\.exe)', re.I)
        _VENDOR_NAME_RX = re.compile(r'intel|abbyy|google|nvidia|amd|realtek|logitech|adobe|oracle|java|autodesk|corsair|razer|asus|msi|hp |dell|lenovo|samsung|epson|canon|brother|kaspersky|eset|avast|bitdefender|update|updater|licens', re.I)
        # A machine-generated name (SUac_3E181CF7, xkpsm) or a 2-5 letter name nobody registered
        # (KslD) is the one thing the vendor whitelist must not swallow: it is judged BEFORE the
        # vendor test, and a user-writable path makes it high on its own.
        # + an 8-character letter/digit mix (amduw23g, FIX_QUEUE №14) - a vendor path keeps it
        # medium, a user-writable path makes it high like the other random names
        _RANDOM_SVC_RX = re.compile(r'^(name: )?([a-z]{2,6}_[0-9a-f]{6,}|[a-z]{2,5}|(?=[a-z0-9]{8}$)(?=.*[0-9])(?=.*[a-z])[a-z0-9]{8})$', re.I)
        _USER_PATH_RX = re.compile(r'\\(users|programdata|windows\\temp|temp|perflogs|public)\\|rar\$', re.I)
        # display-name masquerade (№14): the name of a Windows service that svchost.exe hosts,
        # installed at run time with a .sys driver or a binary outside system32 - case_47's
        # «Performance Counter DLL Host» → drivers\pcdhost.sys, «Program Compatibility
        # Assistant Service» → Windows\Temp\xkpsm.sys. Real Microsoft drivers with Microsoft
        # display names (kdnic.sys, BthHfAud.sys, loop.sys) do not match: the list is the
        # svchost-hosted services, not «Microsoft *».
        _SYS_DISPLAY_RX = re.compile(r'^(name: )?(performance counter dll host|program compatibility assistant service|windows (update|event log|management instrumentation|defender[a-z ]*service|time|search|installer|error reporting|firewall|font cache|license manager|push notifications|audio|backup|biometric|connection manager|image acquisition|modules installer|security service)|task scheduler|print spooler|background intelligent transfer|remote procedure call|security center|cryptographic services|plug and play|user profile service|system event notification|shell hardware detection|application information|diagnostic (policy|service host|system host)|update orchestrator|volume shadow copy|wmi performance adapter|base filtering engine|network (list|location awareness|store interface)|dcom server process launcher|distributed (link tracking|transaction coordinator)|com\+ (event system|system application)|group policy client|local session manager|remote desktop (services|configuration)|server|workstation|themes|power|superfetch|sysmain|dhcp client|dns client|ip helper|secondary logon|storage service|superfetch)$', re.I)
        _SYSTEM_BIN_RX = re.compile(r'^[a-z]:\\windows\\system32\\(svchost|[a-z0-9_.-]+)\.exe(\s|$)', re.I)
        try:
            from analysis.known_good import is_vanilla_path as _kg_path2, status as _kg_status2
            _kg_ok2 = bool((_kg_status2() or {}).get('vanilla'))
        except Exception:
            _kg_path2, _kg_ok2 = None, False
        # _BENIGN_SVC_RE is a PostgreSQL regex (\y = word boundary); Python spells it \b
        try:
            _BENIGN_SVC_PY = re.compile(_BENIGN_SVC_RE.replace(chr(92) + 'y', chr(92) + 'b'), re.I)
        except Exception:
            _BENIGN_SVC_PY = re.compile(r'microsoft|google|intel|nvidia|adobe|eset|kaspersky|avast|bitdefender', re.I)
        _svc_vendor, _svc_odd, _svc_random, _svc_masq = [], [], [], []
        for _nm, _c, _img, _ts, _sf, _rn in (sn or []):
            _nm_s = str(_nm or '')
            if _is_own(_nm_s + ' ' + str(_img or ''), ts=_ts, case_key=case_key):
                continue
            _bare = re.sub(r'^name:\s*', '', _nm_s, flags=re.I).strip()
            _img_s = str(_img or '').strip().strip('"')
            # a 2-5 letter name whose binary is a driver under system32\drivers / DriverStore is
            # how drivers are named (KslD.sys on 7 of 12 machines, igfxn, avgSP, rsRTP) - not a
            # dropper; the short-name rule only bites outside the driver trees
            _short_drv = (re.match(r'^[a-z]{2,5}$', _bare, re.I) and _img
                          and re.search(r'\\(drivers|driverstore|system32)\\', '\\' + str(_img), re.I))
            _masq = bool(_SYS_DISPLAY_RX.match(_bare) and _img_s
                         and (_img_s.lower().endswith('.sys') or not _SYSTEM_BIN_RX.match(_img_s))
                         and not (_kg_ok2 and _kg_path2 and _kg_path2(_img_s) is True))
            if _masq:
                _svc_masq.append((_nm_s, _c, _img, _ts, _sf, _rn))
            elif (_RANDOM_SVC_RX.match(_bare) and not _short_drv and not _BENIGN_SVC_PY.search(_bare)
                  # a vendor word inside a machine-made 8-char name (amd-uw23g) is chance, not a brand
                  and (re.match(r'^[a-z0-9]{8}$', _bare, re.I) or not _VENDOR_NAME_RX.search(_bare))):
                _svc_random.append((_nm_s, _c, _img, _ts, _sf, _rn))
            elif (_img and _VENDOR_DIR_RX.search('\\' + str(_img))) or _VENDOR_NAME_RX.search(_nm_s):
                _svc_vendor.append((_nm_s, _c, _img, _ts, _sf, _rn))
            else:
                _svc_odd.append((_nm_s, _c, _img, _ts, _sf, _rn))
        _nm_bare = lambda n: re.sub(r'^name:\s*', '', n, flags=re.I).strip()
        if _svc_masq:
            add('high', 'Закріплення', 'T1543.003',
                'Служба під назвою системної, але з чужим бінарником',
                'Зафіксовано %d служб(и) EID 7045 з назвою штатної служби Windows (%s), але замість svchost/system32-бінарника вказано %s — '
                'маскування під систему: штатні служби з такими назвами не встановлюються у роботі, а живуть у svchost.exe.'
                % (len(_svc_masq), ', '.join(_nm_bare(x[0])[:40] for x in _svc_masq[:3]),
                   ', '.join(str(x[2] or '')[:70] for x in _svc_masq[:3])),
                len(_svc_masq), ['%s → %s' % (_nm_bare(x[0])[:40], (x[2] or '(без шляху)')[:70]) for x in _svc_masq],
                events=[{'ts': x[3], 'label': 'встановлено службу «%s» з чужим бінарником %s' % (_nm_bare(x[0])[:40], str(x[2] or '')[:60]), 'source': 'System 7045',
                         'artifact': str(x[2] or '')[:160], 'file': x[4], 'record': x[5]} for x in _svc_masq if x[3]],
                iocs=[{'type': 'service', 'value': _nm_bare(x[0]), 'role': 'служба-маскування під системну', 'source': 'System 7045', 'file': x[4], 'record': x[5]} for x in _svc_masq]
                     + [{'type': 'path', 'value': str(x[2]), 'role': 'бінарник служби-маскування', 'source': 'System 7045', 'file': x[4], 'record': x[5]} for x in _svc_masq if x[2]])
        if _svc_random:
            _rnd_hi = [x for x in _svc_random if x[2] and _USER_PATH_RX.search('\\' + str(x[2]))]
            add('high' if _rnd_hi else 'medium', 'Закріплення', 'T1543.003',
                'Служба з випадковим/невідомим іменем',
                'Зафіксовано %d служб(и) EID 7045 з машинно-згенерованим або коротким невідомим іменем (%s)%s — так називають служби дропери, не вендори.'
                % (len(_svc_random), ', '.join(_nm_bare(x[0])[:24] for x in _svc_random[:4]),
                   ' ; %d з них із теки користувача/Temp' % len(_rnd_hi) if _rnd_hi else ' ; бінарник у вендорській теці — перевірити, чи це не інсталятор драйвера'),
                len(_svc_random), ['%s → %s' % (x[0][:40], (x[2] or '(без шляху)')[:70]) for x in _svc_random],
                events=[{'ts': x[3], 'label': 'встановлено службу з випадковим іменем %s' % _nm_bare(x[0])[:40], 'source': 'System 7045', 'artifact': (x[2] or '')[:160], 'file': x[4], 'record': x[5]} for x in _svc_random if x[3]],
                iocs=[{'type': 'service', 'value': _nm_bare(x[0]), 'role': 'служба з випадковим іменем', 'source': 'System 7045', 'file': x[4], 'record': x[5]} for x in _svc_random]
                     + [{'type': 'path', 'value': str(x[2]), 'role': 'бінарник служби', 'source': 'System 7045', 'file': x[4], 'record': x[5]} for x in _svc_random if x[2]])
        if _svc_odd:
            add('medium', 'Закріплення', 'T1543.003', 'Встановлення нових служб',
                'Зафіксовано %d нових служб (EID 7045) поза вендорськими теками/іменами — перевір на закріплення (ще %d служб від відомих вендорів наведено інформаційно).' % (len(_svc_odd), len(_svc_vendor)),
                len(_svc_odd), ['%s → %s' % (x[0][:40], (x[2] or '(без шляху)')[:70]) for x in _svc_odd],
                events=[{'ts': x[3], 'label': 'встановлено службу %s' % x[0][:60], 'source': 'System 7045', 'artifact': (x[2] or '')[:160], 'file': x[4], 'record': x[5]} for x in _svc_odd if x[3]],
                iocs=[{'type': 'service', 'value': x[0], 'role': 'нова служба поза вендорськими теками', 'source': 'System 7045', 'file': x[4], 'record': x[5]} for x in _svc_odd])
        if _svc_vendor:
            add('low', 'Закріплення (інформаційно)', 'T1543.003', 'Нові служби від відомих вендорів',
                'Зафіксовано %d нових служб (EID 7045) з бінарниками у вендорських теках (Program Files/WindowsApps/drivers) — драйвери та оновлювачі, не закріплення атакувальника.' % len(_svc_vendor),
                len(_svc_vendor), ['%s → %s' % (x[0][:40], (x[2] or '')[:70]) for x in _svc_vendor[:6]])
    # ── 9b) Service / DRIVER installed from a user-writable / Temp / Rar$ location ──
    # A persistent service (7045) whose ImagePath points into user Temp, an archiver's
    # Rar$/7z extraction folder, Windows\Temp, Public or Downloads is almost never
    # legitimate — real services/drivers live in Program Files / System32\drivers /
    # DriverStore. This is the case_45 model: SUac_* → Temp\Rar$\<phishing>.exe and a
    # masquerading "Program Compatibility Assistant Service" → C:\Windows\Temp\xkpsm.sys.
    # chr(92) = backslash (avoids all SQL/regex backslash-escaping ambiguity).
    # OEM/firmware helper drivers legit apps stage in a named vendor Temp subfolder
    # (AMI firmware updater, Dell dbutil…) — benign on a victim PC, exclude by name/path.
    _BENIGN_DRV_RE = r'amigendrv|amifldrv|megatrends|american megatrends|dbutil|nvflash|gdrv|rtcore|winring0|asusgio|asrock'
    _susp_svc = _q(cur, """
        SELECT coalesce(nullif(payload->>'ServiceName',''), payload->>'PayloadData1', process_name, '?') AS svc,
               btrim(coalesce(nullif(payload->>'ImagePath',''), command_line, ''), '" ') AS img
        FROM event_logs_v2
        WHERE case_key=%s AND event_id=7045
          AND lower(replace(coalesce(nullif(payload->>'ImagePath',''), command_line, ''), chr(92), '/'))
              ~ '/temp/|rar[$]|/windows/temp/|/users/public/|/downloads/|/perflogs/|/appdata/roaming/[^/]+[.](exe|sys|scr|dll)'
          AND coalesce(nullif(payload->>'ServiceName',''), payload->>'PayloadData1', process_name, '') !~* %s
          AND coalesce(nullif(payload->>'ImagePath',''), command_line, '') !~* %s
          AND coalesce(nullif(payload->>'ImagePath',''), command_line, '') !~* %s""" + _CUT + """
        ORDER BY event_ts ASC, row_id LIMIT 10
    """, (case_key, _BENIGN_SVC_RE, _EXAMINER_PATH_RE, _BENIGN_DRV_RE, _cut_ts))
    if _susp_svc:
        # Check the clean-Windows reference BEFORE calling a driver a rootkit. A stock
        # file keeps its path even when an event names an odd folder, and a wrong call
        # here is the most expensive kind in a report that goes to a client.
        _kg_note = ''
        try:
            from analysis.known_good import is_vanilla_path as _kg_path, status as _kg_status
            if (_kg_status() or {}).get('vanilla'):
                _keep, _stock = [], 0
                for s, i in _susp_svc:
                    if i and _kg_path(i) is True:
                        _stock += 1
                        continue
                    _keep.append((s, i))
                if _stock:
                    _kg_note = (' Ще %d служб(и) відкинуто: їхній шлях є в еталоні чистої '
                                'Windows.' % _stock)
                _susp_svc = _keep
        except Exception:
            pass
        if not _susp_svc:
            _susp_svc = []
    if _susp_svc:
        _drv = [(s, i) for s, i in _susp_svc
                if str(i).lower().endswith('.sys') or '/windows/temp/' in str(i).replace('\\', '/').lower()]
        _sev = 'critical' if _drv else 'high'
        _samples = ['%s → %s' % (str(s)[:34], str(i)[:78]) for s, i in _susp_svc if i]
        _susp_ts, _susp_pv = {}, {}
        for _s, _i, _t, _sf, _rn in (_q(cur, """SELECT coalesce(nullif(payload->>'ServiceName',''), payload->>'PayloadData1', process_name, '?'),
                                             btrim(coalesce(nullif(payload->>'ImagePath',''), command_line, ''), '" '), min(event_ts),
                                             (array_agg(source_file ORDER BY event_ts))[1], (array_agg(payload->>'RecordNumber' ORDER BY event_ts))[1]
                                      FROM event_logs_v2 WHERE case_key=%s AND event_id=7045""" + _CUT + """ GROUP BY 1, 2""", (case_key, _cut_ts)) or []):
            _susp_ts[(str(_s), str(_i))] = _t
            _susp_pv[(str(_s), str(_i))] = (_sf, _rn)
        add(_sev, 'Закріплення', 'T1543.003',
            'Служба/драйвер із підозрілого розташування (Temp/Rar$/Windows\\Temp)',
            'Зафіксовано %d служб(и) EID 7045, ImagePath яких вказує в тимчасові/користувацькі теки '
            '(Temp, Rar$-розпакування архіву, Windows\\Temp, Public, Downloads) — легітимні служби так '
            'не встановлюються. Типова точка закріплення одразу після відкриття фішингового вкладення%s.'
            % (len(_susp_svc), (' Серед них ДРАЙВЕР .sys — можливий kernel-руткіт/обхід захисту.'
                                if _drv else '') + _kg_note),
            len(_susp_svc), _samples,
            events=[{'ts': _susp_ts.get((str(s), str(i))), 'label': 'встановлено службу %s з підозрілого шляху' % str(s)[:40],
                     'source': 'System 7045', 'artifact': str(i)[:160],
                     'file': _susp_pv.get((str(s), str(i)), ('', ''))[0], 'record': _susp_pv.get((str(s), str(i)), ('', ''))[1]} for s, i in _susp_svc if _susp_ts.get((str(s), str(i)))],
            iocs=[{'type': 'service', 'value': str(s), 'role': 'служба з Temp/Rar$/Public', 'source': 'System 7045',
                   'file': _susp_pv.get((str(s), str(i)), ('', ''))[0], 'record': _susp_pv.get((str(s), str(i)), ('', ''))[1]} for s, i in _susp_svc]
                 + [{'type': 'path', 'value': str(i), 'role': 'бінарник служби %s' % str(s)[:30], 'source': 'System 7045',
                     'file': _susp_pv.get((str(s), str(i)), ('', ''))[0], 'record': _susp_pv.get((str(s), str(i)), ('', ''))[1]} for s, i in _susp_svc if i])

    task = _q(cur, "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id IN (4698,4702) AND channel='Security'" + _CUT, (case_key, _cut_ts))
    task_n = task[0][0] if task else 0
    if task_n >= 1:
        add('medium', 'Закріплення', 'T1053.005', 'Створення/зміна запланованих завдань',
            'Зафіксовано %d подій планувальника завдань (EID 4698/4702) — можливе закріплення.' % task_n, task_n)

    # ── 10) Account manipulation (new accounts / privileged-group adds) ──
    # 4720 names the created account in TargetUserName/TargetSid; the `target_user` column
    # holds the SUBJECT (who ran the command) - case_45 read «бекдор 123QW-PC» (RID 1001, the
    # owner's profile) for case_59 RID 1002, NGROK read «User» for case_59 (FIX_QUEUE №15).
    _ACCT_TARGET = "coalesce(nullif(payload->>'TargetUserName',''), nullif(payload->>'SamAccountName',''), target_user, payload->>'PayloadData1')"
    acct = _q(cur, "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id IN (4720,4728,4732,4756) AND channel='Security'" + _CUT, (case_key, _cut_ts))
    acct_n = acct[0][0] if acct else 0
    # the SAM list (local_accounts_v1 / system_profile users) confirms which RID the SID is
    _sam_rid = {}
    try:
        for _u, _rid in (_q(cur, "SELECT username, rid FROM local_accounts_v1 WHERE case_key=%s AND coalesce(rid,'') ~ '^[0-9]+$'", (case_key,)) or []):
            _sam_rid[str(_rid)] = _u
        if not _sam_rid:
            import json as _json
            for (_uj,) in (_q(cur, "SELECT users_json FROM system_profile_v1 WHERE case_key=%s", (case_key,)) or []):
                _uj = _uj if isinstance(_uj, dict) else (_json.loads(_uj) if _uj else {})
                for _u in (_uj.get('users') or []):
                    _m = re.search(r'-(\d+)$', str(_u.get('sid') or ''))
                    if _m:
                        _sam_rid[_m.group(1)] = re.sub(r'\s*\[\d+\]\s*$', '', str(_u.get('username') or ''))
    except Exception:
        _sam_rid = {}
    if acct_n >= 1:
        # Extract WHICH accounts were created (4720) and WHICH privileged groups got new
        # members (4732/4728 → well-known group SIDs), so the report names the backdoor
        # account + target group (e.g. case_59 → Remote Desktop Users), not just a count.
        _GRP = {'544': 'Administrators', '555': 'Remote Desktop Users', '551': 'Backup Operators',
                '546': 'Guests', '547': 'Power Users', '562': 'DCOM Users', '580': 'Remote Management Users'}
        _acc_samples = []
        try:
            _created = _q(cur, "SELECT " + _ACCT_TARGET + ", coalesce(payload->>'TargetSid',''), min(event_ts), "
                               "(array_agg(source_file ORDER BY event_ts))[1], (array_agg(payload->>'RecordNumber' ORDER BY event_ts))[1] "
                               "FROM event_logs_v2 WHERE case_key=%s AND event_id=4720 AND channel='Security'" + _CUT + " GROUP BY 1, 2 ORDER BY 3 LIMIT 8", (case_key, _cut_ts))
            _acc_events, _acc_iocs = [], []
            for r in _created:
                if r and r[0]:
                    _rid = (re.search(r'-(\d+)$', str(r[1] or '')) or [None, ''])[1]
                    _acc_samples.append('створено акаунт: %s%s' % (str(r[0])[:50], (' (RID %s%s)' % (_rid, (', у SAM: ' + _sam_rid[_rid]) if _rid in _sam_rid else '')) if _rid else ''))
                    _acc_events.append({'ts': r[2], 'label': 'створено акаунт %s (EID 4720%s)' % (str(r[0])[:40], (', RID ' + _rid) if _rid else ''), 'source': 'Security 4720',
                                        'artifact': str(r[1] or '')[:80], 'file': r[3], 'record': r[4]})
                    _acc_iocs.append({'type': 'user', 'value': str(r[0])[:50], 'role': 'створений акаунт (ціль події 4720)', 'source': 'Security 4720', 'file': r[3], 'record': r[4]})
            _grps = _q(cur, "SELECT DISTINCT substring(coalesce(payload->>'TargetSid',''), 'S-1-5-32-([0-9]+)$'), coalesce(payload->>'MemberSid', payload->>'MemberName') "
                            "FROM event_logs_v2 WHERE case_key=%s AND event_id IN (4732,4728,4756) AND channel='Security'" + _CUT + " ORDER BY 1,2 LIMIT 12", (case_key, _cut_ts))
            for gsid, member in _grps:
                if gsid and gsid in _GRP:
                    _m = (str(member)[-8:] if member and member != '-' else '?')
                    _acc_samples.append('додано до групи «%s» (member …%s)' % (_GRP[gsid], _m))
        except Exception:
            try: conn.rollback()
            except Exception: pass
        _priv_grps = sorted({_GRP[g] for s in _acc_samples for g in _GRP if _GRP[g] in s})
        _detail = ('Зафіксовано %d подій акаунтів; ' % acct_n) + (
            'додавання до привілейованих груп: %s.' % ', '.join(_priv_grps) if _priv_grps
            else 'створення облікових записів / зміни груп (EID 4720/4728/4732/4756).')
        add('high', 'Закріплення/привілеї', 'T1136.001', 'Створення акаунтів / додавання в привілейовані групи',
            _detail, acct_n, _acc_samples[:8] or None, events=_acc_events[:6], iocs=_acc_iocs[:6])

    # ── 11) Credential dumping (LSASS / SAM / NTDS) ──
    cred = _q(cur, """SELECT count(*) FROM event_logs_v2 WHERE case_key=%s""" + _CUT + """ AND
        -- repeats the predicate of partial index ix_ev2_ck_cmdline (3%% of rows carry
        -- either field); a row with neither cannot match a tool-name pattern
        (coalesce(command_line,'')<>'' OR coalesce(process_name,'')<>'') AND
        lower(coalesce(command_line,'')||' '||coalesce(process_name,'')) ~
        '(procdump|comsvcs|rundll32|mimikatz|nanodump|dumpert|out-minidump).{0,30}lsass|lsass.{0,30}(\\.dmp|minidump|dump\\b)|sekurlsa|reg(\\.exe)?.{0,8}save.{0,14}(\\\\sam|\\\\system|\\\\security)|ntdsutil|esentutl.{0,24}ntds'""", (case_key, _cut_ts))
    cred_n = cred[0][0] if cred else 0
    if cred_n >= 1:
        add('high', 'Крадіжка облікових даних', 'T1003', 'Дамп облікових даних (LSASS/SAM/NTDS)',
            'Зафіксовано %d ознак дампу облікових даних (lsass/comsvcs minidump/reg save SAM/ntdsutil).' % cred_n, cred_n)

    # ── 12) LOLBins / suspicious command-line execution (high-fidelity patterns) ──
    # These fire only when command-line logging exists (Sysmon/4688-cmdline); on logs
    # without it they simply don't fire (no FP) but are READY for richer collections.
    _CMD_SIGS = [
        # Remoting is a TARGET plus a cmdlet. The bare cmdlet names (invoke-cimmethod,
        # invoke-restmethod, reflection.assembly) sit in every profile script, module source
        # and alias table - case_67 (24) and kyiv (13) were a gaming PC and a WinUtil run.
        (r'(invoke-command|enter-pssession|new-pssession|invoke-wmimethod|invoke-cimmethod|get-wmiobject)[^\n]{0,120}(-computername|-cimsession|-session )[^\n]{0,4}[^\n\s$]|\bwinrs(\.exe)?\s+-r:|wsman[^\n]{0,40}://|\bpsexec', 'high', 'Латеральний/виконання', 'T1021.006', 'PowerShell remoting / WMI / WinRM (lateral)'),
        (r'(frombase64string|::frombase64|-encodedcommand|-enc |certutil.{0,20}-decode|certutil.{0,20}-encode|-e [a-z0-9+/=]{20})', 'high', 'Обфускація/кодування', 'T1140', 'Base64/кодування в терміналі або скрипті'),
        (r'(powershell.{0,20}-version 2|powershell.{0,20}-v 2)', 'medium', 'Виконання', 'T1059.001', 'PowerShell downgrade v2 (обхід AMSI/логування)'),
        (r'(start-bitstransfer|copy-item.{0,30}(\\|-tosession)|net use .{0,30}(\\|password)|\yat .{0,20}\\|schtasks.{0,30}/s )', 'medium', 'Латеральний рух', 'T1021.002', 'Віддалене копіювання/виконання по мережі'),
        (r'certutil(\.exe)?[^\n]{0,50}(-urlcache|-decode|-decodehex|-encode|-f\s+http)', 'high', 'Завантаження/Декодування', 'T1140', 'certutil зловживання'),
        (r'bitsadmin(\.exe)?[^\n]{0,40}(/transfer|/addfile|/create)', 'high', 'Завантаження', 'T1197', 'bitsadmin прихована передача'),
        (r'mshta(\.exe)?[^\n]{0,50}(http|javascript:|vbscript:)', 'high', 'Виконання', 'T1218.005', 'mshta запуск віддаленого скрипту'),
        (r'regsvr32(\.exe)?[^\n]{0,50}(/i:http|scrobj|/u?/s[^\n]{0,20}http)', 'high', 'Виконання', 'T1218.010', 'regsvr32 squiblydoo'),
        (r'rundll32(\.exe)?[^\n]{0,50}(javascript:|mshtml|,\s*\w+\s+http|shell32[^\n]{0,15}control_rundll)', 'high', 'Виконання', 'T1218.011', 'rundll32 підозрілий'),
        (r'wmic(\.exe)?[^\n]{0,30}process[^\n]{0,10}call[^\n]{0,10}create', 'high', 'Виконання', 'T1047', 'WMIC process call create'),
        (r'powershell[^\n]{0,80}(-enc\b|-encodedcommand|-e\s+[a-z0-9+/=]{24}|frombase64string|\biex\b|invoke-expression|downloadstring|downloadfile|net\.webclient|-w\s*hidden|-windowstyle\s*hidden|-nop\b|-noni|executionpolicy\s+bypass)', 'high', 'Виконання', 'T1059.001', 'Обфускований/прихований PowerShell'),
        # Defender weakening via PowerShell (now visible once ScriptBlockText is parsed):
        # exclusions added or real-time/behavior protection disabled via *-MpPreference.
        (r'(add|set)-mppreference[^\n]{0,80}(exclusionpath|exclusionprocess|exclusionextension|disablerealtimemonitoring|disablebehaviormonitoring|disableioavprotection|disablescriptscanning|severethreatdefaultaction|highthreatdefaultaction)|exclusionpath\s*=|-exclusionprocess', 'high', 'Захист обходили', 'T1562.001', 'Ослаблення Defender через PowerShell (exclusions / RTP off)'),
        (r'(nltest[^\n]{0,30}/dclist|nltest[^\n]{0,30}/domain|dsquery\s|adfind|net\s+group[^\n]{0,20}domain\s+admins|whoami\s+/all|net\s+view\s|sharphound|bloodhound|net\s+group[^\n]{0,20}/domain)', 'medium', 'Розвідка', 'T1087', 'Розвідка домену/мережі'),
        (r'(advanced_?ip_?scan|advanced_?port_?scan|softperfect|angryip|\bnmap\b|masscan|netscan)', 'medium', 'Розвідка', 'T1046', 'Сканування мережі'),
        (r'vssadmin[^\n]{0,15}delete|wbadmin[^\n]{0,15}delete|bcdedit[^\n]{0,40}recoveryenabled\s*no|wmic[^\n]{0,30}shadowcopy[^\n]{0,12}delete|wbadmin[^\n]{0,20}delete\s+catalog', 'high', 'Анти-відновлення', 'T1490', 'Знищення тіньових копій (cmdline)'),
        (r'(7z|7za|7zr|rar|winrar)(\.exe)?\s+a\s+[^\n]{0,40}(\.7z|\.rar|\.zip)|compress-archive', 'medium', 'Підготовка ексфільтрації', 'T1560.001', 'Архівування даних (стейджинг)'),
        (r'(rclone\s+(copy|sync|move)|megacmd|megasync|mega\.nz|pscp\s|psftp\s|winscp[^\n]{0,60}(\bput\b|/upload|open\s+s?ftp)|filezilla(\.exe)?\s+[^\n]{0,60}s?ftps?://|\bcurl\b[^\n]{0,40}\s(-T|--upload-file)\s|wget[^\n]{0,30}--post)', 'high', 'Ексфільтрація', 'T1567.002', 'Масове вивантаження даних'),
        (r'reg(\.exe)?\s+add[^\n]{0,70}(\\run\b|runonce|userinit|\\shell\b|image\s*file\s*execution|appinit_dlls)', 'high', 'Закріплення', 'T1547.001', 'Автозапуск через reg add'),
        (r'(sc(\.exe)?\s+create|sc(\.exe)?\s+config[^\n]{0,30}binpath|new-service)', 'medium', 'Закріплення', 'T1543.003', 'Створення/зміна служби (sc/PS)'),
        (r'\bfodhelper\b|\bcomputerdefaults\b|delegateexecute|sdclt[^\n]{0,15}/kickoffelev|(eventvwr|slui)[^\n]{0,25}(mscfile|\\shell\\open|hkcu)', 'medium', 'Підвищення привілеїв', 'T1548.002', 'Можливий UAC bypass (fodhelper/IFEO)'),
        (r'(mimikatz|sekurlsa|lsadump|dcsync|kerberoast|rubeus|invoke-mimikatz|hashdump|comsvcs[^\n]{0,15}minidump)', 'high', 'Крадіжка облікових даних', 'T1003', 'Mimikatz/DCSync/Kerberoast/LSASS'),
        (r'(\bnc\b|ncat|netcat)(\.exe)?[^\n]{0,20}(-e\b|-l\s|-lvp)|new-object\s+net\.sockets\.tcpclient|/dev/tcp/', 'high', 'C2 / Reverse shell', 'T1059', 'Reverse/bind shell'),
        (r'(sethc|utilman|osk|magnify|narrator|displayswitch)\.exe[^\n]{0,15}(cmd|powershell)|image\s*file\s*execution[^\n]{0,30}(sethc|utilman)', 'high', 'Закріплення (Accessibility)', 'T1546.008', 'Sticky-keys/Accessibility backdoor'),
        (r'(winword|excel|powerpnt|outlook)\.exe[^\n]{0,60}(cmd|powershell|wscript|cscript|mshta|rundll32)', 'high', 'Початковий доступ (макрос)', 'T1566.001', 'Office-додаток запускає shell (макрос)'),
        (r'(wscript|cscript)(\.exe)?[^\n]{0,40}(\.vbs|\.js|\.jse|\.wsf|\.vbe)|\.hta\b', 'medium', 'Виконання', 'T1059.005', 'Запуск скриптів WSH/HTA'),
        (r'(xmrig|minerd|nbminer|phoenixminer|lolminer|t-rex|gminer|cgminer|ethminer)|(stratum\+tcp|pool\.[^\n]{0,20}xmr|minexmr|nanopool|supportxmr|hashvault)', 'high', 'Майнер (Impact)', 'T1496', 'Криптомайнер / mining pool'),
        (r'taskkill[^\n]{0,30}/im[^\n]{0,40}(sql|veeam|backup|exchange|oracle|msexchange)|net\s+stop[^\n]{0,30}(sql|veeam|backup)', 'high', 'Підготовка до шифрування', 'T1489', 'Зупинка сервісів БД/бекапу (перед ransomware)'),
    ]
    # Read EVERY command line, deterministically. The previous LIMIT 30000 without an
    # ORDER BY handed these twenty-two signatures an arbitrary subset that changed between
    # runs, so findings appeared and disappeared on identical data. Six of eleven cases in
    # the library are above that limit (case_58 98248, case_55 89638, case_45 76517).
    _CMDLINE_HARD_CAP = 400000      # safety valve, far above any case in the library
    _cmds = []
    _cmd_truncated = False
    try:
        # A plain cursor, fetched in batches. A NAMED (server-side) cursor cannot be used:
        # this connection runs with autocommit and psycopg2 rejects one outside a
        # transaction, which made an earlier attempt fall back to LIMIT 30000 silently.
        with conn.cursor() as _cc:
            _cc.execute("SELECT lower(coalesce(command_line,'')||' '||coalesce(process_name,'')) "
                        "FROM event_logs_v2 WHERE case_key=%s AND coalesce(command_line,'')<>'' " + _CUT +
                        "ORDER BY row_id", (case_key, _cut_ts))
            while True:
                _batch = _cc.fetchmany(20000)
                if not _batch:
                    break
                _cmds.extend(c for c in (_ps_effective(r[0]) for r in _batch) if c)
                if len(_cmds) >= _CMDLINE_HARD_CAP:
                    _cmd_truncated = True
                    break
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        _cmds = []
    _cmd_rows_read = len(_cmds)

    # The collector also DECLARES its own two paths in _collector_self.txt. A command
    # line that literally names one of them is ours — subtract exactly those, nothing
    # wider (INTEGRATION_CONTRACT.md §2 п.1). Empty set on every archive without the
    # file, so all existing cases behave exactly as before.
    try:
        from analysis.collector_self import declared_self_paths, contains_declared
        _self_declared = declared_self_paths(case_key)
    except Exception:
        _self_declared, contains_declared = set(), None
    if _self_declared and contains_declared:
        _cmds = [c for c in _cmds if not contains_declared(c, _self_declared)]

    for _pat, _sev, _cat, _mitre, _title in _CMD_SIGS:
        try:
            _rx = re.compile(_pat, re.I)
        except Exception:
            continue
        # The collector runs its own PowerShell (-NoProfile -ExecutionPolicy Bypass
        # -File ...\\Modules\\!DFIRbot\\*.ps1) and adds its own Defender exclusion for
        # C:\\DFIR_Triage. Both matched these signatures verbatim, so the client report
        # accused the attacker of weakening Defender when it was the examiner's tool.
        _hh = [c for c in _cmds if _rx.search(c) and not _OWN_COLLECTOR_RX.search(c)]
        if _hh:
            add(_sev, _cat, _mitre, _title, '%s — %d входжень у командних рядках.' % (_title, len(_hh)),
                len(_hh), [_clean_cmd_sample(h, _rx) for h in _hh[:4]])

    # ── 12b) AD/DC, Kerberos, shares, audit-tampering EID events (JPCERT + AD cheatsheet) ──
    def _ec(ids):
        _r = _q(cur, "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id IN (" + ids + ")" + _CUT, (case_key, _cut_ts))
        return _r[0][0] if _r else 0
    _krb = _ec("4768,4769")
    if _krb >= 1:
        add("medium", "Доступ до кред (Kerberos)", "T1558", "Kerberos-квитки (TGT/TGS)",
            "Зафіксовано %d подій Kerberos (EID 4768/4769) — можливий kerberoasting/голден-тікет; перевір RC4-квитки та нетипові SPN." % _krb, _krb)
    _krbf = _ec("4771,4776")
    if _krbf >= 1:
        add("medium", "Доступ", "T1110", "Kerberos/NTLM невдалі авторизації",
            "Зафіксовано %d подій 4771/4776 (Kerberos pre-auth fail / NTLM) — можливий brute-force/spray/legacy-auth." % _krbf, _krbf)
    # 4648 from a machine account (HOST$) or self-to-self is service/task background, not a
    # lateral move - 263 such rows once became "lateral movement with stolen hashes"
    _r = _q(cur, "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id=4648 "
                 "AND right(coalesce(target_user, payload->>'TargetUserName', ''),1) <> '$' "
                 "AND right(coalesce(payload->>'SubjectUserName', ''),1) <> '$' "
                 "AND lower(coalesce(target_user, payload->>'TargetUserName', '')) <> lower(coalesce(payload->>'SubjectUserName', ''))" + _CUT, (case_key, _cut_ts))
    _exp = _r[0][0] if _r else 0
    if _exp >= 1:
        add("medium", "Латеральний рух", "T1078", "Явні облікові дані (4648)",
            "Зафіксовано %d подій 4648 (explicit credentials, без машинних акаунтів) — runas/PSRemoting/lateral move." % _exp, _exp)
    # security software that died or was stopped right before the incident is a fact the
    # analyst needs dated; ESET crashing (7031) at 04:36 preceded a wiper at 09:49 once
    _AV_RX = AV_SERVICE_RX
    # a series of >50 crashes (case_47: 931×7031, 569 of them Defender's own «Антивірус для
    # Microsoft Defender» under a KMS emulator) is a broken machine, not «захист впав» - it
    # gets its own information line and the AV line drops to informational (FIX_QUEUE №16)
    _crash = _q(cur, "SELECT count(*), min(event_ts), max(event_ts) FROM event_logs_v2 WHERE case_key=%s AND event_id IN (7031,7034) AND channel='System'" + _CUT, (case_key, _cut_ts))
    _crash_n = int(_crash[0][0] or 0) if _crash else 0
    _mass_crash = _crash_n > 50
    if _mass_crash:
        _crash_top = _q(cur, "SELECT left(coalesce(payload->>'PayloadData1',''), 60), count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id IN (7031,7034) AND channel='System'" + _CUT +
                             " GROUP BY 1 ORDER BY 2 DESC LIMIT 3", (case_key, _cut_ts)) or []
        add('low', 'Стан системи (інформаційно)', 'T1499',
            'Масові падіння служб',
            'За період %s → %s зафіксовано %d аварійних завершень служб (EID 7031/7034); топ-3: %s. Це стан системи (нестабільний драйвер/ПЗ), а не дія атакувальника — '
            'окремі падіння захисного ПЗ у цій серії не є свідченням вимкнення захисту.'
            % (str(_crash[0][1])[:10], str(_crash[0][2])[:10], _crash_n, ', '.join('%s ×%d' % (re.sub(r'^Name:\s*', '', n or '')[:40], c) for n, c in _crash_top)),
            _crash_n, ['%s ×%d' % (re.sub(r'^Name:\s*', '', n or '')[:50], c) for n, c in _crash_top])
    _av = _q(cur, "SELECT count(*), min(event_ts), max(event_ts), string_agg(DISTINCT event_id::text, '/') "
                  "FROM event_logs_v2 WHERE case_key=%s AND event_id IN (7031,7034,7036) "
                  "AND channel ILIKE '%%System%%' AND payload::text ~* %s "
                  "AND (event_id <> 7036 OR payload::text ~* 'stopped|зупинен')" + _CUT, (case_key, _AV_RX, _cut_ts))
    if _av and _av[0][0]:
        _n, _t0, _t1, _ids = _av[0]
        _av_rows = _q(cur, "SELECT event_ts, event_id, left(coalesce(payload->>'PayloadData1',''), 80), source_file, payload->>'RecordNumber' FROM event_logs_v2 "
                           "WHERE case_key=%s AND event_id IN (7031,7034,7036) AND channel ILIKE '%%System%%' AND payload::text ~* %s "
                           "AND (event_id <> 7036 OR payload::text ~* 'stopped|зупинен')" + _CUT + " ORDER BY event_ts LIMIT 10", (case_key, _AV_RX, _cut_ts)) or []
        add("low" if _mass_crash else "medium", "Захист (інформаційно)" if _mass_crash else "Захист", "T1562.001", "Захисне ПЗ впало або зупинене",
            ("Служба антивірусу/EDR аварійно завершилась або була зупинена %d раз(и) (EID %s), перша о %s, остання о %s — звір з часом атаки."
             % (_n, _ids, str(_t0)[:19], str(_t1)[:19])) + (' Це частина масової серії падінь служб (%d) — стан системи, не вимкнення захисту.' % _crash_n if _mass_crash else ''), _n,
            [str(r[2]) for r in _av_rows[:4] if r[2]],
            events=[{'ts': r[0], 'label': 'захисне ПЗ впало/зупинене (EID %s): %s' % (r[1], r[2]), 'source': 'System %s' % r[1], 'artifact': r[2], 'file': r[3], 'record': r[4]} for r in _av_rows if r[0]],
            iocs=[] if _mass_crash else [{'type': 'service', 'value': r[2].replace('Name:', '').strip(), 'role': 'AV/EDR-служба, що впала перед атакою', 'source': 'System 7031/7034', 'file': r[3], 'record': r[4]} for r in _av_rows[:3] if r[2]])
    _shr = _ec("5140,5142,5145")
    if _shr >= 1:
        add("medium", "Латеральний рух", "T1021.002", "Доступ до мережевих shares",
            "Зафіксовано %d подій 5140/5142/5145 — lateral movement / staging / enumeration по shares." % _shr, _shr)
    _acc = _ec("4738,4723,4724,4740")
    if _acc >= 1:
        add("medium", "Маніпуляція акаунтами", "T1098", "Зміни акаунтів / скидання паролів",
            "Зафіксовано %d подій (4738 attrs / 4723-4724 password / 4740 lockout) — перевір backdoor-акаунти та reset." % _acc, _acc)
    _ado = _ec("5136,5137,5139,5141")
    if _ado >= 1:
        add("high", "AD-маніпуляція", "T1484", "Зміни AD-об’єктів (GPO/ACL)",
            "Зафіксовано %d подій 5136/5137/5139/5141 — зміни GPO/ACL/делегування в AD." % _ado, _ado)
    _dsrm = _ec("4794")
    if _dsrm >= 1:
        add("high", "AD-персистенс", "T1098", "DSRM-пароль (4794)",
            "Зафіксовано %d подій 4794 (DSRM password set) — чутлива DC-персистенс." % _dsrm, _dsrm)
    # AF_SEVERITY_FIX (case_49 23_07 FP): EID 4907 (object SACL change) and 1100
    # (log-service stop on every reboot) are overwhelmingly benign OS telemetry —
    # counting them produced a false "18k anti-forensics events" HIGH on a clean PC.
    # Genuine log CLEARING is detected separately above (1102/104, channel-guarded).
    # Keep only audit-policy(4719)+time(4616): HIGH only when a real log-clear
    # co-occurs, else MEDIUM only at an anomalous volume; routine counts = no flag.
    _audit_time = _ec("4719,4616")
    _logclr_af = _q(cur, "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND " + _LOGCLR_SQL + _CUT, (case_key, _cut_ts))
    _logclr_af_n = _logclr_af[0][0] if _logclr_af else 0
    if _logclr_af_n >= 1 and _audit_time >= 1:
        add("high", "Захист обходили", "T1562.002", "Зміна аудиту/часу разом з очищенням журналів",
            "Зафіксовано %d подій зміни політики аудиту/системного часу (EID 4719/4616) РАЗОМ з очищенням журналів безпеки (1102/104) — свідоме приховування слідів." % _audit_time, _audit_time)
    elif _audit_time >= 500:
        add("medium", "Захист обходили", "T1562.002", "Багато змін політики аудиту/часу",
            "Зафіксовано %d подій зміни політики аудиту/системного часу (EID 4719/4616). Часто це рутинні GPO/NTP-зміни; аномально велика кількість — перевірити вручну." % _audit_time, _audit_time)

    # ── 13) Remote-access / tunneling tooling (filesystem + program_exec, no cmdline needed) ──
    # NOTE: Postgres POSIX regex word boundary is \y (NOT \b — that is backspace in PG ARE).
    # Short tokens MUST be bounded or they match substrings (bare 'rms' matched 'platfoRMSvc'
    # = legit Veeam → false RAT alert).
    _RAT = ('anydesk|teamviewer|rustdesk|meshagent|meshcentral|romviewer|romserver|romfusclient|'
            'rdpwrap|rdpwinst|tektonit|\\yrms\\y|rutserv|litemanager|\\yatera\\y|screenconnect|connectwise|splashtop|'
            'dwagent|supremo|ammyy|radmin|ultravnc|tightvnc|realvnc|\\yvnc\\y|gotomypc|logmein|'
            'ngrok|pinggy|\\ybore\\y|\\yfrpc\\y|\\yfrps\\y|\\ychisel\\y|\\yplink\\y|\\ysocat\\y|cloudflared|localtonet|\\yplayit\\y')
    try:
        with conn.cursor() as _cc:
            # program_exec (Amcache/ShimCache/Prefetch) = small + captures EXECUTED tools;
            # avoid a regex scan of the huge filesystem_v2 (perf).
            _cc.execute(
                "SELECT DISTINCT lower(coalesce(executable_name,full_path)) FROM program_exec_v2 "
                "WHERE case_key=%s AND lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) ~ %s "
                "AND coalesce(full_path,'') !~* %s" + _CUT + " ORDER BY 1 LIMIT 40",
                (case_key, _RAT, _EXAMINER_PATH_RE, _cut_ts))
            _rats = sorted({(r[0] or '').split('\\')[-1] for r in _cc.fetchall() if r[0]})
            # also mine the IOC tool_name roll-up (cheap, already-extracted)
            _cc.execute("SELECT DISTINCT lower(ioc_value) FROM case_iocs WHERE case_key=%s "
                        "AND ioc_type IN ('tool_name','anydesk_id') AND lower(ioc_value) ~ %s ORDER BY 1 LIMIT 20",
                        (case_key, _RAT))
            _rats = sorted(set(_rats) | {r[0] for r in _cc.fetchall() if r[0]})
    except Exception:
        conn.rollback(); _rats = []
    if _rats:
        _TUNNEL = ('ngrok','pinggy','bore','frpc','frps','chisel','plink','socat','cloudflared','localtonet','playit','rdpwrap','rdpwinst')
        _tun = [r for r in _rats if any(t in r for t in _TUNNEL)]
        _dual = [r for r in _rats if r not in _tun]
        if _tun:
            # first run = earliest Prefetch/BAM/Amcache stamp; a ShimCache-only tool is dated by
            # its ShimCache row and labelled presence («запущено 2026-02-12 21:52:20» on two
            # cases to the second was the PE stamp, FIX_QUEUE №12)
            _tun_rows = _q(cur, """SELECT lower(coalesce(executable_name,full_path)),
                                          coalesce(min(event_ts) FILTER (WHERE source_file NOT ILIKE '%%AppCompatCache%%'), min(event_ts)),
                                          max(nullif(full_path,'')),
                                          (array_agg(source_file ORDER BY """ + _ANCHOR_ORDER_SQL + """, event_ts))[1]
                                   FROM program_exec_v2
                                   WHERE case_key=%s AND lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) ~ %s
                                   AND coalesce(full_path,'') !~* %s""" + _CUT + """ GROUP BY 1 ORDER BY 2 LIMIT 10""",
                            (case_key, '|'.join(re.escape(t) for t in _tun[:10]), _EXAMINER_PATH_RE, _cut_ts)) or []
            _tun_file = {}
            for r in _tun_rows:
                _tun_file.setdefault((r[0] or '').split('\\')[-1], r[3])
            add('high', 'Тунель / прихований канал', 'T1572',
                'Інструменти тунелювання', 'Виявлено тунельні інструменти: %s — типово для прихованого зовнішнього доступу.' % ', '.join(_tun[:10]), len(_tun), _tun,
                events=[{'ts': r[1], 'label': 'запуск тунельного інструмента %s' % (r[0] or '').split('\\')[-1], 'source': 'program_exec_v2', 'artifact': (r[2] or r[0] or '')[:160], 'file': r[3]} for r in _tun_rows if r[1]],
                iocs=[{'type': 'file', 'value': t, 'role': 'тунель/прихований канал', 'source': 'program_exec_v2/case_iocs', 'file': _tun_file.get(t, '')} for t in _tun[:10]])
        if _dual:
            add('medium', 'Інструменти віддаленого доступу (перевірити)', 'T1219',
                'Легітимні dual-use RAT', 'Присутні: %s. САМІ ПО СОБІ НЕ доказ атаки — перевірте, чи санкціоновано; відсутність логів вхідних сеансів = найпевніше легітимний адмін/користувацький доступ.' % ', '.join(_dual[:10]), len(_dual), _dual)

    # ── 13a) several remote-access families next to defence evasion (holdout 14_04 bank) ──
    # ── 12y) Account DELETED - and especially one that was created days earlier ──────
    # Nobody was reporting EID 4726 at all. It is present in four of the seventeen cases,
    # and on the case_42 machine it was the tell: SYSTEM created `wsus`, put it in
    # Administrators, the attacker logged in over RDP, and SYSTEM deleted the account
    # thirty minutes later. An account that appears and disappears inside one session is
    # not administration - it is somebody cleaning up after themselves.
    try:
        _del = _q(cur, """
            SELECT event_ts,
                   coalesce(payload->>'TargetUserName', ''),
                   coalesce(payload->>'SubjectUserName', ''),
                   coalesce(payload->>'SubjectUserSid', ''),
                   coalesce(source_file,''), coalesce(payload->>'RecordNumber','')
            FROM event_logs_v2
            WHERE case_key=%s AND event_id=4726 AND coalesce(channel,'')='Security'
            """ + _CUT + """ ORDER BY event_ts LIMIT 20""", (case_key, _cut_ts)) or []
        if _del:
            _evs_d, _iocs_d, _short_lived = [], [], 0
            for _dts, _who, _by, _bysid, _sf, _rn in _del:
                _who = str(_who or '?')
                # was this same account created in this case, and how long did it live?
                _cre = _q(cur, """SELECT min(event_ts) FROM event_logs_v2
                                  WHERE case_key=%s AND event_id=4720
                                    AND coalesce(channel,'')='Security'
                                    AND lower(coalesce(payload->>'TargetUserName','')) = lower(%s)""",
                          (case_key, _who))
                _cts = _cre[0][0] if (_cre and _cre[0] and _cre[0][0]) else None
                _life = ''
                if _cts and _dts:
                    try:
                        _mins = int((_dts - _cts).total_seconds() // 60)
                        if 0 <= _mins <= 60 * 24 * 7:
                            _short_lived += 1
                            _life = (' — прожив %d хв' % _mins) if _mins < 180 else (' — прожив %d год' % (_mins // 60))
                    except Exception:
                        pass
                _by_sys = str(_bysid).strip() == 'S-1-5-18'
                _evs_d.append({
                    'ts': _dts,
                    'label': 'видалено обліковий запис «%s»%s%s' % (
                        _who, _life, ' (виконано від імені SYSTEM)' if _by_sys else
                        ((' (виконав %s)' % _by) if _by else '')),
                    'source': _sf or 'Security 4726', 'artifact': 'EID 4726',
                    'record': _rn, 'kind': 'anchor'})
                _iocs_d.append({'type': 'user_account', 'value': _who,
                                'role': 'обліковий запис, який видалили (замітання слідів)',
                                'source': _sf or 'Security 4726'})
            if _short_lived:
                add('critical', 'Замітання слідів', 'T1070.009',
                    'Обліковий запис створили і видалили — прибирання за собою',
                    'У системі зʼявився обліковий запис, попрацював і був видалений. Так адміністратори '
                    'не роблять: запис, що живе одну сесію, потрібен лише для того, щоб зайти й не '
                    'лишити його в переліку. Шукай, що він встиг зробити між створенням і видаленням.',
                    count=len(_del), events=_evs_d, iocs=_iocs_d)
            else:
                add('high', 'Замітання слідів', 'T1070.009',
                    'Видалено обліковий запис',
                    'Зафіксовано видалення облікового запису (EID 4726). Саме по собі це буває штатним, '
                    'але якщо запис видалили після інциденту — перевір, що він робив до того.',
                    count=len(_del), events=_evs_d, iocs=_iocs_d)
    except Exception:
        pass
    # ── 12z) DELIVERY: downloaded -> opened -> something installed ────────────────
    # The case_42 case was decided by three filesystem rows nobody joined up:
    # Payment_31_07_2026_5115.pdf.zip landed in Downloads at 10:28:46 carrying its
    # HostUrl and ReferrerUrl, a .lnk appeared in Recent five seconds later (the user
    # opened it), a 28 MB MSI appeared in ProgramData at 10:30:05, and a Remote Utilities
    # service was installed at 10:31:30. The report said "джерело доставки не збереглось"
    # while the provenance sat in the database the whole time.
    #
    # This is the single highest-value pattern in phishing work: it names the entry point,
    # the delivery URL and the moment the user clicked, and it is entirely deterministic.
    try:
        _dl = _q(cur, """
            SELECT event_ts, file_name, coalesce(parent_path,''),
                   substring(coalesce(payload::text,'') from 'HostUrl=([^\\s"\\\\]+)'),
                   substring(coalesce(payload::text,'') from 'ReferrerUrl=([^\\s"\\\\]+)'),
                   coalesce(source_file,'')
            FROM filesystem_v2
            WHERE case_key=%s AND event_ts IS NOT NULL
              AND coalesce(payload::text,'') ~* 'hosturl=|referrerurl='
              AND lower(file_name) ~ '\\.(zip|rar|7z|exe|msi|scr|js|vbs|ps1|bat|cmd|hta|iso|img|lnk|docm|xlsm)(:zone\\.identifier)?$'
            ORDER BY event_ts DESC LIMIT 60""", (case_key,)) or []
        _chains = []
        for _d in _dl:
            _ts, _fn, _pp, _host, _ref, _src = _d
            _base = str(_fn or '').split(':')[0]
            if not _ts or not _base:
                continue
            # did the user open it? a .lnk in Recent within a few minutes
            _op = _q(cur, """SELECT min(event_ts) FROM filesystem_v2
                             WHERE case_key=%s AND lower(coalesce(parent_path,'')) ~ 'recent'
                               AND lower(file_name) = lower(%s)
                               AND event_ts BETWEEN %s AND %s + interval '10 minutes'""",
                     (case_key, _base + '.lnk', _ts, _ts))
            _opened = _op[0][0] if (_op and _op[0] and _op[0][0]) else None
            # did anything get installed right after?
            _svc = _q(cur, """SELECT min(event_ts), min(coalesce(payload->>'ServiceName',''))
                              FROM event_logs_v2
                              WHERE case_key=%s AND event_id=7045 AND coalesce(channel,'')='System'
                                AND event_ts BETWEEN %s AND %s + interval '30 minutes'""",
                      (case_key, _ts, _ts))
            _svc_ts = _svc[0][0] if (_svc and _svc[0] and _svc[0][0]) else None
            _svc_nm = (_svc[0][1] if (_svc and _svc[0]) else '') or ''
            # or a fresh installer dropped into a machine-wide folder
            _drop = _q(cur, """SELECT min(event_ts), min(file_name) FROM filesystem_v2
                               WHERE case_key=%s AND event_ts BETWEEN %s AND %s + interval '30 minutes'
                                 AND lower(coalesce(parent_path,'')) ~ 'programdata|\\\\windows\\\\temp|public'
                                 AND lower(file_name) ~ '\\.(msi|exe)$'""", (case_key, _ts, _ts))
            _drop_ts = _drop[0][0] if (_drop and _drop[0] and _drop[0][0]) else None
            _drop_nm = (_drop[0][1] if (_drop and _drop[0]) else '') or ''
            if _opened and (_svc_ts or _drop_ts):
                _chains.append((_ts, _base, _host or '', _ref or '', _opened,
                                _drop_ts, _drop_nm, _svc_ts, _svc_nm, _src, _pp))
        if _chains:
            _chains.sort(key=lambda x: x[0])
            _c0 = _chains[0]
            _evs = [{'ts': _c0[0], 'label': 'завантажено «%s»%s' % (_c0[1], (' з ' + _c0[2][:70]) if _c0[2] else ''),
                     'source': _c0[9] or 'filesystem_v2', 'artifact': 'Zone.Identifier', 'kind': 'anchor'},
                    {'ts': _c0[4], 'label': 'файл ВІДКРИТО користувачем (ярлик у Recent)',
                     'source': _c0[9] or 'filesystem_v2', 'artifact': 'LNK/Recent', 'kind': 'anchor'}]
            if _c0[5]:
                _evs.append({'ts': _c0[5], 'label': 'у системній теці зʼявився інсталятор «%s»' % _c0[6][:60],
                             'source': 'filesystem_v2', 'artifact': '$MFT', 'kind': 'anchor'})
            if _c0[7]:
                _evs.append({'ts': _c0[7], 'label': 'встановлено службу «%s»' % (_c0[8][:60] or '?'),
                             'source': 'System 7045', 'artifact': 'EID 7045', 'kind': 'anchor'})
            _iocs = [{'type': 'file', 'value': _c0[1], 'role': 'файл-приманка (завантажений і відкритий)',
                      'source': _c0[9] or 'filesystem_v2'}]
            if _c0[2]:
                _iocs.append({'type': 'url', 'value': _c0[2][:300], 'role': 'адреса завантаження приманки',
                              'source': 'Zone.Identifier'})
            if _c0[3]:
                _iocs.append({'type': 'url', 'value': _c0[3][:300], 'role': 'звідки перейшли (реферер)',
                              'source': 'Zone.Identifier'})
            if _c0[6]:
                _iocs.append({'type': 'file', 'value': _c0[6], 'role': 'дропер, що встановився після відкриття',
                              'source': 'filesystem_v2'})
            _gap = ''
            try:
                _last = _c0[7] or _c0[5]
                _mins = int((_last - _c0[0]).total_seconds() // 60)
                _gap = ' Від завантаження до установки — %d хв.' % _mins
            except Exception:
                pass
            add('critical', 'Початковий доступ', 'T1566.002',
                'Точка входу: завантажений файл відкрито, і одразу щось встановилося',
                'Файл «%s» завантажено з мережі, користувач його відкрив, і протягом пів години в системі '
                'зʼявився інсталятор або нова служба.%s Це класичний ланцюг фішингової доставки — '
                'саме тут почалася компрометація.' % (_c0[1], _gap),
                count=len(_chains), events=_evs, iocs=_iocs)
    except Exception:
        pass
    # One dual-use tool is «перевірити»; AnyDesk + LiteManager + RMS + Remote Utilities on one
    # accountant PC with the logs cleared is an attacker toolkit. Correlation, not a new IOC.
    try:
        _FAM = [('AnyDesk', 'anydesk'), ('TeamViewer', 'teamviewer'),
                ('LiteManager', 'litemanager|romserver|romfusclient|romviewer'),
                ('RMS / Remote Utilities', 'remote manipulator|remote utilities|rutserv|rfusclient'),
                ('RustDesk', 'rustdesk'), ('Ammyy', 'ammyy'), ('Supremo', 'supremo'), ('Splashtop', 'splashtop'),
                ('ScreenConnect', 'screenconnect|connectwise'), ('MeshAgent', 'meshagent|meshcentral'),
                ('Radmin', 'radmin'), ('VNC', 'ultravnc|tightvnc|realvnc|winvnc|tvnserver'), ('DWAgent', 'dwagent')]
        _fam_first = {}
        for _fam, _frx in _FAM:
            _r = _q(cur, """SELECT min(event_ts), min(coalesce(full_path, executable_name)) FROM program_exec_v2
                            WHERE case_key=%s AND event_ts IS NOT NULL
                              AND lower(coalesce(full_path,'')||' '||coalesce(executable_name,'')) ~ %s
                              AND lower(coalesce(full_path,'')) !~ '(unins|setup|install)'""", (case_key, _frx))
            if _r and _r[0] and _r[0][0]:
                _fam_first[_fam] = (_r[0][0], _r[0][1] or '', 'presence')
            # A service install (EID 7045) is the authoritative moment the tool was PUT on
            # the machine; an Amcache/ShimCache stamp only says the file existed. On the
            # case_42 case this mattered completely: program_exec dated RMS to 2024-10-16
            # (a PE stamp) while the service was installed 2026-08-03 15:55 - two weeks
            # before the backdoor account, and the real start of the intrusion. Reporting
            # the file stamp hid the entry point entirely.
            _svc = _q(cur, """SELECT min(event_ts), min(coalesce(payload->>'ImagePath',''))
                              FROM event_logs_v2
                              WHERE case_key=%s AND event_id=7045 AND coalesce(channel,'')='System'
                                AND lower(coalesce(payload->>'ImagePath','') || ' ' ||
                                          coalesce(payload->>'ServiceName','')) ~ %s""", (case_key, _frx))
            if _svc and _svc[0] and _svc[0][0]:
                _prev = _fam_first.get(_fam)
                # prefer the service install: it is a real event, and it is what an
                # investigator needs on the timeline
                if not _prev or _svc[0][0] < _prev[0] or _prev[2] == 'presence':
                    _fam_first[_fam] = (_svc[0][0], _svc[0][1] or (_prev[1] if _prev else ''), 'service')
        if len(_fam_first) >= 2:
            # 1102 means "audit log cleared" only in the Security channel, and 104 only in
            # System. Without that, RDP-client and Start-menu events carrying the same
            # numbers made this detector announce cleared logs on machines where nothing
            # was cleared - including this one.
            _ev_n = _q(cur, """SELECT count(*) FROM event_logs_v2 WHERE case_key=%s
                                 AND ((event_id=1102 AND coalesce(channel,'')='Security')
                                   OR (event_id=104 AND coalesce(channel,'')='System'
                                       AND coalesce(provider,'') ILIKE '%%Eventlog%%'))""", (case_key,))
            _cleared = bool(_ev_n and _ev_n[0][0])
            _tun_any = bool(vars().get('_tun'))
            # TeamViewer + AnyDesk is the ordinary consumer pairing (case_56, Asus are clean with both):
            # the cluster needs at least one attacker-favoured family besides them
            _strong = [f for f in _fam_first if f not in ('TeamViewer', 'AnyDesk')]
            if (_cleared or _tun_any) and _strong:
                _fl = sorted(_fam_first.items(), key=lambda kv: kv[1][0])
                add('high', 'Закріплення', 'T1219',
                    'Кілька засобів віддаленого доступу поруч з обходом захисту',
                    'На машині %d різних сімейств віддаленого доступу (%s) і при цьому %s. Один такий засіб — '
                    '«перевірити»; набір із кількох поруч із приховуванням слідів — типовий інструментарій зловмисника.'
                    % (len(_fl), ', '.join(f for f, _ in _fl),
                       'очищено журнали подій' if _cleared else 'присутній тунель / RDP-wrapper'),
                    count=len(_fl),
                    events=[{'ts': v[0],
                             'label': ('встановлено службу віддаленого доступу %s' % f) if v[2] == 'service'
                                      else ('перша поява засобу віддаленого доступу %s' % f),
                             'source': 'System 7045' if v[2] == 'service' else 'program_exec_v2',
                             'artifact': 'EID 7045' if v[2] == 'service' else 'Amcache/ShimCache/Prefetch',
                             'kind': 'anchor' if v[2] == 'service' else 'presence'}
                            for f, v in _fl],
                    iocs=[{'type': 'file', 'value': _exe_from_imagepath(v[1]),
                           'role': 'засіб віддаленого доступу (%s)' % f,
                           'source': 'System 7045' if v[2] == 'service' else 'program_exec_v2'}
                          for f, v in _fl if v[1]])
    except Exception:
        pass

    # ── 13a2) downloaded executable deleted to the Recycle Bin next to an AV detection ──
    try:
        _rb = _q(cur, """SELECT event_ts, file_name, coalesce(parent_path,''), coalesce(source_file,'')
                         FROM filesystem_v2 WHERE case_key=%s AND event_ts IS NOT NULL
                           AND lower(coalesce(parent_path,'')) ~ 'recycle'
                           AND lower(file_name) ~ '^[$]r[a-z0-9]{6}\\.(exe|scr|msi|bat|cmd|js|vbs|ps1|hta)'
                           AND (ltrim(lower(coalesce(extension,'')),'.') = 'identifier' OR lower(file_name) ~ 'zone[.]identifier'
                                OR coalesce(payload::text,'') ~* 'zone[.]identifier|hosturl|referrerurl')""" + _CUT + """
                         ORDER BY event_ts LIMIT 20""", (case_key, _cut_ts)) or []
        if _rb:
            _av = _q(cur, "SELECT event_ts FROM event_logs_v2 WHERE case_key=%s AND event_id IN (1116,1117) ORDER BY 1", (case_key,)) or []
            _av_ts = [r[0] for r in _av if r and r[0]]
            _near = []
            for r in _rb:
                try:
                    if any(abs((r[0] - a).total_seconds()) <= 7200 for a in _av_ts):
                        _near.append(r)
                except Exception:
                    pass
            _sev = 'medium' if _near else 'low'
            _use = _near or _rb
            add(_sev, 'Виконання', 'T1204.002',
                'Завантажений виконуваний файл видалено у Кошик' + (' поруч із детекцією AV' if _near else ''),
                '%d завантажених (з міткою MOTW) виконуваних файлів опинилися у Кошику%s. Оригінальна назва втрачена ($R…) — '
                'ознака спроби запуску завантаженого файлу з подальшим видаленням; перевірити RBCmd-дані та хронологію.'
                % (len(_use), ' у межах 2 год від детекції антивіруса' if _near else ''),
                count=len(_use),
                events=[{'ts': r[0], 'label': 'завантажений exe у Кошику: %s' % str(r[1]).replace(':Zone.Identifier', '')[:40],
                         'source': 'filesystem_v2 (MOTW)', 'artifact': r[3], 'kind': 'anchor'} for r in _use[:6]])
    except Exception:
        pass

    # ── 13a3) antivirus removal tools ──
    try:
        _AVR = r'(avremover|eset[^\\]{0,20}remover|kavremover|kavremvr|mcpr\\.exe|mcafee[^\\]{0,20}(removal|cleanup)|norton[^\\]{0,20}remove|\ynrnr\y|avastclear|avast[^\\]{0,10}clear|avgclear|avg[^\\]{0,10}remover|bitdefender[^\\]{0,20}uninstall|sophos[^\\]{0,10}(zap|remov)|trendmicro[^\\]{0,20}remov|symantec[^\\]{0,20}(cleanwipe|remov)|drweb[^\\]{0,10}remover|windowsdefender[^\\]{0,10}(remover|uninstall)|defendercontrol|dcontrol\\.exe)'
        _avr = _q(cur, """SELECT min(event_ts), lower(coalesce(full_path, executable_name)), (array_agg(source_file ORDER BY event_ts))[1]
                          FROM program_exec_v2 WHERE case_key=%s AND event_ts IS NOT NULL
                            AND lower(coalesce(full_path,'')||' '||coalesce(executable_name,'')) ~ %s
                          GROUP BY 2 ORDER BY 1 LIMIT 6""", (case_key, _AVR)) or []
        if not _avr:
            _avr = _q(cur, """SELECT min(event_ts), lower(file_name), (array_agg(source_file ORDER BY event_ts))[1]
                              FROM filesystem_v2 WHERE case_key=%s AND event_ts IS NOT NULL AND lower(file_name) ~ %s AND lower(file_name) ~ '[.](exe|msi)$'
                              GROUP BY 2 ORDER BY 1 LIMIT 6""", (case_key, _AVR)) or []
        if _avr:
            _sig = _q(cur, "SELECT event_ts FROM event_logs_v2 WHERE case_key=%s AND event_id IN (1116,1117,5001,5010,5012) ORDER BY 1", (case_key,)) or []
            _sig_ts = [r[0] for r in _sig if r and r[0]]
            _hot = False
            for r in _avr:
                try:
                    if any(abs((r[0] - a).total_seconds()) <= 86400 for a in _sig_ts):
                        _hot = True
                except Exception:
                    pass
            add('high' if _hot else 'medium', 'Захист вимикали', 'T1562.001',
                'Засіб видалення антивіруса' + (' поруч із детекцією/вимкненням захисту' if _hot else ''),
                'Знайдено інструмент видалення антивірусного ПЗ: %s.%s Легітимно лише при плановій заміні AV — перевірити, хто запускав.'
                % (', '.join(str(r[1]).split(chr(92))[-1] for r in _avr), ' У межах доби є детекція/вимкнення захисту.' if _hot else ''),
                count=len(_avr),
                events=[{'ts': r[0], 'label': 'засіб видалення AV: %s' % str(r[1]).split(chr(92))[-1][:50], 'source': 'program_exec_v2/filesystem_v2', 'artifact': r[2] or '', 'kind': 'anchor'} for r in _avr],
                iocs=[{'type': 'file', 'value': str(r[1]).split(chr(92))[-1], 'role': 'засіб видалення AV', 'source': 'program_exec_v2/filesystem_v2'} for r in _avr])
    except Exception:
        pass

    # ── 13b) RAT installed right after the phishing executable (FIX_QUEUE №18) ──
    # case_43: «…pdf.exe» from Temp\Rar$ ran 11:19:36 (Prefetch), the LiteManager service
    # was registered 11:19:37 (7045) and its binaries first seen 11:19:43 (Amcache); the
    # report kept LiteManager/RMS as «dual-use, перевірити». A remote-access tool that
    # installs or first runs within 10 minutes of an executable unpacked from an archive
    # attachment IS the payload, and the chain: delivery → execution → RAT.
    _RAT_INSTALL_RX = ('litemanager|romserver|romfusclient|romviewer|tektonit|rutserv|rfusclient|remote manipulator|\\yrms\\y|anydesk|rustdesk|'
                       'teamviewer|ammyy|supremo|splashtop|screenconnect|connectwise|meshagent|meshcentral|dwagent|radmin|ultravnc|tightvnc|realvnc|\\yvnc\\y|\\yatera\\y')
    _rat_chain = []
    for _en, _fp, _t0, _sf in (_ph_exec or []):
        if not _t0:
            continue
        _svc7045 = _q(cur, """SELECT event_ts, coalesce(nullif(payload->>'ServiceName',''), payload->>'PayloadData1', ''),
                                     btrim(coalesce(payload->>'ImagePath',''), '" '), source_file, payload->>'RecordNumber'
                              FROM event_logs_v2 WHERE case_key=%s AND event_id=7045
                              AND event_ts > %s AND event_ts <= %s + interval '10 minutes' AND payload::text ~* %s""" + _CUT + """
                              ORDER BY event_ts LIMIT 4""", (case_key, _t0, _t0, _RAT_INSTALL_RX, _cut_ts)) or []
        _rat_pe = _q(cur, """SELECT min(event_ts), coalesce(nullif(full_path,''), executable_name), (array_agg(source_file ORDER BY event_ts))[1]
                             FROM program_exec_v2 WHERE case_key=%s AND event_ts > %s AND event_ts <= %s + interval '10 minutes'
                             AND source_file NOT ILIKE '%%AppCompatCache%%'
                             AND lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) ~ %s
                             AND coalesce(full_path,'') !~* %s""" + _CUT + """
                             GROUP BY 2 ORDER BY 1 LIMIT 4""", (case_key, _t0, _t0, _RAT_INSTALL_RX, _EXAMINER_PATH_RE, _cut_ts)) or []
        if _svc7045 or _rat_pe:
            _rat_chain.append((_en, _fp, _t0, _sf, _svc7045, _rat_pe))
    if _rat_chain:
        _rc_events, _rc_iocs, _rc_samp, _rc_names = [], [], [], []
        for _en, _fp, _t0, _sf, _svc7045, _rat_pe in _rat_chain[:3]:
            _exe = (_en or _fp or '').replace('/', chr(92)).rsplit(chr(92), 1)[-1]
            _rc_events.append({'ts': _t0, 'label': 'запущено виконуваний файл з архіву-вкладення: %s' % _exe[:60], 'source': 'program_exec_v2', 'artifact': (_fp or _en or '')[:160], 'file': _sf})
            _rc_iocs.append({'type': 'file', 'value': _exe[:80], 'role': 'фішинг-exe, що приніс RAT', 'source': 'program_exec_v2', 'file': _sf})
            for _st, _sn, _si, _ssf, _srn in _svc7045:
                _dt = int((_st - _t0).total_seconds()) if hasattr(_st, 'timestamp') and hasattr(_t0, 'timestamp') else None
                _sn_b = re.sub(r'^name:\s*', '', str(_sn or ''), flags=re.I).strip()
                _rc_events.append({'ts': _st, 'label': 'встановлено службу RAT «%s»%s' % (_sn_b[:40], (' через %d с після запуску %s' % (_dt, _exe[:40])) if _dt is not None else ''),
                                   'source': 'System 7045', 'artifact': (_si or '')[:160], 'file': _ssf, 'record': _srn})
                _rc_iocs.append({'type': 'service', 'value': _sn_b, 'role': 'служба RAT (payload фішингу)', 'source': 'System 7045', 'file': _ssf, 'record': _srn})
                if _si:
                    _rc_iocs.append({'type': 'path', 'value': str(_si)[:200], 'role': 'бінарник RAT', 'source': 'System 7045', 'file': _ssf, 'record': _srn})
                _rc_names.append(_sn_b)
                _rc_samp.append('%s → %s (+%s с)' % (_exe[:40], _sn_b[:40], _dt if _dt is not None else '?'))
            for _pt, _pp, _psf in _rat_pe:
                _dt = int((_pt - _t0).total_seconds()) if hasattr(_pt, 'timestamp') and hasattr(_t0, 'timestamp') else None
                _pb = (_pp or '').replace('/', chr(92)).rstrip(chr(92)).rsplit(chr(92), 1)[-1]
                _rc_events.append({'ts': _pt, 'label': 'перший запуск/поява RAT-бінарника %s%s' % (_pb[:50], (' (+%d с)' % _dt) if _dt is not None else ''),
                                   'source': 'program_exec_v2', 'artifact': (_pp or '')[:160], 'file': _psf})
                _rc_iocs.append({'type': 'path', 'value': (_pp or '')[:200], 'role': 'RAT-бінарник, що зʼявився після фішинг-exe', 'source': 'program_exec_v2', 'file': _psf})
                _rc_names.append(_pb)
        _rc_uni = sorted({n for n in _rc_names if n})
        add('high', 'Payload (RAT після фішингу)', 'T1219',
            'RAT встановлено відразу після фішинг-exe',
            'Протягом 10 хвилин після запуску виконуваного файлу з архіву-вкладення (%s) на машині встановлено/запущено засіб віддаленого доступу: %s. '
            'Це і є корисне навантаження фішингу — RAT дає атакувальнику постійний віддалений доступ; ці інструменти НЕ легітимні, навіть якщо їх бренд відомий.'
            % (', '.join(sorted({((e or f or '').replace('/', chr(92)).rsplit(chr(92), 1)[-1])[:40] for e, f, _, _, _, _ in _rat_chain[:3]})), ', '.join(_rc_uni[:6])),
            len(_rc_uni), _rc_samp[:6] or None, events=_rc_events[:12], iocs=_rc_iocs[:12])

    # ── 14) Web shells — cheap LIKE prefilter (extension + web dir), then suspicious name ──
    try:
        with conn.cursor() as _cc:
            _cc.execute(
                "SELECT file_name, parent_path FROM filesystem_v2 WHERE case_key=%s "
                "AND (file_name ILIKE '%%.aspx' OR file_name ILIKE '%%.asp' OR file_name ILIKE '%%.ashx' "
                "  OR file_name ILIKE '%%.jsp' OR file_name ILIKE '%%.jspx' OR file_name ILIKE '%%.php' OR file_name ILIKE '%%.php5') "
                "AND (parent_path ILIKE '%%inetpub%%' OR parent_path ILIKE '%%wwwroot%%' OR parent_path ILIKE '%%htdocs%%' "
                "  OR parent_path ILIKE '%%tomcat%%' OR parent_path ILIKE '%%\\\\xampp%%' OR parent_path ILIKE '%%frontend\\\\httpproxy%%') "
                "AND lower(file_name) ~ 'cmd|shell|up(load|l)|c99|r57|b374|wso|aspxspy|china|spy|backdoor|hack|tunnel|webadmin|\\bx\\b|\\bz\\b' "
                "ORDER BY parent_path, file_name, row_id LIMIT 12", (case_key,))
            _ws = _cc.fetchall()
    except Exception:
        conn.rollback(); _ws = []
    if _ws:
        add('critical', 'Web shell', 'T1505.003', 'Веб-шелл у веб-корені',
            'Підозрілі скрипт-файли у веб-каталозі (%d) — імовірний web shell.' % len(_ws),
            len(_ws), ['%s @ %s' % (f, (p or '')[:40]) for f, p in _ws[:5]])

    # ── 15) Startup-folder persistence — cheap LIKE on path ──
    try:
        with conn.cursor() as _cc:
            _cc.execute(
                "SELECT file_name FROM filesystem_v2 WHERE case_key=%s "
                "AND parent_path ILIKE '%%\\\\Start Menu\\\\Programs\\\\Startup%%' "
                "AND lower(file_name) ~ '\\.(exe|dll|ps1|vbs|js|jse|bat|cmd|lnk|hta|scr|wsf)$' "
                "AND lower(file_name) <> 'desktop.ini' "
                # ORDER BY is not cosmetic: this runs as a Parallel Seq Scan, so Gather
                # returned the same three rows in a different order on every call and the
                # samples list drifted between runs of untouched code. file_name alone is
                # not a total order (the same .lnk appears twice), hence the row_id tiebreak.
                "ORDER BY file_name, row_id LIMIT 15", (case_key,))
            _su = [r[0] for r in _cc.fetchall()]
    except Exception:
        conn.rollback(); _su = []
    # A printer/vendor shortcut (Xerox MFP PC Fax.lnk, Send to OneNote.lnk) is what the Startup
    # folder is for; it was reported as persistence. Scripts, executables and unknown names stay.
    _STARTUP_VENDOR_RX = re.compile(r'xerox|canon|epson|brother|\bhp\b|hewlett|kyocera|ricoh|konica|onenote|office|dropbox|onedrive|google|teams|zoom|skype|viber|telegram|steam|discord|spotify|nvidia|intel|realtek|logitech|dell|lenovo|asus|acer|samsung|adobe|java|eusign|websigner|1c|almaz|medoc|m\.e\.doc|sonar|bars', re.I)
    _su_odd = [n for n in _su if not (n.lower().endswith('.lnk') and _STARTUP_VENDOR_RX.search(n))]
    _su_vendor = [n for n in _su if n not in _su_odd]
    if _su_vendor and not _su_odd:
        add('low', 'Закріплення (інформаційно)', 'T1547.001', 'Ярлики вендорського ПЗ у папці Startup',
            'У папці Startup лише ярлики відомого ПЗ (%d) — звичайний автозапуск, не закріплення атакувальника.' % len(_su_vendor),
            len(_su_vendor), _su_vendor[:5])
    _su = _su_odd
    if _su:
        add('medium', 'Закріплення', 'T1547.001', 'Автозапуск через папку Startup',
            'У папці Startup знайдено %d виконуваних/скриптових файлів — можливе закріплення.' % len(_su),
            len(_su), _su[:6])

    # ── 16) Registry Run-key persistence — filter parser_family FIRST (selective), then regex ──
    try:
        with conn.cursor() as _cc:
            _cc.execute(
                "SELECT DISTINCT coalesce(payload->>'ValueName', payload->>'value_name', ''), "
                "coalesce(payload->>'ValueData', payload->>'value_data', payload->>'Data', ''), "
                "coalesce(payload->>'KeyPath', payload->>'key_path', ''), coalesce(payload->>'HivePath', ''), "
                "source_file FROM raw_fallback_v2 WHERE case_key=%s "
                "AND parser_family IN ('registry','reg_hunter') "
                "AND coalesce(payload->>'KeyPath', payload->>'key_path', '') ~* %s "
                "AND coalesce(payload->>'ValueData', payload->>'value_data', payload->>'Data', '') ~* %s "
                "AND coalesce(payload->>'ValueName', payload->>'value_name', '') !~* 'appcompatcache' "
                "AND (coalesce(payload->>'ValueName', payload->>'value_name', '') || ' ' || coalesce(payload->>'ValueData', payload->>'value_data', payload->>'Data', '')) !~* %s",
                (case_key, _REG_ASEP_KEY_RE, _REG_ASEP_VAL_RE, _BENIGN_AUTORUN_RE))
            # same entry comes from RECmd batch, ASEP batch and RegRipper: one per (name, data)
            _rkr = list({(r[0], r[1]): r for r in _cc.fetchall()}.values())[:50]
            _rk = len(_rkr)
    except Exception:
        conn.rollback(); _rk = 0; _rkr = []
    if _rk >= 1:
        # 18.10.2026: the finding used to carry only a count, so the report never named the entry
        # (case_45: Run «MsPengEx» -> C:\users\public\documents\MsEdg.exe was invisible)
        _usr = lambda h: (re.search(r'Users[\\/]([^\\/]+)[\\/]NTUSER', h or '', re.I) or [None, ''])[1]
        add('high', 'Закріплення', 'T1547.001', 'Автозапуск у реєстрі (Run/Userinit/IFEO)',
            'У реєстрі знайдено %d підозрілих автозапусків (Run/RunOnce/Userinit/IFEO з temp/appdata/public-шляхів): %s.' % (
                _rk, '; '.join('«%s» → %s' % (r[0], r[1][:120]) for r in _rkr[:4])),
            _rk, ['%s%s\\%s = %s' % (('[%s] ' % _usr(r[3])) if _usr(r[3]) else '', r[2][-70:], r[0], r[1][:160]) for r in _rkr[:6]],
            iocs=[{'type': 'path', 'value': r[1][:200], 'role': 'автозапуск у реєстрі «%s»' % r[0][:60], 'source': 'Registry Run',
                   'file': r[4]} for r in _rkr[:6] if r[1]])

    # ── 18) DCSync (AD replication abuse) — EID 4662 + DS-Replication-Get-Changes GUID ──
    try:
        with conn.cursor() as _cc:
            _cc.execute("SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id=4662 "
                        "AND payload::text ILIKE '%%1131f6aa%%'", (case_key,))
            _dcs = (_cc.fetchone() or [0])[0]
    except Exception:
        conn.rollback(); _dcs = 0
    if _dcs >= 1:
        add('high', 'Крадіжка облікових даних', 'T1003.006',
            'Можливий DCSync (реплікація AD)',
            'Зафіксовано %d подій доступу до AD-реплікації (EID 4662, DS-Replication-Get-Changes) — '
            'можливий DCSync. Перевірити, чи це не легітимна реплікація між контролерами домену.' % _dcs, _dcs)

    # ── 19) WMI permanent event-consumer persistence — EID 5861 (WMI-Activity) ──
    try:
        with conn.cursor() as _cc:
            _cc.execute("SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id=5861 "
                        "AND payload::text ~* %s AND payload::text !~* %s", (case_key, _WMI_CONSUMER_RE, _WMI_BENIGN_CONSUMER_RE))
            _wmi = (_cc.fetchone() or [0])[0]
    except Exception:
        conn.rollback(); _wmi = 0
    if _wmi >= 1:
        add('high', 'Закріплення', 'T1546.003', 'WMI event-consumer закріплення',
            'Зафіксовано %d WMI permanent event-consumer (EID 5861) — закріплення через WMI-підписку.' % _wmi, _wmi)

    # ── 20) DeepBlueCLI / Sigma(Zircolite) high-severity tool alerts — consume the
    #        re-ingested detection corpus that neither the SQL sigs nor the LLM used ──
    try:
        with conn.cursor() as _cc:
            _cc.execute(
                "SELECT lower(coalesce(rule,'')) r, count(*) FROM tool_alerts_v2 "
                "WHERE case_key=%s AND tool IN ('deepbluecli','sigma_json','chainsaw') "
                "AND lower(coalesce(severity,'')) IN ('high','critical','medium')" + _CUT +
                "GROUP BY 1 ORDER BY 2 DESC", (case_key, _cut_ts))
            _rows = _cc.fetchall() or []
    except Exception:
        conn.rollback(); _rows = []
    if _rows:
        _obf = sum(c for r, c in _rows if 'obfusc' in r or 'command line' in r or 'suspicious command' in r)
        # log clearing is judged ONLY by the channel-guarded SQL rule above (1102 Security /
        # 104 System|Security, FIX_QUEUE №16); a detector's «log clear» on other channels
        # (case_43: 117 × System 104 by Windows itself) is not a finding, it is counted out
        _clr = sum(c for r, c in _rows if 'log clear' in r or 'audit log' in r)
        _tot = sum(c for _, c in _rows)
        _samp = ['%s (%d)' % (r[:60], c) for r, c in _rows[:6]]
        if _obf >= 1:
            add('high', 'Виконання', 'T1027',
                'Обфускований PowerShell (DeepBlueCLI)',
                'DeepBlueCLI позначив %d подій обфускованого/підозрілого командного рядка (EID 4104) — приховане виконання.' % _obf,
                _obf, _samp)
        _other = _tot - _obf - _clr
        if _other >= 3:
            add('medium', 'Детекції інструментів', 'T1059',
                'Сигма/DeepBlue детекції (інші)',
                'Ще %d high/critical детекцій від DeepBlueCLI/Sigma не покриті SQL-сигнатурами.' % _other,
                _other, _samp)

    # ── 15) RED COMBOS — temporal correlations between signals. A cleared log or a
    # new service is "medium" alone; the SAME event right AFTER malicious execution
    # is the attack storyline. Anchor = first unambiguously-malicious moment (hard
    # attack tool executed / first Defender detection); dual-use RATs are NOT an
    # anchor (legit on accountant boxes for years — the case_58/bank lesson).
    try:
        _COMBO_TOOL_RE = (r'mimikatz|ngrok|pinggy|rdpwrap|rdpwinst|psexec|procdump|nanodump|chromepass|'
                          r'lazagne|webbrowserpassview|advanced_port_scanner|netscan|sharphound|'
                          r'cobalt|meterpreter|\ychisel\y|\yfrpc\y')
        # An anchor is an ACTION stamp (Prefetch/BAM/Amcache), never a ShimCache row: the
        # ShimCache «last modified» of ngrok preceded the phishing mail on NGROK/case_45/case_47
        # and the CRITICAL combinations stood on it (FIX_QUEUE №12). Sanity floor kept: only
        # within a year of the case's newest event.
        _anch = _q(cur, "SELECT MIN(event_ts) FROM program_exec_v2 WHERE case_key=%s "
                        "AND lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) ~ %s "
                        "AND coalesce(full_path,'') !~* %s "
                        "AND source_file NOT ILIKE '%%AppCompatCache%%'" + _CUT +
                        "AND event_ts >= (SELECT MAX(event_ts) - interval '365 days' "
                        "                 FROM event_logs_v2 WHERE case_key=%s)",
                   (case_key, _COMBO_TOOL_RE, _EXAMINER_PATH_RE, _cut_ts, case_key))
        _anchor_ts = _anch[0][0] if _anch and _anch[0] else None
        _defd = _q(cur, "SELECT MIN(event_ts) FROM event_logs_v2 WHERE case_key=%s "
                        "AND event_id IN (1116,1117) AND coalesce(provider,'') ILIKE '%%Windows Defender%%'" + _CUT, (case_key, _cut_ts))
        _def_ts = _defd[0][0] if _defd and _defd[0] else None
        if _anchor_ts is None or (_def_ts is not None and _def_ts < _anchor_ts):
            _anchor_ts = _anchor_ts or _def_ts
        if _anchor_ts is not None:
            # C1: log clearing AFTER the malicious anchor = deliberate track-hiding
            _c1 = _q(cur, "SELECT count(*), MIN(event_ts) FROM event_logs_v2 WHERE case_key=%s "
                          "AND event_ts > %s AND " + _LOGCLR_SQL + _CUT,
                     (case_key, _anchor_ts, _cut_ts))
            if _c1 and _c1[0][0]:
                add('critical', 'Червона комбінація', 'T1070.001',
                    '🔴 Комбінація: чистка журналів ПІСЛЯ шкідливої активності',
                    'Журнали очищено %d раз(и) ПІСЛЯ першої шкідливої події (%s → перша чистка %s) — '
                    'цілеспрямоване приховування слідів атаки, не збіг.' % (
                        _c1[0][0], str(_anchor_ts)[:16], str(_c1[0][1])[:16]), _c1[0][0])
            # C3: Defender detected the malware, THEN Defender got disabled/tampered
            if _def_ts is not None:
                # a correlation needs proximity: kyiv had unnamed detections in March and a
                # Defender switch-off in June - three months apart is two facts, not a chain
                _c3 = _q(cur, "SELECT count(*), MIN(event_ts) FROM event_logs_v2 WHERE case_key=%s "
                              "AND event_ts > %s AND event_ts < %s + interval '7 days' AND event_id IN (5001,5010,5012,5013)"
                              "AND coalesce(provider,'') ILIKE '%%Windows Defender%%'" + _CUT,
                         (case_key, _def_ts, _def_ts, _cut_ts))
                if _c3 and _c3[0][0] and pua_self:
                    add('medium', 'Захист вимикали', 'T1562.001',
                        'Захист вимикали після детекцій — імовірно, самим користувачем',
                        'Після детекції Defender (%s) зафіксовано %d подій вимкнення захисту '
                        '(перша %s). Оскільки детекції — це засоби активації/зламу, а ознак '
                        'стороннього доступу немає, це схоже на дії самого користувача, '
                        'щоб піратське ПЗ запрацювало.' % (
                            str(_def_ts)[:16], _c3[0][0], str(_c3[0][1])[:16]), _c3[0][0])
                elif _c3 and _c3[0][0]:
                    add('critical', 'Червона комбінація', 'T1562.001',
                        '🔴 Комбінація: Defender виявив загрозу → Defender вимкнули',
                        'Після детекції Defender (%s) зафіксовано %d подій вимкнення/ослаблення захисту '
                        '(перша %s) — атакувальник прибрав захист, що його впіймав.' % (
                            str(_def_ts)[:16], _c3[0][0], str(_c3[0][1])[:16]), _c3[0][0])
            # C4: new service / scheduled task within 2h AFTER the anchor = instant persistence
            _c4 = _q(cur, "SELECT count(*), MIN(event_ts) FROM event_logs_v2 WHERE case_key=%s "
                          "AND event_ts > %s AND event_ts <= %s + interval '2 hours' "
                          "AND ((event_id=7045) OR (event_id=4698 AND channel='Security'))" + _CUT,
                     (case_key, _anchor_ts, _anchor_ts, _cut_ts))
            if _c4 and _c4[0][0]:
                add('high', 'Червона комбінація', 'T1543.003',
                    '🔴 Комбінація: закріплення одразу після компрометації',
                    'Протягом 2 годин після першої шкідливої події (%s) створено %d нових служб/задач '
                    '(перша %s) — механізм закріплення встановлено атакувальником.' % (
                        str(_anchor_ts)[:16], _c4[0][0], str(_c4[0][1])[:16]), _c4[0][0])
        # C2: backdoor account chain — user created (4720), then added to a privileged
        # group (4728/4732/4756) within 48h. Independent of the anchor (works even when
        # the toolset was cleaned). Name-matched via MemberName/MemberSid ~ target_user.
        # The created account is the TARGET of 4720 (TargetUserName/TargetSid); the subject is
        # whoever typed the command. Matched to the group adds by MemberSid = TargetSid first,
        # by name second; the RID is cross-checked against the SAM list (FIX_QUEUE №15).
        _c2 = _q(cur, """
            SELECT coalesce(nullif(u.payload->>'TargetUserName',''), nullif(u.payload->>'SamAccountName',''), u.target_user) AS created_user,
                   coalesce(u.payload->>'TargetSid','') AS created_sid,
                   u.event_ts AS created, MIN(g.event_ts) AS grouped,
                   u.source_file, u.payload->>'RecordNumber',
                   (array_agg(g.source_file ORDER BY g.event_ts))[1], (array_agg(g.payload->>'RecordNumber' ORDER BY g.event_ts))[1],
                   string_agg(DISTINCT substring(coalesce(g.payload->>'TargetSid',''), 'S-1-5-32-([0-9]+)$'), ',')
              FROM event_logs_v2 u
              JOIN event_logs_v2 g
                ON g.case_key = u.case_key
               AND g.event_id IN (4728,4732,4756) AND g.channel='Security'
               AND g.event_ts BETWEEN u.event_ts AND u.event_ts + interval '48 hours'
               AND ((coalesce(g.payload->>'MemberSid','') <> '' AND coalesce(g.payload->>'MemberSid','') = coalesce(u.payload->>'TargetSid',''))
                    OR (coalesce(u.payload->>'TargetSid','') = '' AND coalesce(nullif(u.payload->>'TargetUserName',''), u.target_user, '') <> ''
                        AND lower(coalesce(g.payload->>'MemberName','')) LIKE '%%'||lower(coalesce(nullif(u.payload->>'TargetUserName',''), u.target_user))||'%%'))
             WHERE u.case_key=%s AND u.event_id=4720 AND u.channel='Security'
               AND coalesce(nullif(u.payload->>'TargetUserName',''), u.target_user, '') NOT IN ('','-')
               AND coalesce(u.event_ts < %s, true)
             GROUP BY 1,2,3,5,6 ORDER BY 3 LIMIT 6""", (case_key, _cut_ts))
        _GRP2 = {'544': 'Administrators', '555': 'Remote Desktop Users', '551': 'Backup Operators', '580': 'Remote Management Users'}
        for _usr, _sid, _cts, _gts, _usf, _urn, _gsf, _grn, _gids in (_c2 or []):
            _usr_short = re.sub(r'\s*\(S-1-5-[0-9-]+\)\s*$', '', str(_usr)).split('\\')[-1]
            _usr_sid = _sid or (re.search(r'(S-1-5-[0-9-]+)', str(_usr)) or [None, None])[1]
            _rid = (re.search(r'-(\d+)$', str(_usr_sid or '')) or [None, ''])[1]
            _sam_name = _sam_rid.get(_rid, '') if _rid else ''
            if _sam_name and _sam_name.lower() != _usr_short.lower() and not _usr_short:
                _usr_short = _sam_name
            _rdp = _q(cur, "SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id=4624 "
                           "AND (logon_type ILIKE '%%remote interactive%%' OR logon_type='10' OR substring(payload->>'PayloadData2' from 'LogonType[ ]*([0-9]+)')='10') "
                           "AND (lower(coalesce(payload->>'TargetUserName', target_user, '')) = lower(%s) OR coalesce(payload->>'TargetUserSid','') = %s)" + _CUT,
                      (case_key, _usr_short, _usr_sid or '-', _cut_ts))
            _rdp_n = _rdp[0][0] if _rdp else 0
            _grp_names = [_GRP2[g] for g in str(_gids or '').split(',') if g in _GRP2]
            _rid_note = ''
            if _rid:
                _rid_note = ' (RID %s%s)' % (_rid, (', у SAM: ' + _sam_name) if _sam_name else ', у SAM-переліку відсутній' if _sam_rid else '')
            add('critical' if _rdp_n else 'high', 'Червона комбінація', 'T1136.001',
                '🔴 Комбінація: бекдор-акаунт «%s»' % _usr_short[:24],
                'Акаунт %s%s створено %s → доданий у привілейовану групу%s %s%s — класичний ланцюг '
                'закріплення доступу.' % (
                    _usr_short[:40], _rid_note, str(_cts)[:16],
                    (' (%s)' % ', '.join(_grp_names)) if _grp_names else '', str(_gts)[:16],
                    (' → %d RDP-входів під ним' % _rdp_n) if _rdp_n else ''), 1 + _rdp_n,
                events=[{'ts': _cts, 'label': 'створено акаунт %s (EID 4720%s)' % (_usr_short, (', RID ' + _rid) if _rid else ''), 'source': 'Security 4720', 'artifact': str(_usr_sid or _usr)[:120], 'file': _usf, 'record': _urn},
                        {'ts': _gts, 'label': 'акаунт %s додано до привілейованої групи%s (EID 4728/4732/4756)' % (_usr_short, (' ' + ', '.join(_grp_names)) if _grp_names else ''), 'source': 'Security 4728/4732', 'artifact': str(_usr_sid or _usr)[:120], 'file': _gsf, 'record': _grn}],
                iocs=[{'type': 'user', 'value': _usr_short, 'role': 'бекдор-акаунт (створений і одразу привілейований)', 'source': 'Security 4720+4732', 'file': _usf, 'record': _urn}]
                     + ([{'type': 'sid', 'value': _usr_sid, 'role': 'SID бекдор-акаунта (RID %s)' % (_rid or '?'), 'source': 'Security 4720', 'file': _usf, 'record': _urn}] if _usr_sid else []))

        # C5: Defender protection turned OFF, then a hard attack tool ran within 6h.
        _c5 = _q(cur,
            "SELECT count(*), MIN(pe.event_ts) FROM program_exec_v2 pe "
            "WHERE pe.case_key=%s "
            "AND lower(coalesce(pe.executable_name,'')||' '||coalesce(pe.full_path,'')) ~ %s "
            "AND coalesce(pe.full_path,'') !~* %s "
            "AND pe.source_file NOT ILIKE '%%AppCompatCache%%' AND coalesce(pe.event_ts < %s, true) "
            "AND EXISTS (SELECT 1 FROM event_logs_v2 el WHERE el.case_key=pe.case_key "
            "  AND el.event_id IN (5001,5010,5012,5007) "
            "  AND coalesce(el.provider,'') ILIKE '%%Windows Defender%%' "
            "  AND el.event_ts <= pe.event_ts AND el.event_ts >= pe.event_ts - interval '6 hours')",
            (case_key, _COMBO_TOOL_RE, _EXAMINER_PATH_RE, _cut_ts))
        if _c5 and _c5[0][0]:
            add('critical', 'Червона комбінація', 'T1562.001',
                '🔴 Комбінація: захист вимкнули → одразу шкідливе виконання',
                'Протягом 6 год після ослаблення/вимкнення Defender виконано %d шкідливий(их) інструмент(ів) (перший %s) — атакувальник прибрав захист і запустився (EID 5001/5007 → виконання).'
                % (_c5[0][0], str(_c5[0][1])[:16]), _c5[0][0])

        # C6: RDP interactive logon (type 10) + special privileges (4672) + hard tool execution.
        _c6 = _q(cur,
            "SELECT count(*) FROM event_logs_v2 r "
            "WHERE r.case_key=%s AND r.event_id=4624 "
            "AND (r.logon_type ILIKE '%%remote interactive%%' OR r.logon_type='10' "
            "     OR substring(r.payload->>'PayloadData2' from 'LogonType[ ]*([0-9]+)')='10') "
            "AND coalesce(r.event_ts < %s, true) "
            "AND EXISTS (SELECT 1 FROM event_logs_v2 p WHERE p.case_key=r.case_key AND p.event_id=4672 "
            "  AND p.event_ts BETWEEN r.event_ts - interval '2 minutes' AND r.event_ts + interval '5 minutes') "
            "AND EXISTS (SELECT 1 FROM program_exec_v2 pe WHERE pe.case_key=r.case_key "
            "  AND lower(coalesce(pe.executable_name,'')||' '||coalesce(pe.full_path,'')) ~ %s "
            "  AND coalesce(pe.full_path,'') !~* %s AND pe.source_file NOT ILIKE '%%AppCompatCache%%' "
            "  AND pe.event_ts BETWEEN r.event_ts AND r.event_ts + interval '12 hours')",
            (case_key, _cut_ts, _COMBO_TOOL_RE, _EXAMINER_PATH_RE))
        if _c6 and _c6[0][0]:
            add('critical', 'Червона комбінація', 'T1078',
                '🔴 Комбінація: RDP + привілеї + виконання',
                'Зафіксовано %d RDP-вхід(ів) (4624 type 10) із підвищенням привілеїв (4672) і подальшим запуском шкідливого інструмента — привілейована RDP-сесія з виконанням (RDP + SeDebug/SeImpersonate + тул).'
                % _c6[0][0], _c6[0][0])
    except Exception as _e_combo:
        try: conn.rollback()
        except Exception: pass
        _log.warning('[threat_detect] red combos skipped: %s' % repr(_e_combo)[:120])

    # Log clearing is "high" on the strength of Security 1102 alone. A finding built only from
    # System 104 (Eventlog provider) keeps that rank only when a clear sits within 24h of
    # another high/critical finding's dated events (the wiper day: System cleared 10:02 and
    # 12:48); standalone 104s on a quiet machine are servicing noise and drop to low.
    try:
        _lc = next((f for f in findings if f.get('title') == 'Очищення журналів подій'), None)
        if _lc is not None:
            _has_1102 = any('EID 1102' in (e.get('label') or '') for e in _lc.get('events') or [])
            if not _has_1102:
                _others = [e.get('ts') for f in findings if f is not _lc and f.get('severity') in ('high', 'critical')
                           for e in (f.get('events') or []) if e.get('ts')]
                _near = False
                for e in _lc.get('events') or []:
                    if e.get('kind') == 'presence':
                        continue
                    for t in _others:
                        try:
                            if abs((_as_dt(e['ts']) - _as_dt(t)).total_seconds()) <= 24 * 3600:
                                _near = True
                                break
                        except Exception:
                            continue
                    if _near:
                        break
                if _near:
                    _lc['detail'] += ' Очищення System-журналу збігається в часі (±24 год) з іншою критичною/високою знахідкою.'
                else:
                    _lc['severity'] = 'low'
                    _lc['category'] = 'Анти-форензика (інформаційно)'
                    _lc['detail'] += ' Лише System-журнал (EID 104) без Security 1102 і без інших знахідок поруч у часі — імовірно, обслуговування, не приховування слідів.'
    except Exception:
        pass

    # what the collection-day cut removed (counts only, never listed as attack activity)
    if _cut_at is not None:
        try:
            _ce = _q(cur, "SELECT event_id, count(*) FROM event_logs_v2 WHERE case_key=%s AND event_ts >= %s GROUP BY 1 ORDER BY 2 DESC LIMIT 6", (case_key, _cut_ts)) or []
            _cn = _q(cur, "SELECT (SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_ts >= %s), "
                          "(SELECT count(*) FROM program_exec_v2 WHERE case_key=%s AND event_ts >= %s), "
                          "(SELECT count(*) FROM event_logs_v2 WHERE case_key=%s AND event_id=7045 AND event_ts >= %s), "
                          "(SELECT count(*) FROM tool_alerts_v2 WHERE case_key=%s AND event_ts >= %s)",
                     (case_key, _cut_ts, case_key, _cut_ts, case_key, _cut_ts, case_key, _cut_ts)) or []
            _n_ev, _n_pe, _n_svc, _n_al = (_cn[0] if _cn else (0, 0, 0, 0))
            add('low', 'Дії реагування (не атака)', '—',
                'Дії реагування/збору (не атака)',
                'Збір/реагування на цій машині розпочато %s; усе з %s (t−10 хв) вилучено з ланцюгів, IOC і лічильників як дії експерта/збирача: '
                '%d подій журналів (найчастіші EID: %s), %d записів виконання програм, %d встановлень служб/драйверів, %d детекцій сторонніх сканерів.'
                % (str(_cut_at)[:19], str(_cut_ts)[:16], int(_n_ev or 0), ', '.join('%s×%d' % (e, c) for e, c in _ce) or '—', int(_n_pe or 0), int(_n_svc or 0), int(_n_al or 0)),
                int(_n_ev or 0) + int(_n_pe or 0))
        except Exception:
            try: conn.rollback()
            except Exception: pass

    # ── Exfiltration by volume (SRUM, 2026-10-02) ──
    # SRUM keeps the bytes each application sent; no detector read it, and the case_50 case
    # with ngrok 444 MB, an unknown not.exe 692 MB and nott.exe 54 MB received the seeded
    # answer «ознак ексфільтрації немає». Browsers, updaters, AV and sync clients are the
    # ordinary top senders and stay out; a tunnel/transfer tool counts from 10 MB, any other
    # application from 50 MB.
    try:
        _srum_rows = _q(cur, """SELECT exe_info, sum((payload->>'bytes_tx')::bigint), min(event_ts), max(event_ts),
                                       (array_agg(source_file))[1]
                                FROM srum_v2 WHERE case_key=%s AND coalesce(payload->>'bytes_tx','') ~ '^[0-9]+$'""" + _CUT + """
                                GROUP BY exe_info ORDER BY 2 DESC LIMIT 40""", (case_key, _cut_ts)) or []
    except Exception:
        try: conn.rollback()
        except Exception: pass
        _srum_rows = []
    _SRUM_BENIGN = re.compile(r'(chrome|msedge|firefox|opera|brave|yandex|vivaldi|iexplore|browser|onedrive|dropbox|googledrive'
                              r'|teams|outlook|skype|zoom|telegram|viber|whatsapp|slack|discord|steam|epicgames|battle\.net'
                              r'|svchost|dosvc|\bbits\b|wuauserv|^system$|backgroundtaskhost|msmpeng|nissrv|mpdefender|ekrn|egui'
                              r'|avp\b|avast|avg|kaspersky|eset|mcafee|norton|spotify|itunes|winstore|searchapp|explorer\.exe'
                              r'|smartscreen|officeclicktorun|onenote|excel|winword|powerpnt|msiexec|setup|update'
                              # file sharing with a domain server is ordinary traffic (DVB: «SMB - 216 МБ»)
                              r'|^smb$|lanman|^dns|dhcp|w32time|ntoskrnl|netlogon|^lsass'
                              # security agents ship telemetry (case_51: wazuh-agent 1.4 GB, Cisco AMP);
                              # remote-desktop tools stream the screen, not files (kyiv_dbo: AnyDesk 101 MB) -
                              # remote access is judged by the RDP/RAT detectors, not by volume
                              r'|wazuh|cisco|acnvm|anyconnect|csfalcon|crowdstrike|sentinel|sophos|bitdefender|trendmicro'
                              r'|carbonblack|cylance|symantec|tanium|qualys|nessus|splunk|winlogbeat|elastic|nxlog|zabbix'
                              r'|velociraptor|sysmon|anydesk|teamviewer|rustdesk|mstsc|termservice|rdpclip)', re.I)
    _SRUM_XFER = re.compile(r'(ngrok|rclone|frpc|chisel|megasync|megacmd|winscp|filezilla|\bcurl\b|wget|pscp|psftp|plink'
                            r'|cloudflared|localtonet|^ssh\.exe$|^scp\.exe$|^sftp\.exe$)', re.I)
    # system utilities with no business on the network: a compiler sending 201 MB (jsc.exe on two
    # cases of the case_58 campaign) is a living-off-the-land channel
    _SRUM_LOLBIN = re.compile(r'^(jsc|csc|vbc|msbuild|installutil|regasm|regsvcs|certutil|bitsadmin|mshta|rundll32|regsvr32'
                              r'|wscript|cscript|cmstp|odbcconf|msxsl|forfiles|pcalua)\.exe$', re.I)
    _xf = []
    for _ex, _bytes, _t0, _t1, _sf in _srum_rows:
        _nm = str(_ex or '').replace('/', chr(92)).rsplit(chr(92), 1)[-1]
        if not _nm or _is_own(str(_ex or '')):
            continue
        _mb = float(_bytes or 0) / 1048576.0
        # an unknown program counts only from a user-writable folder: on a managed workstation the
        # top senders are agents and services (case_51: VPN agent, SCCM, telemetry)
        _pl = str(_ex or '').replace('/', chr(92)).lower()
        _user_path = (bool(re.search(r'\\users\\|\\temp\\|\\downloads\\|\\programdata\\[^\\]+\.exe$', _pl))
                      and not re.search(r'\\appdata\\local\\(programs|microsoft)\\|\\windowsapps\\', _pl))
        if ((_SRUM_XFER.search(_nm) and _mb >= 10) or (_SRUM_LOLBIN.search(_nm) and _mb >= 10)
                or (_user_path and not _SRUM_BENIGN.search(_nm) and _mb >= 50)):
            _xf.append((_nm, _mb, _t0, _t1, _sf, str(_ex or '')))
    if _xf:
        _sev_x = 'high' if (any(_SRUM_XFER.search(x[0]) or _SRUM_LOLBIN.search(x[0]) for x in _xf)
                            or sum(x[1] for x in _xf) >= 100) else 'medium'
        add(_sev_x, 'Ексфільтрація', 'T1048',
            'Великий обсяг відправлених даних (SRUM)',
            'Служба обліку використання ресурсів зафіксувала відправлення назовні: %s. Враховано лише засоби '
            'передачі й тунелі, системні утиліти без мережевого призначення та програми з тек користувача; '
            'встановити, що саме і куди передавалось.' % ', '.join('%s (%s) - %.0f МБ' % (x[0], (('…' + x[5][-69:]) if len(x[5]) > 70 else x[5]), x[1]) for x in _xf[:6]),
            len(_xf), ['%s %.0f МБ' % (x[0], x[1]) for x in _xf[:6]],
            events=[{'ts': x[2], 'label': 'відправлено назовні %.0f МБ: %s (останній запис %s)' % (x[1], x[0], str(x[3])[:16]),
                     'source': 'srum_v2', 'artifact': x[5][:160], 'file': x[4], 'kind': 'anchor'} for x in _xf[:8] if x[2]],
            iocs=[{'type': 'file', 'value': x[0], 'role': 'застосунок, що відправив %.0f МБ назовні' % x[1],
                   'source': 'srum_v2', 'file': x[4]} for x in _xf[:8]])

    # ── Chain bounds across the whole incident (2026-10-02) ──
    # add() judges every finding alone: a leg more than 30 days from the median of ITS anchors
    # is relabelled «файл існував раніше». With two anchors the «median» is simply the later
    # one, so on case_50 the real 13.02 launch of ngrok became a «presence» stamp and a
    # collection-day Prefetch run (01.10) became the launch - and «Активна фаза» ran to the
    # day of collection. Judge every leg against the median of all high/critical anchors
    # instead, and restore launches the per-finding rule demoted.
    try:
        _all = []
        for _f in findings:
            if _f.get('severity') not in ('critical', 'high'):
                continue
            for _e in (_f.get('events') or []):
                _dt = _as_dt(_e.get('ts'))
                if _dt is not None and not _PRESENCE_SRC_RX.search(str(_e.get('file') or '')):
                    _all.append(_dt)
        # stamps come both with and without an offset; compare them as UTC
        _all = [d if d.tzinfo is not None else d.replace(tzinfo=timezone.utc) for d in _all]
        if len(_all) >= 3:
            _all.sort()
            _gmed = _all[len(_all) // 2]
            _OUT_LABEL = 'поза вікном інциденту (окремий епізод, перевірити)'
            for _f in findings:
                _changed = False
                for _e in (_f.get('events') or []):
                    _dt = _as_dt(_e.get('ts'))
                    if _dt is None or _PRESENCE_SRC_RX.search(str(_e.get('file') or '')):
                        continue
                    if _dt.tzinfo is None:
                        _dt = _dt.replace(tzinfo=timezone.utc)
                    _lbl = str(_e.get('label') or '')
                    _far = abs(_dt - _gmed) > _ANCHOR_WINDOW
                    if _far and _e.get('kind') == 'anchor':
                        _e['kind'] = 'presence'
                        _e['label'] = '%s: %s' % (_OUT_LABEL, _lbl)
                        _changed = True
                    elif not _far and _e.get('kind') == 'presence' and _lbl.startswith(_PRESENCE_LABEL + ': '):
                        _e['kind'] = 'anchor'
                        _e['label'] = _lbl[len(_PRESENCE_LABEL) + 2:]
                        _changed = True
                    elif _far and _lbl.startswith(_PRESENCE_LABEL + ': '):
                        # a Prefetch / Amcache launch far from the incident is a separate episode,
                        # not a PE/archive stamp - say so
                        _e['label'] = '%s: %s' % (_OUT_LABEL, _lbl[len(_PRESENCE_LABEL) + 2:])
                if _changed:
                    _ws = [_as_dt(_e.get('ts')) for _e in _f['events'] if _e.get('kind') == 'anchor']
                    _ws = [w if w.tzinfo is not None else w.replace(tzinfo=timezone.utc) for w in _ws if w is not None]
                    _f['window'] = [min(_ws).isoformat(sep=' '), max(_ws).isoformat(sep=' ')] if _ws else None
                    _f['events'].sort(key=lambda e: (0 if e.get('kind') == 'anchor' else 1, e.get('ts') or '9999'))
    except Exception as _gw:
        try:
            _log.error('[threat] incident-wide chain bounds failed: %s' % _gw)
        except Exception:
            pass

    sev_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    findings.sort(key=lambda f: (sev_rank.get(f['severity'], 9), -f['count']))
    # ── Fill in file hashes before returning ─────────────────────────────────────
    # Amcache stores SHA1 for a large share of the files it records (1 270 of 2 948 rows
    # on the case_42 case), but no detector was looking it up, so every file indicator
    # in the report was a bare name. A name is not an indicator you can hunt with - a hash
    # is. One lookup here covers every detector instead of touching sixty of them.
    #
    # Files known only from AppCompatCache or $MFT genuinely have no hash: those sources
    # do not store one. Those stay unhashed rather than being quietly dropped.
    try:
        _names = set()
        for _f in findings:
            for _i in (_f.get('iocs') or []):
                if str(_i.get('type', '')) == 'file' and _i.get('value'):
                    _names.add(str(_i['value']).split(chr(92))[-1].lower()[:120])
        if _names:
            _hrows = _q(cur, """
                SELECT lower(split_part(replace(coalesce(full_path, executable_name), '/', '\\'),
                                        '\\', array_length(string_to_array(
                                            replace(coalesce(full_path, executable_name), '/', '\\'), '\\'), 1))),
                       max(hash_sha1)
                FROM program_exec_v2
                WHERE case_key=%s AND coalesce(hash_sha1,'') <> ''
                GROUP BY 1""", (case_key,)) or []
            _hmap = {r[0]: r[1] for r in _hrows if r and r[0] and r[1]}
            _n_filled = 0
            for _f in findings:
                for _i in (_f.get('iocs') or []):
                    if str(_i.get('type', '')) != 'file' or _i.get('sha1'):
                        continue
                    _key = str(_i.get('value', '')).split(chr(92))[-1].lower()[:120]
                    _h = _hmap.get(_key)
                    if _h:
                        _i['sha1'] = _h
                        _i['hash_source'] = 'Amcache'
                        _n_filled += 1
            if _n_filled:
                _log.info('[threat] filled SHA1 for %d file indicator(s)' % _n_filled)
    except Exception as _he:
        try:
            _log.error('[threat] hash enrichment failed: %s' % _he)
        except Exception:
            pass

    # ── 18.10.2026: channels that were collected in 29-34 cases and never read (audit 15.10) ──
    # Each signature was checked against all 34 cases in the DB before it went in: what fires on
    # clean machines (SCM Event Log Consumer, OneDrive/Edge/Adobe BITS jobs, browser mDNS rules)
    # is excluded by name, so these stay quiet unless something unusual is there.
    try:
        # (a) WMI permanent event subscription = persistence (T1546.003). Windows itself ships
        #     only «SCM Event Log Consumer»; SCCM adds CCM_*; anything else is somebody's.
        _wmi = _q(cur, """SELECT event_ts, payload->>'PayloadData2', source_file, payload->>'RecordNumber'
                          FROM event_logs_v2 WHERE case_key=%s AND event_id=5861 AND channel ILIKE '%%WMI-Activity%%'""" + _CUT + """
                          ORDER BY event_ts LIMIT 400""", (case_key, _cut_ts)) or []
        _wmi_hits = {}
        for _ts, _p2, _sf, _rn in _wmi:
            _p2 = str(_p2 or '')
            _cls = (re.search(r'Perm\. Consumer: , instance of (\w+)', _p2) or [None, ''])[1]
            _nm = (re.search(r'Consumer.*?Name = "([^"]+)"', _p2) or [None, ''])[1]
            if _nm in ('SCM Event Log Consumer', 'BVTConsumer') or _cls.startswith('CCM_') or _nm.startswith('CCM_'):
                continue
            _cmd = (re.search(r'(?:CommandLineTemplate|ExecutablePath|ScriptText) = "([^"]{1,300})', _p2) or [None, ''])[1]
            _wmi_hits.setdefault((_cls, _nm), [_ts, _sf, _rn, _cmd, 0])[4] += 1
        if _wmi_hits:
            _exec = any(k[0] in ('CommandLineEventConsumer', 'ActiveScriptEventConsumer') for k in _wmi_hits)
            add('high' if _exec else 'medium', 'Закріплення (WMI)', 'T1546.003',
                'WMI-підписка на події (постійний споживач)',
                'Зареєстровано %d постійних WMI-споживачів, яких немає в чистій Windows: %s. %s' % (
                    len(_wmi_hits), ', '.join('%s «%s»' % (k[0] or '?', k[1] or '?') for k in list(_wmi_hits)[:4]),
                    'Споживач запускає команду/скрипт — класичне безфайлове закріплення.' if _exec else
                    'Перевір, яка програма його створила (часто антивірус або агент керування).'),
                sum(v[4] for v in _wmi_hits.values()),
                ['%s «%s»%s' % (k[0], k[1], (': ' + v[3][:120]) if v[3] else '') for k, v in list(_wmi_hits.items())[:6]],
                events=[{'ts': v[0], 'label': 'WMI-споживач %s «%s»%s' % (k[0], k[1], (' → ' + v[3][:80]) if v[3] else ''),
                         'source': 'WMI-Activity 5861', 'artifact': k[1] or k[0], 'file': v[1], 'record': v[2]}
                        for k, v in list(_wmi_hits.items())[:6] if v[0]],
                iocs=[{'type': 'task', 'value': 'WMI:%s' % (k[1] or k[0]), 'role': 'WMI-споживач %s' % k[0],
                       'source': 'WMI-Activity 5861', 'file': v[1], 'record': v[2]} for k, v in list(_wmi_hits.items())[:6]])
    except Exception as _e:
        _log.error('[threat] wmi-5861 failed: %s' % _e)
    try:
        # (b) BITS used as a downloader (T1197): updaters use it all day, so only a raw public IP
        #     or an executable/script fetched from a host that is not a known vendor counts.
        _bits = _q(cur, """SELECT min(event_ts), count(*), substring(payload->>'PayloadData3' from 'URL: (.*)$'),
                                  (array_agg(payload->>'PayloadData1' ORDER BY event_ts))[1], (array_agg(source_file ORDER BY event_ts))[1],
                                  (array_agg(payload->>'RecordNumber' ORDER BY event_ts))[1]
                           FROM event_logs_v2 WHERE case_key=%s AND event_id=59 AND channel ILIKE '%%Bits-Client%%'""" + _CUT + """
                           GROUP BY 3 ORDER BY 1 LIMIT 500""", (case_key, _cut_ts)) or []
        _VENDOR = re.compile(r'(^|\.)(microsoft\.com|windowsupdate\.com|live\.com|office\.net|office\.com|sfx\.ms|msedge\.net|'
                             r'gvt1\.com|google\.com|googleapis\.com|gstatic\.com|adobe\.com|mozilla\.net|mozilla\.org|dell\.com|hp\.com|'
                             r'lenovo\.com|intel\.com|nvidia\.com|amd\.com|whatsapp\.net|scdn\.co|spotify\.com|bravesoftware\.com|'
                             r'apple\.com|dropbox\.com|zoom\.us|skype\.com|gov\.ua)$', re.I)
        _bits_hits = []
        for _t0, _n, _url, _job, _sf, _rn in _bits:
            _url = str(_url or '').strip()
            _m = re.match(r'^\w+://([^/:]+)', _url)
            if not _m:
                continue
            _h = _m.group(1)
            _is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', _h))
            if _is_ip and re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)', _h):
                continue
            _exe = bool(re.search(r'\.(exe|dll|ps1|bat|cmd|vbs|js|hta|scr|msi|zip|7z|rar)(\?|$)', _url, re.I))
            if _is_ip or (_exe and not _VENDOR.search(_h)):
                _bits_hits.append((_t0, _n, _url, str(_job or '').replace('jobTitle: ', ''), _sf, _rn, _h))
        if _bits_hits:
            add('high', 'Доставка (BITS)', 'T1197',
                'Завантаження через BITS з підозрілої адреси',
                'Служба BITS завантажувала файли з %d підозрілих адрес (IP-адреса напряму або виконуваний файл не з сайту '
                'відомого виробника): %s.' % (len(_bits_hits), ', '.join(x[6] for x in _bits_hits[:4])),
                sum(x[1] for x in _bits_hits), ['%s (завдання «%s», %d раз)' % (x[2][:150], x[3][:60], x[1]) for x in _bits_hits[:6]],
                events=[{'ts': x[0], 'label': 'BITS-завантаження %s (завдання «%s»)' % (x[2][:100], x[3][:40]), 'source': 'Bits-Client 59',
                         'artifact': x[6], 'file': x[4], 'record': x[5]} for x in _bits_hits[:6] if x[0]],
                iocs=[{'type': 'ip' if re.match(r'^\d', x[6]) else 'domain', 'value': x[6], 'role': 'джерело BITS-завантаження',
                       'source': 'Bits-Client 59', 'file': x[4], 'record': x[5]} for x in _bits_hits[:8]])
    except Exception as _e:
        _log.error('[threat] bits-59 failed: %s' % _e)
    try:
        # (c) RDP *from* this machine (RDPClient 1024): where the user/attacker went next (T1021.001)
        _rc = _q(cur, """SELECT substring(payload->>'PayloadData1' from 'Dest: (.*)$'), count(*), min(event_ts), max(event_ts),
                                (array_agg(source_file ORDER BY event_ts))[1], (array_agg(payload->>'RecordNumber' ORDER BY event_ts))[1]
                         FROM event_logs_v2 WHERE case_key=%s AND event_id=1024 AND channel ILIKE '%%RDPClient%%'""" + _CUT + """
                         GROUP BY 1 ORDER BY 2 DESC LIMIT 20""", (case_key, _cut_ts)) or []
        _rc = [r for r in _rc if r[0] and str(r[0]).strip() not in ('-', '')]
        if _rc:
            add('low', 'Рух мережею (RDP вихідний)', 'T1021.001',
                "Вихідні RDP-підключення з цього комп'ютера",
                "З цього комп'ютера RDP-клієнт підключався до %d адрес: %s. Для адміністратора це звично; "
                'при компрометації — це кандидати на наступні уражені машини.' % (len(_rc), ', '.join(str(r[0]) for r in _rc[:6])),
                sum(r[1] for r in _rc), ['%s ×%d (%s..%s)' % (r[0], r[1], str(r[2])[:10], str(r[3])[:10]) for r in _rc[:8]],
                events=[{'ts': r[2], 'label': 'перше вихідне RDP-підключення до %s (усього %d)' % (r[0], r[1]), 'source': 'RDPClient 1024',
                         'artifact': str(r[0]), 'file': r[4], 'record': r[5]} for r in _rc[:6] if r[2]],
                iocs=[{'type': 'ip' if _ip_shaped(r[0]) else 'domain', 'value': str(r[0]), 'role': 'ціль вихідного RDP (%d)' % r[1],
                       'source': 'RDPClient 1024', 'file': r[4], 'record': r[5]} for r in _rc[:8]])
    except Exception as _e:
        _log.error('[threat] rdpclient-1024 failed: %s' % _e)
    try:
        # (d) ISO/VHD mounted (VHDMP 1): a common way to get past Mark-of-the-Web (T1553.005)
        _vh = _q(cur, """SELECT substring(payload->>'PayloadData2' from 'VhdName: (.*)$'), count(*), min(event_ts),
                                (array_agg(source_file ORDER BY event_ts))[1], (array_agg(payload->>'RecordNumber' ORDER BY event_ts))[1]
                         FROM event_logs_v2 WHERE case_key=%s AND event_id=1 AND channel ILIKE '%%VHDMP%%'""" + _CUT + """
                         GROUP BY 1 ORDER BY 3 LIMIT 20""", (case_key, _cut_ts)) or []
        _vh = [r for r in _vh if r[0] and re.search(r'\.(iso|img|vhdx?)$', str(r[0]).strip(), re.I)]
        # Windows Backup mounts its own VHDs from Windows\Temp\WindowsBackupLinks (case_66 18.10: false medium)
        _vh = [r for r in _vh if not re.search(r'windowsbackuplinks|windowsimagebackup', str(r[0]), re.I)]
        if _vh:
            _risky = [r for r in _vh if re.search(r'\\(downloads|temp|appdata|inetcache|content\.outlook)\\', str(r[0]), re.I)]
            add('medium' if _risky else 'low', 'Доставка (ISO/VHD)', 'T1553.005',
                'Змонтовано образи дисків ISO/VHD',
                'Користувач відкривав %d образ(ів) диска: %s. Файли з образу не мають позначки «з Інтернету» '
                '(Mark-of-the-Web), тому так часто доставляють шкідливе ПЗ%s.' % (
                    len(_vh), ', '.join(str(r[0]).split(chr(92))[-1] for r in _vh[:4]),
                    ('; %d з них — із Завантажень/Temp/пошти' % len(_risky)) if _risky else ''),
                sum(r[1] for r in _vh), [str(r[0])[:200] for r in _vh[:6]],
                events=[{'ts': r[2], 'label': 'змонтовано образ %s' % str(r[0])[:120], 'source': 'VHDMP 1',
                         'artifact': str(r[0]).split(chr(92))[-1], 'file': r[3], 'record': r[4]} for r in _vh[:6] if r[2]],
                iocs=[{'type': 'path', 'value': str(r[0]), 'role': 'змонтований образ диска', 'source': 'VHDMP 1', 'file': r[3], 'record': r[4]}
                      for r in (_risky or _vh)[:6]])
    except Exception as _e:
        _log.error('[threat] vhdmp-1 failed: %s' % _e)
    try:
        # (e) Firewall rule that lets a remote-control tool in, or a program from a user-writable folder
        _fw = _q(cur, """SELECT coalesce(payload->>'PayloadData2', ''), payload->>'PayloadData1', count(*), min(event_ts),
                                (array_agg(source_file ORDER BY event_ts))[1], (array_agg(payload->>'RecordNumber' ORDER BY event_ts))[1]
                         FROM event_logs_v2 WHERE case_key=%s AND event_id IN (2004, 2071, 2097) AND channel ILIKE '%%Firewall With%%'
                           AND payload::text ~* 'inbound' AND payload::text ~* 'allow'""" + _CUT + """
                         GROUP BY 1, 2 ORDER BY 4 LIMIT 200""", (case_key, _cut_ts)) or []
        _RAT = re.compile(r'rutserv|rfusclient|remote manipulator|romserver|litemanager|anydesk|teamviewer|radmin|ammyy|screenconnect|'
                          r'connectwise|meshagent|rustdesk|supremo|aeroadmin|dwservice|splashtop|tightvnc|ultravnc|winvnc|atera|'
                          r'netsupport|client32', re.I)
        _fw_hits = []
        for _app, _nm, _n, _t0, _sf, _rn in _fw:
            if _RAT.search('%s %s' % (_app, _nm)) or re.search(r'\\(appdata|temp|users\\public|programdata)\\', str(_app), re.I):
                _fw_hits.append((str(_nm or '').lstrip(': ').strip(), str(_app), _n, _t0, _sf, _rn))
        if _fw_hits:
            add('medium', 'Віддалений доступ (фаєрвол)', 'T1562.004',
                'Фаєрвол відкрито для засобу віддаленого керування',
                'До фаєрвола додано %d правил(о), що дозволяють ВХІДНІ підключення до засобів віддаленого керування або програм '
                'з тек, куди може писати будь-хто: %s. Перевір, хто й навіщо їх встановив.' % (
                    len(_fw_hits), ', '.join('«%s»' % (x[0] or x[1].split(chr(92))[-1]) for x in _fw_hits[:5])),
                sum(x[2] for x in _fw_hits), ['%s — %s' % (x[0], x[1]) for x in _fw_hits[:6]],
                events=[{'ts': x[3], 'label': 'правило фаєрвола «%s» дозволяє вхідні до %s' % (x[0][:60], x[1].split(chr(92))[-1] or '—'),
                         'source': 'Firewall 2004', 'artifact': x[1] or x[0], 'file': x[4], 'record': x[5]} for x in _fw_hits[:6] if x[3]],
                iocs=[{'type': 'path', 'value': x[1], 'role': 'програма з вхідним дозволом фаєрвола', 'source': 'Firewall 2004',
                       'file': x[4], 'record': x[5]} for x in _fw_hits[:6] if x[1]])
    except Exception as _e:
        _log.error('[threat] firewall-2004 failed: %s' % _e)

    try:
        # (f) Executed binary (Amcache SHA1) found in the offline MalwareBazaar dump (18.10.2026).
        # MalwareBazaar also holds legitimate remote-admin builds (tagged AnyDesk, TeamViewer...) and
        # bulk AV-heuristic uploads named "SecuriteInfo.com.*" (ncat, pixiewps, wimlib in our cases):
        # those are reported LOW as dual-use, never as malware.
        from analysis.hash_lookup import known_bad_sha1 as _kb1
        _am = _q(cur, """SELECT lower(hash_sha1), max(coalesce(full_path, executable_name)), min(event_ts),
                                (array_agg(source_file ORDER BY event_ts))[1]
                         FROM program_exec_v2 WHERE case_key=%s AND hash_sha1 IS NOT NULL
                         GROUP BY 1 LIMIT 20000""", (case_key,)) or []
        _bad = _kb1([r[0] for r in _am]) if _am else {}
        _DUAL = re.compile(r'anydesk|teamviewer|radmin|ammyy|rutserv|remoteutilities|screenconnect|rustdesk|'
                           r'aeroadmin|litemanager|supremo|ultravnc|tightvnc|nmap|ncat|netcat|psexec|mimikatz-free', re.I)
        _RISKY = re.compile(r'\\users\\public\\|\\appdata\\local\\temp\\|\\windows\\temp\\|\\programdata\\[^\\]+\.(exe|dll|scr)$|'
                            r'\\appdata\\roaming\\[^\\]+\.(exe|dll|scr)$', re.I)
        _lvl = {'high': [], 'medium': [], 'low': []}
        for _h, _path, _t0, _sf in _am:
            if _h not in _bad:
                continue
            _fam, _mbn, _fs = _bad[_h]
            _heur = str(_mbn or '').lower().startswith('securiteinfo.com')
            if (_fam and _DUAL.search(_fam)) or _heur or (not _fam and _DUAL.search(str(_path))):
                _sev = 'low'
            elif _fam or _RISKY.search(str(_path)):
                _sev = 'high'
            else:
                _sev = 'medium'
            _lvl[_sev].append((_path, _h, _fam, _mbn, _fs, _t0, _sf))
        for _sev, _hits in _lvl.items():
            if not _hits:
                continue
            if _sev == 'low':
                _title = 'Запускались засоби подвійного призначення, відомі MalwareBazaar'
                _why = ('Ці файли є в базі MalwareBazaar, але як легальні засоби віддаленого доступу або мережеві утиліти '
                        '(або за евристикою антивіруса). Самі по собі це не вірус: перевір, чи їх ставив власник ПК.')
            elif _sev == 'medium':
                _title = 'Запускався файл, який є в MalwareBazaar (без назви родини)'
                _why = ('SHA1 з Amcache є в базі MalwareBazaar, але родина шкідливого ПЗ не вказана: туди інколи завантажують '
                        'і легальні утиліти на перевірку. Файл було ЗАПУЩЕНО — перевір його походження.')
            else:
                _title = 'Запускався файл, відомий як шкідливий (MalwareBazaar)'
                _why = ('SHA1 з Amcache збігся з відомим зразком шкідливого ПЗ в офлайн-базі MalwareBazaar. '
                        'Файл було ЗАПУЩЕНО на цьому ПК.')
            add(_sev, 'Шкідливе ПЗ (відомий хеш)', 'T1204.002', _title,
                '%s Збіги: %s.' % (_why, '; '.join('%s (%s)' % (str(x[0]).split(chr(92))[-1], x[2] or x[3] or '—') for x in _hits[:5])),
                len(_hits), ['%s | SHA1 %s | %s' % (x[0], x[1], x[2] or x[3]) for x in _hits[:6]],
                events=[{'ts': x[5], 'label': 'запуск %s — у MalwareBazaar: %s' % (str(x[0]).split(chr(92))[-1], x[2] or x[3] or '—'),
                         'source': 'Amcache', 'artifact': x[0], 'file': x[6]} for x in _hits[:6] if x[5]],
                iocs=[{'type': 'hash', 'value': x[1], 'role': 'хеш виконаного файлу (%s)' % (x[2] or 'MalwareBazaar'),
                       'source': 'Amcache', 'file': x[6]} for x in _hits[:6]]
                     + [{'type': 'path', 'value': x[0], 'role': 'виконаний файл, відомий MalwareBazaar', 'source': 'Amcache',
                         'file': x[6]} for x in _hits[:6] if x[0]])
    except Exception as _e:
        _log.error('[threat] amcache-known-bad failed: %s' % _e)

    try:
        # (g) Executed binary named like a core Windows process, at a path no clean Windows has
        # (VanillaWindowsReference index, 22.10.2026). Measured on all cases: svchost.exe in
        # AppData\Local\log / Startup / an case_59 desktop, csrss.exe in an "rdp brute" kit,
        # explorer.exe in system32. sysnative is the 32-bit alias of system32, not a location.
        from analysis.known_good import is_vanilla_path as _kgp, status as _kgs
        if (_kgs() or {}).get('vanilla'):
            _CORE = {'svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe', 'services.exe', 'smss.exe', 'wininit.exe',
                     'explorer.exe', 'rundll32.exe', 'conhost.exe', 'dllhost.exe', 'taskhost.exe', 'taskhostw.exe',
                     'spoolsv.exe', 'lsm.exe', 'ctfmon.exe', 'taskmgr.exe', 'msiexec.exe', 'regsvr32.exe', 'cmd.exe',
                     'powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'sihost.exe', 'fontdrvhost.exe', 'dwm.exe',
                     'searchindexer.exe', 'wmiprvse.exe', 'audiodg.exe', 'runtimebroker.exe', 'mmc.exe'}
            _MSKIP = re.compile(r'\\windows\\(winsxs|servicing|softwaredistribution|installer|systemapps|sysnative)\\|\$windows\.~(bt|ws)'
                                r'|\\windows\.old\\|\\windowsapps\\|\\program files( \(x86\))?\\|\\driverstore\\|\\\$recycle', re.I)
            _pe = _q(cur, """SELECT lower(coalesce(full_path, executable_name)), min(event_ts),
                                    (array_agg(source_file ORDER BY event_ts))[1], count(*)
                             FROM program_exec_v2 WHERE case_key=%s
                               AND lower(coalesce(full_path, executable_name)) ~ '^[a-z]:\\\\.*\\\\[a-z0-9]+\\.exe$'
                             GROUP BY 1 LIMIT 50000""", (case_key,)) or []
            _mq = [r for r in _pe if r[0].rsplit(chr(92), 1)[-1] in _CORE and not _MSKIP.search(r[0])
                   and _kgp(r[0]) is False]
            if _mq:
                add('high', 'Маскування під систему', 'T1036.005',
                    'Запускався файл з іменем системного процесу не з системної теки',
                    'Знайдено %d файл(ів) з іменами процесів Windows (svchost, csrss, explorer…), %d запис(ів) про запуск; вони лежать там, '
                    'де чиста Windows їх ніколи не тримає (звірено з еталоном VanillaWindowsReference): %s. '
                    'Це типовий прийом шкідливого ПЗ, щоб не впадати в око в диспетчері задач.' % (
                        len(_mq), sum(r[3] for r in _mq), '; '.join(r[0] for r in _mq[:4])),
                    sum(r[3] for r in _mq), [r[0] for r in _mq[:6]],
                    events=[{'ts': r[1], 'label': 'запуск %s з нетипової теки' % r[0].rsplit(chr(92), 1)[-1],
                             'source': 'Amcache/ShimCache/Prefetch', 'artifact': r[0], 'file': r[2]} for r in _mq[:6] if r[1]],
                    iocs=[{'type': 'path', 'value': r[0], 'role': 'системне ім\'я поза системною текою', 'source': 'program execution',
                           'file': r[2]} for r in _mq[:6]])
    except Exception as _e:
        _log.error('[threat] core-process-masquerade failed: %s' % _e)

    try:
        # (h) Data hidden in NTFS alternate data streams (T1564.004). MFT rows carry is_ads since
        # 18.10 (older cases backfilled 22.10). Surveyed on all 34 cases: every stream name is one of
        # the benign ones below except ProgramData\TEMP:<8 hex> on a DIRECTORY in both case_58 cases
        # and the Luminati/BrightData proxy SDK marker (lum_sdk_session_id:LUM).
        _ADS_OK = re.compile(r'^(wofcompresseddata|zone\.identifier|streamedfilestate|encryptable|oecustomproperty|smartscreen'
                             r'|favicon|originalpath|sec\.endpointdlp|\$.*|\{4c8cc155-6c1e-11d1-8e41-00c04fb9386d\}'
                             r'|3or4kl4x13tuuug3byamue2s4b|cm_[0-9a-f]{64}|\{3d0ce612-fdee-43f7-8aca-957bec0ccba0\}\..*'
                             r'|afp_afpinfo|afp_resource|com\.dropbox\.attrs|ms-properties|kpmatt)$')
        _ads = _q(cur, """SELECT parent_path, file_name, (payload->>'file_size'), event_ts, source_file
                          FROM filesystem_v2 WHERE case_key=%s AND action='MFT' AND payload ? 'is_ads'
                            AND file_name LIKE '%%:%%' LIMIT 200000""", (case_key,)) or []
        _odd = []
        for _pp, _fn, _sz, _ts, _sf in _ads:
            _base, _, _sn = str(_fn).rpartition(':')
            if not _sn or _ADS_OK.match(_sn.strip().lower()) or str(_pp or '').startswith('.\\$Extend'):
                continue
            _odd.append((str(_pp or '').lstrip('.'), _base, _sn, int(_sz) if str(_sz or '').isdigit() else 0, _ts, _sf))
        # collector v4.9+: the stream CONTENT, saved by the collector and classified at ingest
        _adsc = {}
        for (_p,) in (_q(cur, """SELECT payload FROM tool_alerts_v2 WHERE case_key=%s AND tool='ads'
                                  LIMIT 2000""", (case_key,)) or []):
            _p = _p or {}
            _k = (re.sub(r'^[a-z]:', '', str(_p.get('path') or ''), flags=re.I).lower(), str(_p.get('stream') or '').lower())
            _adsc[_k] = _p
        _seen = set((('%s\\%s' % (x[0], x[1])).lower(), x[2].lower()) for x in _odd)
        for _k, _p in _adsc.items():
            if _k in _seen:
                continue
            # a stream the collector saw but the $MFT pass did not (or an archive without $MFT)
            _pp, _, _bn = str(_p.get('path') or '').rpartition('\\')
            _odd.append((re.sub(r'^[a-z]:', '', _pp, flags=re.I), _bn, str(_p.get('stream') or ''),
                         int(_p.get('size') or 0), None, 'ads_streams.csv'))
        if _odd:
            _dirs = set(r[0] for r in (_q(cur, """SELECT lower(parent_path || '\\' || file_name) FROM filesystem_v2
                          WHERE case_key=%s AND action='MFT' AND payload->>'is_dir' ILIKE 'true'
                            AND lower(parent_path || '\\' || file_name) = ANY(%s)""",
                          (case_key, list({('.' + x[0] + '\\' + x[1]).lower() for x in _odd}))) or []))
            _hi, _lo = [], []
            for x in _odd:
                _c = _adsc.get((('%s\\%s' % (x[0], x[1])).lower(), x[2].lower())) or {}
                _isdir = ('.' + x[0] + '\\' + x[1]).lower() in _dirs or bool(_c.get('is_folder'))
                _bad = (_isdir and re.match(r'^[0-9a-f]{6,16}$', x[2], re.I)) or re.search(
                    r'\.(exe|dll|scr|ps1|vbs|js|jse|hta|bat|cmd|lnk)$', x[2], re.I) or x[3] > 1048576 \
                    or _c.get('severity') == 'high'
                (_hi if _bad else _lo).append(x + (_isdir, _c))
            _fmt = lambda x: '%s\\%s:%s (%s, %d Б%s)' % (
                x[0], x[1], x[2], 'на теці' if x[6] else 'на файлі', x[3],
                ('; вміст: %s, «%s»' % (x[7].get('kind_label'), str(x[7].get('preview') or '')[:80])) if x[7] else '')
            if _hi:
                add('high', 'Приховування в потоках NTFS', 'T1564.004',
                    'Дані сховано в альтернативному потоці NTFS (ADS)',
                    'Знайдено %d нестандартн(их) потік(ів) ADS, яких не створює ні Windows, ні звичайні програми: %s. '
                    'Потік не видно в Провіднику й у dir без /r; так ховають конфіг, ключ або код завантажувача. '
                    '%s' % (
                        len(_hi), '; '.join(_fmt(x) for x in _hi[:4]),
                        ('Вміст збережено збирачем (файли ads/*.bin в архіві), SHA256 і адреси з нього — серед IOC.'
                         if any(x[7].get('kind') not in (None, 'not_saved') for x in _hi) else
                         'Вміст потоку в CSV KAPE не потрапляє: на живій машині його читає cmd-команда %s '
                         '(збирач з v4.10 зберігає вміст сам).' % ('more < "C:%s\\%s:%s"' % (_hi[0][0], _hi[0][1], _hi[0][2])))),
                    len(_hi), [_fmt(x) for x in _hi[:6]],
                    events=[{'ts': x[4], 'label': 'створено теку/файл з потоком %s:%s' % (x[1], x[2]), 'source': '$MFT',
                             'artifact': '%s\\%s:%s' % (x[0], x[1], x[2]), 'file': x[5]} for x in _hi[:6] if x[4]],
                    iocs=[{'type': 'path', 'value': 'C:%s\\%s:%s' % (x[0], x[1], x[2]), 'role': 'прихований потік NTFS',
                           'source': '$MFT', 'file': x[5]} for x in _hi[:6]]
                         + [{'type': 'sha256', 'value': x[7]['sha256'], 'role': 'вміст прихованого потоку',
                             'source': 'ads_streams.csv', 'file': 'ads_streams.csv'} for x in _hi[:6] if x[7].get('sha256')]
                         + [{'type': 'url', 'value': u, 'role': 'адреса у прихованому потоці',
                             'source': 'ads_streams.csv', 'file': 'ads_streams.csv'} for x in _hi[:6] for u in (x[7].get('urls') or [])[:3]])
            _lum = [x for x in _lo if x[2].lower() == 'lum']
            if _lum:
                add('low', 'Небажане ПЗ', 'T1090',
                    'Проксі-SDK Luminati/BrightData: ПК міг продавати свій інтернет-канал',
                    'Маркер сесії SDK Bright Data (колишній Luminati) у %s. Такий SDK вбудовують у безкоштовні програми; '
                    'через ПК проходить чужий трафік, і в журналах провайдера він виглядає як дії власника ПК.' % (
                        '; '.join('%s\\%s' % (x[0], x[1]) for x in _lum[:3])),
                    len(_lum), ['%s\\%s:%s' % (x[0], x[1], x[2]) for x in _lum[:4]])
    except Exception as _e:
        _log.error('[threat] ads-hidden-data failed: %s' % _e)

    return findings


def verdict_line(findings):
    """One-line verdict from the findings (for the report header)."""
    if not findings:
        return 'Явних ознак відомих атак не виявлено (детермінований шар). Потрібен ручний розбір.'
    rw = next((f for f in findings if f['category'] == 'Ransomware' and f['severity'] == 'critical'), None)
    if rw:
        m = re.search(r'сімейство (\S+?)[);, ]', rw['detail'] + ' ')
        fam = m.group(1) if m else None
        nfiles = ''
        m2 = re.search(r'на (\d+) файл', rw['detail'])
        if m2:
            nfiles = ' (зашифровано ~%s файлів)' % m2.group(1)
        return ('RANSOMWARE — сімейство %s%s' % (fam, nfiles)) if fam and fam != 'unknown' \
            else 'RANSOMWARE (невідоме сімейство)%s' % nfiles
    cats = []
    for f in findings:
        if f['severity'] in ('critical', 'high') and f['category'] not in cats:
            cats.append(f['category'])
    if cats:
        return 'Виявлено ознаки: ' + ', '.join(cats[:5]) + '.'
    # piracy without anyone else on the machine: say so, instead of a calm line that hides
    # the one thing the owner needs to hear (case_56: KMSAuto + Coinminer, no intrusion)
    _pua = next((f for f in findings if f['category'] == 'Самозаподіяне (піратське ПЗ)'), None)
    if _pua:
        return ('Ознак стороннього втручання не виявлено: самозараження піратським ПЗ (активатори/кряки, '
                '%d детекцій) — потрібне очищення, не розслідування атаки.' % int(_pua.get('count') or 0))
    # CALM_SECTION_APPLIED: only medium/low findings -> do NOT scream 'threat'
    return ('Критичних/високих загроз не виявлено. %d пункт(ів) для ручної перевірки — '
            'типово звичайна системна активність (служби/задачі/логони/PowerShell), '
            'сама по собі НЕ підтверджена атака.' % len(findings))


def render_threat_section(findings):
    """Markdown section that LEADS the DFIR report with concrete, grounded detections."""
    if not findings:
        return ''
    se = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '⚪'}
    _has_hi = any(f['severity'] in ('critical', 'high') for f in findings)
    if _has_hi:
        _hdr = '## 🎯 АВТОМАТИЧНІ ДЕТЕКЦІЇ ЗАГРОЗ'
        _sub = '*Прямі SQL-сигнатури по логах (без ШІ) — кожен пункт має кількість і приклади.*'
    else:
        _hdr = '## 🔍 ПУНКТИ ДЛЯ РУЧНОЇ ПЕРЕВІРКИ (високих/критичних загроз НЕ виявлено)'
        _sub = '*Це НЕ підтверджені загрози, а звичайна системна активність, яку варто перевірити вручну. Наявність цих пунктів сама по собі не означає атаку.*'
    out = [_hdr, _sub, '',
           '> **ВЕРДИКТ:** ' + verdict_line(findings), '']
    for f in findings:
        out.append('%s **[%s]** %s' % (se.get(f['severity'], '•'), f['severity'].upper(), f['title']))
        out.append('   - %s _(MITRE %s · %s)_' % (f['detail'], f['mitre'], f['category']))
        if f['samples']:
            out.append('   - приклади: ' + '; '.join(str(s)[:80] for s in f['samples'][:4]))
    return '\n'.join(out)


# 02.10.2026: one report delivery called the detector 17 times (10 for this case, 7 for linked
# cases in the actor portrait) - 19 of 23 minutes. Findings depend only on the ingested data and
# case_iocs, so they are cached by that fingerprint; the TTL is a backstop for anything else.
import copy as _copy
import time
import os as _os
import threading as _threading

_DT_CACHE = {}
_DT_LOCKS = {}
_DT_GUARD = _threading.Lock()
_DT_TTL = float(_os.getenv('DFIR_THREAT_CACHE_TTL', '1800') or 1800)
_DT_DISK_TTL = float(_os.getenv('DFIR_THREAT_DISK_TTL', '604800') or 604800)
_DT_DISK_DIR = _os.getenv('DFIR_THREAT_CACHE_DIR', '/data/state/threat_cache')
import os
import pickle as _pickle
import hashlib as _hashlib
try:
    # a detector change must invalidate the disk copies: key them by this file's own content
    _DT_CODE_SIG = _hashlib.sha1(open(__file__, 'rb').read()).hexdigest()[:12]
except Exception:
    _DT_CODE_SIG = 'unknown'


def _dt_disk_path(case_key):
    if not _DT_DISK_DIR:
        return None
    return os.path.join(_DT_DISK_DIR, re.sub(r'[^\w.-]', '_', str(case_key)) + '.pkl')


def _dt_fingerprint(case_key, conn):
    cur = conn.cursor()
    cur.execute("""SELECT (SELECT count(*) || '/' || coalesce(max(finished_at)::text, '') || '/' ||
                                  coalesce(max(started_at)::text, '') || '/' ||
                                  coalesce(string_agg(DISTINCT status, ','), '')
                           FROM ingest_jobs WHERE case_key=%s),
                          (SELECT count(*) || '/' || coalesce(max(created_at)::text, '')
                           FROM case_iocs WHERE case_key=%s)""", (case_key, case_key))
    return tuple(cur.fetchone() or ())


def detect_threats(case_key, conn, fresh=False):
    """Cached wrapper over _detect_threats_raw (same result, same signature)."""
    if fresh or _DT_TTL <= 0:
        return _detect_threats_raw(case_key, conn)
    try:
        fp = _dt_fingerprint(case_key, conn)
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        _log.warning('[threat_cache] fingerprint failed for %s: %s' % (case_key, e))
        return _detect_threats_raw(case_key, conn)
    with _DT_GUARD:
        lock = _DT_LOCKS.setdefault(case_key, _threading.Lock())
    # one computation per case at a time; parallel callers wait and reuse it
    with lock:
        hit = _DT_CACHE.get(case_key)
        if hit and hit[0] == fp and (time.time() - hit[1]) < _DT_TTL:
            return _copy.deepcopy(hit[2])
        # the disk copy survives a server restart; same fingerprint, longer life (data, not time, decides)
        _dp = _dt_disk_path(case_key)
        try:
            if _dp and os.path.isfile(_dp) and time.time() - os.path.getmtime(_dp) < _DT_DISK_TTL:
                with open(_dp, 'rb') as _fh:
                    _d = _pickle.load(_fh)
                if _d.get('fp') == fp and _d.get('code') == _DT_CODE_SIG:
                    _DT_CACHE[case_key] = (fp, time.time(), _copy.deepcopy(_d['res']))
                    return _d['res']
        except Exception as _de:
            _log.debug('[threat_cache] disk read %s: %s' % (case_key, _de))
        res = _detect_threats_raw(case_key, conn)
        _DT_CACHE[case_key] = (fp, time.time(), _copy.deepcopy(res))
        try:
            if _dp:
                os.makedirs(os.path.dirname(_dp), exist_ok=True)
                _tmp = _dp + '.tmp%d' % os.getpid()
                with open(_tmp, 'wb') as _fh:
                    _pickle.dump({'fp': fp, 'code': _DT_CODE_SIG, 'res': res}, _fh)
                os.replace(_tmp, _dp)
        except Exception as _de:
            _log.debug('[threat_cache] disk write %s: %s' % (case_key, _de))
        return res
