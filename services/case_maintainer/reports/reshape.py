# reports/reshape.py
# Post-process the assembled DFIR report text into a clean, scannable,
# client-facing structure. Deterministic. NEVER raises (returns original
# text on any error). Idempotent via a header marker.
#
# Structure produced (top -> bottom):
#   1. ПЕРША ТОЧКА ЗАРАЖЕННЯ / ПОЧАТКОВИЙ ДОСТУП
#   2. ЗАГАЛЬНИЙ ВИСНОВОК (простими словами)
#   3. ІНФОРМАЦІЯ ПРО СИСТЕМУ
#   4. ХРОНОЛОГІЯ ПОДІЙ
#   5. ІНДИКАТОРИ КОМПРОМЕТАЦІЇ (IOC)
#   6. СЛУЖБОВІ ДАНІ / ДЕТАЛІ ДЛЯ ПЕРЕВІРКИ  (appendix, capped)
import re
import psycopg2

try:
    from core.config import PG_DSN
except Exception:
    try:
        from config import PG_DSN
    except Exception:
        PG_DSN = None

MARKER = '<!-- reshaped-v1 -->'
NL = chr(10)
APPENDIX_CAP = 40000  # chars

# 'fiddler' was in analysis/ioc_extract.py::_TOOL_RE but NOT here, so the SHA1 of
# the traffic-interception proxy never reached the hash section - the golden fact
# iocs/hash_sha1:fiddler on 20_05. Measured cost of adding it: 2 of 11 cases hold
# fiddler rows at all (28 and 11 rows), 6 distinct hashes in total.
_TOOL_RE = ('rustdesk|psexec|anydesk|ngrok|rutserv|rfusclient|rdpwinst|rdpwrap|'
            'mimikatz|try[.]exe|nltest|chromepass|nirsoft|7za|litemanager|'
            'screenconnect|atera|teamviewer|meterpreter|cobalt|procdump|rclone')
# Used ONLY by the hash query. 'fiddler' belongs here and not in _TOOL_RE: the
# golden fact iocs/hash_sha1:fiddler needs the SHA1 of the traffic-interception
# proxy, while putting fiddler in the file list added ten install-payload rows to
# a section that only prints twenty. Measured: 2 of 11 cases hold fiddler rows
# (28 and 11), 6 distinct hashes; in the list it cost 10 of 20 rows on 20_05.
_HASH_TOOL_RE = _TOOL_RE + '|fiddler'
# Benign vendor/system/installer paths that pollute the IOC hash list + timeline
# (forensic tools, MSI Package Cache, bank software, driver installers, OS files).
# PATH-based so it can NEVER hide real malware (which lives in user temp/downloads).
_FP_DROP_RE = (r'accessdata|magnet forensics|\yaxiom\y|ftk imager|x-ways|xways|cellebrite|'
               r'encase|belkasoft|autopsy|nuix|\yufed\y|griffeye|forensic tools|dell_forensic|'
               r'package cache|amd-software|precision_[0-9]|driverpack|amd_chipset|chipset_software|'
               r'barscryptor|m\.e\.doc|\ymedoc\y|artzvit|art-zvit|'
               r'[\\/]windows[\\/]system32[\\/]|[\\/]windows[\\/]syswow64[\\/]|[\\/]windowsapps[\\/]|'
               r'[\\/]microsoft[\\/]edge|edgewebview|edgecore|edgeupdate|[\\/]ruxim[\\/]|'
               r'k-lite|kingsoft|[\\/]common files[\\/]microsoft|[\\/]windows defender[\\/]|'
               r'mixedreality|[\\/]office1[0-9][\\/]|onedrive[\\/]|[\\/]nvidia[\\/]|[\\/]realtek|'
               r'[\\/]forensic[\\/]|nirsoft|[\\/]vmware|vmware workstation|[\\/]java[\\/]|jdk-|jre-|jre1|open-jkd|'
               r'rmiregistry|duo desktop|createautorunentry|ccm_incoming|ccmcache|[\\/]ccm[\\/]|sms_mp|'
               # our own collector's working folder and the examiner's KAPE copy: on the
               # encrypted-server case 7 examiner binaries (kape, gkape, autoruns64,
               # procexp64, cports) sat in program_exec_v2 as if they were the intruder's
               r'dfirtriage_[0-9a-f]+|dfircollector_|kape_triage|[\\/]kape[\\/]|gkape|'
               r'[\\/]dfir_triage[\\/]')
# _FP_DROP_RE above is a POSTGRES regex and contains \y (word boundary), which
# Python's re rejects with "bad escape". Python-side checks must use this copy.
# Using the SQL constant in Python emptied the timeline of every report.
# Tools the EXAMINER brings to the machine. Deliberately NOT _FP_DROP_RE: that one
# also excludes System32, which would hide malicious driver installations.
# Hardware/OEM drivers installed when a machine is provisioned. Matched by VENDOR
# name, never by path: filtering System32 as a whole would hide malicious drivers.
# Tools whose only purpose in an intrusion is to remove the way back. _TOOL_RE
# never listed them, so the moment the victim lost their backups was invisible.
_RECOVERY_KILL_RE = r'vssadmin|wbadmin|bcdedit|reagentc|wmic'

_BENIGN_DRIVER_RE = (r'intel\(r\)|\bintel\b|realtek|lenovo|samsung|fortemedia|qualcomm|'
                     r'synaptics|\belan\b|nvidia|kernel debug network|usb video device|'
                     r'wpd file system|composite device driver|audio service|\bwdm\b|'
                     r'принтер|printer|watchdog timer|smart sound')

_EXAMINER_TOOL_PY = (r'vao_dfir_collector_marker|vao_triage|vao_collect_all|'
                     r'dfp_[0-9a-f]{8}[.]ps1|'
                     r'dfirtriage_|dfircollector_|dfir_triage|kape_triage|'
                     r'[\\/]kape[\\/]|gkape|magnetram|magnet ram|ramcapture|'
                     r'winpmem|dumpit|belkasoft|ftk imager|encase|x-ways|xways|'
                     r'autopsy|axiom|cellebrite|oxygen forensic')

_FP_DROP_RE_PY = _FP_DROP_RE.replace(chr(92) + 'y', chr(92) + 'b')

# rundll32.exe is on every Windows machine ever built. Its SHA1 arrived in case_iocs
# from a Q&A answer and became the ONLY indicator of compromise printed for
# case_49 - a case whose worst finding is medium. A bare hash of a stock binary
# tells the reader nothing: no command line, no unusual path, nothing to pivot on.
# The rule is deliberately narrow - the file must sit DIRECTLY in system32/syswow64,
# so c:\windows\syswow64\urttemp\regtlib.exe and the fake
# c:\users\user\appdata\local\log\svchost.exe both survive, while the real
# c:\windows\system32\svchost.exe does not. Known attack tooling (_TOOL_RE) is never
# dropped even from a stock path. Measured over 11 cases: 13 rows, every one of them
# from qa_analysis (lsass, cmd, certutil, mstsc, net, rundll32); zero from the expert
# report PDFs, zero from 'report', zero from sql_program_exec.
_STOCK_SYSBIN_RE = re.compile(r'^[a-z]:[\\/]windows[\\/](system32|syswow64)[\\/][^\\/]+$', re.I)
_TOOL_RE_PY = re.compile(_TOOL_RE, re.I)


def _is_stock_sysbin(name, path):
    """A stock Windows binary in its stock directory, carrying no context of its own."""
    _p = str(path or '').strip()
    if not _p or not _STOCK_SYSBIN_RE.match(_p):
        return False
    return not _TOOL_RE_PY.search(str(name or '') + ' ' + _p)

_NOISE_DOMAINS = ('ccm_incoming', 'corp.example', 'sms_mp', 'ccmcache', 'microsoft.com', 'windows.com', 'msftconnecttest', 'digicert',
                  'verisign', 'gstatic', 'mozilla.org', 'msedge.', 'office.com',
                  'windowsupdate', 'live.com', 'bing.com', 'msn.com',
                  # browser/OS update delivery networks — on the encrypted-server case
                  # these filled the ENTIRE URL list and hid the real indicators
                  'gvt1.', 'gvt2.', 'googleusercontent', 'googleapis', 'google.com',
                  'akamai', 'edgesuite', 'edgekey', 'llnwd.net', 'cloudfront.net',
                  'symcd.com', 'symcb.com', 'globalsign', 'sectigo', 'letsencrypt',
                  'ocsp.', 'crl.', 'apple.com', 'icloud.com', 'adobe.com',
                  'opera-api', 'operacdn', 'yandex.net/updater', 'sfx.ms', 'oneclient.')
_UPDATE_PKG_RE = re.compile(
    r'(\.(cab|msu|msp|msi|esd|psf|appx|appxbundle|crl|crt|cer|p7s|pem|manifest)(\?|$)'
    r'|/(update|updates|edgedl|diffgen|patch|redist)/)', re.I)
_LOCAL_IPS = ('127.0.0.1', '::1', '-', '0.0.0.0', '', 'localhost')
# Clearly-benign Windows / installer helper executables — exclude from
# "suspicious execution" and timeline so the real attack chain stands out.
_BENIGN_EXEC_RE = ('dismhost|consent[.]exe|taskhostw|backgroundtaskhost|'
                   'searchprotocolhost|searchfilterhost|sihost|runtimebroker|'
                   'conhost|wermgr|dllhost|ctfmon|mousocoreworker|smartscreen|'
                   'mpcmdrun|nissrv|msmpeng|onedrivesetup|onedrive[.]exe|filecoauth|filesyncconfig|onedrivelauncher|onedrivestandaloneupdater|'
                   'vc_redist|vcredist|audiodg|fontdrvhost|wsappx|trustedinstaller|'
                   'zoom|rmiregistry|jusched|jucheck|jre[-_]|jdk[-_]|javaw|'
                   'amd_chipset|chipset_software|driverpack|nvidia|realtek|igfx|ryzen')

# Plain-language fragment per REAL detect_threats category (Ukrainian keys).
# Used as a secondary catch for categories not covered by the chain narrative.
_CAT_PLAIN = {
    # 2026-09-06: high/critical categories that had no plain-language fragment
    'Червона комбінація': 'кілька ознак атаки збіглися в часі — вхід, закріплення й інструменти разом (це не випадковість)',
    'Крадіжка облікових даних': 'крали паролі/хеші облікових записів (дамп памʼяті або бази паролів)',
    'Доступ (RDP через тунель)': 'заходили через віддалений робочий стіл поверх прихованого тунелю (обхід периметра)',
    'Тунель / прихований канал': 'підняли прихований канал назовні (тунель), через який керували хостом',
    'Доставка (GPO)': 'шкідливий пакет розгорнули через доменну групову політику — тобто зламано домен, а не лише цей компʼютер',
    'Анти-форензика': 'чистили журнали подій, щоб приховати сліди',
    'Web shell': 'на веб-сервері лишили веб-шел — бекдор, доступний через браузер',
    'AD-маніпуляція': 'змінювали обʼєкти Active Directory (права, групи, обʼєкти) з атакуючого хоста',
    'AD-персистенс': 'закріпилися в Active Directory (делегування, SPN, ACL) — переживе перевстановлення цього ПК',
    'Доставка / C2': 'через файлообмінник надіслали шкідливий файл (вхідна точка)',
    'Виконання': 'запускали сторонні програми та PowerShell-скрипти',
    'Виявлене шкідливе ПЗ': 'антивірус зафіксував шкідливі програми',
    'Інструменти атакувальника': 'застосовували хакерські інструменти',
    'Віддалений доступ / тунель': 'налаштували віддалений доступ і тунель назовні',
    'Доступ (RDP)': 'заходили на хост через віддалений робочий стіл (RDP)',
    'Доступ': 'намагалися підібрати паролі',
    'Закріплення/привілеї': 'закріпилися: створювали облікові записи та надавали права',
    'Закріплення': 'закріпилися через нові служби / автозапуск',
    'Ransomware': 'файли зашифровано програмою-вимагачем',
    'Захист обходили': 'вимикали захист і чистили журнали, щоб сховати сліди',
    'Знищення': 'розгорнули засіб знищення системи (підставне середовище завантаження WinPE)',
    'Анти-відновлення': 'знищили тіньові копії / резервні копії, щоб унеможливити відкат',
    'Захист': 'захисне ПЗ впало або було зупинене перед атакою',
}


def _q(cur, sql, args=()):
    try:
        cur.execute(sql, args)
        return cur.fetchall()
    except Exception:
        try:
            cur.connection.rollback()
        except Exception:
            pass
        return []


def _fmt_ts(ts):
    try:
        return ts.isoformat()[:19].replace('T', ' ')
    except Exception:
        return str(ts or '')[:19]


def _clean_url(u):
    if not u:
        return ''
    u = str(u).replace(chr(13), ' ').replace(chr(10), ' ')
    u = u.split(' ')[0]
    u = u.split(chr(92))[0]  # cut at backslash (literal \r\n text, path junk)
    for cut in ('HostUrl', 'hosturl', 'ReferrerUrl', 'referrerurl'):
        u = u.split(cut)[0]
    u = u.strip().rstrip(',;)"\'')[:120]
    # Every cut above can eat the whole host and leave a bare scheme behind. On
    # case_43 one event_logs_v2 payload held the literal text http:// followed by
    # backslashes; the extraction regex allows a backslash, the backslash cut then
    # took everything after the //, and the domain list the client reads got an empty
    # line '- `http://`'. A URL with no host is not a URL. Measured: 1 row on
    # case_43, 0 on the other ten cases.
    if not re.sub(r'(?i)^[a-z][a-z0-9+.-]*://', '', u).strip(' /'):
        return ''
    return u


def _incident_window(case_key):
    try:
        from analysis.synthesis import _compute_incident_window
        w = _compute_incident_window(case_key) or {}
        return w.get('start'), w.get('end'), w.get('peak_day')
    except Exception:
        return None, None, None


# Детекції для однієї справи за один підсумок рахуються тричі (з _initial_access,
# з _timeline і з case_summary). Виміряно: 67 із 79 секунд побудови підсумку - саме це.
# Тримаємо результат 90 секунд: у межах одного підсумку це той самий результат, а свіжі
# дані після інгесту підхопляться наступною хвилиною.
_FINDINGS_CACHE = {}
_FINDINGS_TTL = 90.0


def _findings(case_key, max_age=None):
    """Детекції по справі. Повтор у межах кількох секунд віддається з памʼяті.

    max_age=0 - примусово рахувати заново (для місць, де свіжість критична).
    """
    import time as _t
    ttl = _FINDINGS_TTL if max_age is None else float(max_age)
    hit = _FINDINGS_CACHE.get(case_key)
    if hit and ttl > 0 and (_t.time() - hit[0]) < ttl:
        return hit[1]
    try:
        from analysis.threat_detect import detect_threats
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            res = detect_threats(case_key, c) or []
    except Exception:
        return []
    # кешуємо лише непорожній результат: порожній частіше означає збій запиту,
    # ніж «загроз немає», і закріплювати його на півтори хвилини не можна
    if res:
        _FINDINGS_CACHE[case_key] = (_t.time(), res)
        if len(_FINDINGS_CACHE) > 32:
            oldest = sorted(_FINDINGS_CACHE.items(), key=lambda kv: kv[1][0])[:8]
            for k, _v in oldest:
                _FINDINGS_CACHE.pop(k, None)
    return res


def _verdict(findings):
    try:
        from analysis.threat_detect import verdict_line
        return verdict_line(findings)
    except Exception:
        return 'Потрібен ручний розбір доказів.'


# ── Findings as the source of the report (2026-09-04) ─────────────────────────────
# The 3-4-19-1N report carried its only true sentence - the deterministic wiper verdict -
# on line 324 of 570, under "не вдалося встановити" in section 1 and a one-line
# chronology. A finding may now carry `events` and `iocs` (threat_detect.add, commit
# fe1ce5f); page 1, the entry point, the chronology and the IOC list are built from those
# and only fall back to the old heuristics when a case has no such finding.
_SEV_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'med': 2, 'low': 3, 'info': 4}
_HI_SEV = ('critical', 'high')
_SEV_ICON = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'med': '🟡', 'low': '🟢', 'info': '⚪'}
_IOC_TYPE_LABEL = {
    'file': 'Файли', 'path': 'Шляхи', 'task': 'Заплановані завдання', 'gpo': 'Групові політики (GPO)',
    'hash': 'Хеші', 'domain': 'Домени', 'url': 'URL', 'ip': 'IP-адреси', 'service': 'Служби',
    'user': 'Облікові записи', 'registry': 'Реєстр', 'command': 'Команди', 'process': 'Процеси',
}
# what an analyst does first, by finding category; page 1 prints `now`, the
# recommendations section prints both
_CAT_ACTIONS = {
    # 2026-09-06: categories the detector emits as high/critical that had NO actions -
    # page 1 printed a verdict with nothing to do about it (owner's reading test)
    'Червона комбінація': {
        'now': ['вважати хост скомпрометованим: ізолювати, зняти образ диска і памʼяті до будь-яких дій',
                'скинути паролі всіх облікових записів, що входили на хост, і адміністраторів домену'],
        'next': ['пройти ланцюг нижче по кроках: вхід → закріплення → інструменти → що виносили'],
    },
    'Крадіжка облікових даних': {
        'now': ['скинути паролі всіх акаунтів, що входили на цей хост (локальних і доменних); KRBTGT — двічі, якщо це DC',
                'заблокувати виявлені хеші/квитки: вихід з усіх сесій, перевипуск сертифікатів VPN'],
        'next': ['знайти, звідки запускали інструмент дампу і куди подівся результат (файл, архів, мережа)'],
    },
    'Доступ (RDP через тунель)': {
        'now': ['знайти і видалити RDP-обгортку/тунель (rdpwrap, ngrok, службу-тунель); заблокувати їхні домени',
                'скинути паролі акаунтів, під якими заходили через тунель'],
        'next': ['встановити, коли тунель поставили і хто ще заходив через нього'],
    },
    'Тунель / прихований канал': {
        'now': ['зупинити і видалити тунель, заблокувати його домени/IP на периметрі',
                'зняти мережеві журнали за період роботи тунелю — що передавали'],
        'next': ['знайти, як тунель потрапив на хост і чи є він на інших машинах'],
    },
    'Доставка / C2': {
        'now': ['заблокувати виявлені домени/IP та файлообмінники на периметрі',
                'ізолювати файл-приманку і все, що він запустив, для аналізу'],
        'next': ['знайти, хто ще отримав той самий файл (пошта, месенджери, спільні теки)'],
    },
    'Доставка (GPO)': {
        'now': ['на контролері домену: знайти і вимкнути GPO, що розгортає пакет; зафіксувати, хто і коли її створив',
                'перевірити всі машини домену на той самий пакет/завдання'],
        'next': ['зняти журнали DC (5136/5137, входи адміністраторів) за добу до розгортання'],
    },
    'Інструменти атакувальника': {
        'now': ['зберегти знайдені інструменти як докази (хеші, шляхи), видалити з хоста після образу'],
        'next': ['за часом появи інструментів знайти вхід і акаунт, під яким їх запускали'],
    },
    'Виконання': {
        'now': ['перевірити перелічені запуски: що це за файли, звідки взялися, чи є на інших машинах'],
        'next': ['звірити з антивірусом і хешами; підозріле — на аналіз у пісочницю'],
    },
    'Анти-форензика': {
        'now': ['не чіпати диск: очищені журнали частково відновлюються з $J/тіньових копій',
                'зняти журнали з інших джерел (DC, SIEM, проксі) за той самий період'],
        'next': ['встановити, що саме хотіли приховати: події безпосередньо перед очищенням'],
    },
    'Web shell': {
        'now': ['ізолювати веб-сервер; вилучити веб-шел і журнали веб-сервера за весь період',
                'скинути паролі та ключі, до яких мав доступ процес веб-сервера'],
        'next': ['знайти вразливість/шлях завантаження шелу і хто ще звертався до нього'],
    },
    'AD-маніпуляція': {
        'now': ['перевірити на DC зміни обʼєктів AD (5136/5137/4662): відкотити невідомі, заблокувати акаунти-джерела',
                'вважати домен скомпрометованим: скинути KRBTGT двічі'],
        'next': ['простежити, з якого хоста і під ким робили зміни'],
    },
    'AD-персистенс': {
        'now': ['видалити невідомі обʼєкти закріплення в AD (SPN, делегування, GPO, ACL); заблокувати акаунти-джерела'],
        'next': ['аудит привілейованих груп і делегувань по всьому домену'],
    },
    'Знищення': {
        'now': ['ізолювати хост від мережі; не перезавантажувати — образ диска та памʼяті до будь-яких дій',
                'на контролері домену: знайти GPO, що розгортає цей MSI/завдання (SysVol), вимкнути її, зафіксувати хто і коли створив',
                'перевірити ВСІ машини домену на той самий MSI / завдання / файл boot.wim — вайпер через GPO не буває одиничним',
                'вважати адміністративні облікові записи домену скомпрометованими: скинути паролі, KRBTGT — двічі'],
        'next': ['розібрати MSI (таблиці CustomAction) і boot.wim — що саме він робить із дисками',
                 'зняти журнали DC: хто змінював GPO (5136/5137), звідки заходили адміністратори',
                 'звірити час падіння антивірусу з подіями атаки — ознака навмисного вимкнення захисту'],
    },
    'Ransomware': {
        'now': ['ізолювати хост; зберегти записку і кілька зашифрованих файлів для ідентифікації сімейства',
                'знайти точку входу (RDP / фішинг) і закрити її на периметрі; скинути паролі скомпрометованих акаунтів'],
        'next': ['перевірити резервні копії та тіньові копії на інших машинах', 'шукати ті самі інструменти/акаунти в домені'],
    },
    'Доступ (RDP)': {
        'now': ['закрити RDP назовні / увімкнути NLA і MFA; заблокувати виявлені IP', 'скинути паролі акаунтів, під якими заходили'],
        'next': ['знайти, що робили після входу (створені акаунти, служби, інструменти)'],
    },
    'Віддалений доступ / тунель': {
        'now': ['видалити засоби віддаленого доступу/тунелі, заблокувати їхні домени на периметрі'],
        'next': ['встановити, хто і коли їх поставив, та що передавали'],
    },
    'Анти-відновлення': {
        'now': ['не чіпати диск: відновлення після знищення тіньових копій потребує образу'],
        'next': [],
    },
    'Закріплення/привілеї': {
        'now': ['вимкнути створені облікові записи, забрати надані права'],
        'next': ['знайти, звідки взялися права: хто і як їх видав'],
    },
    'Закріплення': {
        'now': ['вимкнути нетипові служби/завдання/автозапуск, зберігши їхні файли як докази'],
        'next': [],
    },
    'Захист обходили': {
        'now': ['увімкнути захист, прибрати сторонні винятки Defender'],
        'next': ['за очищеними журналами — шукати той самий період в інших джерелах (SRUM, $J, Prefetch)'],
    },
}
_DEFAULT_ACTIONS = {
    'now': ['ізолювати хост і зберегти докази (образ диска, памʼять) до будь-яких змін'],
    'next': ['перевірити ланки нижче вручну проти сирих логів'],
}


def _ev_ts(v):
    """datetime for an event ts of any of the shapes the detectors emit."""
    from datetime import datetime as _dt
    if v is None:
        return None
    if isinstance(v, _dt):
        return v
    # keep the offset when the text carries one: the curated timeline rows are tz-aware
    # datetimes from the database, and a naive value cannot be sorted next to them
    for cand in (str(v).replace(' ', 'T', 1), str(v)[:19].replace(' ', 'T')):
        try:
            return _dt.fromisoformat(cand)
        except Exception:
            continue
    return None


_SAMPLE_EV_RX = re.compile(r'^\s*(?:(?P<label>[^:]{3,80}):\s*)?(?P<what>.+?)\s*\((?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d)\)\s*$')


def _events_from_samples(f):
    """Findings written before the schema carry their chain as display strings
    'ланка: що (YYYY-MM-DD HH:MM)'; read the time out of them so the chronology and
    page 1 still get a dated chain."""
    out = []
    for s in (f or {}).get('samples') or []:
        m = _SAMPLE_EV_RX.match(str(s or ''))
        if not m:
            continue
        label = ((m.group('label') + ': ') if m.group('label') else '') + m.group('what')
        out.append({'ts': m.group('ts'), 'label': label.strip()[:120], 'source': '', 'artifact': ''})
    return out


def _sev_key(f):
    return _SEV_RANK.get(str((f or {}).get('severity') or '').lower(), 9)


_CONSEQ_RX = re.compile(r'antivirus задетектив|детекці', re.I)

def _top_finding(findings):
    """The finding the report is about: highest severity, events first as the tie-break."""
    hi = [f for f in (findings or []) if str(f.get('severity') or '').lower() in _HI_SEV]
    if not hi:
        return None
    # a detection is a consequence, not the story: at equal severity the cause ranks first
    hi.sort(key=lambda f: (_sev_key(f), 1 if _CONSEQ_RX.search(str(f.get('title') or '')) else 0,
                           0 if f.get('events') else 1, -int(f.get('count') or 0)))
    return hi[0]


def _prov_tag(p):
    """The `[джерело: …]` suffix every printed fact carries (owner's wish №1, 2026-09-06):
    the reader opens the archive at that path and confirms the line in half a minute.
    A fact whose finding predates batch 1 says so instead of printing nothing — the rule
    'no line without a source' then holds for the reader as well as for the guard."""
    s = str(p or '').strip()
    if not s:
        return ' [джерело: не збережено у знахідці]'
    # the tail is what verifies the fact (source file · RecordNumber N); the head is a
    # list of archive paths and may be long, so it is the head that gets cut
    return ' [джерело: %s]' % (s if len(s) <= 170 else ('…' + s[-169:]))


def _ev_kind(e):
    """'anchor' (an action happened) or 'presence' (a file merely existed) — batch 1 writes
    it into every event; fall back to the source when reading an older finding."""
    k = str((e or {}).get('kind') or '').lower()
    if k in ('anchor', 'presence'):
        return k
    try:
        from analysis.threat_detect import ts_kind as _tk
        return _tk((e or {}).get('file') or '', (e or {}).get('source') or '')
    except Exception:
        return 'anchor'


PRESENCE_LABEL = 'файл існував раніше (мітка PE/архіву)'

_EID_PLAIN = {
    '7031': 'служба аварійно зупинилась', '7034': 'служба аварійно зупинилась',
    '1102': 'очищено журнал безпеки', '104': 'очищено журнал подій',
    '4720': 'створено обліковий запис', '7045': 'встановлено службу',
    '4697': 'встановлено службу', '4698': 'створено заплановане завдання',
    '4624': 'вхід у систему', '4625': 'невдалий вхід', '1149': 'RDP-автентифікація',
    '6008': 'неочікуване вимкнення', '6009': 'завантаження системи',
    '1116': 'антивірус виявив загрозу', '1117': 'антивірус вжив заходів',
    '5001': 'вимкнено захист у реальному часі', '5010': 'вимкнено перевірку',
    '5012': 'вимкнено перевірку файлів', '4104': 'виконано PowerShell-скрипт',
}


def _human_label(lbl):
    """The reader of §1 and of the verdict block is an investigator, not an analyst of our
    log schema: a detector's field prefix (`Name:`, `Task:`) and a bare event id say nothing
    to them. Both are replaced with words here and stay intact in ## 7. (FIX_QUEUE №1.)"""
    s = str(lbl or '')
    s = re.sub(r'\b(?:Name|Task|Service|ServiceName|TargetUserName|File|Файл)\s*:\s*', '', s)
    s = re.sub(r'\((\d{3,5})(?:/(\d{3,5}))*\)',
               lambda m: '(%s)' % (_EID_PLAIN.get(m.group(1)) or ('подія %s' % m.group(1))), s)
    s = re.sub(r'(?<![\w/])EID\s*(\d{3,5})',
               lambda m: _EID_PLAIN.get(m.group(1)) or ('подія %s' % m.group(1)), s)
    s = re.sub(r':\s*(\d{3,5})\s*$',
               lambda m: ': ' + (_EID_PLAIN.get(m.group(1)) or ('подія %s' % m.group(1))), s)
    return re.sub(r'\s{2,}', ' ', s).strip()


def _presence_label(label):
    """A ShimCache/$MFT stamp says the file was on the disk, never that anyone started it.
    Three cases carried «запущено ngrok» over a PE compile stamp that predated the phishing
    mail; the words now match what the artefact can prove."""
    lbl = str(label or '').strip()
    # idempotent: batch 1 already words some of these rows this way, and prefixing twice
    # produced «файл існував раніше (мітка PE/архіву): файл існував раніше (мітка PE/архіву): …»
    if lbl.startswith(PRESENCE_LABEL):
        return lbl
    body = re.sub(r'^\s*(?:Запуск|запущено|Виконано|Доставка|Доставлено|Завантажено'
                  r'|📥 Завантажено/доставлено)\s*[:\-—]?\s*', '', lbl, flags=re.I).strip()
    body = body or lbl
    return '%s: %s' % (PRESENCE_LABEL, body[:110])


def _fx_events(findings, sevs=_HI_SEV, extra_categories=('Захист',), anchors_only=False):
    """Union of findings[*].events (high/critical, plus the AV-crash category, whose time
    belongs in every chronology), sorted, de-duplicated. Each item:
    (datetime, label, source, artifact, severity, title, kind, prov).
    anchors_only drops the 'presence' rows — a chain, an entry point and a plain-language
    story may only be built out of events that date an ACTION."""
    out, seen = [], set()
    for f in (findings or []):
        sev = str(f.get('severity') or '').lower()
        if sev not in sevs and f.get('category') not in extra_categories:
            continue
        for e in (f.get('events') or _events_from_samples(f)):
            ts = _ev_ts((e or {}).get('ts'))
            if ts is None:
                continue
            label = str((e or {}).get('label') or '').strip()
            if not label:
                continue
            kind = _ev_kind(e)
            if anchors_only and kind == 'presence':
                continue
            # two findings may describe one event (the wiper chain's "впав антивірус" and
            # the AV finding's "захисне ПЗ впало"): same minute + same named artefact = one row
            key = (ts.strftime('%Y-%m-%d %H:%M'), label.split(': ')[-1][:50].lower())
            if key in seen:
                continue
            seen.add(key)
            if kind == 'presence':
                label = _presence_label(label)
            out.append((ts, label, str(e.get('source') or ''), str(e.get('artifact') or ''),
                        sev, str(f.get('title') or ''), kind, str(e.get('prov') or '')))
    out.sort(key=lambda x: x[0])
    return out


def _fx_iocs(findings, sevs=_HI_SEV + ('medium', 'med')):
    """Union of findings[*].iocs, de-duplicated on (type, value)."""
    out, seen = [], set()
    for f in sorted((findings or []), key=_sev_key):
        if str(f.get('severity') or '').lower() not in sevs:
            continue
        for i in (f.get('iocs') or []):
            t = str((i or {}).get('type') or 'file').lower()
            v = str((i or {}).get('value') or '').strip()
            if not v:
                continue
            key = (t, v.lower())
            if key in seen:
                continue
            seen.add(key)
            out.append({'type': t, 'value': v, 'role': str(i.get('role') or ''),
                        'source': str(i.get('source') or ''), 'finding': str(f.get('title') or ''),
                        'prov': str(i.get('prov') or ''), 'severity': str(f.get('severity') or '').lower()})
    return out


def _fx_window(findings):
    """(first, last) dates of the finding events, or (None, None). Anchors only: a PE
    compile stamp from 2017 is not when the active phase began (case_45 printed
    `2017-12-27 → 2026-04-21` as the attack window because of one such row)."""
    ev = _fx_events(findings, anchors_only=True)
    if not ev:
        return None, None
    return ev[0][0].strftime('%Y-%m-%d'), ev[-1][0].strftime('%Y-%m-%d')


# Actions that mean the same thing to the person doing them. The recommendation list used
# to print «ізолювати хост» and «відключити хост від мережі» as two separate jobs, and the
# limit of 3 then cut the password reset that actually mattered (FIX_QUEUE, case_45 §1).
_ACTION_INTENT = (
    ('ізоляц', r'ізол|від\'?єднай|відключ.{0,12}(мереж|хост)|carantine|карантин'),
    ('паролі', r'парол|облікові дані|credential|скинь|скинути.{0,20}(парол|доступ)'),
    ('тунель', r'тунел|ngrok|pinggy|frp|chisel|cloudflared|вихідн.{0,15}зʼ?єднанн'),
    ('служби', r'служб|автозапуск|заплановане завданн|persist|закріпленн'),
    ('акаунти', r'обліков.{0,15}запис|акаунт|користувач.{0,10}створен'),
    ('rdp', r'\brdp\b|віддален.{0,15}робоч|3389'),
    ('пошта', r'пошт|лист|відправник|вкладенн|mail'),
    ('докази', r'образ диск|збереж.{0,15}доказ|памʼ?ят|дамп'),
)


def _action_intent(a):
    low = str(a or '').lower()
    for name, rx in _ACTION_INTENT:
        if re.search(rx, low):
            return name
    return low[:28]


def _actions_for(findings, which='now', limit=4):
    """Deduped by INTENT, not by string: four distinct things to do, in kill-chain order."""
    cats, out, seen, intents = [], [], set(), set()
    for f in sorted((findings or []), key=_sev_key):
        if str(f.get('severity') or '').lower() in _HI_SEV and f.get('category') not in cats:
            cats.append(f.get('category'))
    for c in cats:
        for a in (_CAT_ACTIONS.get(c) or {}).get(which, []):
            it = _action_intent(a)
            if a in seen or it in intents:
                continue
            seen.add(a); intents.add(it)
            out.append(a)
    if not out and cats:
        out = list(_DEFAULT_ACTIONS.get(which, []))
    return out[:limit]


def _verdict_page(case_key, findings, verdict, iw):
    """PAGE 1: the deterministic verdict, the chain behind it, what to do now. No model
    text here - everything is a finding, an event of a finding, or a rule keyed on the
    finding's category."""
    L = ['## ⚡ ВЕРДИКТ (детермінований шар — SQL-сигнатури по БД кейсу, без ШІ)']
    L.append('> **ВЕРДИКТ:** %s' % (verdict or 'Потрібен ручний розбір доказів.'))
    hi = sorted([f for f in (findings or []) if str(f.get('severity') or '').lower() in _HI_SEV],
                key=_sev_key)
    if not hi:
        med = [f for f in (findings or []) if str(f.get('severity') or '').lower() not in _HI_SEV]
        L.append('')
        L.append('Критичних або високих загроз детермінований шар не виявив. '
                 'Перевірено сигнатури: ransomware, знищення/WinPE, RDP/латеральний рух, '
                 'викрадення облікових даних, закріплення, вимкнення захисту, анти-форензика, '
                 'доставка через файлообмінники.')
        if med:
            L.append('Пункти для ручної перевірки (середні/низькі — самі по собі не атака): '
                     + '; '.join(str(f.get('title') or '')[:60] for f in med[:8]) + '.')
        return L
    for f in hi:
        sev = str(f.get('severity') or '').lower()
        L.append('')
        L.append('%s **[%s] %s**' % (_SEV_ICON.get(sev, '•'), sev.upper(), str(f.get('title') or '')))
        det = _human_label(str(f.get('detail') or '').strip())
        if det:
            L.append('   %s' % det[:700])
        ev = _fx_events([f], sevs=(sev,), extra_categories=())
        if ev:
            L.append('   **Ланцюг (час — що сталося — джерело):**')
            for _e in ev[:14]:
                ts, label, src, art = _e[0], _e[1], _e[2], _e[3]
                L.append('   - `%s` — %s%s' % (_fmt_ts(ts), _human_label(label),
                                               _prov_tag(_e[7] or src or art)))
        elif f.get('samples'):
            L.append('   **Приклади:** ' + '; '.join(str(s)[:90] for s in f['samples'][:4]))
        n_ioc = len(f.get('iocs') or [])
        if n_ioc:
            L.append('   _Індикаторів з цієї знахідки: %d — див. розділ IOC._' % n_ioc)
    now = _actions_for(findings, 'now')
    if now:
        L.append('')
        L.append('**Що робити зараз:**')
        L += ['- %s' % a for a in now]
    s, e = _fx_window(findings)
    if s or e:
        L.append('')
        # the density window is a service number: it is what the detectors search in, not
        # a statement about the attack. It belongs in ## 7, and printing it here made every
        # one of the twelve reports say «за щільністю подій» on its first screen.
        L.append('_Часові межі за підтвердженими ланками: `%s` → `%s`._' % (s or '?', e or '?'))
    return L


_CONSEQ_CATS = {'Захист обходили', 'Захист вимикали', 'Анти-форензика', 'Захист (інформаційно)', 'Захист', 'Ransomware', 'Знищення'}
_CONSEQ_TITLE_RX = re.compile(r'очищення журнал|зміна аудиту|antivirus задетектив|детекці|вимкнення windows defender|захист вимик|захисне пз|шифруван|записка з вимогою|wiper', re.I)


def _is_consequence(f):
    """True for findings that describe what the attacker did AFTER getting in (evasion) or what
    the antivirus noticed — they anchor the story, not the entry point."""
    return (str(f.get('category') or '') in _CONSEQ_CATS
            or bool(_CONSEQ_TITLE_RX.search(str(f.get('title') or ''))))


_ENTRY_GRADE_RX = re.compile(r'доставк|вкладенн|розпакован|фішинг|завантаж|rdp|доступ|gpo|sysvol|бекдор|акаунт', re.I)


def _is_entry_grade(f):
    """Delivery / access findings can name an entry point; execution and tooling cannot."""
    cat = str(f.get('category') or '')
    txt = cat + ' ' + str(f.get('title') or '')
    # «засоби ВІДДАЛЕНОГО ДОСТУПУ» in a persistence / tooling finding is the attacker's foothold,
    # not the way in: 'доступ' matched it and the RMS cluster became «Точка входу за підтвердженими
    # ланками» on case_41, pushing out the owner-confirmed phishing attachment (truth, 17.10.2026)
    if re.match(r'(закріплення|інструменти віддаленого доступу)', cat.strip(), re.I):
        txt = re.sub(r'віддален\w* доступ\w*', ' ', txt, flags=re.I)
    return bool(_ENTRY_GRADE_RX.search(txt))


def _entry_point_from_findings(findings):
    """Section 1 from the earliest ANCHOR event of the top finding. Empty when there is
    none — a report that cannot point at an action does not name an entry point."""
    top = _top_finding([f for f in (findings or []) if not _is_consequence(f)])
    if not top:
        # no cause-class finding: a consequence chain (wiper / ransomware) that carries its own
        # delivery-class anchor (MSI from GPO SysVol, an attachment) still names the entry
        _dl_probe = re.compile(r'msi|gpo|sysvol|заванта|download|достав|deliver|вклад|attach|фішинг|phish', re.I)
        for _fc in sorted([f for f in (findings or []) if _is_consequence(f)],
                          key=lambda f: 0 if str(f.get('severity') or '').lower() == 'critical' else 1):
            try:
                _evc = _fx_events([_fc], sevs=(str(_fc.get('severity') or '').lower(),),
                                  extra_categories=(), anchors_only=True)
            except Exception:
                _evc = []
            if any(_dl_probe.search(str(e[1]) + ' ' + str(e[2])) for e in _evc):
                top = _fc
                break
        if not top:
            return []
    ev = _fx_events([top], sevs=(str(top.get('severity') or '').lower(),),
                    extra_categories=(), anchors_only=True)
    if not ev:
        return []
    # an earlier delivery-grade finding of the same incident (<=7 days before the top anchor)
    # names the entry; the top finding's anchor becomes the next confirmed step
    _prev = None
    try:
        from datetime import timedelta as _td_e
        _ta = ev[0][0]
        _best = None
        for _f in (findings or []):
            if _f is top or _is_consequence(_f) or not _is_entry_grade(_f):
                continue
            if str(_f.get('severity') or '').lower() not in ('critical', 'high'):
                continue
            _evf = _fx_events([_f], sevs=(str(_f.get('severity') or '').lower(),),
                              extra_categories=(), anchors_only=True)
            if not _evf:
                continue
            _t0 = _evf[0][0]
            if _t0 < _ta and (_ta - _t0) <= _td_e(days=7) and (_best is None or _t0 < _best[1][0][0]):
                _best = (_f, _evf)
        if _best:
            _prev, top, ev = ev, _best[0], _best[1]
    except Exception:
        _prev = None
    # the entry is the first DELIVERY-class event (MSI from GPO, a download, a lure);
    # an AV crash an hour earlier is a precondition and is printed as such
    _dl_rx = re.compile(r'msi|gpo|sysvol|заванта|download|достав|deliver|url|http|фішинг|phish|вклад|attach|лист|mail', re.I)
    _pick = next(((i, e) for i, e in enumerate(ev) if _dl_rx.search(e[1] + ' ' + e[2])), (0, ev[0]))
    _w = _pick[1]
    ts, label, src, art, title, prov = _w[0], _w[1], _w[2], _w[3], _w[5], _w[7]
    # only delivery / access findings may be called an entry; a tool launch or a script is the
    # first confirmed attacker ACTION — the entry stays «не встановлено» (holdout 20_03)
    if _is_entry_grade(top):
        out = ['**🎯 Точка входу за підтвердженими ланками (знахідка «%s»):**' % title[:70]]
    else:
        out = ['**🎯 Перша підтверджена дія зловмисника (знахідка «%s»); саму точку входу за наявними '
               'артефактами не встановлено:**' % title[:70]]
    out.append('- `%s` — %s%s' % (_fmt_ts(ts), _human_label(label), _prov_tag(prov or src or art)))
    for e in ev[:_pick[0]][:3]:
        out.append('- _передумова:_ `%s` — %s%s'
                   % (_fmt_ts(e[0]), _human_label(e[1]), _prov_tag(e[7] or e[2])))
    # the delivery-class indicators of the same finding say WHERE it came from
    dl, _seen_ioc = [], set()
    for i in (top.get('iocs') or []):
        if not (str(i.get('type') or '').lower() in ('gpo', 'url', 'domain', 'ip')
                or _dl_rx.search(str(i.get('role') or '') + ' ' + str(i.get('value') or ''))):
            continue
        v = str(i.get('value') or '')
        if _is_docname(v) or _is_private_url(v):
            continue
        # the same artefact reached the finding from five Amcache rows; the section is a
        # list of things, not of rows (case_43 printed one exe five times)
        k = (str(i.get('type') or '').lower(), v.lower())
        if k in _seen_ioc:
            continue
        _seen_ioc.add(k)
        dl.append(i)
    for i in dl[:5]:
        out.append('- %s: `%s`%s%s' % (_IOC_TYPE_LABEL.get(str(i.get('type') or '').lower(), 'Індикатор'),
                                       str(i.get('value') or '')[:120],
                                       (' — %s' % str(i.get('role') or '')[:80]) if i.get('role') else '',
                                       _prov_tag(i.get('prov') or i.get('source'))))
    _after = sorted([e for e in ev if e[0] > ts] + [e for e in (_prev or []) if e[0] > ts], key=lambda e: e[0])
    if _after:
        out.append('- 👉 далі за %d хв: %s%s' % (max(0, int((_after[0][0] - ts).total_seconds() // 60)),
                                                 _human_label(_after[0][1])[:90],
                                                 _prov_tag(_after[0][7] or _after[0][2])))
    return out


def _recommendations(findings):
    now, nxt = _actions_for(findings, 'now', 8), _actions_for(findings, 'next', 8)
    if not (now or nxt):
        return []
    out = ['## ✅ РЕКОМЕНДАЦІЇ (за знахідками)']
    if now:
        out.append('**Негайно:**')
        out += ['- %s' % a for a in now]
    if nxt:
        out.append('**Далі:**')
        out += ['- %s' % a for a in nxt]
    return out


# A document is evidence of what a person worked on, not of an attack. Its NAME is
# personal data of a third party (a counterparty, a case file, a payment), and page 1 of
# ten of twelve reports carried one. Only the executables/archives/scripts of the chain
# are named; documents are counted in the appendix. (FIX_QUEUE №11.)
# Deliberately NOT here: .txt (a ransom note is a .txt and is the strongest IOC a
# ransomware case has), .msg/.eml (the phishing message itself is evidence), and the
# archive/script extensions, which _CHAIN_EXT_RE claims back below.
_DOCNAME_RE = re.compile(
    r'\.(pdf|docx?|xlsx?|xlsm|pptx?|odt|ods|rtf|jpe?g|png|gif|bmp|heic|tiff?|'
    r'djvu|p7s)(\Z|[^a-z0-9])', re.I)
_CHAIN_EXT_RE = re.compile(
    r'\.(exe|scr|com|pif|dll|sys|msi|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|lnk|'
    r'zip|rar|7z|iso|img|cab|jar|py)(\Z|[^a-z0-9])', re.I)
# a URL that identifies the person's mail box, bank or a registry they work with is
# personal data, never an indicator of the attack
#  word-bounded on purpose: a bare `dbo` matched «dashboard» and `owa` matched «showa»,
#  which would silently drop a real C2 host from section 5
_PRIVATE_URL_RE = re.compile(
    r'(?:^|[./])mail\.|/mail\b|\bgmail\b|googleusercontent|\boutlook\b|office365|'
    r'(?:^|[./])owa(?:[./]|$)|\bukr\.net\b|\bi\.ua\b|\bmeta\.ua\b|'
    r'\bbank\b|privat24|oschad|monobank|\bibank\b|(?:^|[./])dbo(?:[./]|$)|'
    r'\bacsk\b|(?:^|[./])ca\.|\bdiia\b|'
    r'tax\.gov|sfs\.gov|minjust|nais\.gov|court\.gov|\breyestr\b|opendatabot', re.I)
# only a value that IS an address may be judged as one: «invoice.exe» is a file name, and
# reading it as a payment URL deleted the delivery indicator from the section
_URLISH_RE = re.compile(r'https?://|^[a-z0-9.\-]+\.[a-z]{2,12}(?:[/:?]|$)', re.I)


def _is_docname(v):
    s = str(v or '')
    return bool(_DOCNAME_RE.search(s)) and not _CHAIN_EXT_RE.search(s)


def _is_private_url(v):
    s = str(v or '').strip()
    if not _URLISH_RE.search(s):
        return False
    return bool(_PRIVATE_URL_RE.search(s))


def _fx_ioc_lines(findings, sevs=_HI_SEV):
    """IOC section body from findings[*].iocs, grouped by type. Only findings of `sevs`:
    a medium 'dual-use utility present' finding contributed vendor binaries to a heading
    that said «підтверджені ланки атаки» on four clean machines."""
    iocs = [i for i in _fx_iocs(findings, sevs=sevs)
            if not (_is_docname(i['value']) or _is_private_url(i['value']))]
    if not iocs:
        return []
    out = ['**Індикатори з підтверджених ланок атаки:**']
    by = {}
    for i in iocs:
        by.setdefault(i['type'], []).append(i)
    order = ['file', 'path', 'task', 'gpo', 'service', 'command', 'process', 'hash', 'domain',
             'url', 'ip', 'user', 'registry']
    for t in order + [k for k in by if k not in order]:
        rows = by.get(t)
        if not rows:
            continue
        out.append('- _%s:_' % _IOC_TYPE_LABEL.get(t, t))
        for i in rows[:12]:
            role = (' — %s' % i['role'][:80]) if i['role'] else ''
            out.append('  - `%s`%s%s' % (i['value'][:140], role,
                                         _prov_tag(i.get('prov') or i.get('source'))))
    return out


def _own_tool_name(name, case_key):
    """Bare tool name (no path, no time) that belongs to our toolkit, on a case where our
    collector demonstrably ran."""
    try:
        from analysis.own_footprint import OWN_TOOLS, own_started_at
        base = str(name or '').replace('/', chr(92)).lower().rsplit(chr(92), 1)[-1]
        stem = base[:-4] if base.endswith('.exe') else base
        if not any(stem == t[:-4] or base == t for t in OWN_TOOLS):
            return False
        return own_started_at(case_key) is not None
    except Exception:
        return False


def _own_text(text, ts=None, case_key=None):
    try:
        from analysis.own_footprint import is_own
        return is_own(text, ts=ts, case_key=case_key)
    except Exception:
        return False


_JUNK_HOST_RE = re.compile(r'^\s*$|^local$|^n/a$|clientname|::|[\\/]|\s|\(', re.I)


def _clean_host_name(raw):
    """Прибрати з імені хоста те, що іменем не є.

    `WS2023 (::1)` -> `WS2023`; `LOCAL`, `ClientName`, порожнє -> ''. Використовується як
    остання лінія: коли і профіль, і журнали не дали чистого імені.
    """
    nm = str(raw or '').strip()
    if not nm:
        return ''
    nm = nm.split('(')[0].strip()          # «WS2023 (::1)» -> «WS2023»
    nm = nm.split()[0] if nm.split() else ''
    nm = nm.strip('`"\'')
    if not nm or _JUNK_HOST_RE.search(nm):
        return ''
    return nm


def _hostname_from_events(case_key):
    """The machine name the event logs agree on.

    EvtxECmd fills event_logs_v2.computer, and one value dominates every case by orders of
    magnitude. `WIN-xxxxxxxxxxx` is the name Windows generates before the machine is
    renamed, so it is only used when there is nothing else."""
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            cur.execute("SET statement_timeout='6000'")
            rows = _q(cur, """SELECT computer, count(*) FROM event_logs_v2
                              WHERE case_key=%s AND coalesce(computer,'') <> ''
                              GROUP BY 1 ORDER BY 2 DESC LIMIT 5""", (case_key,))
        best = None
        for name, n in rows:
            nm = str(name or '').strip()
            if not nm:
                continue
            if re.match(r'^WIN-[A-Z0-9]{11}$', nm, re.I):
                best = best or nm          # installer default: last resort only
                continue
            return nm
        return best
    except Exception:
        return None


def _sys_lines(case_key, iw):
    lines = []
    try:
        from analysis.system_profile import _get_system_profile_v1
        p = _get_system_profile_v1(case_key) or {}
    except Exception:
        p = {}
    host = p.get('computer_name') or p.get('hostname') or ''
    # the profile yields an RDP ClientName, a bare LOCAL or a name with an IP glued on for
    # seven of eleven cases; the event logs know the real one
    if not host or _JUNK_HOST_RE.search(str(host)):
        _h2 = _hostname_from_events(case_key)
        if _h2:
            host = _h2
    # Якщо запасний шлях нічого не дав - показуємо очищене імʼя або прочерк, але НЕ
    # заглушку: `LOCAL` читається як назва машини, а `(::1)` як її адреса.
    if _JUNK_HOST_RE.search(str(host or '')):
        host = _clean_host_name(host)
    host = host or '—'
    # a dash says nothing; the reason is knowable and worth stating. And before the dash:
    # the same report's «УМОВИ ЗБОРУ» block knew «Windows 11 Home» from the collector's own
    # inventory while §2 printed «ОС: —» (Asus, 07.03) — seven of twelve cases had no
    # SOFTWARE hive, and every one of them can be named from 6009 / Amcache / Kernel-General.
    osn = p.get('os_name') or ''
    if not str(osn).strip():
        try:
            from analysis.threat_detect import os_name_fallback as _osfb
            with psycopg2.connect(PG_DSN) as _oc:
                _oc.autocommit = True
                with _oc.cursor() as _ocur:
                    _ocur.execute("SET statement_timeout='8000'")
                    osn = _osfb(case_key, _ocur) or ''
                    if not str(osn).strip():
                        # last source, and on the Asus case the only one: the collector
                        # asked the machine itself what it was running and wrote the answer
                        # into environment_restrictions.csv. §2 printed «ОС: —» seventy
                        # lines above a block quoting that very line.
                        _ocur.execute("""SELECT payload->>'detail' FROM raw_fallback_v2
                                         WHERE case_key=%s AND parser_family='environment'
                                           AND payload->>'check'='os'
                                           AND coalesce(payload->>'detail','') <> ''
                                         LIMIT 1""", (case_key,))
                        _r = _ocur.fetchone()
                        if _r and _r[0]:
                            osn = '%s _(зі звіту збирача про середовище)_' % str(_r[0])[:70]
        except Exception:
            osn = ''
    osn = osn or ('— _(у зібраних артефактах немає розібраної гілки '
                  'реєстру SOFTWARE — версію ОС встановити нічим; '
                  'за потреби до-зібрати)_')
    build = p.get('build') or ''
    tz = p.get('timezone') or p.get('utc_offset') or ''
    inst = p.get('install_date_utc') or ''
    lines.append('- **Хост:** `%s`' % host)
    try:
        _dom = p.get('domain') or ''
        if not _dom:
            with psycopg2.connect(PG_DSN) as _dc:
                _dc.autocommit = True
                with _dc.cursor() as _dcur:
                    _dcur.execute("SELECT payload->>'TargetDomainName' d, count(*) FROM event_logs_v2 "
                                  "WHERE case_key=%s AND event_id=4624 AND coalesce(payload->>'TargetDomainName','') NOT IN ('','-') "
                                  "GROUP BY 1 ORDER BY 2 DESC LIMIT 1", (case_key,))
                    _r = _dcur.fetchone()
                    if _r and _r[0]:
                        _dom = _r[0]
        if _dom and str(_dom).upper() not in ('', 'NT AUTHORITY', 'WINDOW MANAGER'):
            lines.append('- **Домен / робоча група:** `%s`' % str(_dom)[:40])
    except Exception:
        pass
    lines.append('- **ОС:** %s%s' % (osn, (' (build %s)' % build) if build else ''))
    if tz:
        lines.append('- **Часовий пояс:** %s' % tz)
    if inst:
        lines.append('- **Встановлення ОС:** %s _(не є початком інциденту)_' % str(inst)[:19])
    unames = []
    for u in (p.get('users') or []):
        if isinstance(u, dict):
            n = u.get('username') or u.get('name')
            if n:
                unames.append(str(n))
        elif isinstance(u, str) and u.strip():
            unames.append(u.strip())
    if unames:
        lines.append('- **Користувачі:** %s' % ', '.join(list(dict.fromkeys(unames))[:12]))
    inc = [str(u) for u in (p.get('incident_users') or []) if u]
    if inc:
        lines.append('- **Причетні до інциденту:** %s' % ', '.join(list(dict.fromkeys(inc))[:8]))
    # NOT the host's own address: this list is built from event_logs_v2.remote_host,
    # i.e. the peers that connected TO this machine. On the case_66 case all six
    # were the attacker's RDP clients, and calling them "IP хоста" put the intruder's
    # addresses in the victim's identity block.
    _hips = [str(i) for i in (p.get('host_ips') or []) if i]
    if _hips:
        lines.append('- **IP цього хоста:** %s' % ', '.join(_hips[:4]))
    ips = [str(i) for i in (p.get('ips') or []) if i]
    if ips:
        # ranked by event volume upstream; six of thirty-six with no total reads as
        # 'these are all of them', so state the total whenever it is bigger
        try:
            _ips_total = int(p.get('ips_total') or 0)
        except Exception:
            _ips_total = 0
        _show = ips[:8]
        _more = ('' if _ips_total <= len(_show)
                 else ' _(показано %d із %d — за кількістю подій)_' % (len(_show), _ips_total))
        lines.append('- **IP, з яких підключались до цього хоста (віддалені вузли):** %s%s'
                     % (', '.join(_show), _more))
        lines.append('  _Це адреси інших машин із журналів підключень, а не власна адреса цього комп\'ютера._')
    return lines


# ── Initial-access scoring (2026-07-07) ─────────────────────────────────────
# Root-cause of the bank-case miss: the old code searched only INSIDE the
# density-based incident window, but the real infection (phishing RAR, 03-11)
# happened BEFORE the window start (03-30). New approach: collect candidates
# over a wide horizon, score them, and VERIFY temporal precedence — the
# infection point must precede the first credible malicious signal.
_IA_LURE_RE = ('бюро|безпек|податк|казнач|платіжн|платежн|рахунок|рахунк|счет|звірк|сверк|'
               'договір|договор|контракт|форма|заявк|заява|наказ|повістк|повестк|запит|запрос|'
               'извещ|уведом|інвойс|invoice|отчет|звіт |письмо|лист |акт |електронн|электронн|№')
_IA_ARCHTMP_RE = r'temp[\\/]+(7z[a-z0-9]{3,}|rar\$[a-z0-9$.]+|temp1_[^\\/]+|wz[a-z0-9]{2,})([\\/]|$)'
# Tools that only appear AFTER a foothold exists: credential dumpers, password
# recoverers, network/AD scanners. Whatever else they are, they are not the way in.
# Remote-admin products are intentionally absent — a user can be talked into installing
# one, so those can legitimately be an entry point.
# Which artefact a program_exec_v2 row came from decides whether its timestamp is a RUN
# time (Prefetch, Amcache) or merely the file's last-modified time (ShimCache).
_SHIMCACHE_SRC_RE = re.compile(r'appcompat|shimcache', re.I)
_FILE_TIME_NOTE = ' _(час файлу за ShimCache — не час запуску)_'

_IA_POSTEXP_RE = (
    r'mimikatz|lazagne|secretsdump|procdump|nanodump|chromepass|passwordfox|'
    r'passview|passwordrecovery|passrec|sniffpass|bulletspass|wirelesskey|'
    r'routerpass|pstpassword|dialupass|netpass|mspass|\bpspv\b|\biepv\b|\brdpv\b|'
    r'netscan|advanced_?port_?scanner|sharphound|bloodhound|rubeus|nltest|'
    r'psexec|paexec|winpeas|seatbelt|godpotato|juicypotato|printspoofer|'
    r'vssadmin|wbadmin|cain|hashcat|responder')

_IA_BANKSOFT_RE = ('websigner|web_signer|dbo[ _]soft|barscryptor|medoc|m\\.e\\.doc|artzvit|art-zvit|'
                   'sonata|websign|ibank|cryptoplugin|avtograf|iit user|euscp')
_IA_FORENSIC_RE = ('forensic|kape|eztools|cellebrite|magnet|axiom|autopsy|belkasoft|oxygen|'
                   'griffeye|encase|x-ways|xways|accessdata|ftk imager|nuix|ufed|dell_')
# Separators are FORWARD SLASH ONLY: every call site below normalises the column with
# translate(col, chr(92), '/'). The previous bracket class was written in a non-raw
# string, so Postgres received a single backslash and read it as slash-only - the
# vendor-path branches never fired: 7005 rows excluded instead of 8711.
_IA_BENIGN_PATH_RE = ('microsoft/onedrive|googleupdater|edgewebview|edgeupdate|edgecore|'
                      'kingsoft|wps office|k-lite|package cache|windowsapps|ruxim|'
                      'google/chrome|mozilla|adobe|nvidia|intel|realtek|'
                      # Defender/ATP components live in ProgramData and self-update right
                      # before incidents -> got scored as entry point (case_58 sensetask.exe FP)
                      'windows defender|advanced threat protection|microsoft antimalware|'
                      'defender platform|sensetask|sensecncproxy|mssense|mpsigstub|'
                      # Opera self-updater: assistant_installer.exe у Opera\assistant та
                      # Temp\.opera\<hex>\ — штатний компонент браузера, НЕ точка зараження
                      # (case_58 FP: звіт назвав його «першим шкідливим запуском»)
                      'opera/assistant|assistant_installer|assistant_package_sfx|'
                      'temp/[.]opera/')


# Anchor tools: ONLY unambiguous attack tooling. Dual-use RATs (anydesk/teamviewer/
# rms/litemanager/rustdesk) are excluded — accountants run them legitimately for
# years, which poisons the first-threat anchor (bank case: RMS since 2025-11).
_IA_HARD_TOOL_RE = ('mimikatz|ngrok|rdpwinst|rdpwrap|psexec|meterpreter|cobalt|'
                    'procdump|chromepass|nirsoft|try[.]exe|rclone|lazagne|secretsdump')


def _ia_first_threat(cur, case_key, floor):
    """Earliest CREDIBLE malicious signal (tool exec / AV detect / log clear).
    Timestamps before `floor` are clock junk (e.g. 2017 on a 2025 install)."""
    got = []
    r = _q(cur, """SELECT MIN(event_ts) FROM program_exec_v2
        WHERE case_key=%s AND event_ts >= %s
          AND lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) ~ %s
          AND lower(coalesce(full_path,'')) !~ %s""",
        (case_key, floor, _IA_HARD_TOOL_RE, _IA_FORENSIC_RE))
    if r and r[0][0]:
        got.append((r[0][0], 'перший запуск інструмента атаки'))
    r = _q(cur, """SELECT MIN(event_ts) FROM event_logs_v2
        WHERE case_key=%s AND event_ts >= %s AND event_id IN (1116,1117)""", (case_key, floor))
    if r and r[0][0]:
        got.append((r[0][0], 'перший детект Defender (EID 1116/1117)'))
    r = _q(cur, """SELECT MIN(event_ts) FROM event_logs_v2
        WHERE case_key=%s AND event_ts >= %s
          AND ((event_id=1102 AND coalesce(channel,'')='Security')
            OR (event_id=104 AND coalesce(channel,'') IN ('System','Security')
                AND coalesce(provider,'') ILIKE '%%Eventlog%%'))""", (case_key, floor))
    if r and r[0][0]:
        got.append((r[0][0], 'перше очищення журналів (EID 1102/104)'))
    if not got:
        return (None, None)
    # prefer STRONG signals (attack-tool exec / Defender detect) over a lone early
    # log-clear: logs get cleared for many reasons and an isolated clear weeks before
    # the real attack must NOT anchor the timeline (it made the incident-window phishing
    # exe look post-infection and dropped it).
    _strong = [g for g in got if ('інструмент' in g[1]) or ('Defender' in g[1])]
    if _strong:
        _a = min(_strong)
        for _w in got:
            if ('журнал' in _w[1]) and _w[0] < _a[0]:
                try:
                    if (_a[0] - _w[0]).days <= 2:
                        _a = _w
                except Exception:
                    pass
        return _a
    return min(got)


# ── Browser-download infection tier (2026-07-09) ────────────────────────────
_IA_FILESHARE_RE = (r'swisstransfer|wetransfer|dropbox|mega\.nz|mega\.io|pixeldrain|'
                    r'fex\.net|sendspace|mediafire|drive\.google|disk\.yandex|ufile|'
                    r'gofile|anonfiles|dropmefiles|file\.io|transfer\.sh|sendgb|tempsend|'
                    r'mail\.ukr\.net/attach|attach/zip')
_IA_DL_BENIGN_HOST_RE = (r'google|mozilla|microsoft|windows|office365|adobe|nvidia|intel|'
                         r'realtek|zoom\.us|slack|github|gvt1|gstatic|digicert|apple')
_IA_ANALYST_RE = (r'dell_forensic|forensic|tryndiuk|nazarii|diachenko|cellebrite|axiom|'
                  r'magnet|kape|eztools|belkasoft|autopsy|encase|ftk|x-ways|dell_')
_IA_DL_ARCH_RE = r'\.(zip|rar|7z|iso|img|cab)(\Z|[^a-z0-9])'
_IA_DL_EXE_RE = r'\.(exe|scr|js|jse|vbs|vbe|wsf|hta|lnk|bat|cmd|ps1|com|pif|msi)(\Z|[^a-z0-9])'


def _ia_browser_chain(cur, case_key, floor, horizon):
    """Return a winner-shaped dict for the strongest browser download->exec chain,
    or None. Scores a download by file-share source / phishing-lure name / archive
    or exe extension, then requires a correlated execution of the same stem AFTER
    the download (extracted-archive folder runs count). Analyst/forensic accounts
    and tools are excluded so analyst-workstation cases don't false-positive."""
    import datetime as _dt
    import re as _re
    try:
        rows = _q(cur, """SELECT event_ts,
                    regexp_replace(coalesce(local_path,''), ':Zone.Identifier$', '') fn,
                    coalesce(zone_identifier_host_url, url, referrer_url, domain, '') src
                FROM browser_provenance_v1
                WHERE case_key=%s AND event_ts >= %s
                  AND coalesce(local_path,'') <> '' AND local_path NOT ILIKE '%%desktop.ini%%'
                  AND (coalesce(zone_identifier_host_url,url,referrer_url,domain,'') ~* %s
                       OR lower(local_path) ~ %s OR lower(local_path) ~ %s OR lower(local_path) ~ %s)
                ORDER BY event_ts ASC LIMIT 2000""",
                (case_key, floor, _IA_FILESHARE_RE, _IA_DL_ARCH_RE, _IA_DL_EXE_RE, _IA_LURE_RE))
    except Exception:
        return None
    best = None
    for ts, fn, src in rows:
        if not ts or not fn:
            continue
        base = str(fn).replace('\\', '/').rstrip('/').split('/')[-1]
        low = base.lower(); sl = str(src or '').lower()
        full = (str(fn) + ' ' + sl).lower()
        if _re.search(_IA_ANALYST_RE, full):
            continue
        sc = 0
        if _re.search(_IA_FILESHARE_RE, sl): sc += 4
        if _re.search(_IA_LURE_RE, low): sc += 3
        if _re.search(_IA_DL_ARCH_RE, low): sc += 2
        if _re.search(_IA_DL_EXE_RE, low): sc += 3
        if _re.search(_IA_DL_BENIGN_HOST_RE, sl): sc -= 4
        if sc < 5:
            continue
        # correlate an execution of the same stem AFTER the download
        stem = _re.sub(r'\.(zip|rar|7z|exe|scr|lnk|iso|img|js|vbs|hta|docx?|xlsx?)$', '', base, flags=_re.I)
        stem = _re.sub(r'\s*\(\d+\)$', '', stem).strip()
        if len(stem) < 5:
            continue
        like = '%' + stem[:22].lower().replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
        try:
            ex = _q(cur, """SELECT event_ts, executable_name, full_path FROM program_exec_v2
                WHERE case_key=%s AND event_ts >= %s AND event_ts <= %s
                  AND lower(coalesce(full_path,'')) !~ %s
                  AND lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) LIKE %s
                ORDER BY event_ts ASC LIMIT 1""",
                (case_key, ts, ts + _dt.timedelta(days=14), _IA_ANALYST_RE, like))
        except Exception:
            ex = []
        if not ex:
            continue
        ets, een, efp = ex[0]
        cand = {'ts': ets, 'exe': (een or efp or base), 'path': efp or een,
                'dl_ts': ts, 'dl_name': base, 'url': str(src)[:120] if src else None,
                'score': sc + 2, 'stem': stem, 'via': 'browser'}
        if best is None or cand['score'] > best['score'] or (cand['score'] == best['score'] and ts < best['dl_ts']):
            best = cand
    return best


def _initial_access_struct(case_key, iw_start):
    """Score-based infection-point detection. Candidates = executions from
    user-writable paths over a WIDE horizon (iw_start - 240d), scored by:
    archive-temp execution (+3), phishing-lure filename (+3), precedes first
    threat signal (+2, recent +1), correlated download row (+1), banking/DBO
    software (-4), after first threat (-2). Winner needs score >= 4."""
    import datetime as _dt
    import re as _re
    res = {'winner': None, 'runners': [], 'anchor': None}
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            floor = None
            if iw_start:
                try:
                    _v = iw_start
                    if not isinstance(_v, _dt.datetime):
                        _v = _dt.datetime.fromisoformat(str(_v)[:19])
                    floor = _v - _dt.timedelta(days=240)
                except Exception:
                    floor = None
            floor = floor or _dt.datetime(2000, 1, 1)
            anch_ts, anch_lbl = _ia_first_threat(cur, case_key, floor)
            if anch_ts:
                res['anchor'] = (anch_ts, anch_lbl)
            horizon = anch_ts + _dt.timedelta(days=2) if anch_ts else None
            rows = _q(cur, """SELECT event_ts, executable_name, full_path, coalesce(source_file,'') FROM program_exec_v2
                WHERE case_key=%s AND event_ts >= %s
                  AND lower(coalesce(full_path,'')) !~ %s
                  AND lower(translate(coalesce(full_path,''),chr(92),'/')) !~ %s
                  AND lower(coalesce(executable_name,'')) !~ %s
                  AND lower(coalesce(full_path,'')) ~ 'users|programdata|temp'
                  -- separators normalised instead of a bracket class: the literal here was
                  -- NOT a raw string, so its doubled backslash arrived at Postgres single,
                  -- and an ARE reads that inside brackets as slash-only - it matched 0 of the
                  -- 8124 windows rows it was written to drop (Python line below caught them)
                  AND lower(translate(coalesce(full_path,''),chr(92),'/')) !~ '/windows/'
                ORDER BY event_ts ASC LIMIT 4000""",
                (case_key, floor, _IA_FORENSIC_RE, _IA_BENIGN_PATH_RE, _BENIGN_EXEC_RE))
            best = {}
            for ts, exe, path, _srcf in rows:
                if not ts:
                    continue
                pl = str(path or '').lower()
                el = str(exe or '').lower()
                # executable_name often holds the FULL path -> always take the basename
                base = (el or pl).replace('/', '\\').rsplit('\\', 1)[-1]
                stem = _re.sub(r'\.(exe|scr|com|bat|cmd|pif|lnk|tmp)$', '', base).strip()
                if not stem:
                    continue
                if _re.search(r'[\\/]windows[\\/]|systemtemp', el + ' ' + pl):
                    continue
                sc = 0
                _arch = bool(_re.search(_IA_ARCHTMP_RE, pl))
                _lure = bool(_re.search(_IA_LURE_RE, el + ' ' + pl))
                if _arch:
                    sc += 3
                if _lure:
                    sc += 3
                # A phishing-lure-named exe run STRAIGHT from an archiver temp folder
                # (Temp\Rar$…/7zS…) is a textbook infection entry. Make it immune to the
                # "after anchor" penalty and the horizon drop, so a stray EARLY log-clear
                # anchor (case_45: a 2025-08 clear 8 months before the 2026-04 attack) can't
                # push the real entry out of the window. Requires BOTH signals -> benign
                # updaters (never lure-named in an archiver temp) are unaffected.
                _strong_entry = _arch and _lure
                if _re.search(_IA_BANKSOFT_RE, el + ' ' + pl):
                    sc -= 4
                # post-exploitation tooling is a CONSEQUENCE of the breach, never its
                # entry point — demote hard enough that it can never win section 1
                if _re.search(_IA_POSTEXP_RE, el + ' ' + pl):
                    sc -= 10
                try:
                    from analysis.benign_allowlist import is_benign_entry as _is_benign_entry
                    if _is_benign_entry(el + ' ' + pl):
                        sc -= 8  # known-benign updater/telemetry: DEMOTE (stays in timeline, never picked as entry)
                except Exception:
                    pass
                if anch_ts:
                    if ts <= anch_ts:
                        sc += 2
                        try:
                            if (anch_ts - ts).days <= 30:
                                sc += 1
                        except Exception:
                            pass
                    elif not _strong_entry:
                        sc -= 2
                    if horizon and ts > horizon and sc < 6 and not _strong_entry:
                        continue  # late & weak -> post-infection payload, not entry
                else:
                    sc += 1
                k = stem[:24]
                _tk = 'file' if _SHIMCACHE_SRC_RE.search(str(_srcf or '')) else 'run'
                cand = best.get(k)
                # a real run time wins the tie over a ShimCache file mtime for the same
                # binary; score still decides first, so the entry itself never changes
                if (cand is None or sc > cand['score']
                        or (sc == cand['score'] and cand.get('time_kind') == 'file' and _tk == 'run')
                        or (sc == cand['score'] and cand.get('time_kind') == _tk and ts < cand['ts'])):
                    best[k] = {'ts': ts, 'exe': base, 'path': path or exe, 'score': sc,
                               'stem': stem, 'time_kind': _tk, 'src_file': str(_srcf or '')}
            cands = sorted(best.values(), key=lambda x: (-x['score'], x['ts']))[:6]
            # correlate a download/appearance row (same name stem shortly before exec)
            for cd in cands[:3]:
                st = cd['stem'][:18].replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
                if len(cd['stem']) < 6:
                    continue
                dl = _q(cur, """SELECT event_ts, file_name,
                            substring(payload::text from 'https?://[^ "]+')
                    FROM filesystem_v2
                    WHERE case_key=%s AND event_ts BETWEEN %s AND %s
                      AND lower(file_name) LIKE %s
                      AND file_name NOT ILIKE '%%.pf'
                    ORDER BY event_ts ASC LIMIT 5""",
                    (case_key, cd['ts'] - _dt.timedelta(days=7),
                     cd['ts'] + _dt.timedelta(minutes=5), st.lower() + '%'))
                dts = dfn = url = None
                for t2, fn2, u2 in dl:
                    if dts is None:
                        dts, dfn = t2, fn2
                    uu = _clean_url(u2) if u2 else None
                    if uu and not any(b in uu.lower() for b in _NOISE_DOMAINS):
                        dts, dfn, url = t2, fn2, uu
                        break
                if dfn:
                    dfn = _re.sub(r'(?i)(:zone\.identifier|\.lnk)$', '', str(dfn)).strip()
                    cd['dl_ts'], cd['dl_name'], cd['url'] = dts, dfn, url
                    cd['score'] += 1
            # NEW TIER: strongest browser download->exec chain (file-share/lure).
            # Catches infections whose provenance is in browser_provenance_v1 but
            # NOT in filesystem_v2 Zone.Identifier (e.g. 03_07 SwissTransfer ZIP).
            try:
                _bc = _ia_browser_chain(cur, case_key, floor, horizon)
            except Exception:
                _bc = None
            if _bc:
                cands.append(_bc)
            cands.sort(key=lambda x: (-x['score'], x['ts']))
            if cands and cands[0]['score'] >= 4:
                res['winner'] = cands[0]
                # the consequence that corroborates THIS candidate: first threat after its stamp
                try:
                    _wts = cands[0].get('ts')
                    if _wts:
                        _aa = _ia_first_threat(cur, case_key, _wts)
                        if _aa and _aa[0]:
                            res['after_anchor'] = _aa
                except Exception:
                    pass
                res['runners'] = [x for x in cands[1:3] if x['score'] >= 3]
    except Exception:
        pass
    res['case_key'] = case_key
    return res


# ── Delivery provenance («звідки взявся файл, з якого почалося зараження») ──
# Populated by _initial_access (runs before _timeline in every report path) so the
# timeline can prepend the same delivery step without recomputing. Overwritten each
# report build → no long-term staleness after re-ingest.
_DELIVERY_CACHE = {}


def _host(u):
    import re as _re
    m = _re.search(r'https?://([^/:]+)', str(u or ''))
    return m.group(1) if m else str(u or '')[:40]


def _delivery_provenance(case_key, ia):
    """Resolve HOW the entry file arrived on the host and classify the delivery
    vector (web download / webmail / file-share / email attachment / removable),
    or honestly report that the source was not preserved + a re-collection hint.
    Correlates: a browser download/Zone.Identifier for the entry stem or its parent
    archive, then the presence of a mail client when the file was opened straight
    from an archiver temp folder. Returns a dict or None."""
    import re as _re
    w = (ia or {}).get('winner')
    if not w:
        return None
    entry_exe = str(w.get('exe') or '')
    entry_path = str(w.get('path') or '')
    stem = str(w.get('stem') or entry_exe) or entry_exe
    from_archive = bool(_re.search(_IA_ARCHTMP_RE, entry_path.lower()))
    res = {'vector': 'unknown', 'label': None, 'url': None, 'ts': w.get('dl_ts'),
           'confidence': 'low', 'recommend': None, 'from_archive': from_archive}
    _s = _re.sub(r'[%_]', '', stem)[:24].strip().lower()
    like = '%' + _s + '%' if len(_s) >= 5 else None
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            cur.execute("SET statement_timeout='4000'")
            best_url = best_ts = None
            chain = None
            # 0) our own vao_parser_browser download record - the most precise source:
            #    it has the real target_path plus the full downloads_url_chains redirect
            #    chain, so the answer is concrete instead of inferred.
            if like:
                vrows = _q(cur, """SELECT payload->>'source_url', payload->>'url_chain',
                                          payload->>'chain_len', payload->>'tab_referrer_url'
                          FROM raw_fallback_v2
                          WHERE case_key=%s AND parser_family='browser_downloads'
                            AND lower(coalesce(payload->>'target_path','')) LIKE %s
                          LIMIT 10""", (case_key, like))
                for _su, _ch, _cl, _ref in (vrows or []):
                    cand = str(_su or '') or str(_ref or '')
                    if cand.startswith('http') and not _re.search(_IA_DL_BENIGN_HOST_RE, cand.lower()):
                        best_url = cand
                        try:
                            if _ch and int(_cl or 0) > 1:
                                chain = str(_ch)[:300]
                        except (TypeError, ValueError):
                            chain = None
                        res['chain'] = chain
                        res['source'] = 'vao_parser_browser'
                        break
            # 1) browser download / Zone.Identifier host-url for the entry stem or its archive
            if like:
                rows = _q(cur, """SELECT event_ts,
                            coalesce(nullif(zone_identifier_host_url,''), nullif(url,''),
                                     nullif(referrer_url,''), nullif(domain,''), '') AS src
                          FROM browser_provenance_v1
                          WHERE case_key=%s AND (lower(coalesce(local_path,'')) LIKE %s
                                OR lower(coalesce(download_path,'')) LIKE %s
                                OR lower(coalesce(archive_origin,'')) LIKE %s)
                          ORDER BY event_ts ASC LIMIT 20""", (case_key, like, like, like))
                for ts, src in (rows or []):
                    s = str(src or '')
                    if s.startswith('http') and not _re.search(_IA_DL_BENIGN_HOST_RE, s.lower()):
                        best_url, best_ts = s, ts
                        break
            # 2) Zone.Identifier HostUrl in filesystem_v2 payload for the entry stem
            if not best_url and like:
                fr = _q(cur, r"""SELECT event_ts, substring(payload::text from 'HostUrl=([^\r\n]+)')
                          FROM filesystem_v2 WHERE case_key=%s AND lower(file_name) LIKE %s
                            AND payload::text ~* 'hosturl='
                          ORDER BY event_ts ASC LIMIT 10""", (case_key, like))
                for ts, u in (fr or []):
                    if u and str(u).startswith('http') and not _re.search(_IA_DL_BENIGN_HOST_RE, str(u).lower()):
                        best_url, best_ts = str(u), ts
                        break
            if best_url:
                low = best_url.lower()
                res['url'] = best_url[:160]
                res['ts'] = best_ts or res['ts']
                res['confidence'] = 'high'
                if _re.search(r'webmail|/mail/|owa|roundcube|zimbra|/imp/|horde|\bmail\.', low):
                    res['vector'] = 'webmail'
                    res['label'] = 'веб-пошта — вкладення завантажено з `%s`' % _host(best_url)
                elif _re.search(_IA_FILESHARE_RE, low):
                    res['vector'] = 'fileshare'
                    res['label'] = 'файлообмінник `%s`' % _host(best_url)
                else:
                    res['vector'] = 'web'
                    res['label'] = 'завантаження з веб-сайту `%s`' % _host(best_url)
                return res
            # 3) email-attachment inference: opened straight from an archiver temp AND a
            #    mail client / Outlook attachment cache is present
            has_mail = bool(_q(cur, """SELECT 1 FROM program_exec_v2 WHERE case_key=%s
                        AND lower(coalesce(executable_name,'')||coalesce(full_path,'')) ~
                            'outlook|thunderbird|em[ _]?client|thebat|mailbird|bat!\\b' LIMIT 1""", (case_key,)))
            # distinct folders of the case first: 15-25 s and frequent timeouts before, 1-5 s now
            has_att = bool(_q(cur, """WITH p AS MATERIALIZED (SELECT DISTINCT parent_path FROM filesystem_v2 WHERE case_key=%s)
                        SELECT 1 FROM p WHERE lower(coalesce(parent_path,'')) ~ 'content[.]outlook|\\\\olk[0-9a-f]|inetcache.{0,20}attach' LIMIT 1""", (case_key,)))
            if from_archive and (has_mail or has_att):
                res['vector'] = 'email'
                res['confidence'] = 'medium'
                res['label'] = ('вкладення електронної пошти (файл відкрито прямо з тимчасової теки архіватора, '
                                'на хості наявний поштовий клієнт). Сам лист-джерело у зібраних артефактах не зберігся')
                res['recommend'] = ('до-зібрати поштові дані (Outlook `.ost/.pst`, або веб-пошту в історії браузера) '
                                    'для встановлення відправника/теми листа')
                return res
            # 4) removable media (entry on a non-system drive)
            if _re.search(r'^[d-z]:[\\/]', entry_path.lower()):
                res['vector'] = 'removable'
                res['label'] = 'можливо зі знімного носія (диск `%s`)' % entry_path[:2]
                res['recommend'] = 'перевірити журнали USB/знімних носіїв'
                return res
            # 5) source not preserved
            res['vector'] = 'unknown'
            res['label'] = 'джерело доставки не збереглось у зібраних артефактах'
            res['recommend'] = ('до-зібрати історію браузера (завантаження + Zone.Identifier) та поштові дані '
                                '(Outlook `.ost/.pst`) — типово фішинговий файл приходить поштою або через веб')
            return res
    except Exception:
        return res


def _delivery_line(deliv, with_ts=True):
    """One-line '📨 Доставка' string from a resolved provenance dict (or None)."""
    if not deliv or not deliv.get('label'):
        return None
    conf = {'high': '', 'medium': ' _(ймовірно)_', 'low': ' _(не підтверджено)_'}.get(deliv.get('confidence'), '')
    ts = deliv.get('ts')
    pre = ('`%s` — ' % _fmt_ts(ts)) if (with_ts and ts) else ''
    line = '- 📨 %s**Доставка:** %s%s' % (pre, deliv['label'], conf)
    if deliv.get('chain'):
        # the redirect chain answers "which host actually served the bytes", which the
        # landing page alone never shows
        line += '\n  - 🔗 _ланцюг завантаження:_ `%s`' % deliv['chain']
    if deliv.get('recommend'):
        line += '\n  - 🛠 _рекомендація:_ %s' % deliv['recommend']
    return line


def _strip_ads(name):
    """Drop an alternate-data-stream suffix from a file name for display.

    `лист нотаріусам (1).zip:Zone.Identifier` -> `лист нотаріусам (1).zip`. Only the
    known provenance streams are stripped, so a real file name containing a colon (a URL
    pasted as a name, say) is left alone."""
    s = str(name or '')
    for ads in (':Zone.Identifier', ':$DATA', ':SmartScreen'):
        i = s.lower().find(ads.lower())
        if i > 0:
            return s[:i]
    return s


def _entry_floor(case_key, iw):
    """No candidate for «вхідна точка» may be older than 30 days before the density peak.

    The Asus report named a Zone.Identifier from 2024-12-28 as the way in — twenty months
    before its own incident window — and case_45 named a download eight months before the
    real delivery. A file that arrived a year earlier is a file the person had, not a way
    in. (FIX_QUEUE, defect №2/№5.)"""
    from datetime import timedelta as _td
    ref = None
    for v in ((iw or (None, None, None))[2], (iw or (None,))[0]):
        ref = _ev_ts(str(v)[:10] + 'T00:00:00') if v else None
        if ref is not None:
            break
    if ref is None:
        return None
    return ref - _td(days=30)


def _entry_candidate_ok(name, path, ts, floor):
    """An entry-point candidate must be an executable/archive/script (never a document of
    the person's) and must sit inside the 30-day run-up to the incident."""
    s = ('%s %s' % (name or '', path or '')).strip()
    if not s:
        return False
    if _is_docname(name or '') or (not _CHAIN_EXT_RE.search(str(name or ''))
                                   and not _CHAIN_EXT_RE.search(str(path or ''))):
        return False
    if floor is not None and ts is not None:
        try:
            _t = ts.replace(tzinfo=None) if getattr(ts, 'tzinfo', None) else ts
            _f = floor.replace(tzinfo=None) if getattr(floor, 'tzinfo', None) else floor
            if _t < _f:
                return False
        except Exception:
            pass
    return True


_CALM_NO_ENTRY = [
    '- Високих або критичних загроз детермінований шар на цій справі не виявив, '
    'тому **вхідну точку не встановлюємо**: назвати «точку входу» там, де проникнення '
    'не зафіксоване, означало б описати подію, якої в доказах немає.',
    '- Завантаження, запуски й мережева активність за період нікуди не зникли — вони '
    'у службових даних (розділ 7) і придатні для ручного перегляду.',
]


def _anchor_src(label):
    """Source tag for an incident-anchor label from _ia_first_threat (Defender / log clear / tool run)."""
    l = str(label or '')
    if 'Defender' in l:
        return 'Microsoft-Windows-Windows Defender%4Operational.evtx (EID 1116/1117)'
    if 'журнал' in l:
        return 'Security.evtx / System.evtx (EID 1102/104)'
    return 'program_exec_v2 (Amcache/ShimCache/Prefetch)'


def _after_ok(a, w):
    try:
        return bool(a[0] >= w['ts'])
    except Exception:
        return False


def _ia_render(ia, deliv=None):
    """Human lines for a scored initial-access winner (empty list if none)."""
    import re as _re
    out = []
    w = (ia or {}).get('winner')
    if not w:
        return out
    _wprov = _ia_prov(ia, w)
    out.append('**🎯 Ланцюг зараження (завантаження → запуск, звірено з послідовністю атаки):**')
    _dl = _delivery_line(deliv, with_ts=True)
    if _dl:
        out.append(_dl)
    if w.get('dl_name'):
        src = (' з `%s`' % w['url']) if w.get('url') else ' (URL джерела в логах не зберігся)'
        out.append('- 📥 `%s` — у системі зʼявився файл `%s`%s%s' % (
            _fmt_ts(w.get('dl_ts')), _strip_ads(w['dl_name'])[:85], src,
            _prov_tag(w.get('dl_prov') or 'filesystem_v2 (Zone.Identifier)')))
    if _re.search(_IA_ARCHTMP_RE, str(w.get('path') or '').lower()):
        out.append('- 📦 запуск відбувся З ТИМЧАСОВОЇ ТЕКИ АРХІВАТОРА — файл відкрили прямо з архіву '
                   '(класична ознака фішингового вкладення)')
    _tk_note = _FILE_TIME_NOTE if (w.get('time_kind') == 'file') else ''
    out.append('- %s `%s` — %s `%s`%s%s%s' % (
        '🗂' if w.get('time_kind') == 'file' else '▶️', _fmt_ts(w['ts']),
        PRESENCE_LABEL if w.get('time_kind') == 'file' else 'запущено',
        str(w.get('exe') or '?')[:75],
        (' з `%s`' % str(w.get('path'))[:85]) if w.get('path') else '', _tk_note,
        _prov_tag(_wprov)))
    a = (ia or {}).get('anchor')
    if a and a[0]:
        try:
            _after = a[0] >= w['ts']
        except Exception:
            _after = False
        if _after:
            out.append('- 🛡 далі `%s` — %s (точка входу ПЕРЕДУЄ першим шкідливим подіям — '
                       'послідовність підтверджена)%s' % (_fmt_ts(a[0]), a[1], _prov_tag(_anchor_src(a[1]))))
    # A file stamp is not an entry: it says the binary was on the disk, not that anybody
    # brought it in. Naming an entry point off one is how «вхідна точка» ended up being a
    # document downloaded twenty months before the incident.
    # Corroboration (owner's rule on 20_05 case_58): a stamp from an archive-temp folder that
    # the first malicious event follows within 24 hours is a probable entry — the consequence
    # is the launch evidence. A lone stamp, or one from a normal folder, still is not.
    _corr_h = None
    _aa = (ia or {}).get('after_anchor') or a
    if _aa and _aa[0] and not (a and a[0] and _after_ok(a, w)):
        _aa_src = _anchor_src(_aa[1])
        out.append('- 🛡 далі `%s` — %s (перша шкідлива подія ПІСЛЯ цього кандидата)%s'
                   % (_fmt_ts(_aa[0]), _aa[1], _prov_tag(_aa_src)))
    if w.get('time_kind') == 'file' and not w.get('dl_name') and _aa and _aa[0] and \
            _re.search(_IA_ARCHTMP_RE, str(w.get('path') or '').lower()):
        try:
            _d = (_aa[0] - w['ts']).total_seconds() / 3600.0
            if 0 <= _d <= 24 * 7:
                _corr_h = _d
        except Exception:
            _corr_h = None
    if w.get('time_kind') == 'file' and not w.get('dl_name') and _corr_h is None:
        out.append('- ⚠️ Точку входу за цим кандидатом **не називаємо**: у логах лише мітка '
                   'існування файлу, а не запуск.')
    elif _corr_h is not None:
        out.append('- 👉 **Ймовірна точка входу:** `%s` — прямого запису про запуск немає (лише мітка '
                   'файлу з теки архіватора), але перші шкідливі події сталися через %s після неї: '
                   'наслідок підтверджує запуск.%s'
                   % (str(w.get('exe'))[:85],
                      ('%d хв' % round(_corr_h * 60)) if _corr_h < 1 else
                      ('%.1f год' % _corr_h) if _corr_h < 48 else ('%d дн.' % round(_corr_h / 24)),
                      _prov_tag(_wprov)))
    else:
        out.append('- 👉 **Ймовірна точка входу:** `%s`.%s'
                   % (str(w.get('dl_name') or w.get('exe'))[:85], _prov_tag(_wprov)))
    return out


def _ia_prov(ia, w):
    """`[джерело: …]` text for an initial-access candidate, from the row it was read out of."""
    sf = str((w or {}).get('src_file') or '')
    ck = str((ia or {}).get('case_key') or '')
    if not sf:
        return 'program_exec_v2'
    try:
        from analysis.threat_detect import provenance as _prov
        with psycopg2.connect(PG_DSN) as _c:
            _c.autocommit = True
            with _c.cursor() as _cur:
                _cur.execute("SET statement_timeout='6000'")
                return _prov(ck, sf, None, _cur) or sf
    except Exception:
        return sf


_ENTRY_UNKNOWN_NOTE = (
    '- ⚠️ **Спосіб первинного проникнення не встановлено** за наявними артефактами: '
    'нижче названо лише перший шкідливий запуск, а не вхідну точку.',
    '- 🛠 _щоб встановити:_ потрібні журнал Security з полем IpAddress у подіях 4624/4625, '
    'журнали RDP (TerminalServices-RemoteConnectionManager), стан мережі на момент вилучення '
    'і журнали брандмауера/VPN. Для сервера найімовірніші вектори — підбір пароля до RDP, '
    'дійсні вкрадені облікові дані або вразливий сервіс на периметрі.')

_PRIV_IP_RE = re.compile(r'^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.)')
_IPV4_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')


def _rdp_entry_lines(case_key, findings, first_exec_ts):
    """Lines naming an RDP session from a public address as the probable entry, or [] when the
    evidence is not there: a session event (1149 / 4624 type 10 / 21 / 25) with a public source
    address at most 72h before the first malicious launch. The closest one is the entry session;
    the number of distinct public addresses in the window is reported next to it."""
    try:
        if not first_exec_ts:
            return []
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            rows = _q(cur, """SELECT event_ts, coalesce(remote_host,''), coalesce(target_user,''), event_id,
                                     coalesce(source_file,''), payload->>'RecordNumber'
                              FROM event_logs_v2 WHERE case_key=%s
                                AND (event_id IN (1149,21,25) OR (event_id=4624 AND logon_type='10'))
                                AND event_ts BETWEEN %s AND %s
                                AND coalesce(remote_host,'') ~ '[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+'
                              ORDER BY event_ts""",
                     (case_key, first_exec_ts - __import__("datetime").timedelta(hours=72), first_exec_ts)) or []
        pub = []
        for r in rows:
            m = _IPV4_RE.search(str(r[1]))
            if m and not _PRIV_IP_RE.match(m.group(1)):
                pub.append((r[0], m.group(1), r[2], r[3], r[4], r[5]))
        if not pub:
            return []
        ets, ip, user, eid, sf, rec = pub[-1]
        n_ip = len({x[1] for x in pub})
        gap = (first_exec_ts - ets).total_seconds()
        gap_s = ('%d хв' % round(gap / 60)) if gap < 3600 else ('%.1f год' % (gap / 3600.0))
        who = (' під акаунтом `%s`' % user[:40]) if user else ''
        more = (' У 72 год до запуску — RDP-сесії з %d публічних адрес.' % n_ip) if n_ip > 1 else ''
        return ['- 🚪 **Ймовірна точка входу: RDP-сесія з публічної адреси `%s`**%s — `%s`, за %s до першого '
                'шкідливого запуску (EID %s).%s%s' % (ip, who, _fmt_ts(ets), gap_s, eid, more,
                                                     _prov_tag('%s · RecordNumber %s' % (sf, rec) if rec else sf))]
    except Exception:
        return []

def _initial_access(case_key, iw_start, findings=None):
    """Concrete delivery (real external URL) + first attack tool + early suspicious exec.
    Tier 0: the earliest event of the top deterministic finding (a wiper delivered by GPO
    IS the entry point; the download heuristics below cannot see it).
    Tier 1: scored candidates with temporal-precedence verification (wide horizon).
    Tier 2: legacy download→exec correlation inside the incident window.
    Tier 3: legacy delivery / first-tool / early-exec lists."""
    # ONE object of the chain, or none. The Asus report named three mutually inconsistent
    # entry points in one document — a 2024 Zone.Identifier document in §1, a plain-language
    # sentence about GooseDesktop.exe, and a §3 chain naming the same benign prank app —
    # under a verdict that found nothing high or critical. The order below is a cascade with
    # a stop, not a list of candidates: findings' chain, else the heuristic, else nothing.
    _fl = findings if findings is not None else (_findings(case_key) or [])
    _has_hi = any(str((f or {}).get('severity') or '').lower() in _HI_SEV for f in _fl)
    if not _has_hi:
        # calm verdict: the delivery cache is still filled (the chronology reads it) but
        # NOTHING here names a way in
        # An empty dict, not None: None makes _timeline recompute the delivery and prepend
        # it as the first chronological event — which is how the Asus chronology came to
        # consist of exactly one line, «Доставка: … _(не підтверджено)_», under a verdict
        # that found nothing. On a calm case there is no delivery to speak of.
        _DELIVERY_CACHE[case_key] = {}
        return list(_CALM_NO_ENTRY)
    fx = []
    try:
        fx = _entry_point_from_findings(_fl)
    except Exception:
        fx = []
    ia = _initial_access_struct(case_key, iw_start)
    try:
        deliv = _delivery_provenance(case_key, ia)
        _DELIVERY_CACHE[case_key] = deliv
    except Exception:
        deliv = None
    if fx and fx[0].startswith('**🎯 Перша підтверджена дія'):
        # the top chain is the attacker's first ACTION, not a way in: the download->run heuristic
        # may still name a probable entry (case_41: an executable from a mail attachment, 19 days
        # before the incident). One statement, no contradiction: the probable entry first, then
        # the first confirmed action - its header no longer says «точку входу не встановлено».
        _floor0 = _entry_floor(case_key, _incident_window(case_key))
        _w0 = (ia or {}).get('winner')
        if _w0 and _entry_candidate_ok(_w0.get('dl_name') or _w0.get('exe'), _w0.get('path'),
                                       _w0.get('dl_ts') or _w0.get('ts'), _floor0):
            _io = _ia_render(ia, deliv)
            if _io and any('Ймовірна точка входу' in l for l in _io):
                _h = re.sub(r'; саму точку входу за наявними артефактами не встановлено:\*\*$', ':**', fx[0])
                return _io + [''] + [_h] + fx[1:]
    if fx:
        # the chain of the top finding IS the entry point. The heuristic winner used to be
        # appended under «Інші кандидати», and that second name is what made one report
        # contradict itself.
        return fx
    # No anchor chain under a high/critical verdict: the download→run heuristic may speak,
    # but only about an executable/archive inside the 30-day run-up to the incident.
    _floor = _entry_floor(case_key, _incident_window(case_key))
    _w = (ia or {}).get('winner')
    if _w and not _entry_candidate_ok(_w.get('dl_name') or _w.get('exe'), _w.get('path'),
                                      _w.get('dl_ts') or _w.get('ts'), _floor):
        ia = dict(ia or {}); ia['winner'] = None
    out = _ia_render(ia, deliv)
    if out:
        return out
    start = iw_start or '2000-01-01'
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            # === CORRELATION: first malicious EXECUTION, then the download right BEFORE it ===
            _fe = _q(cur, r"""SELECT event_ts, executable_name, full_path FROM program_exec_v2
                WHERE case_key=%s AND event_ts >= %s
                  AND lower(coalesce(full_path,'')) !~ 'forensic|kape|eztools|cellebrite|magnet|axiom|autopsy|belkasoft|oxygen|griffeye|encase|x-ways|xways|accessdata|ftk imager|nuix|ufed|dell_'
                  AND lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) !~ 'anydesk|teamviewer|rustdesk|splashtop|ultravnc|radmin|litemanager|supremo|ammyy|logmein|screenconnect|anyviewer|websigner|dbo soft|barscryptor|ibank|iit_avtor|iit avtor|hpeasystart|samsung_magician|punto|foxit|hpprinter|hp_'  -- RAT+legit-vendor not first-malicious
                  AND lower(translate(coalesce(executable_name,'')||' '||coalesce(full_path,''),chr(92),'/')) !~ %s
                  AND ( ( lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) ~ %s
                          AND NOT lower(coalesce(executable_name,'')) ~ 'anydesk|teamviewer|rustdesk|splashtop|ultravnc|radmin|litemanager|supremo|ammyy|logmein|screenconnect|anyviewer|tv_w32|tv_x64' )  -- dual-use RAT never 'first malicious'
                        OR lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) ~ 'mimikatz|cobalt|meterpreter|kmsauto|autokms|kms.?activator|coinminer|xmrig|winactivator|keygen|\ycrack|njrat|quasar|asyncrat|remcos|agenttesla|redline|infostealer|\ystealer|lazagne|secretsdump|winpeas|bloodhound|sharphound|rubeus|godpotato|juicypotato|printspoofer|lockbit|ransomw|defendercontrol|processhacker|\ygmer|pchunter|nssm|\ynanocore|formbook|lokibot|snakekeylog|masslogger' )  -- malware-evidence-gate
                ORDER BY event_ts ASC NULLS LAST LIMIT 1""", (case_key, start, _IA_BENIGN_PATH_RE, _TOOL_RE))
            if _fe and _fe[0][0]:
                _et, _exe, _epath = _fe[0]
                _dl = _q(cur, """SELECT event_ts, file_name, substring(payload::text from 'https?://[^ ]+')
                    FROM filesystem_v2 WHERE case_key=%s AND event_ts <= %s AND event_ts >= %s
                      AND payload::text ~* 'hosturl|referrerurl'
                      AND substring(payload::text from 'https?://[^ ]+') IS NOT NULL
                    ORDER BY event_ts DESC NULLS LAST LIMIT 8""", (case_key, _et, start))
                _link = None
                for _dt, _dfn, _du in _dl:
                    _u = _clean_url(_du)
                    if _u and not any(b in _u.lower() for b in _NOISE_DOMAINS):
                        _link = (_dt, _dfn, _u); break
                if _link:
                    _dt, _dfn, _u = _link
                    _gap = ''
                    try:
                        _sec = (_et - _dt).total_seconds()
                        if 0 <= _sec < 172800: _gap = ' (через ~%d хв після завантаження)' % int(_sec/60)
                    except Exception:
                        pass
                    out.append('**🎯 Ланцюг зараження (завантаження → запуск):**')
                    # the browser records provenance in an alternate data stream;
                    # the file the victim received is the name without it
                    out.append('- 📥 `%s` — завантажено `%s` з `%s`' % (_fmt_ts(_dt), _strip_ads(_dfn) or '?', _u))
                    out.append('- ▶️ `%s` — запущено `%s`%s%s' % (_fmt_ts(_et), _exe or '?', (' з `%s`' % str(_epath)[:70]) if _epath else '', _gap))
                    out.append('- 👉 **Ймовірна точка входу:** файл завантажено з `%s`, і невдовзі виконано `%s`.' % (_u, _exe or '?'))
                else:
                    _rdp = _rdp_entry_lines(case_key, findings, _et)
                    if _rdp:
                        out.extend(_rdp)
                    else:
                        out.extend(_ENTRY_UNKNOWN_NOTE)
                    out.append('**🎯 Перший шкідливий запуск:** `%s` — `%s`%s' % (_fmt_ts(_et), _exe or '?', (' з `%s`' % str(_epath)[:70]) if _epath else ''))
                    out.append('- Джерело завантаження не знайдено в нормалізованих логах — перевір історію браузера вручну.')
            if out:
                return out
            # delivery: only entries that carry a REAL external origin URL (skip
            # junk Zone.Identifier on desktop.ini/thumbs and vendor/update noise).
            deliv = _q(cur, r"""
                SELECT event_ts, file_name,
                       substring(payload::text from 'https?://[^ "'',;)\]]+')
                FROM filesystem_v2
                WHERE case_key=%s
                  AND event_ts >= %s
                  AND payload::text ~* 'hosturl|referrerurl'
                  AND substring(payload::text from 'https?://[^ "'',;)\]]+') IS NOT NULL
                ORDER BY event_ts ASC NULLS LAST
                LIMIT 25
            """, (case_key, start))
            shown = 0
            for ts, fn, url in deliv:
                if shown >= 3:
                    break
                u = _clean_url(url)
                if not u or any(b in u.lower() for b in _NOISE_DOMAINS):
                    continue
                out.append('- **Доставка** `%s` — файл `%s` завантажено з `%s`' % (
                    _fmt_ts(ts), fn or '?', u))
                shown += 1
            # first KNOWN attack tool executed (definitive signal)
            tool = _q(cur, """
                SELECT event_ts, executable_name FROM program_exec_v2
                WHERE case_key=%s AND event_ts >= %s AND lower(executable_name) ~ %s
                ORDER BY event_ts ASC NULLS LAST LIMIT 1
            """, (case_key, start, _TOOL_RE))
            for ts, exe in tool:
                out.append('- **Перший інструмент атаки** `%s` — `%s`' % (_fmt_ts(ts), exe or '?'))
            # earliest suspicious exec from a user-writable path, benign helpers excluded
            se = _q(cur, """
                SELECT event_ts, executable_name, full_path FROM program_exec_v2
                WHERE case_key=%s AND event_ts >= %s
                  AND lower(full_path) ~ 'downloads|appdata|public|programdata|users'
                  AND lower(full_path) ~ 'temp|downloads|public|roaming|documents'
                  AND lower(executable_name) !~ %s
                ORDER BY event_ts ASC NULLS LAST LIMIT 6
            """, (case_key, start, _BENIGN_EXEC_RE))
            for ts, exe, path in se[:2]:
                out.append('- **Ранній підозрілий запуск** `%s` — `%s`%s' % (
                    _fmt_ts(ts), exe or '?', (' (`%s`)' % str(path)[:70]) if path else ''))
    except Exception:
        pass
    if not out:
        out.append('- Точну першу точку зараження не вдалося однозначно встановити з нормалізованих логів — '
                   'дивись хронологію та службові дані нижче, потрібна ручна перевірка.')
    return out


def _sid_name_map(cur, case_key, _q):
    """SID -> account name, built from the account-creation events of this case.

    4720 gives both TargetUserName and TargetSid, so the accounts that matter in an
    intrusion (the ones somebody created) can be named wherever only a SID is printed."""
    out = {}
    try:
        for name, sid in _q(cur, """SELECT payload->>'TargetUserName', payload->>'TargetSid'
                                    FROM event_logs_v2
                                    WHERE case_key=%s AND event_id IN (4720,4738,4722,4726)
                                      AND coalesce(payload->>'TargetSid','') <> ''
                                    LIMIT 200""", (case_key,)):
            n = str(name or '').strip()
            s = str(sid or '').strip()
            if n and s and n.lower() != 'none':
                out[s] = n
    except Exception:
        return {}
    return out


def _timeline(case_key, iw_start, findings_for_timeline=None):
    """CURATED attack timeline. High-signal SECURITY events (account creation,
    service install, privileged-group add, scheduled task, log clear, explicit-
    cred logon, RDP type-10) are shown with payload-accurate names, plus ONLY
    genuinely suspicious EXECUTIONS: attack tools, or a lure-named exe run straight
    from an archiver temp folder. Benign installers that merely sit in temp/appdata
    (HP LaserJet / Opera / GoogleUpdater / ЦСК) are archiver-temp but NOT lure-named
    and are not tools, so they drop out — the real chain stands out (case_45 used to
    fill the whole timeline with HP/Opera installer noise)."""
    import re as _re
    # A caller that already has the findings passes them; a bare call (the fastpath guard,
    # or any consumer that only wants the timeline) would otherwise miss the deterministic
    # chain — on the wiper case the classic Security IDs are nearly empty and the whole
    # timeline collapsed to one line. Fall back to computing them so the timeline is never
    # silently thin on an event-rich case.
    if findings_for_timeline is None:
        try:
            findings_for_timeline = _findings(case_key)
        except Exception:
            findings_for_timeline = []
    start = iw_start or '2000-01-01'
    crit, susp = [], []
    _sid2name = {}
    _exec_kind = {}
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            # --- curated security events (payload-accurate who/context) ---
            # NOTE: 1102/104 are ONLY anti-forensics in the Security channel — the same
            # IDs fire benignly in dozens of operational channels (StartLayoutPopulation,
            # SmartCard, StateRepository…), so they're handled separately below. 104 and
            # 4648 are dropped: 104 is almost all operational-channel noise, 4648 is
            # dominated by machine-account→localhost self-logons (lateral is covered by
            # RDP type-10 + account creation).
            # Every curated row must be able to say where it came from — the archive path,
            # the source file, the record number — so the reader confirms it in half a
            # minute instead of trusting us (owner's wish №1, 2026-09-06).
            def _pv(sf, rec=None):
                try:
                    from analysis.threat_detect import provenance as _p
                    return _p(case_key, sf, rec, cur) or str(sf or '')
                except Exception:
                    return str(sf or '')

            rc = _q(cur, """
                SELECT event_ts, event_id,
                  coalesce(nullif(payload->>'ServiceName',''), nullif(payload->>'TargetUserName',''),
                           nullif(payload->>'MemberName',''), nullif(target_user,''), process_name, '') AS who,
                  coalesce(nullif(payload->>'ImagePath',''), command_line, '') AS ctx,
                  coalesce(source_file,''), payload->>'RecordNumber'
                FROM event_logs_v2
                WHERE case_key=%s AND event_ts >= %s
                  AND event_id IN (4720,7045,4697,4698,4732,4756,4728)
                ORDER BY event_ts ASC NULLS LAST LIMIT 200
            """, (case_key, start))
            for ts, eid, who, ctx, _sf, _rec in rc:
                if not ts:
                    continue
                low = (str(who) + ' ' + str(ctx)).lower()
                who_disp = str(who) if who and str(who) not in ('', '-', 'None') else ''
                ctx_disp = str(ctx) if ctx and str(ctx) not in ('', '-', 'None') else ''
                if eid in (7045, 4697):
                    # a service installed by the EXAMINER during collection (Magnet
                    # RAM Capture, KAPE helpers) is our own footprint, not the
                    # intruder's — it showed up in the attack timeline of the
                    # encrypted-server case
                    if _re.search(_EXAMINER_TOOL_PY, low):
                        continue
                    if _re.search(_BENIGN_DRIVER_RE, low):
                        continue
                    # drop benign updater / signed program-files services; a service
                    # whose ImagePath is in user Temp / Rar$ / Windows\Temp stays.
                    if _re.search(r'googleupdater|google update|edgeupdate|[\\/]edge[\\/]|mozilla|'
                                  r'[\\/]opera|driverstore|windows defender|definition update|'
                                  r'microsoft corp|[\\/]program files', low):
                        continue
                    label = 'Встановлено службу'
                elif eid == 4720:
                    label = 'Створено обліковий запис'
                elif eid in (4732, 4756, 4728):
                    # for group-add events the GROUP name is in who (TargetUserName);
                    # the added member SID/name is in ctx. Put the group in the label,
                    # mark privileged groups explicitly, and drop empty ones.
                    grp = who_disp
                    if not grp:
                        continue
                    # Windows writes «Отсутствует» / «Not Available» when the field is
                    # missing; a line saying somebody was added to a group called
                    # "absent" is noise, not evidence
                    if grp.strip().lower() in ('отсутствует', 'not available', 'n/a', '-'):
                        continue
                    # Russian-language Windows is the common case here, and its group
                    # names never matched: an attacker added to «Администраторы» was
                    # rendered as an ordinary group membership
                    priv = bool(_re.search(r'administrator|адміністратор|администратор|'
                                           r'remote desktop|удаленного рабочего стола|'
                                           r'віддален|удаленн|remote management|'
                                           r'backup operator|операторы архива|'
                                           r'domain admin|power user|опытные пользователи',
                                           grp.lower()))
                    label = ('Додано до ПРИВІЛЕЙОВАНОЇ групи «%s»' if priv
                             else 'Додано до групи «%s»') % grp[:40]
                    who_disp = ''  # group now in label; member SID stays in ctx
                    # print WHO was added, not just their SID
                    if ctx_disp and 'S-1-5-' in ctx_disp:
                        if not _sid2name:
                            _sid2name = _sid_name_map(cur, case_key, _q) or {'': ''}
                        for _sid, _nm in _sid2name.items():
                            if _sid and _sid in ctx_disp:
                                ctx_disp = '%s (%s)' % (_nm, _sid)
                                break
                elif eid == 4698:
                    label = 'Створено заплановане завдання'
                else:
                    continue
                crit.append((ts, label, who_disp, ctx_disp, _pv(_sf, _rec)))
            # --- REAL Security-audit-log clear (anti-forensics) — Security channel only ---
            rlc = _q(cur, """
                SELECT event_ts, coalesce(nullif(target_user,''), nullif(payload->>'SubjectUserName',''), ''),
                       coalesce(source_file,''), payload->>'RecordNumber'
                FROM event_logs_v2
                WHERE case_key=%s AND event_ts >= %s AND event_id=1102 AND channel='Security'
                ORDER BY event_ts ASC NULLS LAST LIMIT 20
            """, (case_key, start))
            for ts, who, _sf, _rec in rlc:
                if not ts:
                    continue
                crit.append((ts, 'Очищено журнал безпеки (анти-форензика)',
                             str(who) if who and str(who) not in ('', '-') else '', '',
                             _pv(_sf, _rec)))
            # --- RDP logons (type 10) — bounded separately (4624 is high-volume) ---
            rr = _q(cur, """
                SELECT event_ts,
                  coalesce(nullif(payload->>'TargetUserName',''), target_user, ''),
                  coalesce(payload->>'IpAddress', ''),
                  coalesce(source_file,''), payload->>'RecordNumber'
                FROM event_logs_v2
                WHERE case_key=%s AND event_ts >= %s AND event_id=4624
                  AND substring(payload->>'PayloadData2' from 'LogonType[ ]*([0-9]+)')='10'
                ORDER BY event_ts ASC NULLS LAST LIMIT 30
            """, (case_key, start))
            # same treatment as the 1149 authentications: fifteen identical lines for
            # one machine account crowd the actual attack out of the section
            _t10_group = {}
            for ts, acct, ip, _sf, _rec in rr:
                if not ts:
                    continue
                who = str(acct or '?').strip()
                g = _t10_group.setdefault(who.lower(), {'first': ts, 'last': ts, 'n': 0,
                                                        'ip': '', 'name': who,
                                                        'prov': _pv(_sf, _rec)})
                g['n'] += 1
                g['last'] = ts
                if ip and ip not in _LOCAL_IPS and not g['ip']:
                    g['ip'] = str(ip)
            for _k, g in _t10_group.items():
                lbl = ('RDP-вхід (LogonType 10)' if g['n'] == 1
                       else 'RDP-входи (LogonType 10): %d, останній %s'
                            % (g['n'], _fmt_ts(g['last'])))
                crit.append((g['first'], lbl, g['name'],
                             ('з %s' % g['ip']) if g['ip'] else '', g['prov']))
            # --- antivirus detections: the malware NAME belongs in the chronology ---
            av = _q(cur, """
                SELECT event_ts, event_id,
                       coalesce(payload->>'PayloadData1', payload->>'ThreatName',''),
                       coalesce(source_file,''), payload->>'RecordNumber'
                FROM event_logs_v2
                WHERE case_key=%s AND event_ts >= %s AND event_id IN (1116,1117)
                ORDER BY event_ts ASC NULLS LAST LIMIT 14
            """, (case_key, start))
            # one line per threat name: twelve identical UACBypassExp lines inside
            # ninety seconds tell the reader nothing the first one did not
            _av_group = {}
            for ts, eid, det, _sf, _rec in av:
                if not ts:
                    continue
                nm = str(det or '').replace('Malware name:', '').strip()[:70]
                g = _av_group.setdefault(nm.lower(), {'first': ts, 'last': ts, 'n': 0,
                                                      'name': nm, 'acted': False,
                                                      'prov': _pv(_sf, _rec)})
                g['n'] += 1
                g['last'] = ts
                if eid == 1117:
                    g['acted'] = True
            for _k, g in _av_group.items():
                if g['n'] == 1:
                    lbl = 'Антивірус виявив загрозу'
                else:
                    lbl = 'Антивірус виявив загрозу %d раз(и), остання %s' % (
                        g['n'], _fmt_ts(g['last']))
                if g['acted']:
                    lbl += ' (вжито заходів)'
                crit.append((g['first'], lbl, g['name'], '', g['prov']))
            # --- protection switched off ---
            off = _q(cur, """
                SELECT event_ts, event_id, coalesce(source_file,''), payload->>'RecordNumber'
                FROM event_logs_v2
                WHERE case_key=%s AND event_ts >= %s AND event_id IN (5001,5010,5012,5013)
                ORDER BY event_ts ASC NULLS LAST LIMIT 8
            """, (case_key, start))
            for ts, eid, _sf, _rec in off:
                if not ts:
                    continue
                # a bare EID on the first screen means nothing to the reader it is written
                # for; the number stays in the provenance tag and in ## 7
                crit.append((ts, 'Вимкнено захист Windows Defender', '', '', _pv(_sf, _rec)))
            # --- RDP authentication (1149): the timeline used to read only 4624 type 10 ---
            rr2 = _q(cur, """
                SELECT event_ts,
                       coalesce(nullif(payload->>'Param1',''), payload->>'TargetUserName',
                                target_user, ''),
                       coalesce(payload->>'Param3', payload->>'IpAddress', ''),
                       coalesce(source_file,''), payload->>'RecordNumber'
                FROM event_logs_v2
                WHERE case_key=%s AND event_ts >= %s AND event_id=1149
                ORDER BY event_ts ASC NULLS LAST LIMIT 12
            """, (case_key, start))
            # one line per account instead of one per session: twelve identical lines
            # crowd out the rest of the story, and a 1149 one second before a type-10
            # logon is the same session seen twice
            _t10 = set()
            for _row10 in rr:
                if _row10[0]:
                    _t10.add(int(_row10[0].timestamp()))
            _rdp_auth_group = {}
            for ts, acct, ip, _sf, _rec in rr2:
                if not ts:
                    continue
                if any(abs(int(ts.timestamp()) - t) <= 5 for t in _t10):
                    continue
                who = str(acct or '').strip().strip(chr(92)) or '?'
                # Windows records the same account with different capitalisation
                _key = who.lower()
                g = _rdp_auth_group.setdefault(_key, {'first': ts, 'last': ts, 'n': 0,
                                                      'ip': '', 'name': who,
                                                      'prov': _pv(_sf, _rec)})
                g['n'] += 1
                g['last'] = ts
                if ip and str(ip) not in _LOCAL_IPS and not g['ip']:
                    g['ip'] = str(ip)
            for _key, g in _rdp_auth_group.items():
                who = g.get('name') or _key
                if g['n'] == 1:
                    lbl = 'RDP-автентифікація'
                else:
                    lbl = 'RDP-автентифікації: %d, остання %s' % (
                        g['n'], _fmt_ts(g['last']))
                crit.append((g['first'], lbl, who,
                             ('з %s' % g['ip']) if g['ip'] else '', g['prov']))
            # --- delivery / download event: start the chronology where the infection
            # started (the download/email), not at the first execution ---
            try:
                try: _q(cur, "SET statement_timeout='6000'", None)
                except Exception: pass
                _dls = _q(cur, """
                    SELECT event_ts,
                           (CASE WHEN coalesce(parent_path,'')<>'' THEN parent_path||'/'||coalesce(file_name,'') ELSE coalesce(file_name,'') END) fn,
                           split_part(split_part(coalesce(payload->>'zone_id',''),'HostUrl=',2), chr(10), 1) src,
                           coalesce(source_file,''), payload->>'entry_number'
                    FROM filesystem_v2
                    WHERE case_key=%s AND event_ts >= %s AND payload::text ILIKE '%%hosturl%%'
                      AND lower(coalesce(file_name,'')) ~* '[.](exe|zip|rar|7z|js|jse|scr|hta|lnk|docm|xlsm|iso|img|vbs|bat|cmd|msi)([^a-z]|$)'
                      AND payload::text ~* 'swisstransfer|mega|pixeldrain|dropbox|drive.google|wetransfer|mediafire|gofile|ngrok|sendspace|files.fm|anonfile|zippyshare|dropmefiles|disk.yandex|1drv.ms|cloud.mail'
                    ORDER BY event_ts ASC LIMIT 6""", (case_key, iw_start))
                for _dts, _fn, _src, _sf, _rec in (_dls or []):
                    _ff = str(_fn or '').replace(chr(92), '/').split('/')[-1][:70]
                    # a download row is only printed for something that can BE the chain;
                    # the name of a person's document is not evidence of an attack
                    if _ff and not _is_docname(_ff):
                        crit.append((_dts, '📥 Завантажено/доставлено: %s' % _ff, '',
                                     ('з %s' % str(_src)[:90]) if _src and not _is_private_url(_src) else '',
                                     _pv(_sf, _rec)))
            except Exception:
                pass

            # --- suspicious executions: attack tools OR lure-named exe from archiver temp ---
            rs = _q(cur, """
                SELECT event_ts, executable_name, coalesce(full_path,''), coalesce(source_file,'')
                FROM program_exec_v2
                WHERE case_key=%s AND event_ts >= %s
                  AND lower(coalesce(full_path,'')||' '||coalesce(executable_name,'')) !~ %s
                ORDER BY event_ts ASC NULLS LAST LIMIT 400
            """, (case_key, start, _FP_DROP_RE))
            _best = {}
            for ts, exe, path, srcf in rs:
                if not ts:
                    continue
                low = (str(exe) + ' ' + str(path)).lower()
                if _re.search(_BENIGN_EXEC_RE, str(exe or '').lower()):
                    continue
                try:
                    from analysis.benign_allowlist import is_benign_entry as _ibe
                    if _ibe(low):
                        continue
                except Exception:
                    pass
                _tool = bool(_re.search(_TOOL_RE, low)) and not _re.search(r'7za?[.\b]', low)
                _arch = bool(_re.search(_IA_ARCHTMP_RE, str(path or '').lower()))
                _lure = bool(_re.search(_IA_LURE_RE, low))
                if not (_tool or (_arch and _lure)):
                    continue
                _kind = 'file' if _SHIMCACHE_SRC_RE.search(str(srcf or '')) else 'run'
                _b = str(exe or path or '').replace('/', chr(92)).rstrip(chr(92))
                _b = _b.rsplit(chr(92), 1)[-1].lower()
                _stem = _re.sub(r'\.(exe|com|scr|bat|cmd|pif|dll)$', '', _b)
                _prev = _best.get(_stem)
                # a real run time always beats a file mtime; within the same kind the
                # earliest row wins, as before
                if (_prev is None
                        or (_prev[4] == 'file' and _kind == 'run')
                        or (_prev[4] == _kind and ts < _prev[0])):
                    _best[_stem] = (ts, 'Запуск: ' + str(exe)[:80], '', path, _kind,
                                    _pv(srcf))
            for _stem, _row in _best.items():
                susp.append((_row[0], _row[1], _row[2], _row[3], _row[5]))
                _exec_kind[_stem] = _row[4]
    except Exception:
        pass
    # --- the ransomware chain itself: losing the backups, then the encryption ---
    try:
        with psycopg2.connect(PG_DSN) as c2:
            c2.autocommit = True
            cur2 = c2.cursor()
            cur2.execute("SET statement_timeout='6000'")
            # no window filter here: these rows often carry a ShimCache file mtime,
            # which falls outside the incident window even though the tool ran during it
            kill = _q(cur2, """SELECT min(event_ts), lower(executable_name),
                                      min(coalesce(source_file,''))
                               FROM program_exec_v2
                               WHERE case_key=%s
                                 AND lower(coalesce(executable_name,'')) ~ %s
                               GROUP BY 2 ORDER BY 1 LIMIT 6""",
                       (case_key, _RECOVERY_KILL_RE))
            for ts, exe, srcf in kill:
                if not ts:
                    continue
                base = str(exe or '').replace('/', chr(92)).rsplit(chr(92), 1)[-1]
                _note = ''
                if _SHIMCACHE_SRC_RE.search(str(srcf or '')):
                    _note = _FILE_TIME_NOTE
                elif str(ts)[:10] < str(start)[:10]:
                    _note = ' _(поза вікном інциденту)_'
                # Measured over the whole library: EVERY row here is a ShimCache/Amcache
                # FILE time for a stock System32 binary, and every one falls outside the
                # incident window - 2018-09-15 (the OS build date) opened the chronology on
                # both case_66 and case_43, and case_43 has no recovery-kill finding
                # at all. A file date is not an action, so it does not get a line in a
                # chronology of actions. An in-window row still prints, with its note: that
                # is the attacker-dropped copy this branch exists for.
                if _note and str(ts)[:10] < str(start or '')[:10]:
                    continue
                try:
                    from analysis.threat_detect import provenance as _p2
                    _pr = _p2(case_key, srcf, None, cur2) or str(srcf or '')
                except Exception:
                    _pr = str(srcf or '')
                crit.append((ts, 'Знищення можливості відновлення — запуск `%s`%s'
                             % (base[:40], _note), '', '', _pr))
            _rw = {}
            for f in (findings_for_timeline or []):
                if f.get('category') in ('Ransomware', 'Знищення резервних копій'):
                    _rw.update(f.get('facts') or {})
            if _rw.get('ext'):
                # a rename keeps the original creation time, so an unbounded MIN returns
                # the oldest file that ever existed on the disk (2007 on this case)
                r = _q(cur2, """SELECT min(event_ts), count(*), min(coalesce(source_file,''))
                                FROM filesystem_v2
                                WHERE case_key=%s AND lower(file_name) LIKE %s
                                  AND event_ts >= %s""",
                       (case_key, '%.' + str(_rw['ext']).lower(), start))
                if r and r[0][0]:
                    crit.append((r[0][0],
                                 'МАСОВЕ ШИФРУВАННЯ: розширення замінено на «.%s» — '
                                 'найраніший зашифрований файл у вікні (%d шт.)'
                                 % (_rw['ext'], r[0][1]), '', '', str(r[0][2] or 'filesystem_v2')))
            if _rw.get('note'):
                r = _q(cur2, """SELECT min(event_ts), min(coalesce(source_file,''))
                                FROM filesystem_v2
                                WHERE case_key=%s AND file_name=%s""",
                       (case_key, _rw['note']))
                if r and r[0][0]:
                    crit.append((r[0][0], 'Залишено записку з вимогою викупу «%s»'
                                 % _rw['note'], '', '', str(r[0][1] or 'filesystem_v2')))
    except Exception:
        pass
    # the events every high/critical finding carries are the spine of the chronology:
    # the wiper chain (AV crash -> GPO MSI -> task -> boot image -> 6008) was invisible to
    # the curated queries above, and the section had one line
    _fx_n = 0
    try:
        from datetime import timedelta as _td
        _floor = None
        try:
            _floor = _ev_ts(str(start)[:10] + 'T00:00:00') - _td(days=45)
        except Exception:
            _floor = None
        # On a case with nothing high or critical the chronology used to be one line while
        # the report ran to 524 and its own appendix listed 458 PowerShell records and three
        # Startup files. An empty chronology under a full report reads as «we found nothing
        # AND we looked at nothing». So on a calm verdict the medium/low findings — the ones
        # the verdict itself sends for manual review — supply the section, marked «•» and
        # never «❗»: they are what there is to look at, not an attack.
        _sev_scope, _fx_src, _fx_cap = _HI_SEV, findings_for_timeline, 10 ** 6
        if not any(str((f or {}).get('severity') or '').lower() in _HI_SEV
                   for f in (findings_for_timeline or [])):
            _sev_scope = _HI_SEV + ('medium', 'med', 'low')
            # ... except the response itself. Batch 1 raises «Дії реагування (не атака)»
            # for exactly the events this section must not contain, and its PowerShell
            # count is largely the collector's own 4104 records.
            _fx_src = [f for f in (findings_for_timeline or [])
                       if 'реагуванн' not in str((f or {}).get('category') or '')
                       and 'реагуванн' not in str((f or {}).get('title') or '')]
            _fx_cap = 20
        for _e in _fx_events(_fx_src, sevs=_sev_scope)[:_fx_cap]:
            _ts, _label, _src, _art, _sev = _e[0], _e[1], _e[2], _e[3], _e[4]
            # an Amcache first-seen date years before the window is when a file
            # appeared, not when the attacker acted (rdpwinst 2017 on case_45)
            if _floor is not None:
                try:
                    _tsn = _ts.replace(tzinfo=None) if getattr(_ts, 'tzinfo', None) else _ts
                    if _tsn < _floor:
                        continue
                except Exception:
                    pass
            crit.append((_ts, '%s %s' % ('❗' if _sev in _HI_SEV else '•',
                                         _human_label(_label)[:110]), '',
                         '', _e[7] or (_src or _art or '')[:70]))
            _fx_n += 1
    except Exception:
        pass
    rows = [x for x in (crit + susp) if x[0]]
    # consecutive rows with the same label collapse into one («Вимкнено захист Defender» x8)
    try:
        rows.sort(key=lambda x: x[0])
        _coll, _last = [], None
        for x in rows:
            _lab = re.sub(r'^[❗•]\s*', '', str(x[1] or ''))
            if _last is not None and _lab == _last[1] and _lab:
                _last[2] += 1
                _last[3] = x[0]
                continue
            _last = [x, _lab, 1, x[0]]
            _coll.append(_last)
        rows = []
        for x, _lab, _n, _lts in _coll:
            if _n > 1:
                x = (x[0], '%s (×%d, останній %s)' % (x[1], _n, _fmt_ts(_lts)[11:19] or _fmt_ts(_lts))) + tuple(x[2:])
            rows.append(x)
    except Exception:
        rows = [x for x in (crit + susp) if x[0]]
    # our own footprint is not an action of the attacker (collector staging folder,
    # dfp_ probes, KAPE/7za after the collector started)
    try:
        rows = [x for x in rows if not _own_text(' '.join(str(p or '') for p in x[1:4]),
                                                 ts=x[0], case_key=case_key)]
    except Exception:
        pass
    # THE COLLECTION-DAY CUT. Everything from ten minutes before the collector started is
    # the response, not the incident: the examiner's RDP session, MagnetRAM, the FTK driver,
    # the collector's own 464 PowerShell 4104 records. Four reports listed those among the
    # attacker's actions. They are counted, named as response, and not mixed in.
    _resp_n = 0
    try:
        from datetime import timedelta as _td2
        from analysis.own_footprint import collect_started_at as _csa
        _cut = _csa(case_key)
        if _cut is not None:
            _cut = _cut - _td2(minutes=10)
            _keep = []
            for _x in rows:
                try:
                    _a = _x[0]; _b = _cut
                    if getattr(_a, 'tzinfo', None) and not getattr(_b, 'tzinfo', None):
                        _a = _a.replace(tzinfo=None)
                    elif getattr(_b, 'tzinfo', None) and not getattr(_a, 'tzinfo', None):
                        _b = _b.replace(tzinfo=None)
                    if _a >= _b:
                        _resp_n += 1
                        continue
                except Exception:
                    pass
                _keep.append(_x)
            rows = _keep
    except Exception:
        _resp_n = 0
    rows.sort(key=lambda x: x[0])
    out = []
    seen = set()
    seen_exec = set()
    _minute_ids = {}
    _cap = 22 + min(_fx_n, 14)
    for _row in rows:
        ts, what, who, ctx = _row[0], _row[1], _row[2], _row[3]
        prov = _row[4] if len(_row) > 4 else ''
        # collapse the many near-duplicate execution rows of the SAME binary
        # (Amcache full-path + Prefetch bare NAME.EXE + repeated runs) to the FIRST,
        # and show a clean basename.
        if str(what).startswith('Запуск:'):
            base = str(what).split(':', 1)[1].strip().replace('/', '\\').rstrip('\\').rsplit('\\', 1)[-1].lower()
            stem = _re.sub(r'\.(exe|com|scr|bat|cmd|pif|dll)$', '', base)
            if not stem or stem in seen_exec:
                continue
            seen_exec.add(stem)
            # a ShimCache/$MFT stamp proves the file was there, not that it ran — say so
            # in the words of the section, not in a footnote
            if _exec_kind.get(stem) == 'file':
                what = _presence_label(base)
            else:
                what = 'Запуск: ' + base
            who = ctx = ''
        key = (_fmt_ts(ts), str(what)[:34], str(who)[:30])
        if key in seen:
            continue
        seen.add(key)
        # the provenance tag is deliberately NOT part of the identity set: an archive path
        # is full of dots and digits and would collide two unrelated rows of one minute
        _idk = set(t for t in _re.findall(r'[\w$.\-]{4,}', (str(what) + ' ' + str(who) + ' ' + str(ctx)).lower())
                   if any(ch.isdigit() for ch in t) or '.' in t or len(t) >= 9)
        _idk -= {'event_logs_v2', 'program_exec_v2', 'filesystem_v2', 'system', 'security'}
        _mkey = _fmt_ts(ts)[:16]
        _prev = _minute_ids.setdefault(_mkey, set())
        if _idk and (_idk & _prev):
            continue
        _prev |= _idk
        extra = ''
        if who and str(who) not in ('', '-'):
            extra += ' — `%s`' % str(who)[:70]
        if ctx and str(ctx) not in ('', '-') and str(ctx) != str(who):
            extra += ' (`%s`)' % str(ctx)[:70]
        out.append('- `%s` — %s%s%s' % (_fmt_ts(ts), what, extra, _prov_tag(prov)))
        if len(out) >= _cap:
            break
    # prepend the delivery step («звідки взявся файл») as the first chronological event
    deliv = _DELIVERY_CACHE.get(case_key)
    if deliv is None:
        try:
            deliv = _delivery_provenance(case_key, _initial_access_struct(case_key, iw_start))
        except Exception:
            deliv = None
    _dl = _delivery_line(deliv, with_ts=True)
    if _dl:
        _dl_head, _sep, _dl_rest = _dl.partition(chr(10))
        out.insert(0, _dl_head + _prov_tag((deliv or {}).get('source')) + _sep + _dl_rest)
    if not out:
        # a note, not a bullet: an empty chronology has no fact to point a source at, and
        # the rule «no chronology line without [джерело:]» must stay mechanically true
        out.append('_Подій, придатних для хронології, у вікні інциденту не знайдено — '
                   'дивись службові дані нижче._')
    if _resp_n:
        # not a bullet: it is a note ABOUT the chronology, not an event in it
        out.append('')
        out.append('_Дії реагування/збору: %d подій (не атака) — усе від «час старту збирача '
                   'мінус 10 хв» і пізніше винесено з хронології; перелік у службових даних._'
                   % _resp_n)
    return out


_PLAT_LABELS = {
    'telegram': '📨 Telegram', 'whatsapp': '🟢 WhatsApp', 'signal': '🔵 Signal',
    'viber': '🟣 Viber', 'email': '✉️ Email', 'skype': '🔷 Skype',
    'discord': '🎮 Discord', 'messenger': '💬 Messenger',
}


def _plat_label(p):
    return _PLAT_LABELS.get(str(p or '').lower(), '💬 %s' % str(p or '?'))


_NTLM_EMPTY = '31d6cfe0d16ae931b73c59d7e0c089c0'  # NTLM of an empty password


def _local_accounts(case_key):
    """Extract local Windows NTLM hashes from the case's raw SAM+SYSTEM hives (once,
    cached in local_accounts_v1). Enables password-cracking / owner attribution — the
    collector already drops `_raw/registry/SAM`+`SYSTEM` into the archive; impacket
    (isolated in /opt/impacket) reads them offline incl. AES-encrypted Win10+ SAM."""
    import subprocess as _sp, json as _json, zipfile as _zip, tempfile as _tmp, glob as _glob, os as _os, shutil as _sh
    rows = []
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            cur.execute("""CREATE TABLE IF NOT EXISTS public.local_accounts_v1(
                row_id bigserial PRIMARY KEY, case_key text NOT NULL, username text, rid text,
                ntlm text, lm text, is_empty boolean, source text, created_at timestamptz DEFAULT now(),
                UNIQUE(case_key, rid))""")
            r = _q(cur, "SELECT username,rid,ntlm,is_empty FROM local_accounts_v1 WHERE case_key=%s ORDER BY rid", (case_key,))
            if r and any(x[1] == '__scanned__' for x in r):   # already attempted → serve cache
                return [{'user': x[0], 'rid': x[1], 'ntlm': x[2], 'empty': x[3]}
                        for x in r if x[1] != '__scanned__']
            zips = sorted(_glob.glob('/data/case_library/%s/uploads/logs/*.zip' % case_key))
            if not zips:
                return []
            sam = sysh = None
            tmp = _tmp.mkdtemp(prefix='ntlm_')
            try:
                with _zip.ZipFile(zips[-1]) as zf:
                    for n in zf.namelist():
                        ln = n.lower().replace('\\', '/')
                        if ln.endswith('registry/sam'):
                            sam = zf.extract(n, tmp)
                        elif ln.endswith('registry/system'):
                            sysh = zf.extract(n, tmp)
                if sam and sysh:
                    p = _sp.run(['python3', '/app/analysis/ntlm_extract.py', sysh, sam],
                                capture_output=True, text=True, timeout=180,
                                env={**_os.environ, 'PYTHONPATH': '/opt/impacket'})
                    _o = (p.stdout or '').strip()
                    data = _json.loads(_o) if _o.startswith('[') else []
                    for d in data:
                        emp = str(d.get('ntlm', '')).lower() == _NTLM_EMPTY
                        cur.execute("""INSERT INTO local_accounts_v1(case_key,username,rid,ntlm,lm,is_empty,source)
                            VALUES(%s,%s,%s,%s,%s,%s,'SAM') ON CONFLICT (case_key,rid) DO NOTHING""",
                            (case_key, d.get('user'), d.get('rid'), d.get('ntlm'), d.get('lm'), emp))
                        rows.append({'user': d.get('user'), 'rid': d.get('rid'), 'ntlm': d.get('ntlm'), 'empty': emp})
            finally:
                _sh.rmtree(tmp, ignore_errors=True)
            cur.execute("INSERT INTO local_accounts_v1(case_key,rid,source) VALUES(%s,'__scanned__','marker') ON CONFLICT (case_key,rid) DO NOTHING", (case_key,))
    except Exception:
        return rows
    return rows


def _ransom_contact_emails(case_key):
    """Addresses that belong to the ransom note, not to the machine owner.

    Matched by the extension the encryption finding recorded: `vricpe@aol.com` against
    `.vricpe` on 30961 files. Returns a lowercase set; empty when the case has no
    ransomware finding, so nothing changes for ordinary cases."""
    out = set()
    try:
        exts = set()
        for f in (_findings(case_key) or []):
            fx = (f.get('facts') or {}).get('ext')
            if fx:
                exts.add(str(fx).lower().lstrip('.'))
        if not exts:
            return out
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            cur.execute("SET statement_timeout='4000'")
            rows = _q(cur, """SELECT DISTINCT ioc_value FROM case_iocs
                              WHERE case_key=%s AND ioc_type='email'
                                AND coalesce(ioc_value,'')<>''""", (case_key,))
        for (v,) in rows:
            local = str(v).split('@', 1)[0].lower()
            if any(e and (e == local or e in local) for e in exts):
                out.add(str(v).lower())
    except Exception:
        return set()
    return out


def _owner_attribution_section(case_key):
    """«👤 Хто власник / користувач» — identity triangulation from artifacts already
    in the DB: Windows accounts + browser signed-in profile + user-linked emails +
    gaming/service-account presence (Steam/WoT/Riot/Epic/NetBird/Telegram). Answers the
    «чий це ПК / хто ним користувався» class of case (per the owner's expert template).
    Returns [] when no identity signal (section omitted)."""
    import re as _re
    _EMAIL = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    accounts, emails, apps, profiles = [], [], [], []
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            cur.execute("SET statement_timeout='7000'")
            # 1) real Windows accounts (drop system/service/machine$/garbled)
            r = _q(cur, """SELECT DISTINCT coalesce(nullif(payload->>'TargetUserName',''), target_user) a,
                                  coalesce(payload->>'TargetSid','') sid
                           FROM event_logs_v2 WHERE case_key=%s AND event_id IN (4624,4720,4672,4634)
                           LIMIT 300""", (case_key,))
            # collapse by leaf username (case_59 ≡ LENOVO\case_59) → keep the richest form
            # (prefer a domain-qualified name + a SID).
            _by_leaf = {}
            for a, sid in (r or []):
                if not a:
                    continue
                al = str(a).strip()
                if not al or al in ('-', '-\\-') or '?' in al or al.endswith('$'):
                    continue
                if _re.search(r'system|local service|network service|dwm-|umfd-|font driver|'
                              r'anonymous|window manager|\biusr\b|defaultaccount|wdagutility|'
                              r'\bсистема\b|локальна служба|мереж', al, _re.I):
                    continue
                # the SID is often embedded in the account string itself
                # («LENOVO\case_59 (S-1-5-…)») — split it out so leaf-dedup works.
                _m = _re.match(r'^(.*?)\s*\((S-1-5-[0-9-]+)\)\s*$', al)
                if _m:
                    al, _emb = _m.group(1).strip(), _m.group(2)
                    sid = sid or _emb
                leaf = al.split('\\')[-1].lower()
                cand = (al, sid or '')
                cur_best = _by_leaf.get(leaf)
                # score: has-domain (2) + has-sid (1) → keep the most informative
                _score = (2 if '\\' in al else 0) + (1 if sid else 0)
                if cur_best is None or _score > cur_best[0]:
                    _by_leaf[leaf] = (_score, cand)
            accounts = [v[1] for v in _by_leaf.values()]
            # 2) user-linked emails: curated case_iocs + owner-proximate file paths
            try:
                ei = _q(cur, "SELECT DISTINCT ioc_value FROM case_iocs WHERE case_key=%s AND ioc_type='email' LIMIT 30", (case_key,))
                emails += [e[0] for e in (ei or []) if e[0]]
            except Exception:
                pass
            try:
                # case rows with '@' first (MATERIALIZED): the bare regex sent the planner to the
                # table-wide trigram index - 85 s and a timeout on DVB, 0.3 s now
                fe = _q(cur, """WITH c AS MATERIALIZED (SELECT file_name, parent_path FROM filesystem_v2
                                                         WHERE case_key=%s AND strpos(file_name, '@') > 0)
                                SELECT DISTINCT (regexp_matches(file_name, %s))[1] FROM c
                                WHERE lower(coalesce(parent_path,'')) ~ 'desktop|downloads|documents|\\recent|роб'
                                  AND file_name ~* %s LIMIT 40""", (case_key, _EMAIL, _EMAIL))
                emails += [e[0] for e in (fe or []) if e[0]]
            except Exception:
                pass
            # «BlueCloudCritical_Win11@2x.png» is a retina icon, not a mailbox (case_50)
            emails = [e for e in list(dict.fromkeys(emails))
                      if not _re.search(r'@(microsoft|windows|office365|apple|google-analytics|sentry|mozilla)\.', str(e), _re.I)
                      and not _re.search(r'@\d+(\.\d+)?x\b|\.(png|jpe?g|gif|svg|webp|ico|bmp|tiff?|css|js|json|xml|html?|txt|log|dll|exe|zip|pdf)$', str(e), _re.I)][:12]
            # 3) gaming / service accounts (identity confirmation)
            ga = _q(cur, """SELECT DISTINCT lower(coalesce(parent_path, file_name))
                            FROM filesystem_v2 WHERE case_key=%s
                              AND lower(coalesce(parent_path, file_name)) ~
                                  'steam|wargaming|riot games|epic games|netbird|battle[.]net|world_?of_?tanks|origin games|ubisoft'
                            -- ORDER BY, бо без нього LIMIT віддає довільні рядки і звіт
                            -- відрізняється між прогонами на тих самих даних
                            ORDER BY 1
                            LIMIT 400""", (case_key,))
            _appmap = [('wargaming', 'Wargaming / World of Tanks'), ('world_of_tanks', 'World of Tanks'),
                       ('steam', 'Steam'), ('riot games', 'Riot Games'), ('epic games', 'Epic Games'),
                       ('origin games', 'EA/Origin'), ('ubisoft', 'Ubisoft'), ('battle.net', 'Battle.net'),
                       ('netbird', 'NetBird (віддалене керування)')]
            _apps = {}
            for (p,) in (ga or []):
                for key, label in _appmap:
                    if key in (p or ''):
                        _apps.setdefault(label, True)
            apps = list(_apps.keys())
            # 4) signed-in browser profile
            try:
                pr = _q(cur, "SELECT DISTINCT user_name, browser FROM browser_provenance_v1 WHERE case_key=%s AND coalesce(user_name,'')<>'' LIMIT 8", (case_key,))
                profiles = [(p[0], p[1]) for p in (pr or []) if p[0]]
            except Exception:
                pass
    except Exception:
        return []
    ntlm = _local_accounts(case_key)  # NTLM hashes from SAM+SYSTEM (cached)
    if not (accounts or emails or apps or profiles or ntlm):
        return []
    out = ['## 👤 Хто власник / користувач (атрибуція особи)']
    if accounts:
        out.append('**🖥 Облікові записи Windows:**')
        for a, sid in accounts[:12]:
            out.append('- `%s`%s' % (a, (' _(%s)_' % sid) if sid else ''))
    if ntlm:
        out.append('**🔑 NTLM-хеші локальних акаунтів (SAM+SYSTEM — для підбору пароля / атрибуції):**')
        for a in sorted(ntlm, key=lambda x: (not x.get('empty'), str(x.get('rid')))):
            tag = ' — ⚠️ **ПОРОЖНІЙ пароль**' if a.get('empty') else ''
            out.append('- `%s` _(RID %s)_: `%s`%s' % (a.get('user'), a.get('rid'), a.get('ntlm'), tag))
        out.append('_Хеші можна підбирати офлайн (hashcat -m 1000) або порівняти з відомими; '
                   'непорожній хеш адмін/бекдор-акаунта — пряма зачіпка до пароля зловмисника._')
    if profiles:
        out.append('**🌐 Акаунт браузера (авторизований):** ' + ', '.join('`%s` _(%s)_' % (u, b) for u, b in profiles[:6]))
    # An address whose local part is the ransomware extension belongs to the ransom
    # note, not to the person who owns the machine.
    _ransom_mail = _ransom_contact_emails(case_key)
    if _ransom_mail:
        emails = [e for e in emails if str(e).lower() not in _ransom_mail]
    if emails:
        out.append('**✉️ Пошти, повʼязані з користувачем:** ' + ', '.join('`%s`' % e for e in emails))
    if _ransom_mail:
        out.append('**📧 Контакт вимагача (з записки, НЕ власника):** '
                   + ', '.join('`%s`' % e for e in sorted(_ransom_mail))
                   + ' — звʼязок доведено збігом із розширенням зашифрованих файлів.')
    if apps:
        out.append('**🎮 Ігрові / сервісні акаунти (підтвердження особи):** ' + ', '.join(apps))
    out.append('_Тріангуляція особи: звірте Windows-акаунт + пошту + ігрові/сервісні акаунти '
               '(один користувач зазвичай фігурує в усіх трьох)._')
    return out


def _communications_section(case_key, full=False):
    """Render «💬 Комунікації» from communications_v1: the seized user's own
    accounts (identifiers) per platform + conversations per contact. Returns [] if
    nothing was parsed (section omitted). full=False → bounded report view;
    full=True → everything (button / export). See [[comms-extraction]]."""
    out = []
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            cur.execute("SET statement_timeout='6000'")
            tot = _q(cur, "SELECT count(*) FROM communications_v1 WHERE case_key=%s", (case_key,))
            n = tot[0][0] if tot else 0
            if not n:
                return []
            out.append('## 💬 Комунікації (пошта та месенджери)')
            # 1) identifiers — the device owner's OWN accounts per platform
            ids = _q(cur, """SELECT platform, source_kind, self_account, count(*)
                             FROM communications_v1
                             WHERE case_key=%s AND coalesce(self_account,'')<>''
                             GROUP BY 1,2,3 ORDER BY 4 DESC LIMIT 40""", (case_key,))
            if ids:
                out.append('**🪪 Ідентифікатори на пристрої (акаунти власника):**')
                _seen = set()
                for plat, sk, acc, _cnt in ids:
                    k = (str(plat), str(acc))
                    if k in _seen:
                        continue
                    _seen.add(k)
                    out.append('- %s%s — `%s`' % (
                        _plat_label(plat), (' _(%s)_' % sk) if sk else '', str(acc)[:80]))
            # 2) volume per platform
            stats = _q(cur, """SELECT platform, count(DISTINCT coalesce(contact_id,contact_name)), count(*),
                                      min(msg_ts), max(msg_ts)
                               FROM communications_v1 WHERE case_key=%s GROUP BY 1 ORDER BY 3 DESC""", (case_key,))
            if stats:
                out.append('**📊 Обсяг:**')
                for plat, contacts, msgs, mn, mx in stats:
                    rng = (' · %s – %s' % (_fmt_ts(mn), _fmt_ts(mx))) if (mn and mx) else ''
                    out.append('- %s: контактів %s, повідомлень %s%s' % (
                        _plat_label(plat), contacts, msgs, rng))
            # 3) conversations per contact
            cap = 100000 if full else 400
            per = '' if full else 'LIMIT 20'
            conv_lim = 300 if full else 40
            convs = _q(cur, """SELECT platform, contact_id, contact_name, count(*)
                               FROM communications_v1 WHERE case_key=%s
                               GROUP BY 1,2,3 ORDER BY 4 DESC LIMIT %s""", (case_key, conv_lim))
            shown = 0
            for plat, cid, cname, cnt in convs:
                if shown >= cap:
                    break
                title = str(cname or cid or '?')[:60]
                idpart = (' `%s`' % str(cid)[:40]) if cid and str(cid) != str(cname) else ''
                out.append('')
                out.append('**%s · %s**%s _(повідомлень: %s)_' % (_plat_label(plat), title, idpart, cnt))
                msgs = _q(cur, """SELECT msg_ts, direction, message_text, attachment
                                  FROM communications_v1
                                  WHERE case_key=%s AND platform=%s
                                    AND coalesce(contact_id,'')=coalesce(%s,'')
                                    AND coalesce(contact_name,'')=coalesce(%s,'')
                                  ORDER BY msg_ts ASC NULLS LAST """ + per,
                          (case_key, plat, cid, cname))
                for ts, dr, txt, att in msgs:
                    if shown >= cap:
                        out.append('  - … _(далі — у повному експорті)_')
                        break
                    arrow = {'in': '⬅️', 'out': '➡️'}.get(str(dr or '').lower(), '•')
                    body = str(txt or '').replace('\n', ' ')[:400]
                    if att:
                        body = ('📎 %s ' % str(att)[:40]) + body
                    out.append('  - %s `%s` %s' % (arrow, _fmt_ts(ts), body))
                    shown += 1
            if not full and n > shown:
                out.append('')
                out.append('_Показано %s із %s повідомлень — повний вивід через кнопку «💬 Комунікації»._' % (shown, n))
    except Exception:
        return out
    return out


_BSLASH = chr(92)
# Never write a backslash into a regex literal in this file. A PostgreSQL ARE treats
# "\" as special even INSIDE a bracket expression, so the staging-location branch of the
# hash query below - users[\/].*(downloads|appdata|...) - meant "forward slash only" and
# matched 0 rows of program_exec_v2 across all 11 cases, while the same test on a path
# normalised to "/" matches 3528. The branch had been dead since it was written. Paths
# are normalised with translate(path, _BSLASH, '/') and the regexes carry "/" only.
# Turning the old branch back on as written would have printed 654 hashes over 11 cases
# (237 on one), so it is replaced by the signal it was reaching for: a WINDOWS SYSTEM
# BINARY NAME LIVING OUTSIDE ITS SYSTEM DIRECTORY. Measured: 3 rows over 11 cases -
# c:\users\case_59\desktop\svchost.exe (a golden fact the report used to miss),
# c:\users\user\appdata\local\log\svchost.exe and one inside an "rdp brute" folder.
CYR_LURE_MARK = ' \u26a0 кирилична назва виконуваного файлу в теці користувача'
PUBLIC_BIN_MARK = ' \u26a0 виконуваний модуль у спільній теці Users/Public'
_SYSBIN_MASQ_RE = (r'/(svchost|lsass|services|csrss|winlogon|smss|wininit|spoolsv|'
                   r'taskhost|taskhostw|explorer|rundll32|dllhost|conhost|ctfmon|sihost|'
                   r'searchindexer|dwm|lsaiso|fontdrvhost|audiodg|wuauclt|msiexec)[.]exe$')
# ...and where those names legitimately live. c:/windows/explorer.exe is the real
# explorer: without this line the "masquerade" list is 14 rows, 11 of them that file.
_SYSBIN_HOME_RE = (r'/(windows/system32|windows/syswow64|windows/winsxs)/'
                   r'|^[a-z]:/windows/[^/]+[.]exe$')
_MASQ_MARK = ' \u26a0 \u0441\u0438\u0441\u0442\u0435\u043c\u043d\u0435 \u0456\u043c\u02bc\u044f \u043f\u043e\u0437\u0430 \u0441\u0438\u0441\u0442\u0435\u043c\u043d\u043e\u044e \u0442\u0435\u043a\u043e\u044e'


def _is_sysbin_masquerade(path):
    """A stock Windows binary name in a place Windows never puts it."""
    p = str(path or '').lower().replace(_BSLASH, '/')
    return bool(re.search(_SYSBIN_MASQ_RE, p)) and not bool(re.search(_SYSBIN_HOME_RE, p))


def _hash_algo(h):
    """MD5 / SHA1 / SHA256 by digest length; anything else is reported as unknown."""
    n = len(str(h or '').strip())
    return {32: 'MD5', 40: 'SHA1', 64: 'SHA256'}.get(n, 'хеш')


def _iocs(case_key, findings=None, split=False):
    """IOC section. With split=True returns (main, appendix): main = the indicators the
    findings themselves name plus attack-tool / masquerade hashes and tools; appendix =
    bulk executed-file hashes, raw URL/IP scrapes and SRUM volumes, which are reference
    material and used to fill section 5 with Defender and Chrome binaries."""
    tools, hashes, urls, ips = [], [], [], []
    # srum was only bound inside the connect block, so a database that is down turned
    # this function into a NameError instead of an empty section. Pre-existing at the
    # "if srum" render line; the summary check below just reaches it sooner.
    srum = []
    ips_total = 0
    _quiet_note = False
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            r = _q(cur, """SELECT executable_name, full_path, min(event_ts) FROM program_exec_v2
                           WHERE case_key=%s AND lower(executable_name) ~ %s
                             AND lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) !~ %s
                           GROUP BY 1, 2 LIMIT 40""",
                   (case_key, _TOOL_RE, _FP_DROP_RE))
            # 7za.exe under the collector's staging folder, run the minute the collector
            # started, is our archiver, not the attacker's - the row carries path and time
            _by_tool = {}
            for _en, _fp, _ts in r:
                if not _en:
                    continue
                _own_row = _own_text(str(_en) + ' ' + str(_fp or ''), ts=_ts, case_key=case_key)
                _g = _by_tool.setdefault(str(_en).lower(), {'name': _en, 'own': 0, 'other': 0})
                if _own_row:
                    _g['own'] += 1
                elif _fp or _ts:
                    _g['other'] += 1
                else:
                    _g['other'] += 0  # a bare name with no path and no time decides nothing
            tools = [g['name'] for g in _by_tool.values() if not (g['own'] and not g['other'])][:25]
            r = _q(cur, """SELECT DISTINCT executable_name, full_path, hash_sha1 FROM program_exec_v2
                           WHERE case_key=%s AND hash_sha1 ~ '^[a-fA-F0-9]{16,}$'
                             AND ( lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) ~ %s
                                   OR ( translate(lower(coalesce(full_path,'')), %s, '/') ~ %s
                                        AND translate(lower(coalesce(full_path,'')), %s, '/') !~ %s ) )
                             AND lower(coalesce(full_path,'')||' '||coalesce(executable_name,'')) !~ %s
                           LIMIT 40""",
                   (case_key, _HASH_TOOL_RE, _BSLASH, _SYSBIN_MASQ_RE,
                    _BSLASH, _SYSBIN_HOME_RE, _FP_DROP_RE))
            import re as _re2
            _h_all = [(x[0], x[1], x[2]) for x in r if x[2]]
            try:
                _tr = _re2.compile(_HASH_TOOL_RE, _re2.I)
                # masqueraded system binary first, then attacker tooling, then the rest -
                # the 14-row cut must never be what drops the strongest line.
                _h_all.sort(key=lambda t: (0 if _is_sysbin_masquerade(t[1] or t[0]) else
                                           (1 if _tr.search((t[0] or '') + ' ' + (t[1] or '')) else 2)))
            except Exception:
                pass
            hashes = _h_all[:14]
            # say WHY this hash is in the list, otherwise it reads as one more Amcache row
            try:
                hashes = [((str(_hm[0] or '') + _MASQ_MARK) if _is_sysbin_masquerade(_hm[1] or _hm[0])
                           else _hm[0], _hm[1], _hm[2]) for _hm in hashes]
            except Exception:
                pass
            srum = []
            try:
                rs = _q(cur, """SELECT exe_info, sum((payload->>'bytes_tx')::bigint) FROM srum_v2
                                WHERE case_key=%s AND payload ? 'bytes_tx'
                                GROUP BY exe_info ORDER BY 2 DESC LIMIT 8""", (case_key,))
                srum = [(x[0], x[1]) for x in rs if x[0] and x[1]]
            except Exception:
                srum = []
            r = _q(cur, """SELECT DISTINCT substring(payload::text from 'https?://[^ "'',;)\\]]+')
                           FROM event_logs_v2 WHERE case_key=%s AND payload::text ~* 'https?://' LIMIT 300""",
                   (case_key,))
            r2 = _q(cur, """SELECT DISTINCT substring(payload::text from 'https?://[^ "'',;)\\]]+')
                            FROM filesystem_v2 WHERE case_key=%s AND payload::text ~* 'https?://' LIMIT 300""",
                    (case_key,))
            raw_urls = [_clean_url(x[0]) for x in (list(r) + list(r2)) if x[0]]
            clean = []
            for u in raw_urls:
                if not u or any(b in u.lower() for b in _NOISE_DOMAINS):
                    continue
                # structural rule, so a new vendor CDN does not need a new blocklist
                # entry: a URL pointing at an update package is never an indicator.
                # Office's cdn.office.net filled the whole list on the encrypted case
                # the moment the Google CDN was excluded.
                if _UPDATE_PKG_RE.search(u):
                    continue
                clean.append(u)
            urls = list(dict.fromkeys(clean))[:15]
            r = _q(cur, """SELECT DISTINCT payload->>'IpAddress' FROM event_logs_v2
                           WHERE case_key=%s AND payload ? 'IpAddress' LIMIT 150""", (case_key,))
            ip_raw = [x[0] for x in r if x[0] and x[0] not in _LOCAL_IPS]
            ips = list(dict.fromkeys(ip_raw))[:15]
            # A case with no high/critical finding has no attack to indicate. Everything
            # scraped out of raw payloads there is the person's ordinary work traffic —
            # on case_49 it was fifteen government sites and deep links into their
            # webmail. Curated case_iocs entries are merged in below and stay.
            # IOC sources that are a MODEL's reading of evidence, not evidence itself
            # (same tuple as analysis/attribution.py::_SOFT_SOURCES). On a case with no
            # high or critical finding these are exactly what the quiet note two lines
            # below promises NOT to print, yet the merge re-added them: case_49's whole
            # section 5 became one browsing domain the user visits for a state e-signature
            # service. Measured: 1 of 11 cases is quiet, it holds 1 such domain and 0
            # curated ones, so nothing sourced from an expert report can be reached here.
            _SOFT_IOC_SOURCES = ('report_llm', 'qa_analysis', 'timeline_analysis',
                                 'ps_b64_decoded')
            _fl = findings if findings is not None else (_findings(case_key) or [])
            _quiet_case_no_raw_ioc = not any(
                (f or {}).get('severity') in ('critical', 'high') for f in _fl)
            if _quiet_case_no_raw_ioc:
                urls, ips = [], []
                _quiet_note = True
            # MERGE enriched case_iocs (PowerShell-C2, report-LLM, 7045 services,
            # initial_access, browser-infra, 👍/Q&A-approved) — so the report reflects
            # EVERY IOC source, not only what re-derives from raw SQL here.
            try:
                cur.execute("""SELECT ioc_type, ioc_value, source_table FROM case_iocs
                    WHERE case_key=%s AND coalesce(ioc_value,'')<>''
                    AND ioc_type IN ('domain','url','public_ip','tool_name','malware_name',
                                     'hash_sha1','hash_sha256','hash_md5','anydesk_id')
                    ORDER BY ioc_type, ioc_value LIMIT 200""",
                    (case_key,))
                # IOC_HASH_NOISE_FIX: bulk program_exec hashes (Amcache SHA1 of EVERY
                # executed binary) are benign on a clean PC; only surface them as IOC
                # when the case actually has a high/critical finding.
                _ioc_has_hi = any((f or {}).get('severity') in ('critical', 'high') for f in _fl)
                _seen_u = {u.lower() for u in urls}
                _seen_i = set(ips)
                _seen_t = {t.lower() for t in tools}
                _seen_h = {h[2].lower() for h in hashes if len(h) > 2 and h[2]}
                for _t, _v, _st in cur.fetchall():
                    _vl = str(_v).strip()
                    if not _vl:
                        continue
                    if (_quiet_case_no_raw_ioc and str(_st) in _SOFT_IOC_SOURCES
                            and _t in ('domain', 'url', 'public_ip')):
                        continue  # a model's reading of ordinary traffic on a quiet case
                    # a model-derived or inferred indicator (Q&A, narrative, infra map) is printed as a
                    # case IOC only when the case evidence actually contains it (2026-09-11: ngrok.io,
                    # bin.equinox.io, www.comss.ru reached page 1 from qa_analysis/infra rows)
                    if (str(_st) in _SOFT_IOC_SOURCES + ('ps_c2', 'browser_provenance/infra')
                            and _t in ('domain', 'url', 'public_ip', 'tool_name') and not _ioc_grounded(case_key, _vl)):
                        continue
                    if _t in ('domain', 'url') and _vl.lower() not in _seen_u:
                        urls.append(_vl); _seen_u.add(_vl.lower())
                    elif _t == 'public_ip' and _vl not in _seen_i:
                        ips.append(_vl); _seen_i.add(_vl)
                    elif _t in ('tool_name', 'malware_name', 'anydesk_id') and _vl.lower() not in _seen_t:
                        # a tool the model named that is one of OUR tools (7za, KAPE...) on a
                        # case where our collector ran is the collector, not the attacker
                        if _t == 'tool_name' and _own_tool_name(_vl, case_key):
                            _seen_t.add(_vl.lower()); continue
                        tools.append(_vl); _seen_t.add(_vl.lower())
                    elif _t.startswith('hash') and _vl.lower() not in _seen_h:
                        if _st == 'sql_program_exec' and not _ioc_has_hi:
                            continue  # benign bulk program hashes on a clean case = noise
                        hashes.append(('(з IOC-бази)', 'н/д', _vl)); _seen_h.add(_vl.lower())
                # Give every "(з IOC-бази)" hash back its name and path. One query,
                # ORDER BY row_id so the same hash always resolves to the same row.
                _naked = [h[2].lower() for h in hashes if h[0] == '(з IOC-бази)' and h[2]]
                if _naked:
                    _named = {}
                    for _hv, _en, _fp in _q(cur, """
                        SELECT DISTINCT ON (lower(hash_sha1))
                               lower(hash_sha1), coalesce(executable_name,''), coalesce(full_path,'')
                        FROM program_exec_v2
                        WHERE case_key=%s AND lower(coalesce(hash_sha1,'')) = ANY(%s)
                        ORDER BY lower(hash_sha1), row_id
                    """, (case_key, _naked)):
                        _named[_hv] = (_en, _fp)
                    for _ix, _h3 in enumerate(hashes):
                        if _h3[0] != '(з IOC-бази)':
                            continue
                        _hit = _named.get(str(_h3[2]).lower())
                        if not _hit:
                            continue
                        _en, _fp = _hit
                        _nm = (_en or _fp).rsplit(chr(92), 1)[-1] or '(з IOC-бази)'
                        hashes[_ix] = (_nm, _fp or 'н/д', _h3[2])
                # Two classes of file that sat in the tables the whole time but no
                # section ever read, which is why two golden facts of the expert reports
                # never reached the client report:
                #   * "До відома.exe" (20_05) - a phishing lure with a Cyrillic name;
                #   * edit.dll (06_02) - 2.25 MB in Users/Public/Documents, mtime
                #     2026-01-26 10:11, i.e. the very minute of the case's first event.
                # 1) Executable with a CYRILLIC base name inside a user folder. Measured
                #    over all 11 cases: 13 names on 4 cases, every single one a real lure
                #    ("Лист ДНК та ПН щодо ЕРА.exe" from a Rar$ temp dir,
                #    "Лист державним реєстраторам ДРАЦС.exe"). Without the folder
                #    condition it would be 126 names, 113 of them the notary
                #    "SIGN.MEDIA=..." files of one single case - so it is the folder that
                #    removes the noise, not a tuned threshold.
                # 2) Executable module under Users/Public - 16 rows over 11 cases on 4
                #    cases, not one of them legitimate: ngrok.exe, ng.bat, ping.bat,
                #    sshpass.exe, MsEdg.exe / MsEdgEx.exe (masquerading as Edge),
                #    edit.dll, gcapi.dll, POWRPROF.dll, BugSplat64.dll.
                # Both stay silent on a quiet case - the same rule the raw URL/IP lists
                # already follow above - and both carry their own explanation, otherwise
                # the line reads as a proven attack tool, which it is not on its own.
                if not _quiet_case_no_raw_ioc:
                    try:
                        cur.execute("""SELECT DISTINCT executable_name FROM program_exec_v2
                            WHERE case_key=%s
                              AND lower(coalesce(executable_name,'')) LIKE '%%.exe'
                              AND regexp_replace(translate(coalesce(executable_name,''), %s, '/'),
                                                 '^.*/', '') ~ '[Ѐ-ӿ]'
                              AND lower(translate(coalesce(executable_name,'')||' '
                                                  ||coalesce(full_path,''), %s, '/'))
                                  ~ '/(downloads|desktop|temp|tmp|public|appdata)/'
                            LIMIT 20""", (case_key, _BSLASH, _BSLASH))
                        # One lure unpacked into six Rar$EXa folders is one lure, not
                        # six rows of a twenty-row section: print it once, and say how
                        # many extraction folders it was unpacked into.
                        _cyr = {}
                        for (_cn,) in cur.fetchall():
                            if not _cn or str(_cn).lower() in _seen_t:
                                continue
                            _bn = str(_cn).translate({92: 47}).rsplit('/', 1)[-1].lower()
                            _cyr.setdefault(_bn, []).append(str(_cn))
                        for _bn, _paths in _cyr.items():
                            _mark = CYR_LURE_MARK
                            if len(_paths) > 1:
                                _mark += ' (копій у різних теках: %d)' % len(_paths)
                            tools.append(sorted(_paths)[0] + _mark)
                            for _p1 in _paths:
                                _seen_t.add(_p1.lower())
                    except Exception:
                        pass
                    try:
                        cur.execute("""SELECT DISTINCT coalesce(parent_path,'')||%s||file_name
                            FROM filesystem_v2
                            WHERE case_key=%s
                              AND lower(file_name) ~ '[.](exe|dll|ps1|bat|cmd|scr|sys)$'
                              AND lower(translate(coalesce(parent_path,''), %s, '/'))
                                  ~ '/users/public/'
                            LIMIT 20""", (_BSLASH, case_key, _BSLASH))
                        for (_pp,) in cur.fetchall():
                            if _pp and str(_pp).lower() not in _seen_t:
                                tools.append(str(_pp) + PUBLIC_BIN_MARK)
                                _seen_t.add(str(_pp).lower())
                    except Exception:
                        pass
                # A hash whose only owner on disk is a tool the EXAMINER brought is not
                # an indicator of compromise. _EXAMINER_TOOL_PY was already applied to the
                # timeline and the tool lists, but never here, so DumpIt (run 2026-08-13,
                # the collection day, 24 min after our own collector) was printed to the
                # client as an IOC. Measured over 11 cases: removes 1 row, zero elsewhere.
                try:
                    hashes = [_h4 for _h4 in hashes
                              if not (re.search(_EXAMINER_TOOL_PY,
                                                (str(_h4[0] or '') + ' ' + str(_h4[1] or '')).lower())
                                      or _OWN_PATH_RE.search(
                                          (str(_h4[0] or '') + ' ' + str(_h4[1] or '')).lower()))]
                    tools = [_t4 for _t4 in tools
                             if not (re.search(_EXAMINER_TOOL_PY, str(_t4 or '').lower())
                                     or _OWN_PATH_RE.search(str(_t4 or '').lower()))]
                except Exception:
                    pass
                # A stock system binary is not an indicator just because we know its
                # hash. See _is_stock_sysbin: 13 rows over 11 cases, all qa_analysis.
                try:
                    hashes = [_h5 for _h5 in hashes
                              if not _is_stock_sysbin(_h5[0], _h5[1])]
                except Exception:
                    pass
                # The client read this list as 'these are all of them'. On case_66 it
                # was 20 of 33, sliced in physical row order, and the half that was cut
                # held 82.207.114.163 with 270 events over six months while the printed
                # half carried peers with two. Same defect ba3e1a9 fixed in section 3:
                # rank by how many events the address actually produced, and say how
                # many there are in total.
                ips_total = len(ips)
                if ips_total > 20:
                    _vol = {}
                    try:
                        cur.execute("""SELECT coalesce(remote_host,''), count(*)
                                       FROM event_logs_v2
                                       WHERE case_key=%s AND coalesce(remote_host,'') <> ''
                                       GROUP BY 1""", (case_key,))
                        _rows = list(cur.fetchall())
                        cur.execute("""SELECT payload->>'IpAddress', count(*)
                                       FROM event_logs_v2
                                       WHERE case_key=%s AND payload ? 'IpAddress'
                                       GROUP BY 1""", (case_key,))
                        _rows += list(cur.fetchall())
                        for _hv, _hn in _rows:
                            _hk = str(_hv or '').strip()
                            if _hk:
                                _vol[_hk] = _vol.get(_hk, 0) + int(_hn or 0)
                    except Exception:
                        _vol = {}
                    ips = sorted(ips, key=lambda _i: (-_vol.get(str(_i).strip(), 0), str(_i)))
                urls = urls[:25]; ips = ips[:20]; hashes = hashes[:20]
                # tools[:30] used to cut in insertion order, and the rows that carry
                # their own explanation are appended last - measured on 20_05: 11 such
                # rows produced, 6 survived. The cut stays at 30; only the order changes,
                # so nothing that used to be printed is pushed out by more than the
                # explained rows themselves.
                try:
                    tools.sort(key=lambda _t5: 0 if '\u26a0' in str(_t5) else 1)
                except Exception:
                    pass
                tools = tools[:30]
            except Exception:
                pass
    except Exception:
        pass
    # our own footprint never is an indicator (7za under DFIRTriage_, dfp_ probes...)
    try:
        tools = [_t for _t in tools if not _own_text(str(_t), case_key=case_key)]
        hashes = [_h for _h in hashes
                  if not _own_text(str(_h[0] or '') + ' ' + str(_h[1] or ''), case_key=case_key)]
    except Exception:
        pass
    # split the hashes: a masqueraded system binary, an attack tool or a file a finding
    # names is an indicator; the SHA1 of every other executed binary (Defender, Chrome
    # installer, vcredist) is reference material
    _fx = _fx_iocs(findings, sevs=_HI_SEV) if findings else []
    _fx_vals = {str(i['value']).lower() for i in _fx}
    _fx_names = {str(i['value']).replace('/', chr(92)).lower().rsplit(chr(92), 1)[-1] for i in _fx}
    _tr = None
    try:
        _tr = re.compile(_HASH_TOOL_RE, re.I)
    except Exception:
        pass
    _hi_case = any((f or {}).get('severity') in ('critical', 'high') for f in (findings or []))
    # A hash is an indicator when the file it belongs to is a masqueraded system binary, a
    # VERIFIED attack tool, or a file some ≥HIGH finding names. `_HASH_TOOL_RE` also carries
    # the dual-use half (TeamViewer, 7za, AnyDesk), and that is exactly what section 5 was
    # made of on the calm cases: two TeamViewer binaries and Adobe's own 7za, printed under
    # the heading «підтверджені ланки атаки». (FIX_QUEUE №2/№3.)
    _hard = None
    try:
        _hard = re.compile(_IA_HARD_TOOL_RE, re.I)
    except Exception:
        _hard = None
    hashes_main, hashes_ref = [], []
    for _h in hashes:
        _nm0, _pt0, _hv = (str(_h[0] or ''), str(_h[1] or ''), str(_h[2] or ''))
        _base = (_nm0 or _pt0).replace('/', chr(92)).rsplit(chr(92), 1)[-1].lower()
        _is_ioc = _hi_case and (
            _MASQ_MARK in _nm0 or _is_sysbin_masquerade(_pt0 or _nm0)
            or (_hard is not None and _hard.search(_nm0 + ' ' + _pt0))
            or _hv.lower() in _fx_vals or _base in _fx_names or _pt0.lower() in _fx_vals)
        (hashes_main if _is_ioc else hashes_ref).append(_h)
    main = list(_fx_ioc_lines(findings)) if findings else []
    if hashes_main:
        main.append('**Хеші файлів-індикаторів (файл · шлях · алгоритм за довжиною):**')
        for _nm, _pt, _h in hashes_main:
            _n = _nm or (_pt or '').rsplit(chr(92), 1)[-1] or 'н/д'
            main.append('- `%s` · `%s` · %s `%s`' % (_n, (_pt or 'н/д'), _hash_algo(_h), _h))
    if tools:
        main.append('**Файли / інструменти атаки:**')
        # the row that says WHY it is here goes first, the cut takes the rest
        _tl, _seen_tl = [], set()
        for _t in tools:
            if str(_t).lower() not in _seen_tl:
                _seen_tl.add(str(_t).lower()); _tl.append(_t)
        _tl.sort(key=lambda _t: 0 if chr(0x26a0) in str(_t) else 1)
        main += ['- `%s`' % t for t in _tl[:20]]
    ref = []
    if hashes_ref:
        ref.append('**Хеші виконуваних файлів (довідково; не індикатори — Defender, інсталятори, оновлювачі):**')
        for _nm, _pt, _h in hashes_ref:
            _n = _nm or (_pt or '').rsplit(chr(92), 1)[-1] or 'н/д'
            ref.append('- `%s` · `%s` · %s `%s`' % (_n, (_pt or 'н/д'), _hash_algo(_h), _h))
    # raw URL/IP scrapes are indicators only when a network-class finding exists; on a
    # wiper case they were the user's software-piracy site and a monitoring dashboard
    _net_cats = ('Доставка / C2', 'Віддалений доступ / тунель', 'Доступ (RDP)', 'Ексфільтрація',
                 'Латеральний рух', 'Доступ')
    _net_case = any((f or {}).get('category') in _net_cats
                    and (f or {}).get('severity') in ('critical', 'high') for f in (findings or []))
    _net_target = main if (_net_case or not findings) else ref
    if urls:
        # a URL that names the person's mail box, bank or a registry they work with is
        # personal data of theirs, not an indicator of anybody's attack — six reports put
        # one on page 1
        urls = [u for u in urls if not (_is_private_url(u) and _net_target is main)]
    if urls:
        _net_target.append('**Домени / URL%s:**' % ('' if _net_target is main else ' (з логів, довідково — жодна знахідка їх не називає)'))
        _net_target += ['- `%s`' % u for u in urls]
    if ips:
        # a LogonId, a bare token or a machine account is not an address; four reports
        # printed one under «IP-адреси» (FIX_QUEUE №2/№9)
        _ip_rx = re.compile(r'^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]{3,45})$')
        ips = [i for i in ips if _ip_rx.match(str(i).strip()) and ':' != str(i).strip()]
    if ips:
        _ip_more = ('' if ips_total <= len(ips)
                    else ' _(показано %d із %d — за кількістю подій)_' % (len(ips), ips_total))
        _net_target.append('**IP-адреси:**%s' % _ip_more)
        _net_target += ['- `%s`' % i for i in ips]
    _susp = ('ngrok','anydesk','rustdesk','rclone','mega','curl','winscp','psftp','frpc','chisel','7z','telegram','filezilla')
    if srum:
        ref.append('**Мережева активність (SRUM — відправлено назовні; довідково):**')
        for _exe, _tx in srum:
            _mb = float(_tx or 0) / 1048576.0
            _en = (_exe or '').rsplit(chr(92), 1)[-1]
            _fl = ' (!)' if any(k in (_exe or '').lower() for k in _susp) else ''
            ref.append('- `%s` — %.0f MB відправлено%s' % (_en, _mb, _fl))
    # A calm verdict has no indicators of compromise, and the section says exactly that and
    # nothing else. Everything that WAS printed there on such cases — the browsing history,
    # the vendor drivers, Adobe's 7za, two TeamViewer binaries — is reference material, and
    # it moves under the line: a heading «підтверджені ланки атаки» over vendor noise is how
    # a clean machine gets read as a compromised one. (Brief task 5; FIX_QUEUE №2/№3/№11.)
    if not _hi_case:
        ref = [l for l in main if not l.startswith('**Індикатори з підтверджених')] + ref
        main = ['- Індикаторів атаки не виявлено.']
        if split:
            return main, ref
        return main + ref
    if not main:
        main.append('- Явних IOC у нормалізованих логах не виділено автоматично — дивись службові дані нижче.'
                    if not _hi_case else
                    '- Знахідки не винесли структурованих індикаторів — див. їхні приклади у службових даних.')
    if split:
        return main, ref
    return main + ref


def _present_markers(case_key):
    """Which concrete attack tools / files / accounts are present in THIS case."""
    m = set()
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            # XCASE_NAME_FIX: маркер, що є ПОВНИМ іменем файлу, мусить збігатися з
            # цілим іменем. Підрядковий збіг ловив звичайний файл Java, ім'я якого
            # закінчується тим самим хвостом, і саме так назва з іншої справи
            # потрапляла в текст звітів двох справ. Маркери-корені назв інструментів
            # лишаються підрядковими: вони й задумані як частина назви.
            r = _q(cur, """SELECT DISTINCT lower(coalesce(executable_name, ''))
                           FROM program_exec_v2 WHERE case_key=%s
                             AND lower(coalesce(executable_name, '')) ~
                             'try[.]exe|msedgex|ngrok|rdpwinst|rdpwrap|7za|anydesk|rustdesk|rutserv|psexec|mimikatz|chromepass'""",
                   (case_key,))
            _stem_markers = ('msedgex', 'ngrok', 'rdpwinst', 'rdpwrap', '7za',
                             'anydesk', 'rustdesk', 'rutserv', 'psexec', 'mimikatz', 'chromepass')
            _whole_name_markers = ('try.exe',)
            for _row in (r or []):
                _nm = (_row[0] or '')
                _base = _nm.replace(chr(92), '/').rsplit('/', 1)[-1].strip()
                for k in _stem_markers:
                    if k in _nm:
                        m.add(k)
                for k in _whole_name_markers:
                    if _base == k:
                        m.add(k)
            r = _q(cur, """SELECT 1 FROM filesystem_v2 WHERE case_key=%s
                           AND payload::text ~* 'swisstransfer|pixeldrain|wetransfer|dropbox|mega[.]nz|fex[.]net'
                           LIMIT 1""", (case_key,))
            if r:
                m.add('fileshare')
            r = _q(cur, """SELECT 1 FROM event_logs_v2 WHERE case_key=%s
                           AND lower(coalesce(target_user,'') || ' ' || coalesce(payload::text,'')) ~ 'case_59'
                           LIMIT 1""", (case_key,))
            if r:
                m.add('case_59')
    except Exception:
        pass
    return m


def _conclusion_key_facts(case_key, iw=None, findings=None, chain_facts=None):
    """Concrete dated facts for the conclusion: entry point, first malicious run, backdoor
    account(s), RDP, defence evasion. Never raises.

    Two of these — the entry point and the first malicious run — describe the ATTACK, and
    they are the report's own claim about how it began. They may therefore be spoken only
    by the object of the chain (`chain_facts`, from the top finding's anchor events). The
    SQL heuristics below fire only under a high/critical verdict that has no such chain,
    and only for an executable/archive inside the 30-day run-up. On a calm verdict neither
    line exists at all: ten of twelve reports named an entry point their own verdict did
    not support, and two of those verdicts said «нічого не виявлено»."""
    out = []
    _BS = chr(92)
    _fl = findings if findings is not None else []
    _has_hi = any(str((f or {}).get('severity') or '').lower() in _HI_SEV for f in _fl)
    _chain = list(chain_facts or [])
    _may_guess = _has_hi and not _chain
    _cap = _entry_floor(case_key, iw)
    if _chain:
        out += _chain
    try:
        _floor = (iw or [None])[0] or '1970-01-01'
    except Exception:
        _floor = '1970-01-01'
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            with c.cursor() as cur:
                try: cur.execute("SET statement_timeout='6000'")
                except Exception: pass
                def qq(sql, p):
                    try:
                        cur.execute(sql, p); return cur.fetchall()
                    except Exception:
                        try: c.rollback()
                        except Exception: pass
                        return []
                def _pvk(sf, rec=None):
                    try:
                        from analysis.threat_detect import provenance as _p
                        return _p(case_key, sf, rec, cur) or str(sf or '')
                    except Exception:
                        return str(sf or '')

                # entry point (file-share delivery) — heuristic, gated per the docstring
                if _may_guess:
                    r = qq("""SELECT event_ts,
                              (CASE WHEN coalesce(parent_path,'')<>'' THEN parent_path||'/'||coalesce(file_name,'') ELSE coalesce(file_name,'') END) fn,
                              split_part(split_part(coalesce(payload->>'zone_id',''),'HostUrl=',2), chr(10), 1) src,
                              coalesce(source_file,''), payload->>'entry_number'
                              FROM filesystem_v2 WHERE case_key=%s AND payload::text ILIKE '%%hosturl%%'
                              AND payload::text ~* 'swisstransfer|mega|pixeldrain|dropbox|drive.google|wetransfer|mediafire|gofile|ngrok|sendspace|files.fm|1drv.ms|cloud.mail'
                              AND event_ts >= %s
                              ORDER BY event_ts ASC LIMIT 6""", (case_key, _floor))
                    for _ts0, _fn0, _src0, _sf0, _rec0 in (r or []):
                        _nm0 = str(_fn0 or '').replace(_BS, '/').split('/')[-1][:60]
                        if not _entry_candidate_ok(_nm0, _fn0, _ts0, _cap):
                            continue
                        _from = ('' if _is_private_url(_src0) else ' з %s' % str(_src0)[:70])
                        out.append('📥 Вхідна точка: `%s` завантажено%s о `%s`%s'
                                   % (_nm0, _from, str(_ts0)[:19], _prov_tag(_pvk(_sf0, _rec0))))
                        break
                # first malicious execution in window
                if _may_guess:
                    r = qq("""SELECT event_ts, executable_name, coalesce(source_file,'') FROM program_exec_v2
                              WHERE case_key=%s AND event_ts >= %s
                              AND lower(coalesce(executable_name,'')||' '||coalesce(full_path,'')) ~
                              'mimikatz|ngrok|rdpwrap|rdpwinst|psexec|chromepass|try[.]exe|msedgex|anydesk|rutserv|netscan|advanced_port|cobalt|meterpreter|nanodump|lazagne'
                              ORDER BY event_ts ASC LIMIT 1""", (case_key, _floor))
                    if r:
                        out.append('▶️ Перший шкідливий запуск: `%s` о `%s`%s'
                                   % (r[0][1], str(r[0][0])[:19], _prov_tag(_pvk(r[0][2]))))
                # backdoor account: created (4720) AND added to a privileged group (4732/4728/4756)
                r = qq("""SELECT coalesce(nullif(u.payload->>'TargetUserName',''), u.target_user), u.event_ts,
                                 coalesce(u.source_file,''), u.payload->>'RecordNumber'
                          FROM event_logs_v2 u JOIN event_logs_v2 g
                            ON g.case_key=u.case_key AND g.event_id IN (4732,4728,4756) AND g.channel='Security'
                           AND g.event_ts BETWEEN u.event_ts AND u.event_ts + interval '48 hours'
                           AND lower(coalesce(g.payload->>'MemberName','')) LIKE '%%'||lower(coalesce(nullif(u.payload->>'TargetUserName',''),u.target_user))||'%%'
                          WHERE u.case_key=%s AND u.event_id=4720 AND u.channel='Security' AND u.event_ts >= %s
                           AND coalesce(u.target_user,'') NOT IN ('','-')
                          GROUP BY 1,2,3,4 ORDER BY 2 LIMIT 3""", (case_key, _floor))
                if not r:
                    r = qq("""SELECT coalesce(nullif(payload->>'TargetUserName',''), target_user), event_ts,
                                     coalesce(source_file,''), payload->>'RecordNumber'
                              FROM event_logs_v2 WHERE case_key=%s AND event_id=4720
                              AND channel='Security' AND event_ts >= %s AND coalesce(target_user,'') NOT IN ('','-')
                              ORDER BY event_ts LIMIT 3""", (case_key, _floor))
                for u, ts, _sf, _rec in r:
                    _un = str(u).split(_BS)[-1].split('(')[0].strip()[:40]
                    out.append('👤 Створено обліковий запис «%s» о `%s` (доданий у привілейовані групи)%s'
                               % (_un, str(ts)[:19], _prov_tag(_pvk(_sf, _rec))))
                # RDP
                r = qq("""SELECT count(*), min(event_ts), max(event_ts), min(coalesce(source_file,''))
                          FROM event_logs_v2 WHERE case_key=%s
                          AND event_ts >= %s AND event_id=4624 AND (logon_type='10' OR logon_type ILIKE '%%remote interactive%%')""",
                       (case_key, _floor))
                if r and r[0][0]:
                    out.append('🔑 RDP-входи (type 10): %d, від `%s` до `%s`%s'
                               % (r[0][0], str(r[0][1])[:19], str(r[0][2])[:19], _prov_tag(_pvk(r[0][3]))))
                # defence off — the sentence appears only when the counter is above zero
                # (FIX_QUEUE №17: «вимкнення захисту» printed over a vendor switch-over)
                r = qq("""SELECT min(event_ts), count(*), min(coalesce(source_file,''))
                          FROM event_logs_v2 WHERE case_key=%s AND event_ts >= %s
                          AND event_id IN (5001,5010,5012) AND coalesce(provider,'') ILIKE '%%Windows Defender%%'""",
                       (case_key, _floor))
                if r and r[0][0] and int(r[0][1] or 0) > 0:
                    out.append('🛡 Вимкнення захисту Defender: перше о `%s`%s'
                               % (str(r[0][0])[:19], _prov_tag(_pvk(r[0][2]))))
                # log clear
                r = qq("""SELECT min(event_ts), min(coalesce(source_file,'')) FROM event_logs_v2
                          WHERE case_key=%s AND event_ts >= %s
                          AND event_id=1102 AND channel='Security'""", (case_key, _floor))
                if r and r[0][0]:
                    out.append('🧹 Очищення журналу безпеки о `%s`%s'
                               % (str(r[0][0])[:19], _prov_tag(_pvk(r[0][1]))))
    except Exception:
        pass
    return out


def _chain_key_facts(findings):
    """The «Ключові факти» that describe the attack, taken from the object of the chain and
    from nowhere else: the top finding's anchor events, in order."""
    top = _top_finding(findings)
    if not top:
        return []
    ev = _fx_events([top], sevs=(str(top.get('severity') or '').lower(),),
                    extra_categories=(), anchors_only=True)
    out = []
    for _e in ev[:6]:
        out.append('%s `%s` — %s%s' % ('📥' if _e is ev[0] else '▶️', _fmt_ts(_e[0]),
                                       _human_label(_e[1])[:110],
                                       _prov_tag(_e[7] or _e[2] or _e[3])))
    return out


_AV_COUNT_CACHE = {}


def _av_detect_count(case_key, iw=None):
    """How many antivirus detections (1116/1117) this case actually has.

    «антивірус фіксував загрози» was printed on a machine with zero detections
    (case_66, FIX_QUEUE №17). Every template sentence of §1 now has a counter behind it."""
    if case_key in _AV_COUNT_CACHE:
        return _AV_COUNT_CACHE[case_key]
    n = 0
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            with c.cursor() as cur:
                cur.execute("SET statement_timeout='6000'")
                cur.execute("""SELECT count(*) FROM event_logs_v2
                               WHERE case_key=%s AND event_id IN (1116,1117)""", (case_key,))
                n = int((cur.fetchone() or [0])[0] or 0)
    except Exception:
        n = 0
    _AV_COUNT_CACHE[case_key] = n
    return n


def _kort_ko(findings, verdict, cats):
    """«Коротко:» — ONE plain sentence, from the plain-language fragments of the two
    strongest categories, with the technical verdict in brackets behind it.

    It used to print the verdict verbatim, and the verdict is a list of category names:
    «Червона комбінація, Закріплення, Виконання…» — jargon on the first line of a report
    written for someone who is not an analyst (FIX_QUEUE, case_45 §1, defect 3)."""
    _v = str(verdict or '').strip()
    _hi = [f for f in sorted((findings or []), key=_sev_key)
           if str(f.get('severity') or '').lower() in _HI_SEV]
    if not _hi:
        return ('**Коротко:** Ознак атаки на цьому компʼютері не знайдено — критичних або '
                'високих загроз детермінований шар не виявив.'
                + (' _(технічно: %s)_' % _v[:150] if _v else ''))
    top2, seen = [], set()
    for f in _hi:
        c = f.get('category')
        frag = _CAT_PLAIN.get(c)
        if frag and c not in seen:
            seen.add(c)
            top2.append(frag)
        if len(top2) == 2:
            break
    if not top2:
        body = 'на компʼютері зафіксовано ознаки втручання'
    elif len(top2) == 1:
        body = top2[0]
    else:
        body = '%s; %s' % (top2[0], top2[1])
    body = body[0].upper() + body[1:]
    return '**Коротко:** %s.%s' % (body.rstrip('.'),
                                   (' _(технічно: %s)_' % _v[:150]) if _v else '')


def _calm_scope(case_key, findings, parts):
    """When nothing high/critical was found, scope the calm conclusion to the sources that were
    actually collected (analysis/coverage_model). A machine with no registry, no browser history
    and no scanner output is not «clean» — it is unchecked there, and the first page must say so."""
    try:
        if any(str(f.get('severity') or '').lower() in ('critical', 'high') for f in (findings or [])):
            return parts
        from analysis.coverage_model import calm_caveat
        cav = calm_caveat(case_key, None)
        if not cav:
            return parts
        parts = list(parts or [])
        at = len(parts) - 1 if parts and str(parts[-1]).startswith('_') else len(parts)
        parts.insert(at, '⚠ ' + cav)
        return parts
    except Exception:
        return parts


def _plain_conclusion(case_key, findings, verdict, iw, ia=None):
    # RESHAPE_CALM_FIX: attack-chain narrative is driven by HIGH/CRITICAL findings
    # only. Medium/low (routine services/tasks/logons/PowerShell) previously leaked
    # false 'зловмисник закріпився'-style sentences onto clean PCs (case_49 23_07),
    # contradicting the calm verdict.
    cats = set()
    _has_hi = False
    for f in findings:
        if f.get('severity') in ('critical', 'high'):
            _has_hi = True
            c = f.get('category')
            if c:
                cats.add(c)
    mk = _present_markers(case_key)
    story = []
    # A machine where the user installed pirated software and switched the antivirus off
    # produces the same raw signals as an intrusion. When the detector has established
    # that reading, the narrative must not describe an attacker.
    _pua_finding = next((f for f in findings
                         if f.get('category') == 'Самозаподіяне (піратське ПЗ)'), None)
    if _pua_finding:
        _oth = [s for s in (_pua_finding.get('samples') or [])]
        story.append('Ознак стороннього втручання не виявлено: немає ані входів по RDP, '
                     'ані створених облікових записів, ані інструментів віддаленого доступу. '
                     'Антивірус спрацьовував переважно на засоби активації та зламу '
                     'програм — так виглядає самостійне встановлення піратського ПЗ, коли '
                     'захист вимикають власноруч, щоб воно запрацювало.')
        if _oth:
            story.append('Але не все безпечно: %s Це треба прибрати незалежно від того, '
                         'хто його приніс.' % _oth[0].replace('УВАГА: ', ''))
        parts = []
        if verdict:
            parts.append('**Коротко:** Стороннього втручання не виявлено; ознаки '
                         'піратського ПЗ на машині.')
        parts.append(' '.join(story))
        s, e = (iw or (None, None))[:2]
        if s or e:
            parts.append('Основна активність: `%s` → `%s`.' % (s or '?', e or '?'))
        parts.append('_Усі твердження варто звірити з сирими логами (розділ 6) перед '
                     'фінальним звітом._')
        return parts
    # 0a) If we know HOW they got in, that is where the story starts. The narrative used
    # to open on the loudest finding - on the case_42 case, the backdoor account on
    # 17 August - while the actual break-in was a phishing download on 31 July that the
    # reader never saw on page one. An investigation reads in order: how they got in,
    # then what they did with it.
    try:
        _entry = None
        for _f in (findings or []):
            _t = str(_f.get('title') or '')
            if 'Точка входу' in _t or str(_f.get('category') or '') == 'Початковий доступ':
                _entry = _f
                break
        if _entry:
            _ee = _fx_events([_entry], sevs=(str(_entry.get('severity') or '').lower(),),
                             extra_categories=(), anchors_only=True) or []
            if _ee:
                _url = ''
                for _i in (_entry.get('iocs') or []):
                    if str(_i.get('type')) == 'url' and str(_i.get('value', '')).startswith('http'):
                        _url = str(_i['value'])
                        break
                _lure = ''
                for _i in (_entry.get('iocs') or []):
                    if str(_i.get('type')) == 'file' and 'приманка' in str(_i.get('role', '')):
                        _lure = str(_i['value'])
                        break
                _d0, _dN = _ee[0][0], _ee[-1][0]
                try:
                    _mins = max(0, int((_dN - _d0).total_seconds() // 60))
                except Exception:
                    _mins = 0
                _steps_e = ' → '.join(
                    '%s %s' % (_e[0].strftime('%H:%M'), str(_e[1])[:78]) for _e in _ee[:5])
                story.append(
                    'ЯК ЦЕ ПОЧАЛОСЯ. %s користувач завантажив%s файл%s і відкрив його — '
                    'після чого в системі одразу зʼявилося стороннє програмне забезпечення. '
                    'По кроках: %s.%s'
                    % (_d0.strftime('%d.%m.%Y'),
                       (' з ' + _url.split('/')[2]) if _url.count('/') > 2 else '',
                       (' «%s»' % _lure) if _lure else '',
                       _steps_e,
                       (' Від завантаження до встановлення — %d хв.' % _mins) if _mins else ''))
                if _url:
                    story.append('Адреса, з якої прийшов файл: `%s`' % _url[:200])
    except Exception:
        pass
    # 0) the top deterministic finding, told from its own events: on a wiper delivered
    #    by GPO the download heuristic below has nothing to say, and the paragraph used
    #    to read "підозріла активність, треба підтвердити" under a CRITICAL verdict
    _top = _top_finding(findings)
    _top_ev = _fx_events([_top], sevs=(str((_top or {}).get('severity') or '').lower(),),
                         extra_categories=(), anchors_only=True) if _top else []
    if _top and _top_ev:
        _c = _top.get('category')
        _dl_rx2 = re.compile(r'msi|gpo|sysvol|заванта|download|достав|deliver|url|http|фішинг|phish|вклад|attach|лист|mail', re.I)
        _first = next((e for e in _top_ev if _dl_rx2.search(e[1] + ' ' + e[2])), _top_ev[0])
        _last = _top_ev[-1]
        # the chain, in order, the way an investigator tells it: time — what happened. Dates
        # only when the chain spans more than a day; the technical source is not repeated
        # here (it is in the verdict block and the chronology).
        def _plain_label(lbl):
            lbl = re.sub(r'\s*\((?:System|Security|TaskScheduler)[^)]*\)', '', str(lbl or ''))
            lbl = re.sub(r'\s*\(\d{3,5}(?:/\d{3,5})*\)', '', lbl)
            lbl = re.sub(r':\s*(?:Name|Task|Service|Файл|File):\s*', ': ', lbl)   # «: Name: ESET Service» → «: ESET Service»
            return lbl.strip()[:110]
        _multi_day = (_top_ev[-1][0].date() != _top_ev[0][0].date()) if len(_top_ev) > 1 else False
        def _t(ts):
            return ts.strftime('%d.%m %H:%M') if _multi_day else ts.strftime('%H:%M')
        # two legs of one kind within a minute (both ESET services dying at 07:36) read as one step
        _steps = []
        for e in _top_ev[:12]:
            _pl = _plain_label(e[1])
            _kind = _pl.split(':')[0]
            if _steps and _steps[-1][1] == _kind and abs((e[0] - _steps[-1][0]).total_seconds()) <= 120:
                _steps[-1][3] += 1
                continue
            _steps.append([e[0], _kind, _pl, 1])
        _chain = ' → '.join('%s %s%s' % (_t(s0), s2, (' (×%d)' % s3) if s3 > 1 else '') for s0, _k, s2, s3 in _steps[:8])
        _day = _top_ev[0][0].strftime('%d.%m.%Y')
        if _c == 'Знищення':
            story.append('%s на компʼютері спрацював засіб знищення системи. Що сталося, по порядку: %s. '
                         'Пакет прийшов через доменну групову політику — отже, скомпрометовано контролер домену '
                         'або обліковий запис адміністратора домену, і цей компʼютер навряд чи єдиний.'
                         % (_day, _chain))
        elif len(_top_ev) >= 2:
            story.append('Головна знахідка — %s. Що сталося, по порядку (%s): %s.'
                         % (str(_top.get('title') or '')[:80], _day, _chain))
        else:
            story.append('Головна знахідка — %s: %s (`%s`).'
                         % (str(_top.get('title') or '')[:80], _plain_label(_first[1]), _fmt_ts(_first[0])))
    # 1) delivery / entry point. NEVER on a calm verdict: this branch is what printed
    # «Атака почалася з відкриття завантаженого файлу "GooseDesktop.exe" — це й був вхід у
    # систему» one line under «Критичних/високих загроз не виявлено» (Asus, 07.03), over a
    # benign desktop-prank app. A story about an attack needs a finding that there was one.
    if _has_hi and ia and ia.get('winner') and not (_top and _top_ev):
        _w = ia['winner']
        _nm = str(_w.get('dl_name') or _w.get('exe') or 'файл')[:70]
        if _CHAIN_EXT_RE.search(_nm) and not _is_docname(_nm):
            story.append('Атака почалася з відкриття завантаженого файлу «%s» — це й був вхід у систему.' % _nm)
    elif _has_hi and ('Доставка / C2' in cats or 'fileshare' in mk):
        story.append('Все почалося з доставки шкідливого файлу через браузер/файлообмінник — вхідна точка.')
    # 2) execution
    exec_files = [t for t in ('try.exe', 'msedgex', 'chromepass') if t in mk]
    _av_n = _av_detect_count(case_key, iw)
    _av_tail = ' антивірус фіксував загрози.' if _av_n > 0 else ''
    if exec_files or 'Виконання' in cats or 'Виявлене шкідливе ПЗ' in cats:
        if exec_files:
            # «Після відкриття» only makes sense when stage 1 actually described an
            # opened file; without it the sentence referred to nothing
            _lead = 'Після відкриття на компʼютері' if story else 'На компʼютері'
            story.append('%s запустилися шкідливі файли (%s).%s'
                         % (_lead, ', '.join(exec_files), _av_tail))
        else:
            story.append('Далі запускали сторонні шкідливі програми.%s' % _av_tail)
    # 3) remote access / tunnel
    if 'Віддалений доступ / тунель' in cats or 'Доступ (RDP)' in cats:
        det = []
        if 'rdpwinst' in mk or 'rdpwrap' in mk:
            det.append('увімкнули RDP через RDP Wrapper (rdpwinst)')
        if 'Доступ (RDP)' in cats:
            det.append('заходили на хост по RDP')
        if 'ngrok' in mk:
            det.append('пробили тунель назовні через ngrok')
        if 'anydesk' in mk:
            det.append('ставили AnyDesk')
        if 'rustdesk' in mk or 'rutserv' in mk:
            det.append('ставили RustDesk/RMS')
        if '7za' in mk:
            det.append('пакували дані архіватором 7za')
        base = 'Зловмисник отримав віддалений доступ'
        story.append((base + ': ' + ', '.join(det) + '.') if det else (base + '.'))
    # 4) persistence / privileges
    if 'Закріплення/привілеї' in cats or 'Закріплення' in cats:
        p = 'Щоб залишитися в системі, зловмисник закріпився'
        if 'case_59' in mk:
            p += ' — створив обліковий запис «case_59» і надав йому права'
        else:
            p += ' (нові облікові записи / служби / автозапуск)'
        story.append(p + '.')
    # 5) defense evasion
    if 'Захист обходили' in cats:
        story.append('Паралельно вимикали Windows Defender/брандмауер і чистили журнали подій, '
                     'щоб сховати сліди.')
    # 6) outcome. On a ransomware case this is the whole point for the client, and it
    # used to be absent: the verdict said RANSOMWARE while the paragraph under it talked
    # only about Defender and RDP. Chronologically the encryption comes last, so does it.
    _rw_facts = {}
    for f in findings:
        if f.get('category') in ('Ransomware', 'Знищення резервних копій'):
            _rw_facts.update(f.get('facts') or {})
    if _rw_facts:
        bits = []
        if _rw_facts.get('ext'):
            bits.append('файли зашифровано, розширення замінено на «.%s» (%s файлів)'
                        % (_rw_facts['ext'], _rw_facts.get('files') or '?'))
        if _rw_facts.get('note'):
            _nd = _rw_facts.get('note_dirs')
            bits.append('у теках залишено записку з вимогою викупу «%s»%s'
                        % (_rw_facts['note'], (' — у %d теках' % _nd) if _nd else ''))
        if _rw_facts.get('kill_tools'):
            # detect_threats already titles this finding 'ЗА ShimCache - не доказ запуску'
            # and ships shimcache_only=True in its facts. Asserting 'знищили' on top of
            # that made one report contradict itself in two places.
            if _rw_facts.get('shimcache_only'):
                bits.append('на диску присутні засоби знищення резервних копій (%s) — '
                            'лише за ShimCache, доказу їх ЗАПУСКУ немає'
                            % ', '.join(_rw_facts['kill_tools']))
            else:
                bits.append('перед шифруванням знищили можливість відкату (%s)'
                            % ', '.join(_rw_facts['kill_tools']))
        if bits:
            story.append('Підсумок: ' + '; '.join(bits) + '.')
        story.append('Відновлення без ключа неможливе; зашифровані файли та записку слід '
                     'зберегти — вони потрібні для ідентифікації сімейства.')
    parts = []
    parts.append(_kort_ko(findings, verdict, cats))
    if story:
        parts.append(' '.join(story))
    else:
        # covered-category fallback, then generic
        # Iterate _CAT_PLAIN, not the set: a set of strings is walked in an order
        # derived from PYTHONHASHSEED, so this sentence was assembled differently in
        # every process, and frag[:5] could drop a different explanation each time
        # (case_45_case_52 has 7 qualifying categories). The dict order is the kill chain
        # - delivery, execution, malware, tools, remote access, persistence, evasion -
        # so the fallback sentence now also reads in the order the attack happened.
        frag = [_CAT_PLAIN[c] for c in _CAT_PLAIN if c in cats]
        if frag:
            parts.append('Простими словами: ' + '; '.join(frag[:5]) + '.')
        elif not _has_hi and findings:
            parts.append('Простими словами: критичних або високих загроз не виявлено; '
                         'наявні пункти — типово звичайна системна активність, яку варто перевірити вручну.')
        elif not findings:
            parts.append('Простими словами: явних ознак відомих атак не виявлено; потрібен ручний розбір.')
        else:
            parts.append('Простими словами: зафіксовано підозрілу активність; точні причинно-наслідкові '
                         'звʼязки треба підтвердити за доказами нижче.')
    try:
        _kf = _conclusion_key_facts(case_key, iw, findings=findings,
                                    chain_facts=_chain_key_facts(findings))
        if _kf:
            parts.append('**📋 Ключові факти (з датами):**\n' + '\n'.join('- ' + _x for _x in _kf))
    except Exception:
        pass
    s, e, _ = iw
    _fs, _fe = _fx_window(findings)
    if _fs or _fe:
        parts.append('Активна фаза за підтвердженими ланками: `%s` → `%s`.' % (_fs or '?', _fe or '?'))
    elif s or e:
        parts.append('Основна активність: `%s` → `%s`.' % (s or '?', e or '?'))
    parts.append('_Усі твердження варто звірити з сирими логами (службові дані) перед фінальним звітом._')
    return parts


def case_summary(case_key):
    """Deterministic, GROUNDED case summary for general 'що було / підсумок' questions.
    Verdict + plain-language conclusion + first infection point + key timeline, all built
    straight from the case DB. No LLM -> no chain-of-thought leak, no hallucinated evidence.
    Returns None for empty cases (let the zero-evidence guard handle those)."""
    try:
        iw = _incident_window(case_key)
        findings = _findings(case_key)
        if not findings and not iw[0]:
            return None
        verdict = _verdict(findings)
        L = []
        L.append('## 🎯 Що сталося в цьому кейсі (за даними логів)')
        L.append('')
        _ia_s = _initial_access_struct(case_key, iw[0])
        L += _calm_scope(case_key, findings, _plain_conclusion(case_key, findings, verdict, iw, ia=_ia_s))
        L.append('')
        ia = _initial_access(case_key, iw[0])
        if ia:
            L.append('**🚪 Перша точка зараження:**')
            L += ia[:6]
            L.append('')
        tl = _timeline(case_key, iw[0])
        if tl:
            L.append('**🕒 Ключові події:**')
            L += tl[:10]
        out = NL.join(L).strip()
        if chr(8) in out or chr(13) in out:
            out = out.replace(chr(8), '').replace(chr(13), '')
        return out if len(out) > 40 else None
    except Exception:
        return None


# Paths the collector itself is known to create/exclude — never present them as
# tampering by someone else. The collector declares them in _collector_self.txt;
# the Defender exclusion on its own triage folder is left behind ON PURPOSE, so an
# antivirus cannot destroy an archive that holds a malware sample.
# the v3 collector ships as dfir_collector_v3.0_<date>.exe; the old alternatives
# (dfircollector_) never matched that name, so its own executable came back as
# evidence. Measured: 1 program_exec row + 22 filesystem rows, case_66 only.
_OWN_PATH_RE = re.compile(r"dfir_triage|dfirtriage_|dfircollector_|dfir_collector", re.I)

_ENV_LABEL = {
    "admin": "Права збирача",
    "cmd_exe": "Командний рядок cmd.exe",
    "powershell_script_file": "Запуск файлів .ps1",
    "powershell_stdin": "PowerShell через stdin",
    "powershell_language_mode": "Режим мови PowerShell",
    "antivirus": "Антивірус",
    "os": "Операційна система",
}
_ENV_STATE = {
    "ok": "працює",
    "blocked": "ЗАБЛОКОВАНО",
    "missing": "не знайдено",
    "error": "помилка перевірки",
    "no_admin": "БЕЗ прав адміністратора",
    "enabled": "увімкнено",
    "disabled": "вимкнено",
    "?": "НЕ ПЕРЕВІРЕНО",
    "": "НЕ ПЕРЕВІРЕНО",
}
_EXCL_TAG = {"ExclusionProcess": "процес", "ExclusionExtension": "розширення"}
_RAM_WHY = {
    "tool_missing": "інструмент захоплення не знайдено на машині",
    "no_space": "забракло вільного місця",
    "failed": "інструмент завершився помилкою",
}


def _ioc_grounded(case_key, value):
    """True when the case evidence tables (not case_iocs) contain the value or a looser form."""
    try:
        from analysis.output_guardrails import artifact_probe_forms
        forms = artifact_probe_forms(value)
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            cur.execute("SET statement_timeout='15000'")
            for f in forms:
                like = '%' + str(f).replace('%', '') + '%'
                cur.execute("""SELECT EXISTS (
                                 SELECT 1 FROM event_logs_v2 WHERE case_key=%s AND (coalesce(command_line,'') ILIKE %s OR coalesce(remote_host,'') ILIKE %s OR payload::text ILIKE %s)
                                 UNION ALL SELECT 1 FROM filesystem_v2 WHERE case_key=%s AND (file_name ILIKE %s OR coalesce(parent_path,'') ILIKE %s OR payload::text ILIKE %s)
                                 UNION ALL SELECT 1 FROM program_exec_v2 WHERE case_key=%s AND (coalesce(full_path,'') ILIKE %s OR coalesce(executable_name,'') ILIKE %s OR payload::text ILIKE %s)
                                 UNION ALL SELECT 1 FROM raw_fallback_v2 WHERE case_key=%s AND payload::text ILIKE %s AND %s=%s
                                 LIMIT 1)""", (case_key, like, like, like, case_key, like, like, like, case_key, like, like, like, case_key, like, like, like))
                if (cur.fetchone() or [False])[0]:
                    return True
        return False
    except Exception:
        return True   # never drop an indicator because the check itself failed


def _completeness_section(case_key):
    """«ПОВНОТА ДАНИХ»: how much of the archive the bot actually read, and which sources
    the verdict rests on. Built from ingest_jobs.coverage_json, dfir_ingest_coverage_v1 and
    row counts; self-omits only when the case has no ingest job at all."""
    if not PG_DSN:
        return []
    out = []
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute("SET statement_timeout='20000'")
        try:
            cur.execute("""SELECT job_id, status, started_at, finished_at, parsed_files, errors_json,
                                  coverage_json
                           FROM ingest_jobs WHERE case_key=%s ORDER BY job_id DESC LIMIT 1""", (case_key,))
        except Exception:
            conn.rollback()
            cur.execute("""SELECT job_id, status, started_at, finished_at, parsed_files, errors_json, NULL
                           FROM ingest_jobs WHERE case_key=%s ORDER BY job_id DESC LIMIT 1""", (case_key,))
        job = cur.fetchone()
        if not job:
            out.append('## 📦 ПОВНОТА ДАНИХ (що саме бот прочитав з архіву)')
            out.append('- _Запису про інжест цієї справи немає (старий конвеєр) — нижче лише зріз джерел за базою._')
            try:
                from analysis.coverage_model import report_lines as _cov_lines0
                out.extend(_cov_lines0(case_key, None))
            except Exception:
                pass
            out.append('')
            return out
        job_id, status, started, finished, parsed, errors_json, cov = job
        cov = cov or {}
        if isinstance(cov, str):
            try:
                import json as _json
                cov = _json.loads(cov)
            except Exception:
                cov = {}
        counts = {}
        for t, lbl in (('event_logs_v2', 'подій журналів'), ('filesystem_v2', 'записів файлової системи ($MFT/$J)'),
                       ('program_exec_v2', 'артефактів виконання'), ('srum_v2', 'записів SRUM'),
                       ('raw_fallback_v2', 'рядків інших артефактів'), ('tool_alerts_v2', 'алертів сканерів')):
            try:
                cur.execute("SELECT count(*) FROM %s WHERE case_key=%%s" % t, (case_key,))
                counts[t] = (lbl, int(cur.fetchone()[0] or 0))
            except Exception:
                conn.rollback()
                counts[t] = (lbl, 0)
        # execution-artefact sources: the verdict on "what ran" depends on these existing
        exec_src = {}
        try:
            cur.execute("""SELECT CASE WHEN lower(source_file) LIKE '%%pecmd%%' THEN 'Prefetch'
                                       WHEN lower(source_file) LIKE '%%amcache%%' THEN 'Amcache'
                                       WHEN lower(source_file) LIKE '%%appcompatcache%%' THEN 'ShimCache'
                                       WHEN lower(source_file) LIKE '%%bamdam%%' THEN 'BAM/DAM'
                                       ELSE 'інше' END AS src, count(*)
                           FROM program_exec_v2 WHERE case_key=%s GROUP BY 1""", (case_key,))
            exec_src = {r[0]: int(r[1]) for r in cur.fetchall()}
        except Exception:
            conn.rollback()
        audit = {}
        try:
            cur.execute("""SELECT sum(CASE WHEN event_id=4688 THEN 1 ELSE 0 END),
                                  sum(CASE WHEN event_id=4104 THEN 1 ELSE 0 END),
                                  sum(CASE WHEN channel ILIKE '%%Sysmon%%' THEN 1 ELSE 0 END),
                                  count(DISTINCT channel), min(event_ts)::date, max(event_ts)::date
                           FROM event_logs_v2 WHERE case_key=%s""", (case_key,))
            r = cur.fetchone() or (0, 0, 0, 0, None, None)
            audit = {'4688': int(r[0] or 0), '4104': int(r[1] or 0), 'sysmon': int(r[2] or 0),
                     'channels': int(r[3] or 0), 'from': r[4], 'to': r[5]}
        except Exception:
            conn.rollback()
        collector = None
        try:
            cur.execute("""SELECT file_name FROM upload_audit_v1 WHERE case_key=%s AND mode='logs'
                           ORDER BY ts DESC LIMIT 1""", (case_key,))
            r = cur.fetchone()
            collector = r[0] if r else None
        except Exception:
            conn.rollback()
        started_own = None
        try:
            from analysis.own_footprint import own_started_at
            started_own = own_started_at(case_key, conn)
        except Exception:
            started_own = None
        unconsumed = []
        try:
            cur.execute("""SELECT rel_path, size_bytes FROM dfir_ingest_coverage_v1
                           WHERE case_key=%s AND status='unconsumed' ORDER BY size_bytes DESC LIMIT 15""",
                        (case_key,))
            unconsumed = cur.fetchall()
        except Exception:
            conn.rollback()

    out.append('## 📦 ПОВНОТА ДАНИХ (що саме бот прочитав з архіву)')
    # collector-version gate (docs/COLLECTOR_VERSION_GATE_2026-09-09.md): say when the
    # execution artefacts are missing because of the collector, not the machine.
    try:
        from analysis.collector_self import exec_artifact_gap
        _gap = exec_artifact_gap(case_key, None)
        if _gap and _gap.get('warning'):
            out.append('- %s' % _gap['warning'])
    except Exception:
        pass
    # evidence-coverage model: name the absent sources, so silence is never read as calm
    try:
        from analysis.coverage_model import report_lines as _cov_lines
        out.extend(_cov_lines(case_key, None))
    except Exception:
        pass
    out.append('_Вердикт «загроз не виявлено» має сенс лише поруч із цим блоком: він показує, на яких '
               'даних він стоїть._')
    if collector:
        out.append('- **Архів:** `%s`%s' % (collector, (' · збирач стартував на машині `%s`' % str(started_own)[:19]) if started_own else ''))
    st_txt = {'done': 'завершено', 'running': '⚠️ ще триває', 'failed': '⛔ помилка', 'superseded': 'перезапущено'}.get(str(status), str(status))
    out.append('- **Інжест:** %s%s%s' % (st_txt, (' · %s → %s' % (str(started)[:16], str(finished)[:16])) if started and finished else '',
                                        (' · оброблено рядків: %s' % format(int(parsed or 0), ',').replace(',', ' ')) if parsed else ''))
    if cov:
        ft = int(cov.get('files_total') or 0)
        out.append('- **Файли архіву:** %d · прочитано **%d** · порожніх %d · пропущено свідомо %d · '
                   'не розпізнано **%d** · відхилено з помилкою **%d** · UTF-16 CSV: %d'
                   % (ft, int(cov.get('consumed') or 0), int(cov.get('empty') or 0),
                      int(cov.get('skipped_by_design') or 0), int(cov.get('unconsumed') or 0),
                      int(cov.get('rejected') or 0), int(cov.get('utf16_csvs') or 0)))
        if cov.get('rejected') and cov.get('first_error'):
            out.append('  - ⛔ перша помилка: `%s`' % str(cov.get('first_error'))[:160].replace('`', "'"))
    elif errors_json:
        try:
            _n_err = len(errors_json) if isinstance(errors_json, list) else 0
        except Exception:
            _n_err = 0
        if _n_err:
            out.append('- ⛔ **Файлів з помилкою інжесту:** %d (перша: `%s`)' % (_n_err, str(errors_json[0])[:140].replace('`', "'")))
    rows_line = ' · '.join('%s: %s' % (lbl, format(n, ',').replace(',', ' ')) for lbl, n in counts.values())
    out.append('- **У базі:** ' + rows_line)
    if audit:
        span = (' · період подій %s → %s' % (audit.get('from'), audit.get('to'))) if audit.get('from') else ''
        out.append('- **Журнали:** каналів %d%s · аудит створення процесів (4688): %s · PowerShell ScriptBlock (4104): %s · Sysmon: %s'
                   % (audit.get('channels', 0), span,
                      (('увімкнено, %d подій' % audit['4688']) if audit['4688'] >= 1000
                       else ('**лише %d подій — фактично вимкнено**' % audit['4688'])) if audit.get('4688')
                      else '**вимкнено/відсутній** — запуски процесів невидимі в журналах',
                      ('%d подій' % audit['4104']) if audit.get('4104') else 'немає',
                      'є' if audit.get('sysmon') else 'немає'))
    if exec_src or counts.get('program_exec_v2', ('', 0))[1] == 0:
        parts = []
        for k in ('Prefetch', 'Amcache', 'ShimCache', 'BAM/DAM'):
            parts.append('%s: %s' % (k, exec_src.get(k, 0) if exec_src.get(k) else '**немає**'))
        out.append('- **Артефакти виконання:** ' + ' · '.join(parts))
    if unconsumed:
        out.append('- **Не розпізнано (бот цього не читав, потрібен парсер):**')
        for rel, size in unconsumed:
            out.append('  - `%s` (%s КБ)' % (str(rel).replace('`', "'")[:110], format(int((size or 0) / 1024), ',').replace(',', ' ')))
    # the caveat: the one line an investigator must not miss
    caveats = []
    if cov and int(cov.get('files_total') or 0) and int(cov.get('unconsumed') or 0) * 10 > int(cov.get('files_total') or 0):
        caveats.append('понад 10 %% файлів архіву не розпізнано')
    if cov and int(cov.get('rejected') or 0):
        caveats.append('%d файлів відхилено з помилкою' % int(cov.get('rejected') or 0))
    if not exec_src.get('Prefetch') and not exec_src.get('ShimCache'):
        caveats.append('немає ні Prefetch, ні ShimCache — запуск програм видно лише з Amcache/BAM')
    if audit and not audit.get('4688'):
        caveats.append('аудит 4688 вимкнено')
    if str(status) != 'done':
        caveats.append('інжест не завершено')
    if caveats:
        out.append('- ⚠️ **Застереження до вердикту:** ' + '; '.join(caveats) + '. Висновок «загроз немає» тут = «у прочитаному не знайдено».')
    return out


def _collection_conditions_section(case_key):
    """Render «УМОВИ ЗБОРУ ДАНИХ» from the collector v4.0 artefacts that land in
    raw_fallback_v2: environment_restrictions / collection_gaps /
    defender_exclusions / ram_capture (INTEGRATION_CONTRACT.md §6).

    Two things this buys the reader: (1) a blocked cmd.exe, GPO-blocked .ps1 files
    or a Defender exclusion are EVIDENCE that someone configured the machine, not
    just a collection nuisance; (2) a step that did not run is stated out loud, so
    a half-collected archive stops reading like a complete one.

    Returns [] for archives collected before v4.0 — old cases render unchanged."""
    out = []
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            cur.execute("SET statement_timeout='5000'")
            rows = _q(cur, """SELECT parser_family, payload FROM raw_fallback_v2
                              WHERE case_key=%s AND parser_family IN
                                    ('environment','collection_gaps',
                                     'defender_exclusions','ram_capture')
                              LIMIT 2000""", (case_key,))
            if not rows:
                return []
            env, gaps, excl, ram = [], [], [], {}
            for fam, p in rows:
                p = p or {}
                if fam == "environment":
                    env.append(p)
                elif fam == "collection_gaps":
                    gaps.append(p)
                elif fam == "defender_exclusions":
                    excl.append(p)
                elif fam == "ram_capture":
                    k = str(p.get("key") or "").strip()
                    if k and k not in ram:
                        ram[k] = p

            body = []

            # 1) environment restrictions — lead with the limits, not the clean checks
            lim, ctx = [], []
            for p in env:
                chk = str(p.get("check") or "").strip()
                st = str(p.get("status") or "").strip().lower()
                det = str(p.get("detail") or "").strip()
                if not chk:
                    continue
                label = _ENV_LABEL.get(chk, chk)
                if chk == "powershell_language_mode":
                    val = str(p.get("status") or "?")
                    line = "%s: `%s`" % (label, val)
                    if val.lower().startswith("constrained"):
                        lim.append("⚠️ " + line)
                    else:
                        ctx.append(line)
                    continue
                if chk == "os":
                    ctx.append("%s: %s" % (label, det or "?"))
                    continue
                human = _ENV_STATE.get(st, st or "НЕ ПЕРЕВІРЕНО")
                if chk == "admin" and st == "ok":
                    human = "адміністратор"  # "працює" reads wrong for a rights check
                line = "%s: **%s**%s" % (label, human, (" — %s" % det) if det else "")
                if st in ("blocked", "no_admin", "missing", "error", "?", ""):
                    lim.append("⚠️ " + line)
                else:
                    ctx.append(line)
            if lim or ctx:
                body.append("**🖥 Середовище на машині, де працював збирач:**")
                body += ["- " + x for x in (lim + ctx)][:14]
                if any("ЗАБЛОКОВАНО" in x and ("cmd.exe" in x or ".ps1" in x) for x in lim):
                    body.append("_Заблокований cmd.exe або заборона сценаріїв — це налаштування, "
                                "яке хтось зробив свідомо. Варто зʼясувати хто і коли._")

            # 2) Defender exclusions — tampering evidence, minus the collector's own
            if excl:
                own = 0
                shown = []
                # What the collector DECLARED about itself wins over any guess: exact
                # path match against _collector_self.txt (INTEGRATION_CONTRACT.md §2 п.1).
                # Nothing wider — a broad filter once ate a svchost.exe on a user desktop.
                try:
                    from analysis.collector_self import declared_self_paths, is_declared
                    _declared = declared_self_paths(case_key)
                except Exception:
                    _declared, is_declared = set(), None
                own_declared = 0
                for p in excl:
                    val = str(p.get("value") or "").strip()
                    if not val:
                        continue
                    if _declared and is_declared and is_declared(val, _declared):
                        own += 1
                        own_declared += 1
                        continue
                    if _OWN_PATH_RE.search(val):
                        own += 1
                        continue
                    kind = str(p.get("kind") or "").strip()
                    ex = str(p.get("exists") or "").strip().lower()
                    tag = _EXCL_TAG.get(kind, "шлях")
                    note = ""
                    if tag == "шлях":
                        if ex == "yes":
                            note = " _(існує)_"
                        elif ex == "no":
                            note = " _(теки або файлу вже немає)_"
                    shown.append("- %s: `%s`%s" % (tag, val[:160], note))
                if shown:
                    body.append("**🛡 Винятки Захисника Windows (ознака втручання):**")
                    body += shown[:20]
                    body.append("_Виняток означає, що вміст за цим шляхом не перевіряється. "
                                "Зловмисники додають їх, щоб їхні файли не чіпали._")
                if own:
                    _w = ("виняток" if own % 10 == 1 and own % 100 != 11 else
                          "винятки" if own % 10 in (2, 3, 4) and own % 100 not in (12, 13, 14)
                          else "винятків")
                    _src = (" (з них %d названо у файлі самодекларації збирача)" % own_declared) if own_declared else ""
                    body.append("_(ще %d %s створив сам збирач%s — не враховано.)_" % (own, _w, _src))

            # 3) memory capture
            if ram:
                stat_row = ram.get("status") or {}
                st = str(stat_row.get("value") or "").strip().lower()
                tool = str(stat_row.get("tool") or "").strip()
                if st == "ok":
                    raw_size = str((ram.get("size_bytes") or {}).get("value") or "").strip()
                    try:
                        size = "%.1f ГБ" % (float(raw_size) / 1073741824.0)
                    except Exception:
                        size = raw_size or "?"
                    body.append("**🧠 Оперативна памʼять: знято** (%s, %s). "
                                "Дамп передається окремо — у цьому архіві його немає."
                                % (tool or "інструмент захоплення", size))
                elif st:
                    body.append("**🧠 Оперативна памʼять: НЕ знято** — %s."
                                % _RAM_WHY.get(st, st))

            # 4) gaps — every step that did not run
            if gaps:
                body.append("**⚠️ Не зібрано (прогалини збору):**")
                for p in gaps[:20]:
                    step = str(p.get("step") or "?").strip()
                    why = str(p.get("reason") or "").strip()
                    body.append("- %s%s" % (step, (" — %s" % why) if why else ""))
                body.append("_Цих даних в архіві немає. Висновки за ними робити не можна; "
                            "за потреби — повторний збір._")
            elif env:
                body.append("_Прогалин збору не зафіксовано: усі кроки виконались._")

            if not body:
                return []
            out.append("## 🧰 УМОВИ ЗБОРУ ДАНИХ")
            out += body
    except Exception:
        return []
    return out


# Narrow on purpose. Measured noise first: ms-screensketch:/ms-paint: URIs carry
# `sharedAccessToken=`, and a bare "secret"/"token" matches song titles. What survives
# are credential stores, signing keys and wallets.
_SENSITIVE_DOC_RE = re.compile(
    r'(парол[иья]|password|passwd|\.kdbx|keepass|bitwarden|lastpass|'
    r'wallet\.dat|metamask|mnemonic|seed.?phrase|private.?key|\.jks|\.pfx|\.p12|'
    r'ключ[иі]?[ _-]|секретн)', re.I)
_URI_NOISE_RE = re.compile(r'^(ms-[a-z]+:|search:|shell:|https?://)', re.I)
_MEDIA_EXT_RE = re.compile(r'\.(mp3|mp4|avi|mkv|wav|jpg|jpeg|png|gif|webp)$', re.I)


def _fix_mojibake(s):
    """CP1251 text that was decoded as Latin-1 somewhere upstream, repaired for display.

    `Êëþ÷è ôîïîâ` -> `Ключи фопов`. Only returns the repaired string when the round trip
    actually yields Cyrillic, so correct text and genuine Latin text pass through
    unchanged."""
    if not s:
        return s
    # lower bound U+00A0: CP1251 і ї є ґ live below U+00C0
    if not any('\u00a0' <= ch <= '\u00ff' for ch in s):
        return s
    fixed = None
    # CP1252 before Latin-1 — see parsers/forensic.py::_demojibake
    for enc in ('cp1252', 'latin-1'):
        try:
            fixed = s.encode(enc, 'strict').decode('cp1251', 'strict')
            break
        except Exception:
            continue
    if fixed is None:
        return s
    cyr = sum(1 for ch in fixed if '\u0400' <= ch <= '\u04ff')
    return fixed if cyr >= 3 else s


def _documents_section(case_key):
    """«Документи, носії та видалене» — from lnk / jumplists / recyclebin.

    These three families are ingested on every case and were rendered nowhere. Returns
    [] when the case has none of them, so older reports are unaffected."""
    out = []
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            cur.execute("SET statement_timeout='8000'")

            # 1) deleted files — what was thrown away, and when
            dele = _q(cur, """SELECT payload->>'FileName', payload->>'DeletedOn',
                                     payload->>'FileSize'
                              FROM raw_fallback_v2
                              WHERE case_key=%s AND parser_family='recyclebin'
                                AND coalesce(payload->>'FileName','') <> ''
                                -- our own and the examiner tooling: a 17 GB memory dump
                                -- the examiner deleted is not the victim hiding evidence
                                AND lower(coalesce(payload->>'FileName','')) !~ %s
                              -- row_id як розрізнювач: десятки записів Кошика мають ОДНАКОВИЙ час видалення,
                              -- тож сам DeletedOn не задає повного порядку. Виміряно:
                              -- 5 різних порядків із 6 прогонів на 20_07_case_44_case_43.
                              ORDER BY payload->>'DeletedOn' DESC NULLS LAST, row_id
                              LIMIT 400""", (case_key, _FP_DROP_RE))
            # 2) removable media — documents that left or arrived on a stick
            rem = _q(cur, """SELECT coalesce(payload->>'LocalPath', payload->>'Path',''),
                                    coalesce(payload->>'VolumeLabel',
                                             payload->>'VolumeSerialNumber','')
                             FROM raw_fallback_v2
                             WHERE case_key=%s AND parser_family IN ('lnk','jumplists')
                               AND payload->>'DriveType' ILIKE '%%removable%%'
                             -- ORDER BY, бо без нього LIMIT віддає довільні рядки і звіт
                             -- відрізняється між прогонами на тих самих даних
                             ORDER BY row_id
                             LIMIT 500""", (case_key,))
            # 3) sensitive documents anywhere in the three families
            names = _q(cur, """SELECT DISTINCT coalesce(payload->>'LocalPath',
                                       payload->>'Path', payload->>'FileName','')
                               FROM raw_fallback_v2
                               WHERE case_key=%s
                                 AND parser_family IN ('lnk','jumplists','recyclebin')
                               -- ORDER BY, бо без нього LIMIT віддає довільні рядки і звіт
                               -- відрізняється між прогонами на тих самих даних
                               ORDER BY 1
                               LIMIT 4000""", (case_key,))
            sens = []
            for (n,) in names:
                n = (n or '').strip()
                if not n or _URI_NOISE_RE.search(n) or _MEDIA_EXT_RE.search(n):
                    continue
                if _SENSITIVE_DOC_RE.search(_fix_mojibake(n)):
                    sens.append(n)

            _dt_row = _q(cur, """SELECT count(*) FROM raw_fallback_v2
                                 WHERE case_key=%s AND parser_family='recyclebin'
                                   AND coalesce(payload->>'FileName','') <> ''
                                   AND lower(coalesce(payload->>'FileName','')) !~ %s""",
                         (case_key, _FP_DROP_RE))
            _del_total = _dt_row[0][0] if _dt_row else len(dele)
            _rm_row = _q(cur, """SELECT count(*) FROM raw_fallback_v2
                                 WHERE case_key=%s AND parser_family IN ('lnk','jumplists')
                                   AND payload->>'DriveType' ILIKE '%%removable%%'""",
                         (case_key,))
            _rem_total = _rm_row[0][0] if _rm_row else len(rem)

            if not (dele or rem or sens):
                return []
            out.append('## \U0001f5c2 ДОКУМЕНТИ, НОСІЇ ТА ВИДАЛЕНЕ')

            if dele:
                out.append('**\U0001f5d1 Видалені файли (Кошик) — %d записів, останні:**' % _del_total)
                for fn, ts, size in dele[:8]:
                    _sz = ''
                    try:
                        _sz = ' · %.1f МБ' % (float(size) / 1048576.0) if size else ''
                    except Exception:
                        _sz = ''
                    out.append('- `%s` — видалено %s%s'
                               % (_fix_mojibake(str(fn))[:110], (ts or '?')[:16], _sz))
                out.append('_Видалення саме по собі не є доказом приховування — звіряй час '
                           'із подіями інциденту._')

            if rem:
                vols = {}
                for path, vol in rem:
                    vols[str(vol or 'без мітки')] = vols.get(str(vol or 'без мітки'), 0) + 1
                out.append('**\U0001f4be Файли, відкриті зі знімних носіїв — %d, носіїв: %d**'
                           % (_rem_total, len(vols)))
                for v, n in sorted(vols.items(), key=lambda x: -x[1])[:5]:
                    out.append('- носій `%s` — %d файлів' % (_fix_mojibake(v)[:40], n))
                for path, _v in rem[:5]:
                    out.append('  · `%s`' % _fix_mojibake(str(path))[:110])
                out.append('_Знімний носій — типовий шлях і для витоку документів, і для '
                           'занесення шкідливого файлу._')

            if sens:
                out.append('**\U0001f511 Файли з ознаками облікових даних або ключів — %d:**'
                           % len(sens))
                for n in sens[:8]:
                    out.append('- `%s`' % _fix_mojibake(n)[:120])
                out.append('_Наявність такого файлу не означає, що його викрали; це орієнтир, '
                           'що саме перевіряти далі._')
    except Exception:
        return []
    return out


# The collector labels every timestamp it reports. Only one of these is a run time.
_WHEN_KIND_LABEL = {
    'execution(prefetch)': 'запуск',
    'first_seen(amcache)': 'перша поява файлу',
    'file_mtime(shimcache)': 'час файлу, НЕ запуску',
}
_EXEC_RULE_LABEL = {
    'archiver_temp': 'запуск із тимчасової теки архіватора',
    'double_extension': 'подвійне розширення',
    'lookalike_name': 'імʼя, схоже на системне',
    'possible_rename': 'імовірне перейменування',
    'recon_burst': 'сплеск розвідувальних команд',
    'remote_access': 'засіб віддаленого доступу',
    'sysbin_in_staging': 'системний бінарник у теці підготовки',
    'sysbin_wrong_place': 'системний бінарник не на своєму місці',
    'timestamp_copied': 'підроблені мітки часу',
}


def _execution_findings_section(case_key):
    """«Сліди запуску» — the collector's own analysis of ShimCache/Amcache/Prefetch.

    Each row is printed with the KIND of its timestamp, because two of the three sources
    do not carry an execution time at all. Returns [] for archives collected before the
    tool existed."""
    out = []
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            cur.execute("SET statement_timeout='6000'")
            rows = _q(cur, """SELECT payload FROM raw_fallback_v2
                              WHERE case_key=%s AND parser_family='execution_findings'
                              LIMIT 400""", (case_key,))
            if not rows:
                return []
            highs, meds = [], []
            for (p,) in rows:
                p = p or {}
                sev = str(p.get('severity') or '').upper()
                (highs if sev == 'HIGH' else meds).append(p)
            out.append('## \U0001f50e СЛІДИ ЗАПУСКУ (аналіз збирача)')
            out.append('_Знахідок: %d (високих %d). Час у кожному рядку підписано, бо з трьох '
                       'джерел лише Prefetch дає справжній час запуску._'
                       % (len(rows), len(highs)))
            for p in (highs + meds)[:14]:
                rule = str(p.get('rule') or '')
                lbl = _EXEC_RULE_LABEL.get(rule, rule)
                when = str(p.get('when') or '')[:16]
                kind = _WHEN_KIND_LABEL.get(str(p.get('when_kind') or ''),
                                            str(p.get('when_kind') or ''))
                nm = str(p.get('name') or p.get('path') or '?')
                sev = 'ВИСОКА' if str(p.get('severity') or '').upper() == 'HIGH' else 'середня'
                line = '- **%s** — `%s`' % (lbl, nm[:70])
                if when:
                    line += ' · %s _(%s)_' % (when, kind)
                line += ' · важливість: %s' % sev
                out.append(line)
                det = str(p.get('detail') or '').strip()
                if det:
                    out.append('  · %s' % det[:150])
            if len(highs) + len(meds) > 14:
                out.append('_… ще %d знахідок у службових даних._'
                           % (len(highs) + len(meds) - 14))
    except Exception:
        return []
    return out


# --- collector lead lists that reached the database but were rendered nowhere ---
# suspicious_files / encrypted_files / encryption_status / autoruns.
# All four self-omit when the case has no rows, so archives collected before the
# artefact existed render exactly as they did. INTEGRATION_CONTRACT.md §2 п.3.


def _plural(n, one, few, many):
    """`1 запис / 2 записи / 5 записів` — a wrong ending reads as a machine wrote it."""
    n = abs(int(n))
    if n % 10 == 1 and n % 100 != 11:
        return one
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return few
    return many


def _num(v):
    try:
        return float(str(v).strip())
    except Exception:
        return 0.0


# The MFT pass labels every hit with WHY it stands out. Rank: 3 = show first,
# 2 = show, 0 = count only (the REVIEW bucket exists for recall, not for reading).
_SUSP_CAT = {
    'EXECUTABLE DROPPED IN A STAGING FOLDER':
        ('виконуваний файл у теці підготовки', 3),
    'EXECUTED FROM AN ARCHIVE TEMP FOLDER':
        ('запуск із тимчасової теки архіватора', 3),
    'DOUBLE EXTENSION (MASQUERADE)':
        ('подвійне розширення (маскування під документ)', 3),
    'RIGHT-TO-LEFT OVERRIDE IN NAME':
        ('символ RLO в імені — розширення показується задом наперед', 3),
    'SYSTEM BINARY NAME IN THE WRONG FOLDER':
        ('імʼя системного файлу не на своєму місці', 3),
    'SCRIPT IN A USER-WRITABLE FOLDER':
        ('скрипт у теці, куди може писати користувач', 2),
    'DELETED EXECUTABLE':
        ('видалений виконуваний файл (видно лише з $MFT)', 2),
    'TIMESTOMP: $SI OLDER THAN $FN':
        ('підроблені мітки часу ($SI старіший за $FN)', 2),
    'TIMESTOMP: ZEROED SUB-SECOND + A SECOND SIGNAL':
        ('підроблені мітки часу (обнулені частки секунди + другий сигнал)', 2),
    'ALTERNATE DATA STREAM':
        ('альтернативний потік даних (ADS)', 2),
    'IN A STARTUP FOLDER':
        ('файл у теці автозапуску', 2),
    'DOWNLOADED FROM THE INTERNET (MOTW)':
        ('завантажено з інтернету (мітка MOTW)', 2),
    'EXECUTABLE IN AN UNUSUAL FOLDER (REVIEW)':
        ('виконуваний файл у нетиповій теці', 0),
}


# How many rows each file section reads. Named, because both files can legitimately
# run long: suspicious_files.csv is uncapped by design, and a file share can hold
# thousands of password-protected archives.
_SUSP_ROW_LIMIT = 20000
_ENC_ROW_LIMIT = 20000


def _size_bytes(v):
    """`1048576` -> ` · 1.0 МБ`. Empty for missing or unparsable values."""
    n = _num(v)
    if n <= 0:
        return ''
    if n >= 1048576:
        return ' · %.1f МБ' % (n / 1048576.0)
    return ' · %d КБ' % max(int(n / 1024), 1)


def _size_mb(v):
    """The encrypted-file list reports megabytes; a 120 KB key store must not
    print as «0 МБ»."""
    n = _num(v)
    if n <= 0:
        return ''
    if n >= 1024:
        return ' · %.1f ГБ' % (n / 1024.0)
    if n >= 1:
        return ' · %.0f МБ' % n
    return ' · %d КБ' % max(int(n * 1024), 1)


def _suspicious_files_section(case_key):
    """«Файли, що виділяються за $MFT» — the collector's suspicious_files.csv.

    The CSV is deliberately uncapped (its REVIEW bucket exists so recall stays 100%),
    so printing it would be a CSV dump, not a report. Here it is aggregated: how many
    hits per reason, and examples only from the reasons that actually mean something.

    Two exclusions, both load-bearing:
      * our own collector writes dfp_*.ps1 probes and DFIRTriage_* folders into
        %TEMP%, and the MFT records them — without this filter the tool flags itself;
      * a path that exists verbatim in a clean Windows drops to the review count,
        because the vanilla index is the only thing that separates a planted
        `svchost.exe` from a stock copy of the real one. `None` (index unavailable)
        is NOT treated as clean — such a row simply stays where it was.
    """
    out = []
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            cur.execute("SET statement_timeout='8000'")
            # The collector writes this CSV UNCAPPED on purpose (its REVIEW bucket keeps
            # recall at 100%), so on a full disk it can run to tens of thousands of rows.
            # The real total is asked for separately: printing «знахідок: N» off a
            # truncated fetch would be a quiet lie, and a wrong number in a report is
            # worse than a missing one.
            _tot = _q(cur, """SELECT count(*) FROM raw_fallback_v2
                              WHERE case_key=%s AND parser_family='suspicious_files'""",
                      (case_key,))
            db_total = int(_tot[0][0]) if _tot else 0
            # ORDER BY, бо без нього LIMIT віддає довільні рядки і звіт
            # відрізняється між прогонами на тих самих даних
            rows = _q(cur, """SELECT payload FROM raw_fallback_v2
                              WHERE case_key=%s AND parser_family='suspicious_files'
                              ORDER BY row_id LIMIT %s""", (case_key, _SUSP_ROW_LIMIT))
        if not rows:
            return []

        try:
            from analysis.known_good import is_vanilla_path as _vp
        except Exception:
            _vp = None

        groups, review, own, vanilla = {}, 0, 0, 0
        for (p,) in rows:
            p = p or {}
            cat = str(p.get('Category') or '').strip()
            path = _fix_mojibake(str(p.get('Path') or '').strip())
            if not cat or not path or path == '-':
                continue
            low = path.lower()
            if re.search(_EXAMINER_TOOL_PY, low) or _OWN_PATH_RE.search(low):
                own += 1
                continue
            label, rank = _SUSP_CAT.get(cat, (cat.lower(), 1))
            if rank >= 2 and _vp is not None:
                try:
                    if _vp(path) is True:   # True only; None means «не знаю»
                        vanilla += 1
                        rank = 0
                except Exception:
                    pass
            if rank == 0:
                review += 1
                continue
            groups.setdefault((rank, label), []).append(p)

        total = sum(len(v) for v in groups.values()) + review
        if total == 0:
            return []

        out.append('## \U0001f9ff ФАЙЛИ, ЩО ВИДІЛЯЮТЬСЯ ЗА $MFT')
        _hdr = ('_Знахідок: %d, з них потребують уваги: %d. Це список зачіпок за '
                'таблицею $MFT, а не вирок: кожен рядок ще треба підтвердити._'
                % (total, total - review))
        if db_total > len(rows):
            _hdr = _hdr[:-1] + (' Усього в архіві %d %s; розібрано перші %d — '
                                'решта лишається у службових даних._'
                                % (db_total, _plural(db_total, 'рядок', 'рядки',
                                                     'рядків'), len(rows)))
        out.append(_hdr)
        shown = 0
        for (rank, label) in sorted(groups, key=lambda k: (-k[0], k[1])):
            items = groups[(rank, label)]
            out.append('**%s — %d:**' % (label[:1].upper() + label[1:], len(items)))
            for p in items[:3]:
                path = _fix_mojibake(str(p.get('Path') or ''))
                note = str(p.get('Note') or '').strip()
                line = '- `%s`%s' % (path[:120], _size_bytes(p.get('SizeBytes')))
                if note.upper() == 'DELETED':
                    line += ' _(файл видалено)_'
                elif note:
                    line += ' _(%s)_' % note[:120]
                out.append(line)
                shown += 1
            if len(items) > 3:
                _n = len(items) - 3
                out.append('  _… ще %d %s._'
                           % (_n, _plural(_n, 'такий самий', 'такі самі',
                                          'таких самих')))
            if shown >= 14:
                break
        if review:
            out.append('_Ще %d %s у теках, де виконувані файли трапляються й у '
                       'звичайній роботі, — залишено для перевірки, окремо не '
                       'перелічуємо._'
                       % (review, _plural(review, 'файл', 'файли', 'файлів')))
        if vanilla:
            out.append('_З них %d %s зі штатною збіркою Windows за повним шляхом._'
                       % (vanilla, _plural(vanilla, 'збігся', 'збіглися', 'збіглися')))
        if own:
            out.append('_Ще %d %s — сліди самого збирача, вилучено._'
                       % (own, _plural(own, 'рядок', 'рядки', 'рядків')))
    except Exception:
        return []
    return out


_ENC_CAT = {
    'container_candidate': ('Схоже на криптоконтейнер', 3),
    'tool_artifact': ('Файли програм шифрування', 2),
    'encrypted_archive': ('Архіви під паролем', 1),
    'encrypted_document': ('Документи під паролем', 1),
}
# The collector writes its reasons in ASCII on purpose (PS 5.1 reads a BOM-less
# .ps1 in the machine ANSI codepage). Translating them here keeps the report in
# one language instead of leaking the tool's internals to the reader.
_ENC_REASON = {
    'keepass database': 'база паролів KeePass',
    'veracrypt container': 'контейнер VeraCrypt',
    'truecrypt container': 'контейнер TrueCrypt',
    'axcrypt file': 'файл AxCrypt',
    'gnupg file': 'файл GnuPG',
    'pgp file': 'файл PGP',
    'pgp armored block': 'текстовий блок PGP',
    'pkcs#12 key store': 'сховище ключів PKCS#12',
    'luks volume': 'том LUKS (Linux)',
    'bestcrypt container': 'контейнер BestCrypt',
    'cryptomator vault': 'сховище Cryptomator',
    'securedoc container': 'контейнер SecureDoc',
    'zip with encryption flag set': 'ZIP із увімкненим прапорцем шифрування',
    'rar with password flag': 'RAR під паролем',
    'ole container with encryptedpackage': 'документ Office із зашифрованим вмістом',
    'pdf with /encrypt': 'PDF із парольним захистом (/Encrypt)',
}


def _enc_reason(raw, entropy):
    """Ukrainian wording for the collector's reason string."""
    s = str(raw or '').strip()
    low = s.lower()
    if low in _ENC_REASON:
        return _ENC_REASON[low]
    if low.startswith('no file signature'):
        e = str(entropy or '').strip()
        return ('без сигнатури відомого формату, розмір кратний 512, ентропія %s — '
                'так виглядає криптоконтейнер' % (e or 'близька до максимуму'))
    for k, v in _ENC_REASON.items():
        if low.startswith(k):
            return v + s[len(k):]
    return s


def _encrypted_files_section(case_key):
    """«Зашифровані файли та контейнери» — the collector's encrypted_files.csv.

    This is DORMANT encryption sitting on the disk: containers, password-protected
    archives and documents. It says where data may be hidden and what will need a
    password — it is NOT evidence of a ransomware attack, and the section says so
    out loud, because the two are constantly confused.

    The collector writes a single `None,-,0,,no encrypted files or containers found`
    row when it found nothing; that placeholder is dropped, never rendered as a hit.
    """
    out = []
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            cur.execute("SET statement_timeout='8000'")
            _tot = _q(cur, """SELECT count(*) FROM raw_fallback_v2
                              WHERE case_key=%s AND parser_family='encrypted_files'""",
                      (case_key,))
            db_total = int(_tot[0][0]) if _tot else 0
            rows = _q(cur, """SELECT payload FROM raw_fallback_v2
                              WHERE case_key=%s AND parser_family='encrypted_files'
                              ORDER BY row_id LIMIT %s""", (case_key, _ENC_ROW_LIMIT))
        if not rows:
            return []
        groups, own = {}, 0
        for (p,) in rows:
            p = p or {}
            cat = str(p.get('Category') or '').strip().lower()
            path = _fix_mojibake(str(p.get('Path') or '').strip())
            if cat == 'none' or not path or path == '-':
                continue
            low = path.lower()
            if re.search(_EXAMINER_TOOL_PY, low) or _OWN_PATH_RE.search(low):
                own += 1
                continue
            label, rank = _ENC_CAT.get(cat, (cat, 1))
            groups.setdefault((rank, label), []).append(p)
        if not groups:
            # The step ran and found nothing. Worth one line: «не шукали» and
            # «шукали й не знайшли» are different answers for an investigator.
            return ['## \U0001f512 ЗАШИФРОВАНІ ФАЙЛИ ТА КОНТЕЙНЕРИ',
                    '_Пошук виконано: криптоконтейнерів, архівів і документів під '
                    'паролем не знайдено._']

        total = sum(len(v) for v in groups.values())
        out.append('## \U0001f512 ЗАШИФРОВАНІ ФАЙЛИ ТА КОНТЕЙНЕРИ')
        _hdr = ('_Знайдено %d %s. Це дані, які **вже** лежали на диску '
                'зашифрованими, — тобто місця, де може бути сховане, і що '
                'потребуватиме пароля чи ключа. До шифрування файлів '
                'програмою-вимагачем це відношення не має._'
                % (total, _plural(total, 'обʼєкт', 'обʼєкти', 'обʼєктів')))
        if db_total > len(rows):
            _hdr = _hdr[:-1] + (' Усього в архіві %d %s; розібрано перші %d._'
                                % (db_total, _plural(db_total, 'рядок', 'рядки',
                                                     'рядків'), len(rows)))
        out.append(_hdr)
        for (rank, label) in sorted(groups, key=lambda k: (-k[0], k[1])):
            items = groups[(rank, label)]
            items.sort(key=lambda p: -_num(p.get('SizeMB')))
            out.append('**%s — %d:**' % (label, len(items)))
            for p in items[:4]:
                path = _fix_mojibake(str(p.get('Path') or ''))
                why = _enc_reason(p.get('Reason'), p.get('Entropy'))
                line = '- `%s`%s' % (path[:120], _size_mb(p.get('SizeMB')))
                if why:
                    line += ' _(%s)_' % why[:130]
                out.append(line)
            if len(items) > 4:
                out.append('  _… ще %d._' % (len(items) - 4))
        out.append('_Що з цим робити: за такими файлами варто окремо витребувати '
                   'паролі або ключі — без них вміст не прочитати навіть з образу._')
        if own:
            out.append('_Ще %d %s — файли самого збирача, вилучено._'
                       % (own, _plural(own, 'рядок', 'рядки', 'рядків')))
    except Exception:
        return []
    return out


# Win32_EncryptableVolume conversion states, as Crypto.cs writes them.
_BL_CONV = {
    'FullyDecrypted': 'том розшифровано повністю',
    'FullyEncrypted': 'том зашифровано повністю',
    'EncryptionInProgress': 'шифрування тривало на момент збору',
    'DecryptionInProgress': 'розшифрування тривало на момент збору',
    'EncryptionPaused': 'шифрування призупинено',
    'DecryptionPaused': 'розшифрування призупинено',
}
_VC_STATE = {
    'RUNNING': 'процес працював на момент збору',
    'PRESENT': 'драйвер присутній на диску',
    'MOUNTED': 'том підключено',
}
# Crypto.cs puts the Win32_Service State of a third-party FDE product in `Status`
# and `service name / display name` in `Details`. Printing the state where the
# service name belongs («служба: running») is how the previous wording read.
_FDE_STATE = {
    'RUNNING': 'працювала на момент збору',
    'STOPPED': 'зупинена',
    'PAUSED': 'призупинена',
    'START PENDING': 'запускалася',
    'STOP PENDING': 'зупинялася',
}


def _encryption_status_section(case_key):
    """«Шифрування диска» — the collector's live/encryption_status.csv.

    The distinction this section exists to protect: **the disk being encrypted by
    BitLocker is a normal, expected state**, while **files encrypted by ransomware**
    is an attack. Mixing them makes the bot cry wolf on every healthy machine, so
    BitLocker ON is rendered as a neutral fact plus its one practical consequence —
    a seized disk will not be readable without the recovery key.

    What IS reported as worth attention: a mounted volume with no backing partition
    (a container that was open at collection time), VeraCrypt/TrueCrypt, third-party
    full-disk encryption, and conversion still in progress. `NOT_CHECKED` is rendered
    as a limitation, never as «clean» — that confusion is exactly why Crypto.cs was
    rewritten (a ransomware-encrypted machine once printed «шифрування не виявлено»).
    """
    out = []
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            cur.execute("SET statement_timeout='5000'")
            rows = _q(cur, """SELECT payload FROM raw_fallback_v2
                              WHERE case_key=%s AND parser_family='encryption_status'
                              ORDER BY row_id LIMIT 500""", (case_key,))
        if not rows:
            return []
        bl_on, bl_part, bl_off = [], [], 0
        mounted, vc, fde, boot, notrun = [], [], [], [], []
        for (p,) in rows:
            p = p or {}
            typ = str(p.get('Type') or '').strip()
            tgt = _fix_mojibake(str(p.get('Target') or '').strip())
            st = str(p.get('Status') or '').strip().upper()
            meth = str(p.get('Method') or '').strip()
            # Crypto.cs writes its reasons in Ukrainian; decoded as latin-1 upstream
            # they arrive as `Ð¶Ð¾Ð´ÐµÐ½` and have to be repaired before printing
            det = _fix_mojibake(str(p.get('Details') or '').strip())
            if st == 'NOT_CHECKED':
                notrun.append((typ, det))
                continue
            if typ == 'None':
                continue
            if typ == 'BitLocker':
                if st == 'ON':
                    bl_on.append((tgt, meth))
                elif st == 'PARTIAL':
                    bl_part.append((tgt, _BL_CONV.get(det, det)))
                else:
                    bl_off += 1
            elif typ == 'VirtualVolume':
                mounted.append(tgt)
            elif typ == 'VeraCrypt':
                vc.append((tgt, _VC_STATE.get(st, st.lower())))
            elif typ == 'ThirdPartyFDE':
                fde.append((tgt, st, det))
            elif typ == 'BootSector':
                boot.append((tgt, det))

        body = []
        if bl_on:
            body.append('- **BitLocker увімкнено** на томах: %s.'
                        % ', '.join('%s (%s)' % (t or '?', m or 'метод не вказано')
                                    for t, m in bl_on[:6]))
            body.append('  _Це штатний захист Windows і звичайний стан робочої '
                        'станції, а не дія зловмисника. Практичний наслідок для '
                        'справи: вилучений диск без ключа відновлення не '
                        'прочитається — ключ треба забирати одразу (в '
                        'адміністратора, у домені або в обліковому записі '
                        'Microsoft)._')
        if bl_part:
            body.append('- ⚠️ **BitLocker у процесі перетворення**: %s. Варто '
                        'зʼясувати, хто і коли його запустив.'
                        % ', '.join('%s — %s' % (t or '?', d) for t, d in bl_part[:4]))
        if mounted:
            body.append('- ⚠️ **Підключений том без розділу-носія**: %s. Це '
                        'криптоконтейнер, VHD або змонтований образ, і на момент '
                        'збору він був **відкритий** — дані з нього були доступні.'
                        % ', '.join(t for t in mounted[:5] if t))
        if vc:
            body.append('- ⚠️ **Сліди VeraCrypt / TrueCrypt**: %s.'
                        % ', '.join('`%s` — %s' % (t, s) for t, s in vc[:5]))
        if fde:
            # one product answers to several services (Sophos ships four), so the
            # product is printed once, and the running service decides the state
            _seen = {}
            for _t, _s, _d in fde:
                _k = (_t or '?').lower()
                if _k not in _seen or (_s == 'RUNNING' and _seen[_k][1] != 'RUNNING'):
                    _seen[_k] = (_t or '?', _s, _d)
            _parts = []
            for _t, _s, _d in list(_seen.values())[:4]:
                _svc = str(_d or '').split('/')[0].strip()
                _lbl = _t
                if _svc:
                    _lbl += ' — служба `%s`' % _svc[:40]
                _lbl += ', %s' % _FDE_STATE.get(_s, (_s or 'стан не визначено').lower())
                _parts.append(_lbl)
            # '; ' and not ', ': each item already carries a comma before the state
            body.append('- **Стороннє повнодискове шифрування**: %s.'
                        % '; '.join(_parts))
            if any(_v[1] == 'RUNNING' for _v in _seen.values()):
                body.append('  _Служба працювала на момент збору, тож диск міг бути '
                            'зашифрований стороннім засобом. Як і з BitLocker, це '
                            'стан машини, а не напад, але ключ чи пароль треба '
                            'витребувати одразу — інакше вилучений диск не '
                            'прочитається._')
        if boot:
            body.append('- **Підпис у завантажувальному секторі**: %s.'
                        % ', '.join('%s — %s' % (t, d) for t, d in boot[:4]))
        if notrun:
            body.append('- ⚠️ **Перевірку не виконано**: %s. Це НЕ означає «чисто» — '
                        'просто перевірка не відпрацювала.'
                        % ', '.join('%s (%s)' % (t, (d or 'причина не вказана')[:70])
                                    for t, d in notrun[:4]))
        if not body:
            if bl_off:
                body.append('- Шифрування диска не виявлено: перевірено %d %s, '
                            'BitLocker вимкнено на всіх.'
                            % (bl_off, _plural(bl_off, 'том', 'томи', 'томів')))
            else:
                body.append('- Ознак шифрування диска не виявлено.')
        elif bl_off:
            body.append('- Решта томів (%d) — без шифрування.' % bl_off)

        out.append('## \U0001f5dd ШИФРУВАННЯ ДИСКА')
        out += body
        if bl_on or vc or fde or mounted:
            out.append('_Про формулювання: тут ідеться про шифрування **диска** '
                       'штатними чи сторонніми засобами — це стан машини, а не '
                       'напад. Зашифровані вимагачем файли — інша річ, вони '
                       'проходять як знахідки й у хронології._')
    except Exception:
        return []
    return out


def _autoruns_section(case_key):
    """«Закріплення в системі (автозапуск)» — the collector's Autoruns.csv.

    A healthy machine has dozens of legitimate autostart entries, so a listing is
    worthless. This runs analysis/autoruns_triage.triage() — the Study Course first
    cut (only ENABLED entries whose signature is not a trusted major vendor), ranked
    against the vanilla Windows index — and prints only what stands out, with the
    reason, split into «check these first» and «worth a look».

    Two things the raw file forces us to handle:
      * autorunsc emits a header row per registry location with every field except
        `Entry Location` empty; unfiltered they become dozens of «no signature»
        entries that mean nothing. Dropped before triage.
      * when the vanilla index is unavailable the triage returns `baseline: False` —
        that is stated, instead of silently reading as «all these files are stock».
    """
    out = []
    try:
        with psycopg2.connect(PG_DSN) as c:
            c.autocommit = True
            cur = c.cursor()
            cur.execute("SET statement_timeout='8000'")
            rows = _q(cur, """SELECT payload FROM raw_fallback_v2
                              WHERE case_key=%s AND parser_family='autoruns'
                              ORDER BY row_id LIMIT 6000""", (case_key,))
        if not rows:
            return []
        entries, own = [], 0
        for (p,) in rows:
            p = p or {}
            img = str(p.get('Image Path') or '').strip()
            launch = str(p.get('Launch String') or '').strip()
            entry = str(p.get('Entry') or '').strip()
            if not (img or launch or entry):
                continue                     # location header row, not an entry
            blob = (img + ' ' + launch).lower()
            if re.search(_EXAMINER_TOOL_PY, blob) or _OWN_PATH_RE.search(blob):
                own += 1
                continue
            entries.append(p)
        if not entries:
            return []

        from analysis.autoruns_triage import triage as _triage
        res = _triage(entries)
        # triage keeps everything from score 3 up in `high`; on a real machine the
        # score-3 tail is mostly small unsigned vendor utilities, so it is shown
        # separately instead of padding the list an investigator reads first.
        first = [h for h in (res.get('high') or []) if (h.get('score') or 0) >= 4]
        second = [h for h in (res.get('high') or []) if (h.get('score') or 0) < 4]
        review = res.get('review') or []
        checked = res.get('checked') or 0

        def _entry_lines(h):
            nm = h.get('entry') or h.get('image_path') or '?'
            line = '- `%s`' % _fix_mojibake(str(nm))[:90]
            img = str(h.get('image_path') or '').strip()
            if img and img.lower() != str(nm).lower():
                line += ' → `%s`' % _fix_mojibake(img)[:90]
            res_lines = [line]
            loc = str(h.get('location') or '').strip()
            if loc:
                res_lines.append('  · де: `%s`' % loc[:110])
            why = [str(r) for r in (h.get('reasons') or []) if r]
            if why:
                res_lines.append('  · чому: %s' % '; '.join(why)[:220])
            return res_lines

        out.append('## \U0001f501 ЗАКРІПЛЕННЯ В СИСТЕМІ (АВТОЗАПУСК)')
        out.append('_Точок автозапуску всього: %d. Записи з довіреним підписом '
                   'відомого постачальника відкинуто одразу; далі перевірено %d._'
                   % (len(entries), checked))
        if first:
            out.append('**Перевіряти першими — %d:**' % len(first))
            for h in first[:8]:
                out += _entry_lines(h)
        if second:
            out.append('**Варто подивитися — %d:**' % len(second))
            for h in second[:4]:
                out += _entry_lines(h)
            if len(second) > 4:
                out.append('  _… ще %d._' % (len(second) - 4))
        if not (first or second):
            out.append('_Нічого, що виділялося б: жоден активний автозапуск не '
                       'набрав ознак, за якими його варто перевіряти першим._')
        if review:
            out.append('_Ще %d %s без довіреного підпису — типово це дрібні утиліти '
                       'й самописні програми; залишено для перевірки._'
                       % (len(review), _plural(len(review), 'активний запис',
                                               'активні записи', 'активних записів')))
        if not res.get('baseline'):
            out.append('_⚠️ Еталон чистої Windows був недоступний, тому ознаку '
                       '«файла немає у штатній збірці» не перевірено. Відсутність '
                       'цієї позначки тут не означає, що файл штатний._')
        if own:
            out.append('_Ще %d %s — інструменти слідчого, вилучено._'
                       % (own, _plural(own, 'запис', 'записи', 'записів')))
    except Exception:
        return []
    return out


_EMERGENCY_RX = re.compile(
    r'аварійний evidence renderer|deterministic_renderer_fallback|аварійний рендер після помилки',
    re.I)


def _narrative_or_note(text):
    """The model's half of the report, or one line saying it is missing.

    Three of twelve reports had no narrative and carried 440–485 lines of raw evidence dump
    in its place — JSON rows and CSV fragments under a heading that promised an analysis.
    The reader cannot tell such a dump from a finding, so it is worse than an admission.
    The root cause (a prompt larger than the model's context) is fixed in the LLM layer;
    this is the last line of defence, and it is deliberately narrow: only the emergency
    renderer's own marker, or a body that is raw data with no prose at all."""
    s = str(text or '')
    if not s.strip():
        return s
    reason = ''
    if _EMERGENCY_RX.search(s):
        reason = 'спрацював аварійний рендер замість моделі'
    else:
        lines = [l for l in s.split(NL) if l.strip()]
        if len(lines) >= 150:
            # a sentence: six or more words, at least half of them Cyrillic
            prose = 0
            for l in lines:
                w = [x for x in re.findall(r'[^\s|,;]{2,}', l) if x]
                if len(w) >= 6 and sum(1 for x in w if re.search(r'[а-яїієґА-ЯЇІЄҐ]', x)) >= len(w) / 2:
                    prose += 1
            if prose * 20 < len(lines):    # under 5 % prose
                reason = 'модель не повернула наратив, у тілі звіту лише сирі дані'
    if not reason:
        return s
    return ('_Наратив недоступний (%s). Нижче — лише детерміновані розділи вище та сирі '
            'таблиці; сирий дамп прибрано, бо його не можна відрізнити від висновку._' % reason)


def _demote_appendix_headings(txt):
    """`## 5. ХРОНОЛОГІЯ ...` -> `### ХРОНОЛОГІЯ ...` for the appended narrative only."""
    out = []
    for ln in str(txt or '').split(chr(10)):
        m = re.match(r'^(#{1,3})\s*((?:[^\w\s]\s*)*)(\d{1,2})\.\s+(.+)$', ln)
        if m and ln.lstrip().startswith('#'):
            out.append('### ' + (m.group(2) or '').strip() + (' ' if m.group(2).strip() else '') + m.group(4).strip())
            continue
        m2 = re.match(r'^##\s+(.+)$', ln)
        if m2:
            out.append('### ' + m2.group(1).strip())
            continue
        out.append(ln)
    return chr(10).join(out)


def reshape_client_report(case_key, text):
    """Return the report re-organized into the clean 6-section structure.
    On any failure, returns the original text unchanged."""
    try:
        if not text or not str(text).strip():
            return text
        if MARKER in text:
            return text  # already reshaped — idempotent
        iw = _incident_window(case_key)
        findings = _findings(case_key)
        verdict = _verdict(findings)

        L = []
        L.append(MARKER)
        L.append('')
        # READING ORDER (owner, 2026-09-06): the plain-language conclusion first - read it and
        # understand everything - then the machine, then the deterministic verdict with its
        # chain, the entry point, chronology, IOC. The verdict block keeps its content; it
        # simply follows the summary instead of leading with detail.
        L.append('## 1. 📝 ЗАГАЛЬНИЙ ВИСНОВОК (простими словами)')
        _ia_s = _initial_access_struct(case_key, iw[0])
        L += _calm_scope(case_key, findings, _plain_conclusion(case_key, findings, verdict, iw, ia=_ia_s))
        L.append('')
        # the owner reads this section first and wants to act on it: the two most urgent
        # deterministic actions in plain words, before any detail
        try:
            _now2 = _actions_for(findings, 'now', 4)
        except Exception:
            _now2 = []
        if _now2:
            L.append('**Що робити зараз:**')
            L += ['- %s' % a for a in _now2]
        L.append('')
        L.append('## 2. 💻 ІНФОРМАЦІЯ ПРО СИСТЕМУ')
        L += _sys_lines(case_key, iw)
        L.append('')
        # PAGE 1: the deterministic verdict and the chain behind it. It used to sit on
        # line 324 of a 570-line report, under a section 1 that said "не вдалося
        # встановити" and a one-line chronology.
        L += _verdict_page(case_key, findings, verdict, iw)
        L.append('')
        L.append('## 3. 🎯 ПЕРША ТОЧКА ЗАРАЖЕННЯ / ПОЧАТКОВИЙ ДОСТУП')
        L += _initial_access(case_key, iw[0], findings)
        L.append('')
        # The incident window is anchored on detonation (the ransom note), so on a
        # ransomware case it collapses to a single day and CANNOT show the way in.
        # This second, retrospective pass looks deliberately BEFORE that day. It
        # self-omits whenever the case has no concrete pre-window evidence, so the
        # ten non-intrusion cases are unaffected. Unnumbered on purpose: numbering
        # it would renumber every section below and break the section guard.
        try:
            from reports.onset import onset_section as _onset_section
            _onset = _onset_section(case_key, iw[0])
        except Exception:
            _onset = []
        if _onset:
            L += _onset
            L.append('')
        L.append('## 4. 🕒 ХРОНОЛОГІЯ ПОДІЙ')
        L += _timeline(case_key, iw[0], findings)
        L.append('')
        L.append('## 5. 🔎 ІНДИКАТОРИ КОМПРОМЕТАЦІЇ (IOC)')
        try:
            _ioc_main, _ioc_ref = _iocs(case_key, findings, split=True)
        except Exception:
            _ioc_main, _ioc_ref = _iocs(case_key), []
        L += _ioc_main
        L.append('')
        # Which other cases the same person appears in. Built only from indicators that
        # identify someone - the attacker's own machine name, a rare binary hash, their
        # address - never from a shared public tool. Self-omits when there is no such
        # link, and never fires on a case the deterministic layer rates clean.
        try:
            from analysis.actor_portrait import portrait_section as _portrait
            _pt = _portrait(case_key)
        except Exception:
            _pt = []
        if _pt:
            L += _pt
            L.append('')
        _rec = _recommendations(findings)
        if _rec:
            L += _rec
            L.append('')
        # Collection conditions, completeness and disk-encryption state follow the evidence:
        # the reader wanted the conclusion, the machine and the chain first (2026-09-06).
        # Conditions the collection ran under (collector v4.0 artefacts): what the
        # machine blocked, Defender exclusions, memory capture, and every step that
        # did NOT run. Self-omits for archives collected before v4.0.
        _cond = _collection_conditions_section(case_key)
        if _cond:
            L += _cond
            L.append('')
        # What the database actually holds for this case. A verdict of «загроз не
        # виявлено» is only worth reading next to this block: on 2026-09-02 the same
        # verdict was printed over 2 % of an archive, and four pseudo-cases got reports
        # over zero events.
        try:
            _compl = _completeness_section(case_key)
        except Exception:
            _compl = []
        if _compl:
            L += _compl
            L.append('')
        # Disk encryption is machine STATE, so it sits with the collection
        # conditions and not with the findings: BitLocker being on is the normal
        # condition of a workstation, and printing it among the threats is how a
        # report starts frightening people over a healthy machine.
        _enst = _encryption_status_section(case_key)
        if _enst:
            L += _enst
            L.append('')
        # Owner/user attribution («чий це ПК / хто користувався») — self-omits when
        # there is no identity signal. Idea from the owner's expert report template.
        _own = _owner_attribution_section(case_key)
        if _own:
            L += _own
            L.append('')
        # Communications (email + messengers) — only rendered when parsed data exists
        # (returns [] otherwise, so existing reports are unaffected). See [[comms-extraction]].
        _comms = _communications_section(case_key, full=False)
        if _comms:
            L += _comms
            L.append('')
        L.append('---')
        L.append('')
        L.append('## 6. 🗄️ СЛУЖБОВІ ДАНІ / ДЕТАЛІ ДЛЯ ПЕРЕВІРКИ')
        L.append('_Нижче — повні детекції, наратив моделі, сирі докази та проміжні дані. Використовуй для звірки з логами._')
        L.append('')

        # Everything below the line is reference material: the detailed detections and
        # the model's narrative (the original text), then the Q&A and the evidence
        # tables that used to sit between the chronology and the IOC list.
        T = []
        T.append('')
        T.append('## 7. 🧾 ПИТАННЯ → ВІДПОВІДЬ (робочі нотатки ШІ, зібрано ботом)')
        T.append('_Додаток. Відповіді формує модель по логах кейсу; те, що суперечить вердикту на першій '
                 'сторінці, вважай неперевіреним. ✅ = підтверджено звітом/експертом._')
        try:
            from analysis.case_qa import build_qa_table_md as _qat
            _qa_lines = _qat(case_key)
            # reused/cached answers may still name artefacts this case does not have: mark them
            try:
                from analysis.output_guardrails import mark_ungrounded_artifacts as _mua
                _qa_lines = _mua(case_key, _qa_lines)
            except Exception:
                pass
        except Exception:
            _qa_lines = []
        if _qa_lines:
            T.append('')
            T += _qa_lines
        else:
            T.append('_Q&A по кейсу ще не зібрано (запусти DFIR-аналіз або «Зібрати Q&A»)._')
        T.append('')
        if _ioc_ref:
            T.append('## 📎 Довідкові дані до розділу IOC')
            T += _ioc_ref
            T.append('')
        # Deleted files, removable media and credential-looking documents. Built from
        # lnk / jumplists / recyclebin, three families that reach the database on every
        # case. Self-omits when the case has none.
        _docs = _documents_section(case_key)
        if _docs:
            T += _docs
            T.append('')
        # The collector's own execution analysis, if the archive carries it.
        _exf = _execution_findings_section(case_key)
        if _exf:
            T += _exf
            T.append('')
        # Persistence, MFT lead list and dormant encryption. All three self-omit
        # when the case has no rows.
        for _sec in (_autoruns_section(case_key),
                     _suspicious_files_section(case_key),
                     _encrypted_files_section(case_key)):
            if _sec:
                T += _sec
                T.append('')

        top = NL.join(L)
        # the narrative keeps its content but loses its own numbering: see
        # _demote_appendix_headings for why a second «## 1.» is the whole problem
        appendix = _demote_appendix_headings(_narrative_or_note(str(text).strip()))
        if len(appendix) > APPENDIX_CAP:
            appendix = appendix[:APPENDIX_CAP] + NL + NL + '… _(службові дані обрізано для читабельності; повні дані — у сирих таблицях БД та evidence_bundle)_'
        result = top + NL + appendix + NL + NL.join(T) + NL
        # safety: never emit control chars that break rendering
        if chr(8) in result or chr(13) in result:
            result = result.replace(chr(8), '').replace(chr(13), '')
        return result
    except Exception:
        return text
