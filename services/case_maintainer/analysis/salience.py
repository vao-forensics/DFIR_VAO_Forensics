# -*- coding: utf-8 -*-
"""Скільки рядок важить для розслідування — щоб зріз на 4000 символів різав хвіст, а не суть.

Кожна відповідь ReAct-інструмента ріжеться до 4000 символів, перш ніж її побачить модель
(коміт 9cba081 зробив цей зріз видимим, але не змінив, ЩО в нього потрапляє). Виміряно по
11 бойових справах: `suspicious_executables` ріже на 11 з 11, `download_artifacts` — на 9.
На справі case_30 у відкинутій половині лежали `rutserv.exe` і
`rfusclient.exe` з теки Remote Manipulator System та `AAct.exe` — а доїжджав службовий
мотлох Windows: драйвери Intel із `ProgramData\\Package Cache`, `msvcr120.dll`, оновлювачі
Chrome.

Модуль НІЧОГО не викидає. Він лише дає рядку ранг, за яким інструмент робить **стійке**
(stable) сортування: шум опускається вниз, у межах одного рангу порядок — той, що був
(зазвичай хронологічний). Склад виводу від цього не змінюється, а маркер обрізання чесно
пише, скільки рядків не увійшло.

Ранги (менше = важливіше):

    0  інструмент атакувальника    — analysis/attack_tools.py + токени лише для ранжування
    1  виконуваний файл там, де його тримає атакувальник; кейлогер; маскування під систему;
       створення/видалення облікового запису; піратський активатор; зовнішня IP
    2  оманлива форма доставки     — подвійне розширення, вкладення з пошти чи файлообмінника
    3  невідомо                    — типове значення
    4  штатний шум Windows         — WinSxS, servicing, Package Cache, оновлювачі,
                                     збіг з еталоном чистої Windows, [BACKGROUND-NOISE]
    5  наш власний інструментарій  — збирач і засоби дослідника не мають виглядати як атака

⚠ `known_good` повертає None = «невідомо», а не «чисто». Тут на ранг 4 опускає лише
явне True: відсутній довідник не сміє створювати вирок.

Ранжування нічого не стверджує у звіті — воно лише вирішує, що модель побачить першим.
Саме тому сюди входить і категорія «віддалений доступ», яку `HIGH_SIGNAL_CATEGORIES`
свідомо виключає зі звинувачень: RMS на case_43 вирішує справу, і побачити його треба.
"""
import re as _re

try:
    from analysis import attack_tools as _atk
except Exception:  # pragma: no cover - модуль має працювати навіть без сусіда
    _atk = None
try:
    from analysis import known_good as _kg
except Exception:  # pragma: no cover
    _kg = None

ATTACK = 0
SUSPECT = 1
DECEPTIVE = 2
UNKNOWN = 3
WINDOWS_NOISE = 4
EXAMINER = 5

# ── наше власне: збирач, KAPE, EZTools, THOR, Hayabusa ───────────────────────────────
_EXAMINER_RE = _re.compile(
    r'vao_dfir_collector_marker|vao_triage|vao_collect_all|'
    r'\\kape\\|\\gkape|\\eztools|\\zimmerman|\\hayabusa|\\chainsaw|\\velociraptor|'
    r'\\ftk imager|\\oxygen forensics|\\magnet forensics|\\autopsy|\\dfirtriage|'
    r'(^|[^a-z0-9])(kape|gkape|mftecmd|evtxecmd|pecmd|lecmd|jlecmd|sbecmd|recmd|rbcmd|'
    r'srumecmd|wxtcmd|amcacheparser|appcompatcacheparser|hayabusa|chainsaw|thor64?|loki|'
    r'dumpit|winpmem|magnetramcapture|magnetprocesscapture|densityscout|capa)\.exe',
    _re.I)

# ── інструменти атакувальника, яких ще нема в attack_tools.py ────────────────────────
# Тільки для ранжування: додавати їх у attack_tools.py означало б змінити зміст звітів
# по всій системі (threat_detect, reshape, chat), а це окремий прохід з власною регресією.
# «remote manipulator» — рівно та назва теки, у якій на case_43 лежить rutserv.exe:
# жоден токен REMOTE_ACCESS її не покриває, бо там є 'rutserv' і 'tektonit', але не
# розгорнута назва продукту.
_EXTRA_ATTACK_RE = _re.compile(
    r'remote manipulator|rms_log_|romfusclient|rfusclient|rutview|'
    r'lmnoipserver|nrcontrol|nrserver|'
    r'keylog|(^|[^a-z0-9])logs\.dat|'
    r'mimikatz|rdpwrap|rdpwinst', _re.I)

# ── піратські активатори: не атака ззовні, але й не «чиста Windows» ──────────────────
_PIRACY_RE = _re.compile(
    r'(^|[^a-z0-9])(aact|kmsss|kmspico|kmsauto|kms_?tools|activator|keygen|'
    r'autokms|re-?loader|w10digitalactivation)([^a-z0-9]|$)|'
    r'(^|[^a-z0-9])crack([^a-z0-9]|$)', _re.I)

# ── маскування під системні процеси ──────────────────────────────────────────────────
_MASQUERADE_RE = _re.compile(
    r'(^|[^a-z0-9])(system32|svchost32|lsass32|explorer32|csrss32|svch0st|scvhost|'
    r'lsasss|winiogon|explore)\.exe', _re.I)

# ── місця, де атакувальник тримає виконувані файли ───────────────────────────────────
# Свідомо НЕ ставлю сюди весь `\programdata\`: під ним живе купа легального софту
# (Pervasive PSQL, Package Cache), і тоді ранг 1 отримали б 60 рядків мотлоху.
# Тільки корінь ProgramData — там і лежав AAct.exe на case_43.
_ATTACKER_DIR_RE = _re.compile(
    r'\\users\\public(\\|$)|\\appdata\\roaming(\\|$)|\\appdata\\local\\temp(\\|$)|'
    r'\\windows\\temp(\\|$)|\\downloads?(\\|$)|\\perflogs(\\|$)|\\intel(\\|$)|'
    r'\\\$recycle\.bin|\\recycler(\\|$)|\\programdata$|\\programdata\\[^\\]*$|'
    r'\\users\\[^\\]+\\documents(\\|$)|\\users\\[^\\]+\\desktop(\\|$)|'
    r'\\windows\\fonts(\\|$)|\\windows\\debug(\\|$)|\\windows\\addins(\\|$)', _re.I)

_EXEC_EXT_RE = _re.compile(
    r'\.(exe|dll|scr|com|pif|js|jse|vbs|vbe|wsf|bat|cmd|ps1|psm1|msi|msp|hta|jar|'
    r'cpl|sys|lnk)([^a-z0-9]|$)', _re.I)

# ── оманлива форма доставки ──────────────────────────────────────────────────────────
_DOC_THEN_EXEC_RE = _re.compile(
    r'\.(jpe?g|png|gif|bmp|pdf|docx?|xlsx?|pptx?|txt|rtf|htm|html)\b[^\\/|]*'
    r'\.(exe|scr|com|pif|js|vbs|bat|cmd|ps1|msi|hta|jar|lnk)\b', _re.I)
_DOC_THEN_ARCHIVE_RE = _re.compile(
    r'\.(jpe?g|png|gif|bmp|pdf|docx?|xlsx?|pptx?|txt|rtf)\b[^\\/|]*'
    r'\.(zip|rar|7z|ace|iso|img|cab|asice)\b', _re.I)
_DELIVERY_RE = _re.compile(
    r'mail-attachment|mail\.google|mail\.ukr\.net|mail\.i\.ua|attach|'
    r'swisstransfer|wetransfer|gofile|mega\.nz|pixeldrain|fex\.net|dropmefiles|'
    r'sendspace|zippyshare|mediafire|anonfiles|file\.io|temp\.sh|onionshare|sendgb',
    _re.I)

# ── сайт самого виробника: звідки завантаження очікуване ─────────────────────────────
# Виконуваний файл, узятий із сайту його ж виробника, — слабший сигнал, ніж той самий
# файл із невідомого домену. Перевіряється ПІСЛЯ пошти й файлообмінників, бо
# `mail-attachment.googleusercontent.com` — це вкладення, а не сайт Google.
_VENDOR_DL_RE = _re.compile(
    r'https?://[^\s|]*?(microsoft\.com|windowsupdate\.com|live\.com|office\.com|'
    r'mozilla\.(org|net)|adobe\.com|apple\.com|oracle\.com|java\.com|'
    r'steampowered\.com|rockstargames\.com|telegram\.org|opera\.com|'
    r'7-zip\.org|videolan\.org|notepad-plus-plus\.org|sourceforge\.net|'
    r'chrome\.google\.com|dl\.google\.com|storage\.googleapis\.com|'
    r'id\.gov\.ua|czo\.gov\.ua|iit\.com\.ua|nais\.gov\.ua|zakon\.rada\.gov\.ua)',
    _re.I)

# ── штатний шум Windows ──────────────────────────────────────────────────────────────
_WINDOWS_NOISE_RE = _re.compile(
    r'\\winsxs(\\|$)|\\servicing(\\|$)|package_for_|\\package cache(\\|$)|'
    r'\\driverstore(\\|$)|\\windows\\installer(\\|$)|\\windows\\assembly(\\|$)|'
    r'\\softwaredistribution(\\|$)|\\catroot|\\windows\\inf(\\|$)|'
    r'\\systemtemp\\chrome_unpacker|chrome_installer|updatersetup\.exe|'
    r'chrome_updater|googleupdate|\\edgeupdate|mozilla maintenance|'
    r'\\windowsapps(\\|$)|\\microsoft\.net\\|\\windows\\policydefinitions|'
    r'pathunknown|\[background-noise\]', _re.I)

# ── явні позначки, які інструменти вже друкують самі ─────────────────────────────────
_TOOL_FLAG_RE = _re.compile(
    r'\*\*\* ?(!!!)? ?(КЕЙЛОГЕР|НОВИЙ АКАУНТ|ВИДАЛЕНО|ПІДОЗРІЛИЙ|ПОШТА/FILE-SHARE)|'
    r'(^|\| )(KEYLOGGER|MASKED) |User Created|User Deleted|Explicit Creds|Failed Logon|'
    r'rdp_external_burst|external ip burst',
    _re.I)

_IPV4_RE = _re.compile(r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b')


def _norm(text):
    return str(text or '').replace('/', '\\').lower()


def is_public_ip(text):
    """Чи є у рядку зовнішня (не приватна) IPv4. Вхід зі шляхами теж безпечний:
    версії на кшталт 136.0.7103.114 відсіюються перевіркою октетів ≤ 255 та тим,
    що поруч немає літер шляху — тому дивимось лише на явні `from=`/`IP:` фрагменти."""
    for m in _IPV4_RE.finditer(str(text or '')):
        o = [int(x) for x in m.groups()]
        if any(v > 255 for v in o):
            continue
        if o[0] in (10, 127, 0) or (o[0] == 192 and o[1] == 168) \
           or (o[0] == 172 and 16 <= o[1] <= 31) or (o[0] == 169 and o[1] == 254):
            continue
        return True
    return False


def _vanilla(name, path):
    """True лише коли еталон чистої Windows справді містить файл. None → не «чисто»."""
    if _kg is None:
        return False
    try:
        if path and _kg.is_vanilla_path(path) is True:
            return True
        if name and _kg.is_vanilla_name(name) is True:
            return True
    except Exception:
        return False
    return False


def tier(text, name=None, path=None, downloaded=False):
    """Ранг рядка: 0 — вирішує справу, 5 — наш власний інструмент. Ніколи не кидає.

    `downloaded=True` — рядок описує файл, що приїхав із мережі. Тоді саме розширення
    вже є сигналом: у теці Downloads кожен другий файл — документ, і виконуваний серед
    них помітний сам собою, без огляду на шлях. Без цього прапорця `.exe` без
    «атакувальної» теки падав у «невідомо» і опинявся НИЖЧЕ поштових вкладень — на
    28_07_case_45_case_52 це витіснило зі зрізу NPE_x64.exe, HitmanPro_x64.exe і
    EmsisoftEmergencyKit.exe заради 30 рядків .zip з документами."""
    try:
        blob = _norm(text)
        if name:
            blob += ' ' + _norm(name)
        if path:
            blob += ' ' + _norm(path)
        if not blob.strip():
            return UNKNOWN

        # наше власне — завжди вниз, навіть якщо назва схожа на атакувальну
        if _EXAMINER_RE.search(blob):
            return EXAMINER

        # інструмент атакувальника — раніше за будь-яку перевірку «чистоти»:
        # msvcr120.dll має ванільне ім'я, але лежить у теці Remote Manipulator System
        if _EXTRA_ATTACK_RE.search(blob):
            return ATTACK
        if _atk is not None:
            try:
                if _atk.categorize(blob):
                    return ATTACK
            except Exception:
                pass

        if _MASQUERADE_RE.search(blob) or _PIRACY_RE.search(blob):
            return SUSPECT
        if _TOOL_FLAG_RE.search(str(text or '')):
            return SUSPECT
        if _EXEC_EXT_RE.search(blob) and _ATTACKER_DIR_RE.search(blob):
            return SUSPECT
        if _DOC_THEN_EXEC_RE.search(blob):
            return SUSPECT

        if downloaded and _EXEC_EXT_RE.search(blob):
            return UNKNOWN if _VENDOR_DL_RE.search(blob) else SUSPECT

        if _DOC_THEN_ARCHIVE_RE.search(blob) or _DELIVERY_RE.search(blob):
            return DECEPTIVE

        if _WINDOWS_NOISE_RE.search(blob):
            return WINDOWS_NOISE
        if _vanilla(name, path):
            return WINDOWS_NOISE

        return UNKNOWN
    except Exception:
        return UNKNOWN


def sort_lines(lines, downloaded=False):
    """Стійке сортування готових рядків за рангом. У межах рангу порядок не рухається."""
    try:
        return sorted(lines, key=lambda x: tier(x, downloaded=downloaded))
    except Exception:
        return list(lines)


def sort_groups(groups, text_of=None, downloaded=False):
    """Те саме для груп рядків, які не можна роз'єднувати (файл + HostUrl + Referrer)."""
    try:
        if text_of is None:
            text_of = lambda g: ' '.join(g)
        return sorted(groups, key=lambda g: tier(text_of(g), downloaded=downloaded))
    except Exception:
        return list(groups)
