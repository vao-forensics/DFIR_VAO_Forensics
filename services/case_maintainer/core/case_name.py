# -*- coding: utf-8 -*-
"""One shape for a case name, and a way to offer it instead of arguing about it.

MEASURED on the live library (2026-08-21): twelve of fourteen cases already read
DD_MM_YYYY_name - case_04, case_36 - and two
do not (case_61, case_65). So the convention exists and is
almost universal; what is missing is anything that holds people to it. Nothing validates
the field today: whatever is typed becomes a directory name, a database key and part of
every later report.

The rule this module enforces is deliberately narrow, because a case key is used as a
filesystem path and a SQL value:

    DD_MM_YYYY_<latin name>      e.g. 21_08_2026_case_58_phishing

and the module's real job is not rejection but REPAIR: pull a date out of whatever was
typed (dots, slashes, dashes, ISO, or none at all), transliterate Cyrillic, drop
everything a path should not carry, and hand back candidates a person can pick from.
"""
import datetime
import re

TRANSLIT = {
    'а': 'a', 'б': 'b', 'в': 'v', 'г': 'h', 'ґ': 'g', 'д': 'd', 'е': 'e', 'є': 'ie',
    'ж': 'zh', 'з': 'z', 'и': 'y', 'і': 'i', 'ї': 'i', 'й': 'i', 'к': 'k', 'л': 'l',
    'м': 'm', 'н': 'n', 'о': 'o', 'п': 'p', 'р': 'r', 'с': 's', 'т': 't', 'у': 'u',
    'ф': 'f', 'х': 'kh', 'ц': 'ts', 'ч': 'ch', 'ш': 'sh', 'щ': 'shch', 'ь': '',
    'ю': 'iu', 'я': 'ia', 'ы': 'y', 'э': 'e', 'ъ': '', 'ё': 'e',
}

CANON = re.compile(r'^\d{2}_\d{2}_\d{4}_[A-Za-z0-9][A-Za-z0-9_.-]{1,60}$')
MAX_NAME = 60

# Dates people actually type. Order matters: the most specific pattern wins.
_DATE_PATTERNS = [
    (re.compile(r'\b(\d{4})[-_./](\d{1,2})[-_./](\d{1,2})\b'), 'ymd'),
    (re.compile(r'\b(\d{1,2})[-_./](\d{1,2})[-_./](\d{4})\b'), 'dmy'),
    (re.compile(r'\b(\d{1,2})[-_./](\d{1,2})[-_./](\d{2})\b'), 'dmy2'),
    (re.compile(r'\b(\d{2})(\d{2})(\d{4})\b'), 'dmy'),
    (re.compile(r'\b(\d{4})(\d{2})(\d{2})\b'), 'ymd'),
]

# A date the way the convention wants it: FIRST, then the name, any separator between
# the parts (including underscore). Anchored at the start so a "3-4-19" inside a
# description is never mistaken for the case date.
_PREFIX_PATTERNS = [
    (re.compile(r'^(\d{1,2})[-_./](\d{1,2})[-_./](\d{4})(?=[-_./]|$)'), 'dmy'),
    (re.compile(r'^(\d{4})[-_./](\d{1,2})[-_./](\d{1,2})(?=[-_./]|$)'), 'ymd'),
    (re.compile(r'^(\d{2})(\d{2})(\d{4})(?=[-_./]|$)'), 'dmy'),
    (re.compile(r'^(\d{4})(\d{2})(\d{2})(?=[-_./]|$)'), 'ymd'),
]

# Pseudo-cases the pipeline creates for itself; never rewrite these.
RESERVED_PREFIXES = ('tooljob-', 'ZZ_', '__')


def _translit(s):
    """Cyrillic to Latin, keeping the case that was typed.

    Half the library is mixed case - case_66, case_45, case_56 - and flattening a name to
    lower case is a change the person did not ask for.
    """
    out = []
    for c in (s or ''):
        low = c.lower()
        if low in TRANSLIT:
            rep = TRANSLIT[low]
            out.append(rep.capitalize() if (c.isupper() and rep) else rep)
        else:
            out.append(c)
    return ''.join(out)


def _clean_name(s):
    s = _translit(s)
    s = re.sub(r'[^A-Za-z0-9_]+', '_', s)   # spaces/dots/dashes -> underscore (owner wants clean keys)
    s = re.sub(r'_{2,}', '_', s).strip('._-')
    return s[:MAX_NAME]


def extract_date(raw):
    """Return (DD_MM_YYYY, leftover-text) or (None, raw) when nothing looks like a date."""
    raw = raw or ''
    # a leading date wins - that is where the convention puts it, and matching it here
    # means an all-underscore name (02_09_2026_DVB_...) is not missed by the \b search
    for pat, kind in _PREFIX_PATTERNS:
        m = pat.match(raw)
        if not m:
            continue
        a, b, c = m.group(1), m.group(2), m.group(3)
        try:
            if kind == 'ymd':
                y, mo, d = int(a), int(b), int(c)
            else:
                d, mo, y = int(a), int(b), int(c)
            datetime.date(y, mo, d)
        except (ValueError, TypeError):
            continue
        return '%02d_%02d_%04d' % (d, mo, y), raw[m.end():].strip()
    for pat, kind in _DATE_PATTERNS:
        m = pat.search(raw or '')
        if not m:
            continue
        a, b, c = m.group(1), m.group(2), m.group(3)
        try:
            if kind == 'ymd':
                y, mo, d = int(a), int(b), int(c)
            elif kind == 'dmy':
                d, mo, y = int(a), int(b), int(c)
            else:                                   # two-digit year
                d, mo, y = int(a), int(b), 2000 + int(c)
            datetime.date(y, mo, d)                 # rejects 31_02 and friends
        except (ValueError, TypeError):
            continue
        rest = (raw[:m.start()] + ' ' + raw[m.end():]).strip()
        return '%02d_%02d_%04d' % (d, mo, y), rest
    return None, (raw or '')


def normalize(raw, today=None):
    """Best single candidate for what was typed, or '' when there is no name at all."""
    raw = (raw or '').strip()
    if not raw:
        return ''
    date, rest = extract_date(raw)
    name = _clean_name(rest)
    if not name:
        return ''
    if not date:
        d = today or datetime.date.today()
        date = '%02d_%02d_%04d' % (d.day, d.month, d.year)
    return '%s_%s' % (date, name)


def suggest(raw, today=None, limit=3):
    """Candidates to offer as buttons. The first is the one to preselect.

    A second option is only added when it is genuinely different - offering the same
    string twice is worse than offering one, because it reads as a broken menu.
    """
    out = []

    def _add(x):
        if x and x not in out:
            out.append(x)

    primary = normalize(raw, today)
    _add(primary)

    date, rest = extract_date(raw or '')
    name = _clean_name(rest)
    d = today or datetime.date.today()
    todays = '%02d_%02d_%04d' % (d.day, d.month, d.year)

    if name:
        _add('%s_%s' % (todays, name))          # same name, dated today
        parts = [p for p in name.split('_') if p]
        if len(parts) >= 3:                      # long descriptions: offer a short form
            _add('%s_%s' % (date or todays, '_'.join(parts[:2])))
        _add((primary or '').lower())
    return out[:limit]


def check(raw, today=None):
    """(ok, reason, suggestions). ok means: use it exactly as typed."""
    raw = (raw or '').strip()
    if not raw:
        return False, u'Назва справи порожня.', suggest('', today)
    if raw.startswith(RESERVED_PREFIXES):
        return True, '', []
    if CANON.match(raw):
        return True, '', []
    date, rest = extract_date(raw)
    name = _clean_name(rest)
    if not name:
        return False, (u'У назві немає жодного слова латиницею чи кирилицею - '
                       u'самі цифри й розділові знаки.'), suggest(raw, today)
    if not date:
        return False, (u'Назва має починатися з дати у форматі ДД_ММ_РРРР, '
                       u'а її тут немає.'), suggest(raw, today)
    return False, (u'Назва майже правильна, але формат має бути '
                   u'ДД_ММ_РРРР_назва_латиницею.'), suggest(raw, today)
