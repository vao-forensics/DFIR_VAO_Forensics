"""analysis/intent.py — ONE intent+shape contract for the DFIR bot.

THE PLAN (Phase Intent): a single, cheap, deterministic classifier computed
ONCE per query and threaded through every answer path so the ANSWER SHAPE
matches the ASK. Replaces the scattered, divergent signals (_brief regex that
only lived in the per-case fast-path, _is_cross_case_query, _detect_question_topic)
with one structured result.

classify_query(question, session=None) -> {
    scope:      single_case | cross_case | general | definition
    topic:      str  (best-effort keyword topic, '' if none)
    shape:      list | brief | deep | clarify | definition
    confidence: float 0..1   (rule precision; callers fall back to current
                              behaviour when this is low)
    terms:      [str]  (normalized search terms extracted from the question)
}

HARD SAFETY RULE: this is purely ADDITIVE and must NEVER regress a working
answer. It does NO LLM call (sub-millisecond). When the rules are uncertain it
returns a LOW confidence + the most conservative shape ('deep') so callers keep
their existing behaviour. Callers gate on `confidence` and `shape` and only
*change* behaviour for the high-precision shapes (list / definition / brief).
"""
from __future__ import annotations

import re

try:  # reuse the existing keyword topic map; tolerate import order issues
    from analysis.chat import _detect_question_topic as _chat_topic
except Exception:  # pragma: no cover
    _chat_topic = None


# ── Lexicons (Ukrainian / Russian / English) ────────────────────────────────

# "give me a LIST" verbs — enumerate cases / items, concise.
_LIST_RE = re.compile(
    r'(?i)(перел[іи]ч|перерах|спис[ок]|список|які кейс|котрі кейс|'
    r'скільки кейс|usі кейс|всі кейс|усі кейс|list (all|the )?cases?|'
    r'which cases?|show (all|me all)? ?cases?|how many cases?|enumerate)'
)

# explicit CONCISE / BRIEF markers.
_BRIEF_RE = re.compile(
    r'(?i)(коротк|стисл|в двох словах|у двох словах|briefly|in short|'
    r'tl;?dr|підсумуй|зведенн|одним рядком|одне речення|in a nutshell)'
)

# explicit DEEP / detailed markers.
_DEEP_RE = re.compile(
    r'(?i)(розпиши|детальн|докладн|повна хронолог|повний розбір|деталь|'
    r'in detail|full timeline|deep dive|step by step|покроково|'
    r'розгорнут|вичерпн|максимально докладно)'
)

# DEFINITION / "what is X" markers.
_DEFINE_RE = re.compile(
    r'(?i)(^|\s)(що таке|що означає|шо таке|поясни що таке|define|'
    r'what is|what does .* mean|meaning of|як працює|how does .* work)\b'
)

# CROSS-CASE scope markers (superset of chat._CROSS_CASE_KEYWORDS phrasings).
_CROSS_RE = re.compile(
    r'(?i)(інших кейс|всіх кейс|по всіх|по кейсах|всі кейси|усі кейси|'
    r'global search|глобальн.{0,4} пошук|cross-?case|compare cases|'
    r'схожі кейси|порівняй кейси|чи є в інш|по всій базі|у всій базі|всю базу|'
    r'у якому кейс|в якому кейс|якому кейс|котрому кейс|які кейс|'
    r'в яких кейс|у яких кейс|яких кейс|котрі кейс|across cases)'
)

# Date-list scope: "які кейси були у квітні 2026"
_UA_MONTHS_RE = re.compile(
    r'(?i)(січ|лют|берез|квіт|трав|черв|лип|серп|верес|жовт|листоп|груд)')
_YEAR_RE = re.compile(r'\b(20\d{2})\b')

_STOPWORDS = frozenset([
    'яка', 'яке', 'яки', 'які', 'що', 'коли', 'де', 'як', 'чи', 'по', 'для',
    'був', 'була', 'були', 'є', 'та', 'або', 'від', 'до', 'його', 'про',
    'the', 'and', 'for', 'are', 'was', 'were', 'what', 'which', 'show', 'list',
    'кейс', 'кейси', 'кейсів', 'case', 'cases', 'мені', 'будь', 'ласка',
])


def _extract_terms(question: str, limit: int = 10) -> list[str]:
    toks = re.findall(r'[A-Za-zА-Яа-яІіЇїЄєҐґ0-9_.-]{3,}', question or '')
    out: list[str] = []
    for t in toks:
        if t.lower() in _STOPWORDS:
            continue
        if t not in out:
            out.append(t)
        if len(out) >= limit:
            break
    return out


def classify_query(question: str, session: dict | None = None) -> dict:
    """Deterministic, sub-ms intent+shape classifier. Never raises."""
    q = (question or '').strip()
    q_low = q.lower()
    result = {
        'scope': 'general',
        'topic': '',
        'shape': 'deep',          # conservative default → keep current behaviour
        'confidence': 0.0,
        'terms': _extract_terms(q),
    }
    if not q:
        return result

    # ── topic (best-effort, reuse existing map) ──
    try:
        if _chat_topic is not None:
            result['topic'] = _chat_topic(q) or ''
    except Exception:
        result['topic'] = ''

    # ── shape detection (high-precision first) ──
    is_list = bool(_LIST_RE.search(q))
    is_brief = bool(_BRIEF_RE.search(q))
    is_deep = bool(_DEEP_RE.search(q))
    is_define = bool(_DEFINE_RE.search(q))

    # ── scope detection ──
    is_cross = bool(_CROSS_RE.search(q))
    has_date_list = ('кейс' in q_low and
                     (bool(_UA_MONTHS_RE.search(q_low)) or bool(_YEAR_RE.search(q_low))))

    # Date-list ("which cases in April 2026") is a strong, unambiguous list+cross signal.
    if has_date_list:
        result['scope'] = 'cross_case'
        result['shape'] = 'list'
        result['confidence'] = 0.95
        return result

    # Definition has top priority for shape when matched and not asking about a case set.
    if is_define and not is_list:
        result['scope'] = 'definition'
        result['shape'] = 'definition'
        result['confidence'] = 0.9
        return result

    # LIST: "перелічи/які кейси про X" → concise per-case list. Cross-case by nature.
    if is_list:
        result['scope'] = 'cross_case'
        result['shape'] = 'list'
        # if the user ALSO said "коротко", that only reinforces list.
        result['confidence'] = 0.92 if (is_cross or is_brief) else 0.85
        return result

    # From here scope is single/cross/general independent of list.
    if is_cross:
        result['scope'] = 'cross_case'

    # BRIEF vs DEEP: explicit markers win; brief beats deep only if deep absent.
    if is_brief and not is_deep:
        result['shape'] = 'brief'
        result['confidence'] = 0.85
        return result
    if is_deep:
        result['shape'] = 'deep'
        result['confidence'] = 0.8
        return result

    # No explicit shape marker. If clearly cross-case keep 'deep' but mark mid
    # confidence; otherwise low confidence so callers keep their default path.
    result['shape'] = 'deep'
    result['confidence'] = 0.5 if is_cross else 0.2
    return result


# ═══════════════════════════════════════════════════════════════════════════
# LLM-DRIVEN intent step (CORE IDEA): understand arbitrary phrasings like a
# smart agent instead of regex-per-phrasing. ONE fast 20b chat call returns a
# STRICT JSON contract; on ANY failure we fall back to the deterministic
# classify_query above so QA never breaks. Purely ADDITIVE.
#
# Contract returned by classify_query_llm():
#   {
#     shape:       list_cases | case_brief | case_deep | fact | definition | cross_analysis
#     scope:       single_case | cross_case | general
#     target_case: <case_key or ''>      (resolved from case_list when the ask names a case)
#     terms:       [str]                  (normalized search terms)
#     brief_reason:str                    (one short line; why this shape/scope)
#     source:      'llm' | 'heuristic'    (provenance, for logging/tests)
#   }
# ═══════════════════════════════════════════════════════════════════════════
import json as _json
import os as _os
import re as _re_llm
import urllib.request as _urlreq
import logging as _logging

_ilog = _logging.getLogger('app')

try:  # config is only importable on the VM; tolerate host-side import
    from core.config import LLM_URL as _LLM_URL, LLM_FAST_MODEL as _FAST_MODEL, LLM_MODEL as _STRONG_MODEL
except Exception:  # pragma: no cover
    _LLM_URL = _os.getenv('DFIR_LLM_URL', 'http://192.168.100.1:1234')
    _FAST_MODEL = _os.getenv('DFIR_FAST_MODEL', 'gpt-oss-20b-heretic')
    _STRONG_MODEL = _os.getenv('DFIR_LLM_MODEL', 'gpt-oss-120b-heretic-v2')

# Valid enum values — anything the model returns outside these is repaired.
_VALID_SHAPES = {'list_cases', 'case_brief', 'case_deep', 'fact', 'definition', 'cross_analysis'}
_VALID_SCOPES = {'single_case', 'cross_case', 'general'}

# Map the NEW LLM shape vocabulary back onto the OLD heuristic shape vocabulary
# (list|brief|deep|definition) that _run_global_search / callers already branch
# on, so existing routing keeps working unchanged.
_SHAPE_TO_LEGACY = {
    'list_cases':     'list',
    'cross_analysis': 'deep',     # cross-case synthesis -> real commonality answer
                                  # (general_mode librarian), NOT the per-case list
    'case_brief':     'brief',
    'case_deep':      'deep',
    'fact':           'deep',     # a grounded fact answer uses the deep/grounded path, concisely
    'definition':     'definition',
}


def legacy_shape(shape):
    """Translate a new-contract shape to the legacy shape token callers branch on."""
    return _SHAPE_TO_LEGACY.get(str(shape or '').strip(), 'deep')


_LLM_SYS = (
    "Ти - маршрутизатор запитів DFIR-бота. Класифікуй ПИТАННЯ користувача та поверни "
    "СТРОГО ОДИН JSON-обєкт (без markdown, без пояснень навколо).\n\n"
    "Поля:\n"
    '  "shape": один із list_cases | case_brief | case_deep | fact | definition | cross_analysis\n'
    '  "scope": один із single_case | cross_case | general\n'
    '  "target_case": точний case_key зі списку доступних кейсів, якщо питання про ОДИН конкретний кейс; інакше ""\n'
    '  "terms": масив 1-6 ключових пошукових слів (без стоп-слів)\n'
    '  "brief_reason": один короткий рядок - чому саме така форма\n\n'
    "ПРАВИЛА вибору shape:\n"
    "- list_cases: користувач хоче ПЕРЕЛІК кейсів за ознакою (які кейси повязані з X, "
    "перелічи кейси про Y, в яких кейсах є Z). scope=cross_case.\n"
    "- case_deep: детальний розбір ОДНОГО кейсу (розкажи детально про кейс ..., "
    "повна хронологія кейсу ...). scope=single_case, target_case=цей кейс.\n"
    "- case_brief: короткий підсумок одного кейсу (коротко що в кейсі ...). scope=single_case.\n"
    "- fact: конкретний факт по кейсу/кейсах (які IOC в кейсі X, яка IP, коли зараження).\n"
    "- definition: загальне поняття без привязки до кейсу (що таке amcache, як працює ngrok). scope=general.\n"
    "- cross_analysis: порівняння/звязок МІЖ кількома кейсами (що спільного, порівняй кейси). scope=cross_case.\n\n"
    "Якщо питання називає ознаку, що підходить під КІЛЬКА кейсів (напр. нотаріус) і просить перелік - це list_cases. "
    "Якщо називає ОДИН конкретний кейс і просить деталі - case_deep з target_case.\n"
    "Розвязуй target_case за списком доступних case_key (підбирай за змістом, не за точним написанням)."
)


def _extract_json(text):
    """Robustly pull the first {...} JSON object out of an LLM response."""
    if not text:
        return None
    text = _re_llm.sub(r'```(?:json)?', '', text)
    m = _re_llm.search(r'\{.*\}', text, _re_llm.DOTALL)
    if not m:
        return None
    blob = m.group(0)
    for attempt in (blob, blob[:blob.rfind('}') + 1]):
        try:
            obj = _json.loads(attempt)
            if isinstance(obj, dict):
                return obj
        except Exception:
            continue
    return None


def _resolve_target_case(raw_target, terms, question, case_list):
    """Best-effort map an LLM-named case onto a real case_key from case_list."""
    if not case_list:
        return ''
    cl = list(case_list)
    rt = str(raw_target or '').strip()
    for ck in cl:
        if ck == rt:
            return ck
    haystacks = [rt.lower(), (question or '').lower()]
    best, best_score = '', 0
    for ck in cl:
        ck_low = ck.lower()
        toks = [t for t in _re_llm.split(r'[^a-z0-9]+', ck_low) if len(t) >= 3]
        for hs in haystacks:
            score = sum(1 for t in toks if t in hs)
            if score > best_score:
                best, best_score = ck, score
    return best if best_score >= 2 else ''


def classify_query_llm(question, session=None, case_list=None, timeout=12.0):
    """LLM-driven intent+shape classifier (CORE IDEA). Fast 20b call -> strict JSON.

    case_list: iterable of available case_keys so the model can resolve a named
    case (e.g. "нотаріус з ngrok" -> the matching case_key) and decide list vs deep.

    NEVER raises. On any failure (network, bad JSON, missing config) it falls back
    to the deterministic classify_query above and tags source='heuristic' so the
    answer path degrades to current behaviour instead of breaking.
    """
    q = (question or '').strip()
    base = classify_query(q, session)
    fallback = {
        'shape': {'list': 'list_cases', 'brief': 'case_brief',
                  'deep': 'case_deep', 'definition': 'definition'}.get(base.get('shape'), 'case_deep'),
        'scope': base.get('scope') if base.get('scope') in _VALID_SCOPES else 'general',
        'target_case': '',
        'terms': base.get('terms') or [],
        'brief_reason': 'heuristic fallback',
        'source': 'heuristic',
        'confidence': base.get('confidence', 0.0),
        'legacy_shape': base.get('shape', 'deep'),
    }
    if not q:
        return fallback

    cl = list(case_list or [])
    case_block = '\n'.join('  - ' + str(c) for c in cl[:60]) if cl else '  (немає)'
    user = ('Доступні кейси (case_key):\n' + case_block +
            '\n\nПИТАННЯ: ' + q + '\n\nПоверни лише JSON.')
    messages = [{'role': 'system', 'content': _LLM_SYS},
                {'role': 'user', 'content': user}]
    body = _json.dumps({
        'model': _FAST_MODEL or _STRONG_MODEL,
        'messages': messages,
        'temperature': 0.0,
        # gpt-oss can burn the whole budget on the hidden reasoning channel and
        # return EMPTY content. Force low reasoning + a generous content budget so
        # the JSON always lands (otherwise we silently drop to the heuristic).
        'reasoning_effort': 'low',
        'max_tokens': 700,
        'stream': False,
    }).encode()

    try:
        req = _urlreq.Request(_LLM_URL.rstrip('/') + '/v1/chat/completions',
                              data=body, headers={'Content-Type': 'application/json'})
        with _urlreq.urlopen(req, timeout=timeout) as resp:
            rd = _json.loads(resp.read().decode('utf-8', 'ignore'))
        content = ((rd.get('choices') or [{}])[0].get('message', {}).get('content') or '')
    except Exception as e:
        _ilog.warning('[intent-llm] call failed, heuristic fallback: %s' % e)
        return fallback

    obj = _extract_json(content)
    if not isinstance(obj, dict):
        _ilog.warning('[intent-llm] no JSON parsed, heuristic fallback')
        return fallback

    shape = str(obj.get('shape') or '').strip()
    scope = str(obj.get('scope') or '').strip()
    if shape not in _VALID_SHAPES:
        shape = fallback['shape']
    if scope not in _VALID_SCOPES:
        scope = ('general' if shape == 'definition'
                 else 'cross_case' if shape in ('list_cases', 'cross_analysis')
                 else 'single_case')

    terms = obj.get('terms')
    if not isinstance(terms, list):
        terms = fallback['terms']
    terms = [str(t).strip() for t in terms if str(t).strip()][:6] or fallback['terms']

    target = _resolve_target_case(obj.get('target_case', ''), terms, q, cl)

    return {
        'shape': shape,
        'scope': scope,
        'target_case': target,
        'terms': terms,
        'brief_reason': str(obj.get('brief_reason') or '')[:200],
        'source': 'llm',
        'confidence': 0.9,
        'legacy_shape': legacy_shape(shape),
    }

# ── period in the question (2026-09-12) ───────────────────────────────────────────────────
import datetime as _dtm
import calendar as _cal

_MONTHS_ANY = {
    'січ': 1, 'янв': 1, 'jan': 1, 'лют': 2, 'фев': 2, 'feb': 2, 'берез': 3, 'март': 3, 'mar': 3, 'квіт': 4, 'апр': 4, 'apr': 4,
    'трав': 5, 'ма[йя]': 5, 'may': 5, 'черв': 6, 'июн': 6, 'jun': 6, 'лип': 7, 'июл': 7, 'jul': 7, 'серп': 8, 'авг': 8, 'aug': 8,
    'верес': 9, 'сент': 9, 'sep': 9, 'жовт': 10, 'окт': 10, 'oct': 10, 'листоп': 11, 'нояб': 11, 'nov': 11, 'груд': 12, 'дек': 12, 'dec': 12,
}
_MONTH_RX = '(' + '|'.join(_MONTHS_ANY.keys()) + ')' + r'\w*'


def _month_num(word):
    w = (word or '').lower()
    for k, v in _MONTHS_ANY.items():
        if re.match(k, w):
            return v
    return None


def _hour_range(q):
    """(HH:MM:SS, HH:MM:SS) when the question narrows the day by hours, else None."""
    m = re.search(r'(?:між|з|from|between)\s+(\d{1,2})[:.](\d{2})\s+(?:і|та|по|до|and|to|-|–)\s+(\d{1,2})[:.](\d{2})', q)
    if m:
        return ('%02d:%s:00' % (int(m.group(1)), m.group(2)), '%02d:%s:59' % (int(m.group(3)), m.group(4)))
    m = re.search(r'(?:до|before|until)\s+(\d{1,2})[:.](\d{2})', q)
    if m:
        return ('00:00:00', '%02d:%s:59' % (int(m.group(1)), m.group(2)))
    m = re.search(r'(?:після|after|з|from)\s+(\d{1,2})[:.](\d{2})', q)
    if m:
        return ('%02d:%s:00' % (int(m.group(1)), m.group(2)), '23:59:59')
    return None


def question_date_window(question, default_year=None):
    """(start_iso, end_iso, label) for the period the question asks about, or None.
    Understands 12.08.2026 / 2026-08-12 / 12 серпня 2026 / серпень 2026 / з 10 по 13 серпня 2026,
    plus an hour range on a single day («між 07:00 і 10:00», «до 10:00», «після 18:00»)."""
    w = _question_date_window_day(question, default_year)
    if not w:
        return None
    q = (question or '').lower()
    hr = _hour_range(q)
    if hr and w[0][:10] == w[1][:10]:
        d = w[0][:10]
        return (d + ' ' + hr[0], d + ' ' + hr[1], '%s %s–%s' % (d, hr[0][:5], hr[1][:5]))
    return w


def _question_date_window_day(question, default_year=None):
    q = (question or '').lower()
    yr = default_year or _dtm.date.today().year
    # range: з 10 по 13 серпня 2026 | 10-13.08.2026
    m = re.search(r'з\s+(\d{1,2})\s+(?:по|до)\s+(\d{1,2})\s+' + _MONTH_RX + r'(?:\s+(20\d{2}))?', q)
    if m:
        mo = _month_num(m.group(3)); y = int(m.group(4) or yr)
        if mo:
            try:
                a = _dtm.date(y, mo, int(m.group(1))); b = _dtm.date(y, mo, int(m.group(2)))
                return (a.isoformat() + ' 00:00:00', b.isoformat() + ' 23:59:59', '%s – %s' % (a, b))
            except ValueError:
                pass
    m = re.search(r'\b(\d{1,2})[./](\d{1,2})[./](20\d{2})\b', q)
    if m:
        try:
            a = _dtm.date(int(m.group(3)), int(m.group(2)), int(m.group(1)))
            return (a.isoformat() + ' 00:00:00', a.isoformat() + ' 23:59:59', a.isoformat())
        except ValueError:
            pass
    m = re.search(r'\b(20\d{2})-(\d{2})-(\d{2})\b', q)
    if m:
        try:
            a = _dtm.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            return (a.isoformat() + ' 00:00:00', a.isoformat() + ' 23:59:59', a.isoformat())
        except ValueError:
            pass
    m = re.search(r'\b(\d{1,2})\s+' + _MONTH_RX + r'(?:\s+(20\d{2}))?', q)
    if m:
        mo = _month_num(m.group(2)); y = int(m.group(3) or yr)
        if mo:
            try:
                a = _dtm.date(y, mo, int(m.group(1)))
                return (a.isoformat() + ' 00:00:00', a.isoformat() + ' 23:59:59', a.isoformat())
            except ValueError:
                pass
    m = re.search(r'(?<![\d.])' + _MONTH_RX + r'\s+(20\d{2})\b', q)
    if m:
        mo = _month_num(m.group(1)); y = int(m.group(2))
        if mo:
            last = _cal.monthrange(y, mo)[1]
            return ('%04d-%02d-01 00:00:00' % (y, mo), '%04d-%02d-%02d 23:59:59' % (y, mo, last), '%04d-%02d' % (y, mo))
    return None
