"""
translate_uk.py - Stage C.5: batch-translate ONLY the description text to Ukrainian.

HARD RULES (owner decision, enforced here):
  * We translate ONLY `IndexRow.description` -> `IndexRow.desc_uk`.
  * We NEVER translate: commands, flags, tool names, Event IDs, artifact names
    ($MFT, vol.py, $UsnJrnl...), file paths, ports/protocols, acronyms.
    These are protected with a [[N]] wrap (same convention as the sidecar
    glossary proxy) so they survive the LLM byte-identical.
  * The Topic/Command column is NEVER touched here (stays verbatim English).
  * OFFLINE ONLY: the LLM base_url is checked with assert_local_url; no course
    content ever leaves the host. If the local LLM is unreachable or misbehaves,
    we fall back to the English description (desc_uk = description) so the
    bilingual outputs are never blank.

Batch ~40 rows per call, temperature 0, JSON-only response.
"""
from __future__ import annotations

import re
from typing import Optional

from .llm_client import assert_local_url, LLMClient, extract_json_array
from .normalize import IndexRow


# ---------------------------------------------------------------------------
# Verbatim-term protection
# ---------------------------------------------------------------------------
# Multi-word / mixed-case tool & concept names that must stay English. All-caps
# acronyms and $-artifacts, paths, flags and *.ext tokens are caught by the
# regex below; this list covers the ones plain casing would let slip through.
_GLOSSARY_TERMS = [
    "AppCompatCache", "ShimCache", "Amcache", "Prefetch", "Shellbags", "UserAssist",
    "Volatility", "Wireshark", "PowerShell", "Mimikatz", "Sysmon", "Sleuth Kit",
    "Plaso", "Timeline Explorer", "Registry Explorer", "Event Log", "Event ID",
    "Scheduled Task", "Run key", "Master File Table", "USN Journal", "LogFile",
    "bulk_extractor", "log2timeline", "MFTECmd", "PECmd", "EvtxECmd", "AmcacheParser",
    "AppCompatCacheParser", "RECmd", "SBECmd", "KAPE", "gkape", "Autoruns",
    "Velociraptor", "osquery", "Zeek", "Suricata", "Sigma", "YARA",
]
# Longest first so "Event Log" wins before "Event".
_GLOSSARY_TERMS.sort(key=len, reverse=True)

# Phrase patterns that must stay verbatim as a UNIT (number included).
_PHRASE_PATTERNS = [
    re.compile(r"\bEvent ID\s+\d+\b", re.I),
    re.compile(r"\bport\s+\d+\b", re.I),
    re.compile(r"\bTCP/\d+\b", re.I),
    re.compile(r"\bUDP/\d+\b", re.I),
]

# Token-level technical patterns (order matters; applied after phrases).
_TOKEN_PATTERNS = [
    re.compile(r"\$[A-Za-z][\w:$]*"),                       # $MFT, $UsnJrnl, $STANDARD_INFORMATION
    re.compile(r"(?:[A-Za-z]:)?[\w.-]*[/\\][\w./\\-]+"),    # paths: /var/log/auth.log, C:\Windows\...
    re.compile(r"\b[\w-]+\.(?:py|exe|dll|sys|log|evtx|csv|db|raw|txt|bin|json|xml|reg|pf|lnk)\b", re.I),  # vol.py, mem.raw
    re.compile(r"(?<!\w)--?[A-Za-z][\w-]*"),                # -sS, --csv flags
    re.compile(r"\b[A-Z][A-Z0-9]{1,9}\b"),                 # acronyms: SMB, LSASS, KDC, MFT, SRUM, SI, FN
]


def _protect(text: str, store: list[str]) -> str:
    """Replace every verbatim technical token with a [[N]] placeholder.

    Identical tokens reuse the same placeholder to keep the payload small and
    guarantee a consistent restore.
    """
    index: dict[str, str] = {}

    def _sub(m: re.Match) -> str:
        tok = m.group(0)
        ph = index.get(tok)
        if ph is None:
            ph = "[[%d]]" % len(store)
            store.append(tok)
            index[tok] = ph
        return ph

    # Glossary phrases first (as whole-word, case-insensitive units).
    for term in _GLOSSARY_TERMS:
        pat = re.compile(r"(?<!\w)" + re.escape(term) + r"(?!\w)", re.I)
        text = pat.sub(_sub, text)
    for pat in _PHRASE_PATTERNS:
        text = pat.sub(_sub, text)
    for pat in _TOKEN_PATTERNS:
        text = pat.sub(_sub, text)
    return text


def _restore(text: str, store: list[str]) -> str:
    """Put the original tokens back, byte-identical. Highest index first so
    [[1]] is not eaten while restoring [[10]]."""
    if not text:
        return text
    for k in range(len(store) - 1, -1, -1):
        text = text.replace("[[%d]]" % k, store[k])
    return text


# ---------------------------------------------------------------------------
# Translation
# ---------------------------------------------------------------------------
_SYSTEM_UK = (
    "Ти професійний перекладач технічної документації з цифрової криміналістики (DFIR). "
    "Переклади КОЖЕН англійський опис УКРАЇНСЬКОЮ, точно й стисло. "
    "Технічні терміни, назви інструментів, команди, прапорці, Event ID, порти, шляхи "
    "та артефакти ЛИШАЙ англійською — не перекладай їх. "
    "Будь-який токен виду [[N]] (наприклад [[0]], [[1]]) КОПІЮЙ ТОЧНО і без змін — "
    "ніколи не перекладай і не змінюй такі токени. "
    'Поверни ЛИШЕ валідний JSON-обʼєкт вигляду {"translations": ["...", "..."]}, '
    "де масив має РІВНО стільки рядків, скільки описів на вході, у тому самому порядку, "
    "без коментарів."
)


def _translate_batch(client: LLMClient, texts: list[str]) -> Optional[list[str]]:
    """Translate one batch of already-protected strings. Returns a list of the
    same length or None on any failure.

    The local server is forced into JSON-object mode (response_format), so we
    request {"translations": [...]}; extract_json_array unwraps the array."""
    import json as _json
    numbered = [{"i": i, "en": t} for i, t in enumerate(texts)]
    user = (
        "Переклади поле en кожного елемента українською. Поверни JSON-обʼєкт "
        '{"translations": [...]} з РІВНО %d рядків у тому самому порядку індексів i.\n'
        % len(texts) + _json.dumps({"items": numbered}, ensure_ascii=False)
    )
    try:
        out = client.chat_json(_SYSTEM_UK, user)
    except Exception:
        return None
    # extract_json_array unwraps {"translations": [...]} to the inner list.
    if isinstance(out, list) and len(out) == len(texts) and all(
            isinstance(x, str) for x in out):
        return out
    # Defensive: some models answer [{"i":0,"uk":"..."}] — recover by index.
    if isinstance(out, list) and len(out) == len(texts) and all(
            isinstance(x, dict) for x in out):
        vals = []
        for x in out:
            v = x.get("uk") or x.get("translation") or x.get("text") or x.get("en")
            if not isinstance(v, str):
                return None
            vals.append(v)
        return vals
    return None


def translate_rows_uk(rows: list[IndexRow], *, llm_base_url: str,
                      llm_model: str, backend: str = "openai",
                      batch_size: int = 20, timeout: int = 180,
                      client=None) -> int:
    """Populate `desc_uk` on every row (in place). Returns the count translated.

    Offline-guarded. Falls back to the English description for any row/batch the
    local model cannot translate, so the bilingual outputs are never blank.
    `client` may be injected (tests); otherwise a local LLMClient is built.
    """
    if not rows:
        return 0
    assert_local_url(llm_base_url)

    if client is None:
        try:
            client = LLMClient(backend=backend, base_url=llm_base_url,
                               model=llm_model, temperature=0, timeout=timeout)
        except Exception:
            client = None

    # Rows worth translating (non-empty description).
    todo = [r for r in rows if (r.description or "").strip()]
    # Default: English fallback everywhere (never blank).
    for r in rows:
        if not (r.desc_uk or "").strip():
            r.desc_uk = r.description

    if client is None:
        return 0

    def _run_pass(items: list[IndexRow], bsize: int) -> int:
        ok = 0
        for i in range(0, len(items), bsize):
            batch = items[i:i + bsize]
            stores: list[list[str]] = []
            protected: list[str] = []
            for r in batch:
                store: list[str] = []
                protected.append(_protect(r.description.strip(), store))
                stores.append(store)
            # Retry once on failure — a single malformed batch response should not
            # silently drop a whole batch to English (that caused mixed EN/UA output).
            translated = _translate_batch(client, protected)
            if translated is None:
                translated = _translate_batch(client, protected)
            if translated is None:
                continue  # keep English fallback for this batch
            for r, store, uk in zip(batch, stores, translated):
                r.desc_uk = _restore(uk.strip(), store) or r.description
                ok += 1
        return ok

    n_ok = _run_pass(todo, batch_size)

    # Second pass: some models ECHO a few short descriptions back untranslated
    # within an otherwise-good batch. Re-translate only rows that still have no
    # Cyrillic (and had translatable English words) in small batches.
    def _has_cyr(s: str) -> bool:
        return bool(re.search(r"[а-яіїєґ]", (s or "").lower()))

    def _has_words(s: str) -> bool:
        return bool(re.search(r"[A-Za-z]{4,}", s or ""))

    residual = [r for r in todo if not _has_cyr(r.desc_uk) and _has_words(r.description)]
    if residual:
        _run_pass(residual, max(6, batch_size // 3))

    return n_ok
