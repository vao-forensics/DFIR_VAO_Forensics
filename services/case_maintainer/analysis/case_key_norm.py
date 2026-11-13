"""SHARED PREREQUISITE (Theme B/C): case_key normalizer.

kb_reports stores some cases under BOTH single-underscore and double-underscore
variants (e.g. 'case_39' vs
'29_04_2026__case_58_phishing_case_59'), while the DB / kb_artifacts canonical
key is the DOUBLE-underscore one. Some keys also carry Cyrillic look-alike
letters (e.g. NGROK case '..._NGROK_і_case_59' with Cyrillic 'і'). Without
normalising on every report<->case<->lessons join the lookups silently miss.

Pure function module — no imports, no DB, no network. Safe to import anywhere.
"""

# Cyrillic look-alike -> ASCII (lowercased keys; applied case-insensitively).
_CYR_FOLD = {
    'і': 'i', 'о': 'o', 'а': 'a', 'е': 'e', 'с': 'c',
    'р': 'p', 'к': 'k', 'х': 'x', 'у': 'y', 'м': 'm',
    'т': 't', 'в': 'b', 'н': 'h',
}


def _fold_cyrillic(s):
    out = []
    for ch in s:
        low = ch.lower()
        rep = _CYR_FOLD.get(low)
        if rep is None:
            out.append(ch)
        elif ch == low:
            out.append(rep)
        else:
            out.append(rep.upper())
    return ''.join(out)


def norm_case_key(s):
    """Normalize a case_key: ASCII-fold Cyrillic look-alikes, collapse runs of
    '_' to a single '_', strip surrounding whitespace/underscores-adjacent ws.
    Returns '' for falsy input."""
    if not s:
        return ''
    s = str(s).strip()
    s = _fold_cyrillic(s)
    # collapse runs of '_' to a single '_'
    out = []
    prev_us = False
    for ch in s:
        if ch == '_':
            if prev_us:
                continue
            prev_us = True
        else:
            prev_us = False
        out.append(ch)
    return ''.join(out).strip()


def candidates(s):
    """Return a dict of candidate keys for matching a (report) key to BOTH
    single- and double-underscore DB variants.
      raw       — the input as-is
      collapsed — single-underscore, Cyrillic-folded (norm_case_key)
      double    — collapsed with each '_' doubled (the DB canonical variant)
    Callers should probe these against the real DB to resolve the live key."""
    raw = str(s or '')
    collapsed = norm_case_key(raw)
    # double every single underscore in the collapsed form
    double = collapsed.replace('_', '__')
    return {'raw': raw, 'collapsed': collapsed, 'double': double}


def same_case(a, b):
    """True iff a and b normalize to the same canonical (collapsed) key."""
    return bool(a) and bool(b) and norm_case_key(a) == norm_case_key(b)


def resolve_db_key(report_key, db_keys):
    """Given a report key and an iterable of live DB case_keys, return the DB key
    whose normalized form matches the report key (or '' if none)."""
    target = norm_case_key(report_key)
    if not target:
        return ''
    for k in db_keys or []:
        if norm_case_key(k) == target:
            return k
    return ''
