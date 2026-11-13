"""
normalize.py - Stage C: normalize, group, dedup candidate rows into index rows.

  * normalize topic for matching (trim/collapse/casefold); keep display form.
  * group near-identical topics; keep genuinely different meanings separate.
  * per group keep up to 3 page refs sorted ascending, formatted "45; 78; 210".
  * pick best (longest, non-generic) description.
  * dedup acronyms into a single row with expansion + pages.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .extract import Candidate


GENERIC_DESC = re.compile(
    r"^(see|refer|note|this|the|a |an |placeholder|command .* with flags"
    r"|.*command-line usage$|powershell cmdlet$|kape triage option$"
    r"|windows (security )?event log identifier)",
    re.IGNORECASE,
)


@dataclass
class IndexRow:
    topic: str            # display form
    description: str
    page: str             # "45; 78; 210"
    book: str
    category: str
    weight: int
    n_refs: int
    from_table: bool
    footer_mismatch: bool
    flag_reason: str = ""
    desc_uk: str = ""     # Ukrainian translation of `description` (Stage C.5)


def norm_topic(topic: str) -> str:
    """Matching key: casefold, collapse whitespace, drop trailing punctuation."""
    t = topic.strip().lower()
    t = re.sub(r"\s+", " ", t)
    t = t.strip(" .,:;")
    return t


def _desc_score(desc: str, topic: str) -> int:
    """Higher = better. Penalise generic/empty/echo-of-topic descriptions."""
    d = desc.strip()
    if not d:
        return -100
    if d.lower() == topic.strip().lower():
        return -50
    if GENERIC_DESC.match(d):
        return len(d) - 200   # heavily penalised but still comparable
    return len(d)


def _fmt_pages(pages: list[int]) -> tuple[str, int]:
    uniq = sorted(set(p for p in pages if p is not None))
    total = len(uniq)
    shown = uniq[:15]
    return "; ".join(str(p) for p in shown), total


def normalize(candidates: list[Candidate], min_weight: int = 1) -> list[IndexRow]:
    # Filter by weight first. Also drop FRONT-MATTER candidates (printed_page < 1):
    # cover/TOC/legal pages are not real indexable content and their page refs are
    # meaningless (<= 0).
    cands = [c for c in candidates
             if c.weight >= min_weight and (c.printed_page is None or c.printed_page >= 1)]

    # Group by (normalized topic, category) so different meanings stay apart.
    groups: dict[tuple[str, str], list[Candidate]] = {}
    for c in cands:
        key = (norm_topic(c.topic), c.category)
        groups.setdefault(key, []).append(c)

    rows: list[IndexRow] = []
    for (ntopic, cat), members in groups.items():
        # Display form: prefer the most common exact spelling; tie -> longest.
        display_counts: dict[str, int] = {}
        for m in members:
            display_counts[m.topic.strip()] = display_counts.get(m.topic.strip(), 0) + 1
        display = sorted(display_counts.items(), key=lambda kv: (-kv[1], -len(kv[0])))[0][0]

        # Best description.
        best = max(members, key=lambda m: _desc_score(m.description, display))
        description = best.description.strip()

        pages = [m.printed_page for m in members]
        page_str, n_refs = _fmt_pages(pages)

        weight = max(m.weight for m in members)
        from_table = any(m.has_table for m in members)
        footer_mismatch = any(m.footer_mismatch for m in members)

        rows.append(IndexRow(
            topic=display,
            description=description,
            page=page_str,
            book=members[0].book_label,
            category=cat,
            weight=weight,
            n_refs=n_refs,
            from_table=from_table,
            footer_mismatch=footer_mismatch,
        ))

    return rows


def add_flags(rows: list[IndexRow]) -> list[IndexRow]:
    """Populate flag_reason ONLY for genuinely low-confidence rows, so the review
    file is a short, actionable subset (not ~100% of entries).

    A flag means "a human should check this specific row" — reserved for:
      * missing/degenerate descriptions (nothing useful to read),
      * the page number is in doubt (bottom-margin number disagreed),
      * an implausibly large number of page refs (likely an over-merged topic).
    Being on a table page, or having a serviceable auto-generated description,
    is NOT a defect and is no longer flagged."""
    for r in rows:
        reasons = []
        d = r.description.strip()
        if not d:
            reasons.append("empty description")
        elif d.lower() == r.topic.strip().lower():
            reasons.append("description repeats topic")
        # footer_mismatch is the only page-accuracy signal and is exam-critical.
        if r.footer_mismatch:
            reasons.append("page number in doubt (footer disagreed)")
        if r.n_refs > 8:
            reasons.append(f"{r.n_refs} page refs (>8) — possibly over-merged")
        r.flag_reason = "; ".join(reasons)
    return rows


# Natural sort key: acronyms/numbers sort intuitively, case-insensitive.
_NAT_RE = re.compile(r"(\d+)")


def natural_key(topic: str):
    parts = _NAT_RE.split(topic.lower())
    return [int(p) if p.isdigit() else p for p in parts]


def sort_rows(rows: list[IndexRow]) -> list[IndexRow]:
    return sorted(rows, key=lambda r: natural_key(r.topic))


def _merge_base(row):
    """Grouping key for dedup: same term regardless of category; for commands/tools also
    strip flags/args so `autorunsc -accepteula` and `autorunsc.exe` collapse to one."""
    base = norm_topic(row.topic)
    if row.category in ("command", "tool"):
        base = re.sub(r"\s+[-/].*$", "", base).strip() or base   # drop flags and everything after
        base = re.sub(r"\.(exe|ps1|py|bat|cmd)$", "", base).strip() or base  # unify tool.exe / tool
    return base


def merge_dupes(rows: list[IndexRow]) -> list[IndexRow]:
    """Merge duplicate terms (across categories / command-arg variants) into one row with
    the union of pages. Best-effort: on any error returns the input unchanged."""
    try:
        from collections import OrderedDict
        groups = OrderedDict()
        for r in rows:
            groups.setdefault(_merge_base(r), []).append(r)
        out = []
        for base, members in groups.items():
            if len(members) == 1:
                out.append(members[0])
                continue
            pages = []
            for m in members:
                for p in re.split(r"[;,]", m.page or ""):
                    p = p.strip()
                    if p.isdigit():
                        pages.append(int(p))
            uniq = sorted(set(pages))
            page_str = "; ".join(str(p) for p in uniq[:15])
            best = max(members, key=lambda m: _desc_score(m.description, m.topic))
            cats = {}
            for m in members:
                cats[m.category] = cats.get(m.category, 0) + 1
            cat = sorted(cats.items(), key=lambda kv: -kv[1])[0][0]
            # display: prefer a clean member without flags; else the shortest form
            clean = [m.topic.strip() for m in members
                     if " -" not in m.topic and " /" not in m.topic]
            display = min(clean, key=len) if clean else min(
                (m.topic.strip() for m in members), key=len)
            m0 = members[0]
            out.append(IndexRow(
                topic=display, description=best.description.strip(), page=page_str,
                book=m0.book, category=cat,
                weight=max(m.weight for m in members),
                n_refs=len(uniq),
                from_table=any(m.from_table for m in members),
                footer_mismatch=any(m.footer_mismatch for m in members),
            ))
        return out
    except Exception:
        return rows
