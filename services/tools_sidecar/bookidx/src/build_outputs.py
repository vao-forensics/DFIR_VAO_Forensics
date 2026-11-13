"""
build_outputs.py - Stage D: write all output artifacts.

  * index.xlsx + index.csv : columns EXACTLY  Topic | Description | Page | Book
    (VanAwful Book-Index-Creator compatible), no leading spaces, no empty rows,
    sorted alphabetically by Topic (case-insensitive, acronyms natural).
  * index_review.csv : same cols + flag_reason.
  * index.docx : printable BILINGUAL two-column A-Z index
    (English Topic + Ukrainian description + page + book).
  * commands_cheatsheet.csv       : English cheat sheet (unchanged).
  * commands_cheatsheet_uk.csv    : Tool | Command | Опис UA | Page | Book.
  * commands_cheatsheet.docx      : same, printable table.
  * run_report.txt : stats.

Bilingual rule (owner decision): only the DESCRIPTION is Ukrainian (r.desc_uk);
Topic / Command / Tool stay VERBATIM English.
"""
from __future__ import annotations

import os
import re
from collections import Counter

import pandas as pd

from .normalize import IndexRow, sort_rows


def _clean(s: str) -> str:
    return (s or "").strip()


def _uk(r: IndexRow) -> str:
    """Ukrainian description with an English fallback (never blank)."""
    return _clean(getattr(r, "desc_uk", "") or r.description)


def _rows_to_records(rows: list[IndexRow]) -> list[dict]:
    recs = []
    for r in rows:
        topic = _clean(r.topic)
        if not topic:
            continue  # no empty rows
        recs.append({
            "Topic": topic,
            "Description": _clean(r.description),
            "Page": _clean(r.page),
            "Book": _clean(r.book),
        })
    return recs


def write_csv_xlsx(rows: list[IndexRow], out_dir: str):
    rows = sort_rows(rows)
    recs = _rows_to_records(rows)
    df = pd.DataFrame(recs, columns=["Topic", "Description", "Page", "Book"])

    csv_path = os.path.join(out_dir, "index.csv")
    xlsx_path = os.path.join(out_dir, "index.xlsx")
    df.to_csv(csv_path, index=False, encoding="utf-8")
    try:
        df.to_excel(xlsx_path, index=False, engine="openpyxl")
    except Exception as e:  # pragma: no cover
        xlsx_path = f"(xlsx skipped: {e})"
    return csv_path, xlsx_path, len(recs)


# Course: infer the tool from a command's leading token for the cheatsheet.
_CHEATSHEET_TOOL_MAP = {
    "vol.py": "Volatility", "vol": "Volatility", "volatility": "Volatility",
    "volatility3": "Volatility",
    "log2timeline.py": "Plaso", "log2timeline": "Plaso",
    "psort.py": "Plaso", "psort": "Plaso",
    "kape.exe": "KAPE", "kape": "KAPE", "gkape": "KAPE", "gkape.exe": "KAPE",
    "fls": "Sleuth Kit", "icat": "Sleuth Kit", "mactime": "Sleuth Kit",
    "mmls": "Sleuth Kit", "istat": "Sleuth Kit",
    "bulk_extractor": "bulk_extractor",
}


def _infer_tool(command: str) -> str:
    """Map a command/tool topic to its owning tool (leading-token heuristic)."""
    cmd = (command or "").strip()
    if not cmd:
        return ""
    first = cmd.split()[0]
    return _CHEATSHEET_TOOL_MAP.get(first.lower(), first)


def _cheatsheet_rows(rows: list[IndexRow], include_tools: bool = True) -> list[IndexRow]:
    """De-duplicated command/tool rows for the cheat sheet.

    Real runs emit the same command from both the regex pre-pass (generic
    description) and the LLM (rich description) under slightly different topics.
    We collapse by a normalized command key and keep the row with the BEST
    (longest, non-generic) description, so the cheat sheet has one clean line
    per command."""
    from .normalize import GENERIC_DESC
    cats = {"command"} | ({"tool"} if include_tools else set())

    def score(r: IndexRow) -> int:
        d = (r.description or "").strip()
        if not d or d.lower() == r.topic.strip().lower():
            return -100
        if GENERIC_DESC.match(d):
            return len(d) - 200
        return len(d)

    best: dict[str, IndexRow] = {}
    for r in rows:
        if r.category not in cats:
            continue
        topic = _clean(r.topic)
        if not topic:
            continue
        key = re.sub(r"\s+", " ", topic.lower()).strip()
        cur = best.get(key)
        if cur is None or score(r) > score(cur):
            best[key] = r
    out = list(best.values())
    # Drop low-value FRAGMENTS: a row with a generic auto-description whose command
    # is a strict prefix of a longer, richer command (same tool) is just noise
    # (e.g. 'vol.py -f' vs 'vol.py -f mem.raw malfind'). Keep the fuller one.
    def _generic(r: IndexRow) -> bool:
        d = (r.description or "").strip()
        return (not d) or bool(GENERIC_DESC.match(d))
    cmds = [(_infer_tool(r.topic).lower(), r.topic.strip()) for r in out]
    keep = []
    for i, r in enumerate(out):
        tool_i, cmd_i = cmds[i]
        if _generic(r) and any(
                j != i and cmds[j][0] == tool_i
                and cmds[j][1].lower().startswith(cmd_i.lower() + " ")
                for j in range(len(out))):
            continue
        keep.append(r)
    keep.sort(key=lambda r: (_infer_tool(r.topic).lower(), r.topic.lower()))
    return keep


def _cheatsheet_records(rows: list[IndexRow], include_tools: bool = True,
                        uk: bool = False) -> list[dict]:
    desc_col = "Опис UA" if uk else "Description"
    recs = []
    for r in _cheatsheet_rows(rows, include_tools=include_tools):
        topic = _clean(r.topic)
        recs.append({
            "Tool": _infer_tool(topic),
            "Command": topic,                       # VERBATIM English
            desc_col: _uk(r) if uk else _clean(r.description),
            "Page": _clean(r.page),
            "Book": _clean(r.book),
        })
    return recs


def write_commands_cheatsheet(rows: list[IndexRow], out_dir: str,
                              include_tools: bool = True):
    """Course CyberLive cheat sheet (English): Tool | Command | Description
    | Page | Book, for command (and optionally tool) rows."""
    recs = _cheatsheet_records(rows, include_tools=include_tools, uk=False)
    df = pd.DataFrame(recs, columns=["Tool", "Command", "Description", "Page", "Book"])
    path = os.path.join(out_dir, "commands_cheatsheet.csv")
    df.to_csv(path, index=False, encoding="utf-8")
    return path


def write_commands_cheatsheet_uk(rows: list[IndexRow], out_dir: str,
                                 include_tools: bool = True):
    """First-class BILINGUAL commands cheat sheet — the artifact the student
    needs most for the CyberLive portion.

    Writes:
      * commands_cheatsheet_uk.csv : Tool | Command | Опис UA | Page | Book
      * commands_cheatsheet.docx   : a printable table with BOTH languages:
        Tool | Command / Syntax | What it does (EN) | Опис (UK) | Page
        de-duplicated, sorted by Tool then Command.
    Command/Tool stay verbatim English; only descriptions are translated.
    Returns (csv_path, docx_path)."""
    uk_cols = ["Tool", "Command", "Опис UA", "Page", "Book"]
    recs = _cheatsheet_records(rows, include_tools=include_tools, uk=True)

    csv_path = os.path.join(out_dir, "commands_cheatsheet_uk.csv")
    pd.DataFrame(recs, columns=uk_cols).to_csv(csv_path, index=False, encoding="utf-8")

    # Bilingual DOCX: one clean, deduped, tool-sorted table with EN + UK columns.
    doc_rows = _cheatsheet_rows(rows, include_tools=include_tools)
    cols = ["Tool", "Command / Syntax", "What it does (EN)", "Опис (UK)", "Page"]
    docx_path = os.path.join(out_dir, "commands_cheatsheet.docx")
    try:
        from docx import Document
        from docx.shared import Pt, Inches
        from docx.enum.section import WD_ORIENT

        doc = Document()
        for section in doc.sections:
            # Landscape gives the wide command/description columns room.
            section.orientation = WD_ORIENT.LANDSCAPE
            section.page_width, section.page_height = section.page_height, section.page_width
            section.top_margin = Inches(0.4)
            section.bottom_margin = Inches(0.4)
            section.left_margin = Inches(0.4)
            section.right_margin = Inches(0.4)
        style = doc.styles["Normal"]
        style.font.name = "Calibri"
        style.font.size = Pt(9)

        title = doc.add_paragraph()
        trun = title.add_run("BOOKIDX Commands Cheat Sheet / Шпаргалка команд (EN + UA)")
        trun.bold = True
        trun.font.size = Pt(14)
        sub = doc.add_paragraph()
        srun = sub.add_run(f"{len(doc_rows)} commands/tools — sorted by tool. "
                           "Page = PRINTED page number.")
        srun.italic = True
        srun.font.size = Pt(9)

        table = doc.add_table(rows=1, cols=len(cols))
        try:
            table.style = "Table Grid"
        except Exception:
            pass
        hdr = table.rows[0].cells
        for i, c in enumerate(cols):
            hdr[i].text = c
            for p in hdr[i].paragraphs:
                for run in p.runs:
                    run.bold = True
        for r in doc_rows:
            topic = _clean(r.topic)
            cells = table.add_row().cells
            cells[0].text = _infer_tool(topic)
            cells[1].text = topic
            cells[2].text = _clean(r.description)
            cells[3].text = _uk(r)
            cells[4].text = _clean(r.page)
        doc.save(docx_path)
    except Exception as e:  # pragma: no cover
        docx_path = f"(cheatsheet docx skipped: {e})"
    return csv_path, docx_path


def write_review(rows: list[IndexRow], out_dir: str):
    rows = sort_rows(rows)
    recs = []
    for r in rows:
        topic = _clean(r.topic)
        if not topic:
            continue
        recs.append({
            "Topic": topic,
            "Description": _clean(r.description),
            "Page": _clean(r.page),
            "Book": _clean(r.book),
            "flag_reason": _clean(r.flag_reason),
        })
    df = pd.DataFrame(recs, columns=["Topic", "Description", "Page", "Book", "flag_reason"])
    # Only rows that actually have a flag land in the review file.
    df = df[df["flag_reason"].str.len() > 0]
    path = os.path.join(out_dir, "index_review.csv")
    df.to_csv(path, index=False, encoding="utf-8")
    return path, len(df)


def write_docx(rows: list[IndexRow], out_dir: str):
    """Printable BILINGUAL two-column A-Z index.

    Each entry: English Topic (bold) + Ukrainian description + (Book, p.Page).
    Topic stays verbatim English; only the description is Ukrainian (desc_uk,
    English fallback if translation was unavailable)."""
    from docx import Document
    from docx.shared import Pt, Inches

    rows = sort_rows(rows)
    doc = Document()

    # Small margins.
    for section in doc.sections:
        section.top_margin = Inches(0.4)
        section.bottom_margin = Inches(0.4)
        section.left_margin = Inches(0.4)
        section.right_margin = Inches(0.4)

    # Base style ~9-10pt.
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(9)

    # Two-column layout.
    sectPr = doc.sections[0]._sectPr
    from docx.oxml.ns import qn
    cols = sectPr.find(qn("w:cols"))
    if cols is None:
        cols = sectPr.makeelement(qn("w:cols"), {})
        sectPr.append(cols)
    cols.set(qn("w:num"), "2")
    cols.set(qn("w:space"), "180")

    title = doc.add_paragraph()
    trun = title.add_run("BOOKIDX Exam Index / Індекс для іспиту (EN → UA)")
    trun.bold = True
    trun.font.size = Pt(12)

    current_letter = None
    for r in rows:
        topic = _clean(r.topic)
        if not topic:
            continue
        letter = topic[0].upper()
        if not letter.isalpha():
            letter = "#"
        if letter != current_letter:
            current_letter = letter
            hdr = doc.add_paragraph()
            hrun = hdr.add_run(letter)
            hrun.bold = True
            hrun.font.size = Pt(11)

        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(1)
        p.paragraph_format.space_before = Pt(0)
        rt = p.add_run(topic)          # English topic, verbatim
        rt.bold = True
        desc = _uk(r)                  # Ukrainian description (EN fallback)
        if desc:
            p.add_run(f" — {desc}")
        loc = f"  ({_clean(r.book)}, p.{_clean(r.page)})"
        rloc = p.add_run(loc)
        rloc.italic = True

    path = os.path.join(out_dir, "index.docx")
    doc.save(path)
    return path


def write_run_report(out_dir: str, rows: list[IndexRow], stats: dict):
    """stats keys: pages_per_book(dict), pages_errored(int), used_mock(bool),
    llm_used(bool), backend(str), uk_translated(int)."""
    lines = []
    lines.append("BOOKIDX INDEX GENERATOR - RUN REPORT")
    lines.append("=" * 40)
    lines.append(f"LLM backend        : {stats.get('backend', 'n/a')}")
    lines.append(f"LLM used           : {stats.get('llm_used')}")
    lines.append(f"Used mock LLM      : {stats.get('used_mock')}")
    lines.append(f"UA descriptions    : {stats.get('uk_translated', 0)} translated")
    # Page-offset provenance — the #1 correctness signal for the student.
    if "page_offset" in stats:
        lines.append(f"Page offset        : {stats.get('page_offset')} "
                     f"(printed = pdf_index - offset)")
        lines.append(f"Offset method      : {stats.get('offset_method', 'n/a')}")
        if stats.get("offset_detail"):
            lines.append(f"Offset detail      : {stats.get('offset_detail')}")
    lines.append("")
    lines.append("Pages processed per book:")
    for book, n in stats.get("pages_per_book", {}).items():
        lines.append(f"  {book:20s}: {n}")
    lines.append("")

    total = len([r for r in rows if _clean(r.topic)])
    lines.append(f"Total index entries : {total}")

    cat_counts = Counter(r.category for r in rows)
    lines.append("Entries per category:")
    for cat, n in sorted(cat_counts.items()):
        lines.append(f"  {cat:15s}: {n}")

    # Course CyberLive: command + cheatsheet coverage.
    n_cmd = cat_counts.get("command", 0)
    n_tool = cat_counts.get("tool", 0)
    lines.append(f"Command entries     : {n_cmd}")
    lines.append(f"Cheatsheet rows     : {n_cmd + n_tool} (command + tool)")

    flagged = [r for r in rows if _clean(r.flag_reason)]
    lines.append(f"Entries flagged     : {len(flagged)}")
    lines.append(f"Pages errored (LLM) : {stats.get('pages_errored', 0)}")
    lines.append("")

    # Which books had most flags.
    flags_per_book = Counter(r.book for r in flagged)
    if flags_per_book:
        lines.append("Flags per book (most first):")
        for book, n in flags_per_book.most_common():
            lines.append(f"  {book:20s}: {n}")
    else:
        lines.append("Flags per book      : none")

    text = "\n".join(lines) + "\n"
    path = os.path.join(out_dir, "run_report.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path, text
