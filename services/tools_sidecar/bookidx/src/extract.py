"""
extract.py - Stage A: deterministic PDF text extraction (NO LLM).

Responsibilities:
  * PyMuPDF (fitz) primary text extraction; pdfplumber fallback for table pages.
  * Per-page record: book_label, printed_page, pdf_index, text, has_table,
    block_count.
  * printed_page = pdf_page_index_1based - page_offset  (from config, per book).
  * Strip recurring headers/footers.
  * Optional footer page-number verification (WARN only; never used to decide
    the printed page - page numbers come ONLY from deterministic parsing).
  * Chunk long pages to ~400-800 tokens with small overlap; every chunk keeps
    its exact printed_page (never merge across pages).
  * Deterministic regex pre-pass for high-value items (commands, Event IDs,
    ports, acronyms) - independent of the LLM.

IMPORTANT: The end user points this at their real PDFs locally. This module
never phones home.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Iterable, Optional

import fitz  # PyMuPDF

try:
    import pdfplumber  # table fallback
    _HAVE_PDFPLUMBER = True
except Exception:  # pragma: no cover
    _HAVE_PDFPLUMBER = False


# ---------------------------------------------------------------------------
# Data records
# ---------------------------------------------------------------------------
@dataclass
class PageRecord:
    book_label: str
    printed_page: int
    pdf_index: int          # 1-based PDF page index
    text: str
    has_table: bool = False
    block_count: int = 0
    footer_mismatch: bool = False   # footer page number disagreed w/ computed


@dataclass
class Chunk:
    book_label: str
    printed_page: int
    pdf_index: int
    text: str
    has_table: bool = False
    footer_mismatch: bool = False


# A candidate index row (from regex pre-pass OR the LLM later).
@dataclass
class Candidate:
    topic: str
    description: str
    category: str
    weight: int
    book_label: str
    printed_page: int
    source: str = "regex"          # "regex" or "llm"
    has_table: bool = False
    footer_mismatch: bool = False


# ---------------------------------------------------------------------------
# Token estimate (offline, no tokenizer dependency): ~4 chars/token.
# ---------------------------------------------------------------------------
def est_tokens(text: str) -> int:
    return max(1, len(text) // 4)


# ---------------------------------------------------------------------------
# Header/footer detection
# ---------------------------------------------------------------------------
def _first_last_lines(text: str):
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return None, None
    return lines[0], lines[-1]


def detect_recurring_lines(page_texts: list[str], min_repeats: int = 3) -> set[str]:
    """Find first/last lines that recur across many pages (headers/footers)."""
    counter: Counter[str] = Counter()
    for t in page_texts:
        first, last = _first_last_lines(t)
        for ln in (first, last):
            if ln and len(ln) <= 120:
                # Normalise page-number digits so "Page 12"/"Page 13" collapse.
                norm = re.sub(r"\d+", "#", ln)
                counter[norm] += 1
    return {ln for ln, c in counter.items() if c >= min_repeats}


def strip_headers_footers(text: str, recurring: set[str]) -> str:
    if not recurring:
        return text
    out = []
    for ln in text.splitlines():
        norm = re.sub(r"\d+", "#", ln.strip())
        if norm in recurring:
            continue
        out.append(ln)
    return "\n".join(out)


# Footer page-number verification -------------------------------------------
_FOOTER_PAGENUM = re.compile(r"(?:page\s+)?(\d{1,4})\s*$", re.IGNORECASE)


def footer_page_number(text: str) -> Optional[int]:
    """Return an integer page number parsed from the last non-empty line, if any."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return None
    m = _FOOTER_PAGENUM.search(lines[-1])
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None
    return None


def detect_page_offset(raw_texts: dict, sample: int = 25):
    """Auto-detect page_offset = pdf_1based_index - printed_footer_number.
    Scans the first `sample` pages, tallies the offset implied by each footer page
    number, and returns the mode ONLY if a strong majority agrees (>=3 pages and
    >=60% of pages that HAD a footer number). Returns None if inconclusive — the
    caller then falls back to the user-supplied offset."""
    from collections import Counter
    votes = Counter()
    seen = 0
    for pdf_index in sorted(raw_texts.keys())[:sample]:
        fnum = footer_page_number(raw_texts[pdf_index])
        if fnum is None or fnum <= 0:
            continue
        seen += 1
        votes[pdf_index - fnum] += 1
    if not votes:
        return None
    off, cnt = votes.most_common(1)[0]
    if cnt >= 3 and cnt >= 0.6 * seen:
        return off
    return None


# ---------------------------------------------------------------------------
# ROBUST positional page-offset detection (primary method).
#
# Root cause of "wrong pages": Study books have front matter (cover/TOC/legal),
# so the PRINTED page number a student navigates to != the PDF page index. The
# old detector only inspected the LAST TEXT LINE for a trailing number; on real
# course PDFs the printed page number is a standalone element in the bottom
# margin that PyMuPDF frequently does NOT emit as the final text line (it may be
# followed by "© Study", a module tag, or a right-aligned block). Result: no
# footer number parsed -> offset falls back to 0 -> every printed page is wrong
# by the front-matter amount.
#
# Fix: read the words in the BOTTOM MARGIN BAND by their y-coordinate, treat a
# standalone integer there as the printed page number, and take the offset
# (pdf_index - printed) that is CONSISTENT across many pages. A true page number
# increments 1:1 with the PDF page, so its implied offset is CONSTANT and wins by
# vote; constant noise (a year like 2023, "of N" totals) yields a DIFFERENT
# offset on every page and never accumulates -> automatically rejected.
# ---------------------------------------------------------------------------
_STANDALONE_INT_RE = re.compile(r"^\(?(\d{1,4})\)?[.,]?$")


def _bottom_band_page_numbers(page, band_frac: float = 0.14) -> set:
    """Return the set of standalone integers found in the bottom `band_frac` of
    the page (candidate printed page numbers), using word positions."""
    out: set = set()
    try:
        h = page.rect.height
        words = page.get_text("words")  # (x0,y0,x1,y1, word, block,line,wordno)
    except Exception:
        return out
    if not h:
        return out
    cutoff = h * (1.0 - band_frac)
    for w in words:
        y0 = w[1]
        if y0 < cutoff:
            continue
        m = _STANDALONE_INT_RE.match(str(w[4]).strip())
        if m:
            try:
                out.add(int(m.group(1)))
            except ValueError:
                pass
    return out


def detect_page_offset_positional(doc, lo: int, hi: int, max_scan: int = 80):
    """Primary offset detector using bottom-margin word positions.

    Returns (offset:int, info:str) on success, else (None, reason:str).
    offset is chosen so printed_page = pdf_index - offset. Requires a strong,
    self-consistent vote AND a run of >=3 consecutive PDF pages whose bottom-band
    number matches the offset (guards against sparse coincidences)."""
    from collections import Counter
    votes = Counter()
    cand_by_page: dict[int, set] = {}
    scanned = 0
    for pdf_index in range(lo, min(hi, lo + max_scan - 1) + 1):
        try:
            page = doc[pdf_index - 1]
        except Exception:
            continue
        nums = _bottom_band_page_numbers(page)
        scanned += 1
        cand_by_page[pdf_index] = nums
        for n in nums:
            off = pdf_index - n
            # sane: at most ~60 front-matter pages; printed page within the book.
            if 0 <= off <= 60 and 0 < n <= hi:
                votes[off] += 1
    if not votes:
        return None, "no bottom-margin page numbers found"

    off, cnt = votes.most_common(1)[0]
    # Pages whose bottom band matches this offset.
    matching = sorted(p for p, s in cand_by_page.items() if (p - off) in s)
    # Longest run of consecutive matching PDF pages.
    best_run = run = 0
    prev = None
    for p in matching:
        run = run + 1 if prev is not None and p == prev + 1 else 1
        best_run = max(best_run, run)
        prev = p

    pages_with_nums = sum(1 for s in cand_by_page.values() if s)
    strong = (
        cnt >= 5
        and best_run >= 3
        and (pages_with_nums == 0 or cnt >= 0.5 * pages_with_nums)
    )
    info = (f"offset={off} votes={cnt}/{scanned} run={best_run} "
            f"pages_with_numbers={pages_with_nums}")
    if strong:
        return off, info
    return None, "inconclusive: " + info


# ---------------------------------------------------------------------------
# Deterministic regex pre-pass (high-value items, independent of the LLM)
# ---------------------------------------------------------------------------
# CLI command with at least one flag, e.g. `nmap -sS`, `tcpdump -nn -i eth0`.
_CMD_RE = re.compile(
    r"\b([a-z][a-z0-9._-]{1,20})(\s+-{1,2}[A-Za-z0-9][\w-]*)+"
)
# Bases that are prose words, not tools.
_CMD_STOPWORDS = {
    "the", "and", "for", "with", "this", "that", "then", "when", "note", "see",
    "use", "run", "using", "e.g", "i.e", "a", "an", "is", "are", "to", "of",
}
# File extensions that indicate a DATA FILE (evidence), never an executable.
_DATA_FILE_EXTS = {
    "raw", "dd", "e01", "aff", "vmem", "mem", "dump", "img", "bin",
    "evtx", "evt", "pcap", "pcapng", "cap", "csv", "txt", "log", "json",
    "xml", "db", "sqlite", "hive", "dat", "pf", "lnk", "reg",
}
# PowerShell cmdlets (Verb-Noun) — high-yield, have NO leading dash so _CMD_RE
# misses them. e.g. Get-WinEvent, Get-FileHash, Invoke-Command.
_PSCMDLET_RE = re.compile(
    r"\b((?:Get|Set|New|Remove|Invoke|Import|Export|Select|Where|ForEach|Start|"
    r"Stop|Test|Enable|Disable|Add|Clear|Convert|Format|Out|Write|Read)-[A-Z][A-Za-z]+)\b"
)
# Windows Event IDs (4xxx logon/audit family + generic 4-digit security events).
_EVENTID_RE = re.compile(r"\bEvent\s*ID[:\s]*?(\d{3,5})\b", re.IGNORECASE)
_EVENTID_BARE_RE = re.compile(r"\b(4\d{3})\b")   # 4000-4999 security log family
# port/protocol pairs, e.g. "445 SMB", "port 3389 (RDP)", "TCP/88 Kerberos".
_PORT_RE = re.compile(
    r"\b(?:port\s+|tcp/|udp/)?(\d{1,5})\s*[\/\-\(\s]*([A-Za-z][A-Za-z0-9+/._-]{1,20})",
    re.IGNORECASE,
)
# ALL-CAPS acronym with parenthetical expansion, e.g. "KDC (Key Distribution Center)".
_ACRONYM_RE = re.compile(r"\b([A-Z]{2,8})\s*\(([^)]{3,60})\)")
# Also catch "KDC = Key Distribution Center" / "KDC - Key Distribution Center".
_ACRONYM_EQ_RE = re.compile(r"\b([A-Z]{2,8})\s*[=:\-–]\s*([A-Z][A-Za-z ]{3,60})")

_COMMON_PROTOCOLS = {
    "smb", "rdp", "ssh", "ftp", "http", "https", "dns", "kerberos", "ldap",
    "smtp", "snmp", "tftp", "telnet", "ntp", "rpc", "netbios", "sip", "imap",
    "pop3", "krb", "winrm",
}


# ---------------------------------------------------------------------------
# Course high-yield deterministic patterns (fire even with zero LLM).
# CyberLive is hands-on -> command syntax + tool OUTPUT are the highest value,
# so these all emit weight 3 (add() below hardcodes weight=3).
# ---------------------------------------------------------------------------

# Windows Event IDs -> meaning (each becomes its OWN index row).
EVENT_ID_MEANINGS = {
    "4624": "Successful account logon",
    "4625": "Failed logon attempt",
    "4634": "Account logoff",
    "4647": "User-initiated logoff",
    "4648": "Logon using explicit credentials (runas)",
    "4672": "Special privileges assigned to new logon",
    "4688": "Process creation (new process)",
    "4689": "Process termination",
    "4697": "Service installed (Security log)",
    "4698": "Scheduled task created",
    "4720": "User account created",
    "4724": "Password reset attempt",
    "4732": "Member added to security-enabled local group",
    "4740": "User account locked out",
    "4776": "NTLM credential validation",
    "1102": "Security/audit log was cleared",
    "7045": "Service installed (System log)",
    "7034": "Service crashed unexpectedly",
    "7040": "Service start type changed",
}
# Non-4xxx high-value IDs detected bare (distinctive enough to avoid FPs).
_EVENTID_SYS_RE = re.compile(r"\b(7045|7034|7040|1102)\b")

# EZ Tools (Eric Zimmerman) -> the artifact each one parses.
_EZTOOLS = {
    "MFTECmd": "Parses $MFT/$J/$LogFile/$Boot NTFS metadata to CSV",
    "PECmd": "Parses Prefetch: program execution run count + times",
    "AppCompatCacheParser": "Parses ShimCache/AppCompatCache execution evidence",
    "AmcacheParser": "Parses Amcache: program execution + SHA1 hashes",
    "RECmd": "Parses registry hives via batch queries",
    "EvtxECmd": "Parses Windows EVTX event logs to CSV",
    "SBECmd": "Parses Shellbags: folder access/browsing evidence",
    "LECmd": "Parses LNK shortcut files (opened files/paths)",
    "JLECmd": "Parses Jump Lists (recent files per application)",
    "Timeline Explorer": "Views/filters CSV timelines (EZ Tools output)",
}
_EZTOOLS_LOWER = {k.lower(): (k, v) for k, v in _EZTOOLS.items()}
_EZTOOLS_RE = re.compile(
    r"(?<![\w])(" + "|".join(re.escape(k) for k in sorted(_EZTOOLS, key=len, reverse=True))
    + r")(?![\w])", re.IGNORECASE,
)

# Volatility memory-forensics plugins -> what they output/prove.
_VOL_PLUGINS = {
    "pslist": "Volatility: active processes via EPROCESS list walk",
    "psscan": "Volatility: scans for processes incl. hidden/terminated",
    "pstree": "Volatility: process tree (parent-child relationships)",
    "dlllist": "Volatility: DLLs loaded per process",
    "malfind": "Volatility: detects injected/hidden code in process memory",
    "netscan": "Volatility: recovers network connections and sockets",
    "netstat": "Volatility: active network connections from memory",
    "cmdline": "Volatility: per-process command-line arguments",
    "handles": "Volatility: open handles per process",
    "svcscan": "Volatility: Windows services present in memory",
}
_VOL_PLUGIN_RE = re.compile(r"\b(" + "|".join(_VOL_PLUGINS) + r")\b")
# Only emit volatility plugin rows when memory-forensics context is present
# (avoids treating bare "handles"/"netstat"/"cmdline" prose as plugins).
_VOL_CONTEXT_RE = re.compile(r"(vol(?:atility)?(?:\.py)?|--profile|malfind|pslist|psscan)",
                             re.IGNORECASE)
_VOL_PROFILE_RE = re.compile(r"--profile\b")

# KAPE triage collection.
_KAPE_DESC = {
    "kape.exe": "KAPE: targeted triage collection (Targets/Modules)",
    "gkape": "KAPE GUI front-end (gkape)",
    "gkape.exe": "KAPE GUI front-end (gkape)",
    "--tsource": "KAPE flag: target source volume",
    "--tdest": "KAPE flag: target destination",
    "--target": "KAPE flag: Target (artifact set) to collect",
    "--module": "KAPE flag: Module (tool) to run",
    "--msource": "KAPE flag: module source",
    "--mdest": "KAPE flag: module destination",
}
_KAPE_RE = re.compile(
    r"(kape\.exe|gkape\.exe|gkape|--tsource|--tdest|--target|--module|--msource|--mdest)",
    re.IGNORECASE,
)

# Plaso super-timeline tooling.
_PLASO = {
    "log2timeline.py": "Plaso: build super timeline from artifacts",
    "log2timeline": "Plaso: build super timeline from artifacts",
    "psort.py": "Plaso: filter/sort timeline into output format",
    "psort": "Plaso: filter/sort timeline into output format",
}
_PLASO_RE = re.compile(r"\b(log2timeline\.py|log2timeline|psort\.py|psort)\b")

# Sleuth Kit + bulk_extractor.
_SLEUTHKIT_CMD = {
    "fls": "Sleuth Kit: list files/dirs incl. deleted entries",
    "icat": "Sleuth Kit: extract file content by inode",
    "mactime": "Sleuth Kit: build MAC timeline from body file",
    "mmls": "Sleuth Kit: display partition layout of image",
    "istat": "Sleuth Kit: display metadata for an inode",
}
_SLEUTHKIT_RE = re.compile(r"\b(fls|icat|mactime|mmls|istat)\b")
_BULK_RE = re.compile(r"\bbulk_extractor\b")

# Windows forensic artifacts -> what each PROVES/contains.
_WIN_ARTIFACTS = {
    "Prefetch": "Proves program execution: run count + last-run times",
    "ShimCache": "AppCompatCache: program presence/execution evidence",
    "AppCompatCache": "ShimCache: program presence/execution evidence",
    "Amcache": "Program execution evidence + SHA1 of executables",
    "UserAssist": "GUI program execution count/times per user",
    "BAM": "Background Activity Moderator: last run time per user",
    "DAM": "Desktop Activity Moderator: last run time per user",
    "SRUM": "System Resource Usage: app + network bytes per app",
    "$MFT": "Master File Table: every file with MACB timestamps",
    "$LogFile": "NTFS transaction log (file operation journaling)",
    "$UsnJrnl": "USN journal: file create/delete/rename history",
    "$J": "USN journal data stream ($UsnJrnl:$J) change records",
    "$Boot": "NTFS boot record: cluster and sector size",
    "Shellbags": "Folder access/browsing evidence per user",
    "$STANDARD_INFORMATION": "SI timestamps (target of timestomping)",
    "$FILE_NAME": "FN timestamps (resist timestomping)",
}
_WIN_ART_LOWER = {k.lower(): (k, v) for k, v in _WIN_ARTIFACTS.items()}
_WIN_ART_RE = re.compile(
    r"(?<![\w$])(" + "|".join(re.escape(k) for k in sorted(_WIN_ARTIFACTS, key=len, reverse=True))
    + r")(?![\w])", re.IGNORECASE,
)

# Linux log / history paths.
_LINUX_PATHS = {
    "/var/log/auth.log": "Linux auth/sudo events (Debian/Ubuntu)",
    "/var/log/secure": "Linux authentication events (RHEL/CentOS)",
    "/var/log/syslog": "Linux general system log (Debian/Ubuntu)",
    "/var/log/messages": "Linux general system log (RHEL/CentOS)",
    "/var/log/wtmp": "Linux login records (last/who)",
    "/var/log/btmp": "Linux failed login records",
    "~/.bash_history": "User shell command history",
}
_LINUX_RE = re.compile(
    r"(" + "|".join(re.escape(k) for k in sorted(_LINUX_PATHS, key=len, reverse=True)) + r")"
)


def regex_candidates(text: str, book_label: str, printed_page: int,
                     has_table: bool = False, footer_mismatch: bool = False
                     ) -> list[Candidate]:
    """Emit high-value candidate rows found purely by regex (weight 3)."""
    out: list[Candidate] = []
    seen: set[tuple[str, str]] = set()

    def add(topic, desc, cat):
        topic = topic.strip()
        key = (topic.lower(), cat)
        if not topic or key in seen:
            return
        seen.add(key)
        out.append(Candidate(
            topic=topic, description=desc.strip(), category=cat, weight=3,
            book_label=book_label, printed_page=printed_page, source="regex",
            has_table=has_table, footer_mismatch=footer_mismatch,
        ))

    # Commands with flags.
    for m in _CMD_RE.finditer(text):
        cmd = re.sub(r"\s+", " ", m.group(0)).strip()
        base = m.group(1)
        # Skip obvious prose false-positives (e.g. "the -best").
        if len(cmd) > 60 or base.lower() in _CMD_STOPWORDS:
            continue
        # Skip DATA FILES masquerading as commands: `mem.raw --profile`,
        # `image.E01 ...` etc. Executable extensions (.py/.exe/.sh/.ps1) stay.
        if "." in base:
            ext = base.rsplit(".", 1)[-1].lower()
            if ext in _DATA_FILE_EXTS:
                continue
        # Skip a bare data-file-extension word wrongly split off a filename,
        # e.g. `Security.evtx --csv` -> `evtx --csv`.
        if base.lower() in _DATA_FILE_EXTS:
            continue
        add(cmd, f"{base} command-line usage", "command")

    # PowerShell cmdlets (Verb-Noun) — no leading flag, so caught separately.
    for m in _PSCMDLET_RE.finditer(text):
        cmd = m.group(1)
        add(cmd, "PowerShell cmdlet", "command")

    # Event IDs -> EACH one is its own row; use known meanings when available.
    def add_event(eid: str):
        meaning = EVENT_ID_MEANINGS.get(eid, "Windows event log identifier")
        add(f"Event ID {eid}", meaning, "artifact")

    # Explicit "Event ID NNNN" (any number).
    for m in _EVENTID_RE.finditer(text):
        add_event(m.group(1))
    # Bare 4xxx security-log IDs.
    for m in _EVENTID_BARE_RE.finditer(text):
        add_event(m.group(1))
    # Bare non-4xxx high-value system-log IDs (7045, 1102, ...).
    for m in _EVENTID_SYS_RE.finditer(text):
        add_event(m.group(1))

    # Ports / protocols.
    for m in _PORT_RE.finditer(text):
        port, proto = m.group(1), m.group(2)
        try:
            pnum = int(port)
        except ValueError:
            continue
        if not (0 < pnum <= 65535):
            continue
        if proto.lower() in _COMMON_PROTOCOLS:
            add(f"Port {port} ({proto})", f"{proto} service on port {port}", "port_protocol")

    # Acronyms with parenthetical expansion.
    for m in _ACRONYM_RE.finditer(text):
        acro, expansion = m.group(1), m.group(2).strip()
        # Expansion should look like Title-case words, not another random token.
        if any(c.isalpha() for c in expansion):
            add(acro, expansion, "acronym")
    for m in _ACRONYM_EQ_RE.finditer(text):
        acro, expansion = m.group(1), m.group(2).strip()
        add(acro, expansion, "acronym")

    # --- Course high-yield deterministic patterns ---

    # EZ Tools (Eric Zimmerman) -> tool row + the artifact it parses.
    for m in _EZTOOLS_RE.finditer(text):
        canon, desc = _EZTOOLS_LOWER[m.group(1).lower()]
        add(canon, desc, "tool")

    # Volatility plugins (only with memory-forensics context; command syntax).
    if _VOL_CONTEXT_RE.search(text):
        for m in _VOL_PLUGIN_RE.finditer(text):
            plug = m.group(1)
            add(f"vol.py {plug}", _VOL_PLUGINS[plug], "command")
        if _VOL_PROFILE_RE.search(text):
            add("vol.py --profile", "Volatility: select memory image profile/OS build",
                "command")

    # KAPE triage collection.
    for m in _KAPE_RE.finditer(text):
        tok = m.group(1)
        desc = _KAPE_DESC.get(tok.lower(), _KAPE_DESC.get(tok, "KAPE triage option"))
        if tok.lower() in ("kape.exe", "gkape", "gkape.exe"):
            add(tok.lower(), desc, "tool")
        else:
            add(f"kape {tok}", desc, "command")

    # Plaso super-timeline tooling.
    for m in _PLASO_RE.finditer(text):
        tok = m.group(1)
        add(tok, _PLASO[tok], "command")

    # Sleuth Kit + bulk_extractor.
    for m in _SLEUTHKIT_RE.finditer(text):
        tok = m.group(1)
        add(tok, _SLEUTHKIT_CMD[tok], "command")
    for _ in _BULK_RE.finditer(text):
        add("bulk_extractor", "Carves features (emails, URLs, cards) from an image",
            "tool")

    # Windows forensic artifacts -> what each proves.
    for m in _WIN_ART_RE.finditer(text):
        canon, desc = _WIN_ART_LOWER[m.group(1).lower()]
        add(canon, desc, "artifact")

    # Linux log / history paths.
    for m in _LINUX_RE.finditer(text):
        path = m.group(1)
        add(path, _LINUX_PATHS[path], "artifact")

    return out


# ---------------------------------------------------------------------------
# Chunking (never merges across pages; every chunk keeps its printed_page)
# ---------------------------------------------------------------------------
def chunk_page(rec: PageRecord, target_tokens: int = 600, max_tokens: int = 800,
               overlap_tokens: int = 60) -> list[Chunk]:
    text = rec.text.strip()
    if not text:
        return []
    if est_tokens(text) <= max_tokens:
        return [Chunk(rec.book_label, rec.printed_page, rec.pdf_index, text,
                      rec.has_table, rec.footer_mismatch)]

    # Split on paragraph/line boundaries, greedily fill to target token budget.
    words = text.split()
    target_words = target_tokens * 4 // 4  # ~ tokens*4 chars, but count in words
    # Use word count budget: ~0.75 words/token -> words ≈ tokens * 0.75.
    wb = max(50, int(target_tokens * 0.75))
    overlap_w = max(0, int(overlap_tokens * 0.75))

    chunks: list[Chunk] = []
    i = 0
    n = len(words)
    while i < n:
        piece = words[i : i + wb]
        chunk_text = " ".join(piece)
        chunks.append(Chunk(rec.book_label, rec.printed_page, rec.pdf_index,
                            chunk_text, rec.has_table, rec.footer_mismatch))
        if i + wb >= n:
            break
        i += wb - overlap_w
    return chunks


# ---------------------------------------------------------------------------
# Main per-book extraction
# ---------------------------------------------------------------------------
def _page_has_table_fitz(page) -> bool:
    """Heuristic: PyMuPDF table finder (available in recent versions)."""
    try:
        tf = page.find_tables()
        return bool(tf.tables)
    except Exception:
        return False


def extract_book(pdf_path: str, book_label: str, page_offset: int,
                 start_page: Optional[int] = None, end_page: Optional[int] = None,
                 strip_hf: bool = True, footer_verify: bool = True,
                 hf_min_repeats: int = 3, limit_pages: Optional[int] = None,
                 offset_info: Optional[dict] = None
                 ) -> list[PageRecord]:
    """Extract all in-range pages of one book into PageRecords."""
    doc = fitz.open(pdf_path)
    n_pages = doc.page_count

    lo = (start_page or 1)
    hi = (end_page or n_pages)
    lo = max(1, lo)
    hi = min(n_pages, hi)

    # First pass: raw text per page (for header/footer detection).
    raw_texts: dict[int, str] = {}
    table_flags: dict[int, bool] = {}
    for pdf_index in range(lo, hi + 1):
        page = doc[pdf_index - 1]
        txt = page.get_text("text") or ""
        raw_texts[pdf_index] = txt
        table_flags[pdf_index] = _page_has_table_fitz(page)

    recurring = set()
    if strip_hf:
        recurring = detect_recurring_lines(list(raw_texts.values()), hf_min_repeats)

    # AUTO page-offset. This is THE fix for "wrong page numbers": the printed page
    # the student navigates to must equal pdf_index - offset. Try, in order:
    #   1) positional bottom-margin detector (robust; handles real Study footers),
    #   2) last-text-line detector (legacy fallback),
    #   3) the caller-supplied offset (e.g. from config/watcher).
    _method = "caller-supplied"
    _pos, _pos_info = detect_page_offset_positional(doc, lo, hi)
    if _pos is not None:
        page_offset = _pos
        _method = "positional-footer"
    else:
        _auto = detect_page_offset(raw_texts)
        if _auto is not None:
            page_offset = _auto
            _method = "last-line-footer"
    if offset_info is not None:
        offset_info["offset"] = page_offset
        offset_info["method"] = _method
        offset_info["positional_info"] = _pos_info
    try:
        import logging as _lg
        _lg.getLogger('bookidx').warning(
            'page_offset=%d via %s (%s)', page_offset, _method, _pos_info)
    except Exception:
        pass

    # pdfplumber fallback (open once) for table pages.
    plumber_doc = None
    if _HAVE_PDFPLUMBER and any(table_flags.values()):
        try:
            plumber_doc = pdfplumber.open(pdf_path)
        except Exception:
            plumber_doc = None

    records: list[PageRecord] = []
    produced = 0
    for pdf_index in range(lo, hi + 1):
        if limit_pages is not None and produced >= limit_pages:
            break
        raw = raw_texts[pdf_index]
        has_table = table_flags[pdf_index]

        text = raw
        # Table fallback: prefer pdfplumber's layout-aware text on table pages.
        if has_table and plumber_doc is not None:
            try:
                p = plumber_doc.pages[pdf_index - 1]
                ptxt = p.extract_text() or ""
                # Append extracted table rows as pipe-joined lines.
                for tbl in (p.extract_tables() or []):
                    for row in tbl:
                        cells = [c for c in row if c]
                        if cells:
                            ptxt += "\n" + " | ".join(str(c).strip() for c in cells)
                if ptxt.strip():
                    text = ptxt
            except Exception:
                pass

        # Footer verification: compare the computed printed page against the
        # actual number in the page's bottom margin. Only a REAL disagreement
        # (page has a bottom-band number, and none of them matches) flags a
        # mismatch -> keeps the review file meaningful.
        printed_page = pdf_index - page_offset
        footer_mismatch = False
        if footer_verify:
            band_nums = _bottom_band_page_numbers(doc[pdf_index - 1])
            if band_nums and printed_page not in band_nums:
                footer_mismatch = True

        if strip_hf:
            text = strip_headers_footers(text, recurring)

        block_count = len([b for b in raw.split("\n\n") if b.strip()])

        records.append(PageRecord(
            book_label=book_label,
            printed_page=printed_page,
            pdf_index=pdf_index,
            text=text,
            has_table=has_table,
            block_count=block_count,
            footer_mismatch=footer_mismatch,
        ))
        produced += 1

    doc.close()
    if plumber_doc is not None:
        plumber_doc.close()
    return records
