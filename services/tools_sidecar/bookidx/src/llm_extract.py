"""
llm_extract.py - Stage B: per-chunk LLM extraction, merged with regex pre-pass.

The LLM NEVER decides page numbers. It receives a text chunk (already tagged
with book+page by Stage A) and returns topics/descriptions only; this module
re-attaches the KNOWN printed_page from the chunk.

Robustness: temperature 0, JSON-only requested. Malformed JSON -> retry once
with a "valid JSON only" reminder; still bad -> log the page to an errors file
and continue (never crash the run).
"""
from __future__ import annotations

import json
import os
from typing import Optional

from .extract import Chunk, Candidate, regex_candidates


VALID_CATEGORIES = {
    "command", "tool", "artifact", "port_protocol", "acronym", "concept", "table_ref",
}

SYSTEM_PROMPT = (
    "You extract concise, high-yield lookup entries from cybersecurity/DFIR "
    "course text for an open-book BOOKIDX exam index. You output ONLY a JSON array. "
    "Each element: {\"topic\": str, \"description\": str, \"category\": one of "
    "[command, tool, artifact, port_protocol, acronym, concept, table_ref], "
    "\"weight\": 1-3}.\n"
    "DESCRIPTION RULES (exam-oriented, <= 18 words): state what it IS and WHEN a "
    "student would use it or what it PROVES/OUTPUTS. Never write vague fillers "
    "like 'a command', 'see text', or just repeat the topic. For a command, say "
    "what the command DOES. For an artifact, say what it PROVES. For an Event ID, "
    "give its exact meaning. weight 3 = must-know exam lookup, 1 = minor.\n"
    "COMMAND EXTRACTION (highest priority — this exam has a hands-on CyberLive "
    "portion): capture EVERY command, tool invocation, flag/switch, and syntax "
    "example you see, INCLUDING inline-in-prose and multi-line ones. Put the full "
    "command with its flags in `topic` (e.g. 'vol.py -f mem.raw malfind', "
    "'MFTECmd -f $MFT --csv .', 'log2timeline.py plaso.dump image.E01', "
    "'Get-WinEvent -FilterHashtable @{...}', 'grep -i failed /var/log/auth.log', "
    "'regripper -f system', 'yara -r rules.yar'). Cover Volatility/vol.py plugins, "
    "EZ Tools (MFTECmd/PECmd/EvtxECmd/AppCompatCacheParser/AmcacheParser/RECmd), "
    "KAPE, Plaso (log2timeline.py/psort.py), Sleuth Kit (fls/icat/mactime/mmls), "
    "RegRipper, YARA, bulk_extractor, tshark/tcpdump, and PowerShell cmdlets. "
    "Do NOT invent commands that are not in the text; do NOT treat a data file "
    "(mem.raw, image.E01, Security.evtx) as if it were the command itself.\n"
    "ALSO extract, each as its OWN row: (1) forensic artifacts and what each "
    "PROVES (Prefetch, ShimCache/AppCompatCache, Amcache, UserAssist, SRUM, "
    "Shellbags, $MFT, $UsnJrnl/$J, $LogFile); (2) each Windows Event ID as its "
    "own row mapping number -> meaning; (3) registry hives/keys; (4) ports/"
    "protocols; (5) acronyms WITH their expansion; (6) timestamps/timestomping "
    "($STANDARD_INFORMATION/SI vs $FILE_NAME/FN); (7) Linux log paths.\n"
    "Do NOT copy anything that resembles an exam question or answer. Do NOT emit "
    "page numbers. If nothing worth indexing, return []."
)

FEW_SHOT = (
    "Example input:\n"
    "\"Use nmap -sS for a stealth SYN scan. The KDC (Key Distribution Center) "
    "issues Kerberos tickets on port 88. Event ID 4624 records a successful logon. "
    "Run vol.py -f mem.raw malfind to find injected code. MFTECmd -f $MFT --csv . "
    "parses the master file table. Prefetch shows how many times a program ran. "
    "Event ID 4688 logs new process creation.\"\n"
    "Example output:\n"
    "[{\"topic\":\"nmap -sS\",\"description\":\"Stealth SYN scan\",\"category\":\"command\",\"weight\":3},"
    "{\"topic\":\"KDC\",\"description\":\"Key Distribution Center; issues Kerberos tickets\",\"category\":\"acronym\",\"weight\":3},"
    "{\"topic\":\"Port 88\",\"description\":\"Kerberos authentication port\",\"category\":\"port_protocol\",\"weight\":3},"
    "{\"topic\":\"Event ID 4624\",\"description\":\"Successful account logon\",\"category\":\"artifact\",\"weight\":3},"
    "{\"topic\":\"Volatility malfind\",\"description\":\"Detects injected/hidden code in process memory\",\"category\":\"command\",\"weight\":3},"
    "{\"topic\":\"MFTECmd -f $MFT\",\"description\":\"Parses master file table to CSV\",\"category\":\"command\",\"weight\":3},"
    "{\"topic\":\"Prefetch\",\"description\":\"Proves program execution: run count + last-run times\",\"category\":\"artifact\",\"weight\":3},"
    "{\"topic\":\"Event ID 4688\",\"description\":\"Process creation (new process)\",\"category\":\"artifact\",\"weight\":3}]"
)


def _clean_rows(rows, chunk: Chunk) -> list[Candidate]:
    """Validate LLM rows and re-attach the KNOWN page from the chunk."""
    out: list[Candidate] = []
    if not isinstance(rows, list):
        return out
    for r in rows:
        if not isinstance(r, dict):
            continue
        topic = str(r.get("topic", "")).strip()
        desc = str(r.get("description", "")).strip()
        if not topic:
            continue
        cat = str(r.get("category", "concept")).strip().lower()
        if cat not in VALID_CATEGORIES:
            cat = "concept"
        try:
            weight = int(r.get("weight", 1))
        except (TypeError, ValueError):
            weight = 1
        weight = max(1, min(3, weight))
        # Trim descriptions to ~20 words defensively.
        words = desc.split()
        if len(words) > 20:
            desc = " ".join(words[:20])
        out.append(Candidate(
            topic=topic, description=desc, category=cat, weight=weight,
            book_label=chunk.book_label, printed_page=chunk.printed_page,  # KNOWN page
            source="llm", has_table=chunk.has_table,
            footer_mismatch=chunk.footer_mismatch,
        ))
    return out


def llm_extract_chunk(client, chunk: Chunk, max_retries: int = 1,
                      errors_path: Optional[str] = None) -> list[Candidate]:
    """Call the local LLM for one chunk; return validated candidates (may be [])."""
    user = f"{FEW_SHOT}\n\nNow extract from this text:\n\"\"\"\n{chunk.text}\n\"\"\""

    attempts = 0
    last_err = None
    while attempts <= max_retries:
        reminder = attempts > 0
        try:
            rows = client.chat_json(SYSTEM_PROMPT, user, reminder=reminder)
            return _clean_rows(rows, chunk)
        except Exception as e:  # network error OR JSON parse error
            last_err = e
            attempts += 1

    # Give up on this chunk: log and continue.
    if errors_path:
        try:
            with open(errors_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "book": chunk.book_label,
                    "printed_page": chunk.printed_page,
                    "pdf_index": chunk.pdf_index,
                    "error": str(last_err),
                    "text_preview": chunk.text[:160],
                }) + "\n")
        except Exception:
            pass
    return []


def _ckpt_load(path):
    """Return {chunk_key: [candidate_dict, ...]} from a checkpoint JSONL (best-effort)."""
    import json as _j, os as _os
    done = {}
    if not path or not _os.path.exists(path):
        return done
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    rec = _j.loads(line)
                    done[rec["k"]] = rec.get("c", [])
                except Exception:
                    continue
    except Exception:
        return {}
    return done


def extract_candidates(client, chunks: list[Chunk], use_llm: bool = True,
                       max_retries: int = 1, errors_path: Optional[str] = None,
                       progress=None, checkpoint_path=None) -> tuple[list[Candidate], int]:
    """Run regex pre-pass on every chunk + optional LLM; merge results.

    checkpoint_path (optional): a persistent JSONL. Each chunk's LLM candidates are appended
    as {"k": chunk_key, "c": [asdict(cand)...]}; on a later run the already-done chunks are
    skipped and their saved candidates reused, so a crash/timeout resumes instead of restarting.
    All checkpoint I/O is best-effort — any failure degrades to plain (non-resumable) behaviour.

    Returns (candidates, error_page_count).
    """
    import dataclasses as _dc, json as _j
    candidates: list[Candidate] = []
    errored_pages: set[tuple[str, int]] = set()

    # regex pre-pass first (deterministic, cheap, not checkpointed)
    for ch in chunks:
        candidates.extend(regex_candidates(
            ch.text, ch.book_label, ch.printed_page,
            has_table=ch.has_table, footer_mismatch=ch.footer_mismatch,
        ))

    if not (use_llm and client is not None):
        if progress is not None:
            for _ in chunks:
                progress.update(1)
        return candidates, len(errored_pages)

    done = _ckpt_load(checkpoint_path)
    _cf = None
    if checkpoint_path:
        try:
            _cf = open(checkpoint_path, "a", encoding="utf-8")
        except Exception:
            _cf = None

    def _key(c):
        return "%s|%s" % (c.book_label, c.pdf_index)

    for ch in chunks:
        k = _key(ch)
        if k in done:
            for d in done[k]:
                try:
                    candidates.append(Candidate(**d))
                except Exception:
                    continue
        else:
            rows = llm_extract_chunk(client, ch, max_retries=max_retries,
                                     errors_path=errors_path)
            candidates.extend(rows)
            if _cf is not None:
                try:
                    _cf.write(_j.dumps({"k": k, "c": [_dc.asdict(r) for r in rows]}) + "\n")
                    _cf.flush()
                except Exception:
                    pass
        if progress is not None:
            progress.update(1)

    if _cf is not None:
        try:
            _cf.close()
        except Exception:
            pass
    return candidates, len(errored_pages)
