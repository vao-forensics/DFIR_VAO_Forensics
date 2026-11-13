"""
bot_api.py — thin programmatic entry point for the DFIR-bot integration.

`run_single_pdf()` runs the full A→D pipeline on ONE already-local PDF and returns
the produced output file paths. It never touches the network except the local LLM
(guarded by assert_local_url). The bot passes an already-decrypted PDF path.
"""
from __future__ import annotations

import os
import time as _time

from .extract import extract_book, chunk_page
from .llm_client import build_client, MockLLM, assert_local_url
from .llm_extract import extract_candidates
from .normalize import normalize, add_flags, sort_rows
from .translate_uk import translate_rows_uk
from .build_outputs import (
    write_csv_xlsx, write_review, write_docx, write_run_report,
    write_commands_cheatsheet, write_commands_cheatsheet_uk,
)


def run_single_pdf(pdf_path: str, out_dir: str, *, book_label: str = "Book 1",
                   page_offset: int = 0, start_page=None, end_page=None,
                   llm_base_url: str = "http://127.0.0.1:1234/v1",
                   llm_model: str = "synth-dfir", backend: str = "openai",
                   min_weight: int = 1, make_docx: bool = True,
                   use_mock_on_failure: bool = True,
                   translate_uk: bool = True, uk_model: str = None) -> dict:
    """Run the pipeline on one local PDF. Returns dict of output paths + stats.

    Raises on a hard failure (bad PDF); the LLM stage degrades to regex-only /
    mock so a transient/busy local model never blocks the index. UA translation
    of descriptions (Stage C.5) is offline-guarded and falls back to English."""
    os.makedirs(out_dir, exist_ok=True)
    errors_path = os.path.join(out_dir, "llm_errors.jsonl")
    open(errors_path, "w", encoding="utf-8").close()

    # Offline guarantee: refuse any non-local LLM URL (Study rule enforced in code).
    assert_local_url(llm_base_url)

    llm_cfg = {"backend": backend, backend: {"base_url": llm_base_url, "model": llm_model},
               "use_mock_on_failure": use_mock_on_failure, "max_retries": 1}
    client = None
    # A cold host answers no pings: llama-swap comes up after the VM does, and a single
    # failed ping used to condemn the whole book to the mock LLM. Wait for it instead.
    _ping_tries = int(os.getenv("BOOKIDX_PING_TRIES", "10"))
    _ping_wait = float(os.getenv("BOOKIDX_PING_WAIT", "15"))
    try:
        client = build_client(llm_cfg)
        for _try in range(max(1, _ping_tries)):
            if client.ping():
                break
            if _try + 1 < _ping_tries:
                _time.sleep(_ping_wait)
        else:
            client = MockLLM() if use_mock_on_failure else None
    except Exception:
        client = MockLLM() if use_mock_on_failure else None

    offset_info: dict = {}
    records = extract_book(pdf_path=pdf_path, book_label=book_label,
                           page_offset=page_offset, start_page=start_page, end_page=end_page,
                           offset_info=offset_info)
    chunks = []
    for rec in records:
        chunks.extend(chunk_page(rec))
    _ckpt = None
    try:
        import hashlib as _hl
        _cdir = os.getenv("BOOKIDX_CKPT_DIR", "/bookidx_ckpt")
        os.makedirs(_cdir, exist_ok=True)
        with open(pdf_path, "rb") as _pf:
            _head = _pf.read(1 << 20)
        _key = _hl.md5(_head + str(os.path.getsize(pdf_path)).encode()).hexdigest()[:16]
        _ckpt = os.path.join(_cdir, "%s.jsonl" % _key)
        import json as _js
        _meta = {"key": _key, "book": book_label, "chunks": len(chunks),
                 "pages": len(records), "started": _time.time()}
        with open(os.path.join(_cdir, "%s.meta.json" % _key), "w", encoding="utf-8") as _mf:
            _js.dump(_meta, _mf)
        # the watcher cannot recompute this key (the engine indexes a normalised copy of
        # the PDF, not the file on disk), so point at the running job explicitly
        with open(os.path.join(_cdir, "_current.json"), "w", encoding="utf-8") as _cf:
            _js.dump(_meta, _cf)
    except Exception:
        _ckpt = None
    cands, errored = extract_candidates(client, chunks, use_llm=(client is not None),
                                        max_retries=1, errors_path=errors_path,
                                        checkpoint_path=_ckpt)

    try:
        from .normalize import merge_dupes as _merge_dupes
        rows = sort_rows(add_flags(_merge_dupes(normalize(cands, min_weight=min_weight))))
    except Exception:
        rows = sort_rows(add_flags(normalize(cands, min_weight=min_weight)))

    # Stage C.5: translate ONLY descriptions to Ukrainian (offline-guarded).
    # Never uses the MockLLM (it is not a translator); a real local model or
    # English fallback only.
    uk_n = 0
    if translate_uk:
        try:
            uk_n = translate_rows_uk(
                rows, llm_base_url=llm_base_url,
                llm_model=(uk_model or os.getenv("BOOKIDX_UK_MODEL") or llm_model),
                backend=backend)
        except Exception:
            uk_n = 0

    csv_path, xlsx_path, n = write_csv_xlsx(rows, out_dir)
    review_path, n_flagged = write_review(rows, out_dir)
    cheatsheet_path = write_commands_cheatsheet(rows, out_dir)
    cheatsheet_uk_csv, cheatsheet_uk_docx = write_commands_cheatsheet_uk(rows, out_dir)
    docx_path = write_docx(rows, out_dir) if make_docx else None
    report_path, _ = write_run_report(out_dir, rows, {
        "backend": backend if client and not isinstance(client, MockLLM) else ("mock" if isinstance(client, MockLLM) else "none (regex-only)"),
        "llm_used": client is not None, "used_mock": isinstance(client, MockLLM),
        "uk_translated": uk_n,
        "pages_per_book": {book_label: len(records)}, "pages_errored": errored,
        "page_offset": offset_info.get("offset", page_offset),
        "offset_method": offset_info.get("method", "caller-supplied"),
        "offset_detail": offset_info.get("positional_info", ""),
    })
    return {"csv": csv_path, "xlsx": xlsx_path, "review": review_path,
            "cheatsheet": cheatsheet_path,
            "cheatsheet_uk_csv": cheatsheet_uk_csv,
            "cheatsheet_uk_docx": cheatsheet_uk_docx,
            "docx": docx_path, "report": report_path,
            "entries": n, "flagged": n_flagged, "pages": len(records),
            "uk_translated": uk_n,
            "page_offset": offset_info.get("offset", page_offset),
            "offset_method": offset_info.get("method", "caller-supplied")}
