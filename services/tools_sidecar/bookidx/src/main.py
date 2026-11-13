"""
main.py - CLI orchestrator.

Usage:
  python -m src.main --config config.yaml
Options:
  --books-dir DIR      override directory that holds the PDFs
  --model NAME         override LLM model
  --min-weight N       drop candidates below weight N
  --only-book "Book 1" process a single book by label
  --limit-pages N      cap pages per book (fast sanity checks)
  --no-docx            skip the .docx output
  --no-llm             regex pre-pass only (no LLM calls at all)

Deterministic & re-runnable: same input -> same output.
"""
from __future__ import annotations

import argparse
import os
import sys

import yaml
from tqdm import tqdm

from .extract import extract_book, chunk_page
from .llm_client import build_client, MockLLM, assert_local_url
from .llm_extract import extract_candidates
from .normalize import normalize, add_flags, sort_rows
from .build_outputs import (
    write_csv_xlsx, write_review, write_docx, write_run_report,
    write_commands_cheatsheet,
)


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def resolve_client(llm_cfg: dict, no_llm: bool):
    """Return (client, llm_used, used_mock). Honors offline guard + mock fallback."""
    if no_llm:
        return None, False, False

    backend = llm_cfg.get("backend", "openai")
    sub = llm_cfg.get(backend, {})
    # Offline enforcement (raises if not local) - always runs.
    assert_local_url(sub.get("base_url", ""))

    try:
        client = build_client(llm_cfg)
    except Exception as e:
        print(f"[llm] client build failed: {e}", file=sys.stderr)
        client = None

    if client is not None and client.ping():
        print(f"[llm] connected: {client.name}")
        return client, True, False

    # Fallback to mock (keeps the pipeline useful / testable).
    if llm_cfg.get("use_mock_on_failure", True):
        print("[llm] local LLM unreachable/overloaded -> using built-in MockLLM.",
              file=sys.stderr)
        return MockLLM(), True, True

    print("[llm] local LLM unreachable and mock disabled -> regex-only.",
          file=sys.stderr)
    return None, False, False


def main(argv=None):
    ap = argparse.ArgumentParser(description="BOOKIDX open-book exam index generator (offline).")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--books-dir", default=None)
    ap.add_argument("--model", default=None)
    ap.add_argument("--min-weight", type=int, default=None)
    ap.add_argument("--only-book", default=None)
    ap.add_argument("--limit-pages", type=int, default=None)
    ap.add_argument("--no-docx", action="store_true")
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--output-dir", default=None)
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    base_dir = os.path.dirname(os.path.abspath(args.config))

    llm_cfg = cfg.get("llm", {})
    if args.model:
        backend = llm_cfg.get("backend", "openai")
        llm_cfg.setdefault(backend, {})["model"] = args.model

    chunk_cfg = cfg.get("chunk", {})
    ex_cfg = cfg.get("extraction", {})
    min_weight = args.min_weight if args.min_weight is not None else cfg.get("min_weight", 1)

    out_dir = args.output_dir or os.path.join(base_dir, "output")
    os.makedirs(out_dir, exist_ok=True)
    errors_path = os.path.join(out_dir, "llm_errors.jsonl")
    # Fresh errors file each run (deterministic).
    open(errors_path, "w", encoding="utf-8").close()

    books = cfg.get("books", [])
    if args.only_book:
        books = [b for b in books if b.get("book_label") == args.only_book]
        if not books:
            print(f"No book with label {args.only_book!r} in config.", file=sys.stderr)
            return 2

    client, llm_used, used_mock = resolve_client(llm_cfg, args.no_llm)

    all_candidates = []
    pages_per_book = {}
    pages_errored_total = 0

    for b in books:
        rel = b["path"]
        pdf_path = rel if os.path.isabs(rel) else os.path.join(base_dir, rel)
        if args.books_dir:
            pdf_path = os.path.join(args.books_dir, os.path.basename(rel))
        label = b.get("book_label", os.path.basename(pdf_path))

        if not os.path.exists(pdf_path):
            print(f"[skip] {label}: file not found: {pdf_path}", file=sys.stderr)
            continue

        print(f"[extract] {label}  <- {pdf_path}")
        records = extract_book(
            pdf_path=pdf_path,
            book_label=label,
            page_offset=b.get("page_offset", 0),
            start_page=b.get("start_page"),
            end_page=b.get("end_page"),
            strip_hf=ex_cfg.get("strip_headers_footers", True),
            footer_verify=ex_cfg.get("footer_verification", True),
            hf_min_repeats=ex_cfg.get("header_footer_min_repeats", 3),
            limit_pages=args.limit_pages,
        )
        pages_per_book[label] = len(records)

        # Chunk (every chunk keeps its printed_page).
        chunks = []
        for rec in records:
            chunks.extend(chunk_page(
                rec,
                target_tokens=chunk_cfg.get("target_tokens", 600),
                max_tokens=chunk_cfg.get("max_tokens", 800),
                overlap_tokens=chunk_cfg.get("overlap_tokens", 60),
            ))

        with tqdm(total=len(chunks), desc=f"  {label}", unit="chunk") as bar:
            cands, errored = extract_candidates(
                client, chunks,
                use_llm=(client is not None),
                max_retries=llm_cfg.get("max_retries", 1),
                errors_path=errors_path,
                progress=bar,
            )
        all_candidates.extend(cands)
        pages_errored_total += errored

    # Count logged LLM errors (pages) from the errors file.
    try:
        with open(errors_path, "r", encoding="utf-8") as f:
            pages_errored_total += sum(1 for _ in f)
    except Exception:
        pass

    # Stage C: normalize + flag.
    rows = normalize(all_candidates, min_weight=min_weight)
    rows = add_flags(rows)
    rows = sort_rows(rows)

    # Stage D: outputs.
    csv_path, xlsx_path, n = write_csv_xlsx(rows, out_dir)
    review_path, n_flagged = write_review(rows, out_dir)
    cheatsheet_path = write_commands_cheatsheet(rows, out_dir)
    docx_path = None
    if not args.no_docx:
        docx_path = write_docx(rows, out_dir)

    backend_name = llm_cfg.get("backend") if llm_used else "none (regex-only)"
    if used_mock:
        backend_name = "mock"
    report_path, report_text = write_run_report(out_dir, rows, {
        "backend": backend_name,
        "llm_used": llm_used,
        "used_mock": used_mock,
        "pages_per_book": pages_per_book,
        "pages_errored": pages_errored_total,
    })

    print("\n=== DONE ===")
    print(f"  {csv_path}")
    print(f"  {xlsx_path}")
    print(f"  {review_path}  ({n_flagged} flagged)")
    print(f"  {cheatsheet_path}  (Course command cheat sheet)")
    if docx_path:
        print(f"  {docx_path}")
    print(f"  {report_path}")
    print(f"  total entries: {n}")
    print()
    print(report_text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
