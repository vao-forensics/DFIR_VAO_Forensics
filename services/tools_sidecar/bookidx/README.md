# BOOKIDX Open-Book Exam Index Generator (fully offline)

Reads your Study course PDFs **locally** and produces an exam-ready lookup
index: **Topic -> Description -> Page -> Book**. Output is a CSV/XLSX compatible
with the VanAwful *Book-Index-Creator*, plus a printable DOCX and a review CSV.

## Offline / no-cloud guarantee

- **Nothing is ever sent to a cloud API.** The only "AI" step calls a **local**
  LLM (an OpenAI-compatible server such as llama-swap/LM Studio, or Ollama).
- This is enforced *in code*: `assert_local_url()` (in `src/llm_client.py`)
  refuses to run unless the LLM host is `localhost`, loopback, or a private LAN
  range (`10.*`, `192.168.*`, `172.16-31.*`, `::1`, ...).
- **Page numbers come ONLY from deterministic PDF parsing** (PyMuPDF /
  pdfplumber), never from the LLM. The LLM sees text chunks already tagged with
  book+page and returns topics/descriptions only; the code re-attaches the known
  page.
- You can run with `--no-llm` for a purely deterministic (regex) index.

## Install

```powershell
cd C:\Users\<user>\bookidx_index
python -m venv .venv ; .\.venv\Scripts\Activate.ps1   # optional
pip install -r requirements.txt
```

## Quick start (synthetic self-test, no real PDFs)

```powershell
python make_sample_pdf.py            # writes books/sample.pdf (fake content)
python -m src.main --config config.yaml
# -> output/index.csv, index.xlsx, index.docx, index_review.csv, run_report.txt
```

## Point it at your real course PDFs

1. Copy your PDFs into `books/` (this folder is git-ignored; PDFs never leave
   your machine).
2. Edit `config.yaml` -> `books:` — one entry per PDF:
   ```yaml
   - path: "books/501_book1.pdf"
     book_label: "Book 1"
     page_offset: 2          # see below
     start_page: null        # optional 1-based PDF page to start
     end_page: null          # optional 1-based PDF page to stop
   ```

### Setting `page_offset` (IMPORTANT)

`printed_page = pdf_page_index_1based - page_offset`

Open the PDF in a viewer. Find the PDF page whose **printed** number is `1`.
`page_offset = (that PDF page index) - 1`. Example: if printed page 1 is the 3rd
PDF page, `page_offset = 2`.

**Footer-verification tip:** the extractor reads the page-number printed in the
footer and *warns* (flags the row in `index_review.csv`) when it disagrees with
the computed printed page. Run one book first and check for footer-mismatch
flags — a wall of them means your `page_offset` is wrong. The footer is only a
sanity check; it is **never** used to decide the page number.

### Sanity-check one book first

```powershell
python -m src.main --config config.yaml --only-book "Book 1" --limit-pages 20
```
Confirm the `Page` column matches what's printed in your PDF before running all
2000+ pages.

## CLI options

```
python -m src.main --config config.yaml [options]
  --books-dir DIR        override the folder holding the PDFs
  --model NAME           override the LLM model
  --min-weight N         drop candidates below weight N (1-3)
  --only-book "Book 1"   process a single book by label
  --limit-pages N        cap pages per book (fast checks)
  --no-docx              skip the DOCX output
  --no-llm               regex pre-pass only (no LLM at all)
```

## LLM backend (configurable, both supported)

`config.yaml -> llm.backend`:

- `"openai"` — OpenAI-compatible server, e.g. local llama-swap at
  `http://127.0.0.1:1234/v1`, model e.g. `gpt-small-20b`.
- `"ollama"` — `http://localhost:11434`, model e.g. `qwen2.5:14b`.

Temperature is 0 and JSON-only output is requested. Malformed JSON triggers one
retry with a "valid JSON only" reminder; if it still fails, the page is logged to
`output/llm_errors.jsonl` and the run continues. If the local LLM is unreachable
and `use_mock_on_failure: true`, a built-in mock LLM is used so the run still
completes — and the **deterministic regex pre-pass** alone already catches
commands+flags, Windows Event IDs, ports/protocols, and acronyms.

## Outputs (in `output/`)

| File | Purpose |
|------|---------|
| `index.csv` / `index.xlsx` | Columns exactly `Topic \| Description \| Page \| Book`; sorted A-Z; VanAwful-compatible. |
| `index_review.csv` | Same columns + `flag_reason` (only flagged rows). |
| `commands_cheatsheet.csv` | Course CyberLive cheat sheet: `Tool \| Command \| Description \| Page \| Book`, sorted by Tool. |
| `index.docx` | Printable compact two-column A-Z index (~9-10pt). |
| `run_report.txt` | Stats: pages/book, entries, per-category, flagged, errored. |
| `llm_errors.jsonl` | Pages whose LLM JSON could not be parsed (if any). |

### Feeding into VanAwful Book-Index-Creator

`output/index.csv` already uses the exact `Topic, Description, Page, Book`
header with no leading spaces or empty rows. Import it directly, or open
`index.xlsx` and copy the sheet into the creator's expected sheet.

## Course notes

This build is tuned for **Study Course (Exam)**. The exam includes a hands-on
**CyberLive** portion, so **command syntax and expected tool OUTPUT are the
highest-yield lookups** — command/tool/output rows are weighted 3.

- **Deterministic regex pre-pass** (fires even with `--no-llm`) now recognises
  Course high-value items: **EZ Tools** (MFTECmd, PECmd, AppCompatCacheParser,
  AmcacheParser, RECmd, EvtxECmd, SBECmd, LECmd, JLECmd, Timeline Explorer),
  **Volatility** plugins (pslist, psscan, pstree, dlllist, malfind, netscan,
  netstat, cmdline, handles, svcscan, `--profile`), **KAPE**, **Plaso**
  (log2timeline.py / psort.py), **Sleuth Kit** (fls, icat, mactime,
  bulk_extractor), **Windows artifacts** (Prefetch, ShimCache/AppCompatCache,
  Amcache, UserAssist, BAM/DAM, SRUM, `$MFT`, `$LogFile`, `$UsnJrnl/$J`, `$Boot`,
  Shellbags, `$STANDARD_INFORMATION`/SI vs `$FILE_NAME`/FN), **each Windows Event
  ID as its own row** (number → meaning), and **Linux log paths**
  (`/var/log/auth.log`, `/var/log/secure`, `~/.bash_history`).
- The LLM prompt is enriched to extract, for DFIR chunks, what each command
  **proves/outputs** and what each artifact **proves** (page numbers still come
  ONLY from deterministic parsing — never the LLM).
- **`output/commands_cheatsheet.csv`** — a CyberLive quick-reference of every
  command/tool row: `Tool | Command | Description | Page | Book`, sorted by Tool
  then Command. `Tool` is inferred from the command's leading token
  (`vol.py …` → Volatility, `MFTECmd …` → MFTECmd, `log2timeline.py` → Plaso).

## OCR (out of scope, how to enable later)

Scanned/image-only pages are **not** OCR'd here. To add it later: install
Tesseract + `pytesseract`, and in `src/extract.py` where a page's `get_text()`
returns empty, render the page to an image (`page.get_pixmap()`) and run
`pytesseract.image_to_string()`. Keep it deterministic and still fully offline.

## Password-protected PDFs (future)

`pikepdf` is listed in requirements and imported behind a guard for future
password support; it is not required for normal use.
