# Hindsight (ObsidianForensics) Browser Forensics — Ingest Contract

**Status:** ADDITIVE branch in `services/case_maintainer/parsers/forensic.py` (added 2026-06-23).
Does **not** change the existing `webbrowsers/*.csv` browser routing or the MOTW /
`:Zone.Identifier` (`fs_motw`) routing. Hindsight is processed in its own JSONL pass,
invisible to every existing collection (`.jsonl` is not matched by the CSV/JSON/THOR/
LOKI/RegRipper passes).

---

## 1. What the collector must produce

The host KAPE collector's `ObsidianForensics_Hindsight` module (run **FULL mode**,
`Category=WebBrowsers`) must drop its **JSONL** export into the `WebBrowsers` folder of
the KAPE output that gets zipped into `cases/<case>/uploads/logs/<case>.zip`:

```
WebBrowsers/
    Hindsight_output.jsonl      <-- REQUIRED, consumed by the bot
    Hindsight_output.xlsx       <-- ignored by the bot (optional human artifact)
    User_chrome_history.csv     <-- existing per-browser CSVs, still parsed as before
    User_chrome_downloads.csv
    ...
```

**Recognition rule** (`is_hindsight_file`): a file routes to the Hindsight pass iff it is
under the `webbrowsers/` folder, its name contains `hindsight`, and it ends with `.jsonl`.
Folder/name matching is case-insensitive. One JSON object per line.

> **Collector note:** prefer the **JSONL**. Do **not** rely on a `Hindsight_output.csv`
> for ingestion — if Hindsight also emits a generic `.csv` into `WebBrowsers/`, the
> pre-existing catch-all `webbrowsers/*.csv → fb_browser_misc` rule will ingest it as
> undifferentiated raw misc (not split into history/downloads/cookies). The JSONL is the
> richest, type-tagged source and the one this branch maps properly.

---

## 2. Record fields consumed

Each line is a Hindsight record. The record's **type** is read from the first present of:
`type`, `row_type`, `rowtype`, `record_type` (pyhindsight uses `row_type`). Field lookups
are case-insensitive and alias-tolerant (`_hpick`), so version/format variants are handled.

| Hindsight type (substring) | Stored as `parser_family` | Fields consumed (first alias present) |
|---|---|---|
| `download` | `browser_downloads` | `url`; `target_path`/`full_path`/`current_path`/`value`/`path`; `referrer`/`from`/`from_url`/`referring_url`/`tab_url` (or first URL found in `interpretation`); `received_bytes`/`bytes`/`size`; `total_bytes`; `end_time`/`timestamp`/`start_time` |
| `url` / `visit` / `history` | `browser_history` | `url`; `title`/`name`; `timestamp`/`last_visit_time`/`visit_time`; `visit_count`/`visits` |
| `cookie (...)` | `browser_misc` | `host`/`host_key`/`domain` (or host parsed from `url`); `url`; `name`/`cookie_name`/`key`; `timestamp`/`creation_utc` |
| anything else (autofill, local storage, …) | — | skipped (returns `None`) |

Records with no useful data (e.g. a download with neither `url` nor a target path, a
cookie with neither host nor name) are skipped. A malformed JSON line, or a single record
that raises, is skipped without aborting ingestion.

---

## 3. Where it is stored (zero new consumer code)

All Hindsight records land in **`raw_fallback_v2`** with the SAME `parser_family` values the
bot already mines for the per-browser CSVs (`fb_browser_history` → `browser_history`, etc.).
The output payload keys are chosen to match what the existing consumers query, so
`assemblers.py` / `agent_tools.py` / `chat.py` pick them up automatically:

- `browser_downloads` payload: `url`, `target_path`, `current_path`, `filename`,
  `end_time`, `start_time`, `received_bytes`, `total_bytes`, `referrer`, `interpretation`
  — read by `_agent_tool_get_browser_downloads` / `_agent_tool_get_browser_activity`
  (`payload->>'url' / 'target_path' / 'current_path' / 'filename' / 'end_time' / 'total_bytes'`).
  `start_time` mirrors `end_time` because `chat.py` (`browser_downloads` schema map) and the
  activity display loop also read `payload->>'start_time'`.
- `browser_history` payload: `url`, `title`, `last_visit_time`, `visit_count`.
- `browser_misc` payload: `host`, `url`, `name`, `last_visit_time`
  — `chat.py` cookie queries filter on `payload ? 'host'`.

> `referrer` is stored per the task spec. Note no current consumer reads `referrer` from
> `raw_fallback_v2.browser_downloads` (download referrer/provenance is surfaced from
> `browser_provenance_v1` and from MOTW `:Zone.Identifier`); the field is preserved for
> future use and is verified by the test.

---

## 4. Verification

- Unit test (no DB / container / network): `python3 services/case_maintainer/test_hindsight_parse.py`
  → `ALL TESTS PASSED`. Asserts routing + the consumer-contract payload keys above.
- Backup of `forensic.py` before this change: `backups/20260623_213533_forensic.py`.
