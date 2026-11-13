# MOTW / :Zone.Identifier Integration — Collector ↔ Parser Contract

**Status:** code merged into `parsers/forensic.py` (2026-06-23). **Deploy (container
restart) PENDING user confirmation.** This doc defines the CSV the host-side KAPE
build must produce so the bot can mine browser/download provenance.

---

## 1. Why

A downloaded file on Windows carries a `:Zone.Identifier` Alternate Data Stream
(ADS) — the Mark-of-the-Web (MOTW). For internet downloads it contains:

```
[ZoneTransfer]
ZoneId=3
HostUrl=https://…            ← the direct download URL (where the file came from)
ReferrerUrl=https://…        ← the page that initiated the download
```

The bot's provenance logic (assemblers.py `zone_identifier_host_url` /
`zone_identifier_referrer_url`, and ~6 agent_tools timeline/download queries)
reads this from `filesystem_v2.payload->>'zone_id'`, filtering on
`extension='identifier'` and `payload->>'zone_id' ILIKE '%HostUrl%'`, then
extracting with regex `HostUrl=([^\r\n]+)` / `ReferrerUrl=([^\r\n]+)`.

Historically that field was only populated when MFTECmd happened to capture the
ADS contents (`ZoneIdContents` column), which is frequently empty. A dedicated
MOTW collector closes that gap.

---

## 2. What the collector must produce

### 2.1 Location (folder)

Place the CSV in **either**:

- a new top-level KAPE output folder named **`motw`** — any `*.csv` there is ingested; **or**
- the existing **`webbrowsers`** folder, with a filename containing **`zone_identifier`** / **`zoneidentifier`** / **`motw`** (e.g. `20260101120000_zone_identifier.csv`).

Routing is by folder + filename only (KAPE timestamps the filename prefix; that is
fine). See `is_motw_csv()` in `parsers/forensic.py`.

### 2.2 Filename

Any `.csv`. Recommended: `*_zone_identifier.csv` or `*_motw.csv`.

### 2.3 Columns (header row required)

Comma-separated, UTF-8 (BOM tolerated), `\r\n` or `\n` line endings. Column names
are **case-insensitive** and several aliases are accepted:

| Purpose                       | Preferred header | Accepted aliases                          | Required |
|-------------------------------|------------------|-------------------------------------------|----------|
| Full path of the host file    | `Path`           | `File`, `FullPath`, `FilePath`, `TargetPath` | yes¹     |
| MOTW zone number              | `ZoneId`         | `Zone`, `ZoneIdValue`                      | optional |
| Direct download URL           | `HostUrl`        | `Host`                                     | yes²     |
| Referring page URL            | `ReferrerUrl`    | `Referrer`                                 | yes²     |
| When the ADS/file was written | `Timestamp`      | `TimeStamp`, `Created`, `CreationTime`, `LastWriteTime` | **recommended³** |

¹ Used to derive `file_name` (basename) and `parent_path`. The basename keeps its
  real extension so suspicious-archive ordering (`\.exe|\.zip|\.rar…`) still works;
  the parser appends `:Zone.Identifier`.

² A row is **only ingested if `HostUrl` OR `ReferrerUrl` is non-empty** (rows with
  neither carry no provenance and are skipped — same guard as MFTECmd's
  `ZoneIdContents`). Provide both when available.

³ **Strongly recommended.** Rows without a timestamp still appear in the assembler
  provenance view and in `get_browser_downloads`, but several **time-windowed**
  agent tools filter `event_ts BETWEEN …` / `>= attack_start` and will silently
  drop NULL-timestamp MOTW rows from those windows. Emit an ISO-8601 / `yyyy-MM-dd
  HH:mm:ss` value (the existing `_parse_ts` handles common KAPE/.NET formats).

### 2.4 Example CSV

```
Path,ZoneId,HostUrl,ReferrerUrl,Timestamp
C:\Users\victim\Downloads\invoice.zip,3,https://swisstransfer.com/d/abc123/invoice.zip,https://mail.example.org/inbox/msg42,2026-06-20T11:05:00Z
C:\Users\victim\Downloads\setup.exe,3,http://198.51.100.7/payload/setup.exe,,2026-06-21T09:00:00Z
```

### 2.5 Suggested KAPE module

A `!**:Zone.Identifier`-aware collector (e.g. a custom Target that copies ADS
contents, or a Module wrapping a small PowerShell/`Get-Content -Stream
Zone.Identifier` enumeration over `C:\Users\*\Downloads`, `\Desktop`, `\AppData`,
temp paths) that writes the columns above. Parse the raw ADS body into the
`ZoneId` / `HostUrl` / `ReferrerUrl` columns, or — if easier — emit the raw ADS
text into a single column; the parser only needs `HostUrl=`/`ReferrerUrl=` to be
present somewhere it can be reconstructed. (Current parser expects the discrete
columns above.)

---

## 3. How the parser maps it (for maintainers)

`parsers/forensic.py`:

- `is_motw_csv(rel_path)` → routing predicate (folder/filename).
- `classify()` returns kind **`fs_motw`** for such CSVs (checked before the
  webbrowsers suffix rules).
- `motw_row_to_fields(row)` (module-level, pure) → `(file_name, extension,
  parent_path, zone_id_text, ts_raw)`; reconstructs the ADS body as
  `[ZoneTransfer]\r\nZoneId=…\r\nHostUrl=…\r\nReferrerUrl=…`.
- nested `map_motw(row, src)` → 8-tuple, inserted into **`filesystem_v2`**
  (`extension='identifier'`, `action='MOTW'`, `payload={'zone_id': <ADS text>}`)
  by `_flush_batch` (reuses the existing `fs_mft`/`fs_usn` INSERT).

No new consumer code is required: the rows land in exactly the storage the
existing `zone_identifier_*` consumers already query.

### Test

`services/case_maintainer/test_motw_parse.py` — feeds a synthetic CSV through
`is_motw_csv` + `motw_row_to_fields` and asserts `HostUrl`/`ReferrerUrl` are
extractable with the consumers' own regex. No DB / no container needed:

```
python3 services/case_maintainer/test_motw_parse.py
```
