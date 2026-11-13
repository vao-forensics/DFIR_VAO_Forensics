#!/usr/bin/env python3
"""Standalone test for the MOTW / :Zone.Identifier ingest path.

Feeds a small synthetic Zone.Identifier collector CSV through the REAL parser
helpers (parsers.forensic.is_motw_csv + motw_row_to_fields) and asserts that
HostUrl / ReferrerUrl become extractable using the SAME regex the bot's
consumers use (assemblers.py / agent_tools.py read
``filesystem_v2.payload->>'zone_id'`` with ``HostUrl=([^\\r\\n]+)``).

No DB, no container, no network. The heavy module-level imports of forensic.py
(psycopg2 / core.config / core.db) are stubbed so the file is runnable on the
bare host as well as inside the case_maintainer container:

    python3 services/case_maintainer/test_motw_parse.py
    # or inside the container:
    python3 /app/test_motw_parse.py
"""
import csv
import io
import os
import re
import sys
import types

# --- Stub heavy/env-bound deps so we import the REAL forensic.py transform ----
# (motw_row_to_fields / is_motw_csv are pure; they do not use these stubs, but
#  the module's top-level imports must resolve.)
if 'psycopg2' not in sys.modules:
    _pg = types.ModuleType('psycopg2')
    _extras = types.ModuleType('psycopg2.extras')
    _extras.Json = lambda x: x  # passthrough; not exercised by the helpers under test
    _pg.extras = _extras
    sys.modules['psycopg2'] = _pg
    sys.modules['psycopg2.extras'] = _extras

if 'core' not in sys.modules:
    _core = types.ModuleType('core')
    _core.__path__ = []  # mark as package
    _cfg = types.ModuleType('core.config')
    _cfg.PG_DSN = 'stub://'
    _cfg.CASE_LIB = '/tmp'
    _db = types.ModuleType('core.db')
    _db._parse_ts = lambda v: v
    sys.modules['core'] = _core
    sys.modules['core.config'] = _cfg
    sys.modules['core.db'] = _db

# Make `parsers.forensic` importable regardless of CWD.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from parsers.forensic import is_motw_csv, motw_row_to_fields  # noqa: E402

# Consumers' actual extraction regex (assemblers.py:550-551, agent_tools.py:590-591).
HOST_RE = re.compile(r'HostUrl=([^\r\n]+)')
REF_RE = re.compile(r'ReferrerUrl=([^\r\n]+)')

# Synthetic collector CSV — columns the KAPE MOTW module must emit.
SYNTHETIC_CSV = (
    "Path,ZoneId,HostUrl,ReferrerUrl,Timestamp\r\n"
    # 1) Suspicious archive from a file-share host + referrer page.
    "C:\\Users\\victim\\Downloads\\invoice.zip,3,"
    "https://swisstransfer.com/d/abc123/invoice.zip,"
    "https://mail.example.org/inbox/msg42,2026-06-20T11:05:00Z\r\n"
    # 2) EXE with HostUrl but no referrer (still valid provenance).
    "C:\\Users\\victim\\Downloads\\setup.exe,3,"
    "http://198.51.100.7/payload/setup.exe,,2026-06-21T09:00:00Z\r\n"
    # 3) Row with NO provenance (no HostUrl / ReferrerUrl) — must be skipped.
    "C:\\Users\\victim\\Documents\\notes.txt,,,\r\n"
)

FAILS = []


def check(cond, msg):
    print(("  PASS" if cond else "  FAIL") + " — " + msg)
    if not cond:
        FAILS.append(msg)


def main():
    print("== classify routing (is_motw_csv) ==")
    check(is_motw_csv('webbrowsers/20260101_zone_identifier.csv'), "webbrowsers/*zone_identifier*.csv routes to MOTW")
    check(is_motw_csv('webbrowsers/host_motw_export.csv'), "webbrowsers/*motw*.csv routes to MOTW")
    check(is_motw_csv('motw/anything.csv'), "any CSV under motw/ routes to MOTW")
    check(is_motw_csv('zone_identifier.csv') is False,
          "bare filename with no folder does NOT route")
    check(is_motw_csv('webbrowsers/20260101_downloads.csv') is False,
          "ordinary webbrowsers downloads CSV does NOT route to MOTW")
    check(is_motw_csv('motw/readme.txt') is False, "non-CSV under motw/ does NOT route")

    print("\n== row mapping + consumer-regex extraction (motw_row_to_fields) ==")
    rows = list(csv.DictReader(io.StringIO(SYNTHETIC_CSV)))
    mapped = [motw_row_to_fields(r) for r in rows]

    # Row 3 has no provenance → must be dropped.
    check(mapped[2] is None, "row with no HostUrl/ReferrerUrl is skipped (returns None)")

    # Row 1 — full provenance.
    fn1, ext1, parent1, zone1, ts1 = mapped[0]
    check(ext1 == 'identifier', "extension is 'identifier' (load-bearing for consumer filter)")
    check(fn1 == 'invoice.zip:Zone.Identifier',
          "file_name keeps real ext + ':Zone.Identifier' suffix (got %r)" % fn1)
    check(parent1 == 'C:/Users/victim/Downloads', "parent_path normalised (got %r)" % parent1)
    h1 = HOST_RE.search(zone1)
    r1 = REF_RE.search(zone1)
    check(bool(h1) and h1.group(1) == 'https://swisstransfer.com/d/abc123/invoice.zip',
          "HostUrl extracted via consumer regex (got %r)" % (h1 and h1.group(1)))
    check(bool(r1) and r1.group(1) == 'https://mail.example.org/inbox/msg42',
          "ReferrerUrl extracted via consumer regex (got %r)" % (r1 and r1.group(1)))
    check('%HostUrl%'.strip('%') in zone1 and zone1.startswith('[ZoneTransfer]'),
          "zone_id text mirrors raw ADS body and contains 'HostUrl' for ILIKE match")
    check(ts1 == '2026-06-20T11:05:00Z', "timestamp column passed through (got %r)" % ts1)

    # Row 2 — HostUrl, no referrer.
    fn2, ext2, parent2, zone2, ts2 = mapped[1]
    h2 = HOST_RE.search(zone2)
    check(bool(h2) and h2.group(1) == 'http://198.51.100.7/payload/setup.exe',
          "HostUrl extracted when referrer absent (got %r)" % (h2 and h2.group(1)))
    check(REF_RE.search(zone2) is None, "no ReferrerUrl line emitted when column empty")
    check(fn2 == 'setup.exe:Zone.Identifier', "exe file_name preserved for ordering regex (got %r)" % fn2)

    print("\n== column-name tolerance ==")
    alt = motw_row_to_fields({'File': 'D:/dl/a.7z', 'Zone': '4', 'Host': 'https://x.test/a.7z'})
    check(alt is not None and HOST_RE.search(alt[3]).group(1) == 'https://x.test/a.7z',
          "alternate column headers (File/Zone/Host) accepted")

    print("\n" + ("ALL TESTS PASSED" if not FAILS else "FAILURES: %d" % len(FAILS)))
    return 0 if not FAILS else 1


if __name__ == '__main__':
    sys.exit(main())
