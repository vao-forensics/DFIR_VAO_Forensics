#!/usr/bin/env python3
"""Standalone test for the additive Hindsight (ObsidianForensics) JSONL ingest path.

Feeds a tiny synthetic Hindsight-format JSONL through the REAL parser helpers
(parsers.forensic.is_hindsight_file + hindsight_record_to_fallback) and asserts the
records land in the right raw_fallback_v2 parser_family with the EXACT payload keys
the bot's EXISTING browser consumers read — NOT the mapper's internal keys. The
contract checked here is what agent_tools.py / chat.py actually query:
  browser_downloads → url, target_path, current_path, filename, end_time,
                      received_bytes, total_bytes   (+ referrer per task spec)
  browser_history   → url, title, last_visit_time, visit_count
  browser_misc      → host                          (chat.py filters payload ? 'host')

No DB, no container, no network — the heavy module-level imports of forensic.py
(psycopg2 / core.config / core.db) are stubbed so it runs on the bare host too:

    python3 services/case_maintainer/test_hindsight_parse.py
    # or inside the container:
    python3 /app/test_hindsight_parse.py
"""
import json
import os
import sys
import types

# --- Stub heavy/env-bound deps so we import the REAL forensic.py transform ----
if 'psycopg2' not in sys.modules:
    _pg = types.ModuleType('psycopg2')
    _extras = types.ModuleType('psycopg2.extras')
    _extras.Json = lambda x: x  # passthrough; not exercised by the pure helpers
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

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from parsers.forensic import is_hindsight_file, hindsight_record_to_fallback  # noqa: E402

# Synthetic Hindsight JSONL — one object per line. Field names mirror pyhindsight
# (row_type / full_path / host_key) plus a couple of alias variants to prove tolerance.
SYNTHETIC_JSONL = "\n".join([
    # 1) download with url + referrer + target_path (+ bytes)
    json.dumps({
        "row_type": "download",
        "url": "https://swisstransfer.com/d/abc123/invoice.zip",
        "full_path": "C:\\Users\\victim\\Downloads\\invoice.zip",
        "received_bytes": 204800,
        "total_bytes": 204800,
        "end_time": "2026-06-20T11:05:00Z",
        "referrer": "https://mail.example.org/inbox/msg42",
    }),
    # 2) download where referrer is buried in the interpretation text (no referrer field)
    json.dumps({
        "row_type": "download",
        "url": "http://198.51.100.7/payload/setup.exe",
        "target_path": "C:\\Users\\victim\\Downloads\\setup.exe",
        "received_bytes": 51200,
        "interpretation": "Downloaded from https://phish.example.net/landing via Chrome",
    }),
    # 3) a visit / url row → history
    json.dumps({
        "row_type": "url",
        "url": "https://example.org/login",
        "title": "Example Login",
        "timestamp": "2026-06-20T10:50:00Z",
        "visit_count": 3,
    }),
    # 4) a cookie row → browser_misc (host_key alias)
    json.dumps({
        "row_type": "cookie (accessed)",
        "url": "https://swisstransfer.com/",
        "host_key": "swisstransfer.com",
        "name": "session",
    }),
    # 5) unsupported type → must be skipped (returns None)
    json.dumps({"row_type": "local storage", "url": "https://example.org/", "value": "x"}),
    # 6) malformed-but-parseable empty object → skipped
    json.dumps({}),
])

FAILS = []


def check(cond, msg):
    print(("  PASS" if cond else "  FAIL") + " — " + msg)
    if not cond:
        FAILS.append(msg)


def main():
    print("== classify routing (is_hindsight_file) ==")
    check(is_hindsight_file('WebBrowsers/Hindsight_output.jsonl'),
          "WebBrowsers/Hindsight_output.jsonl routes to Hindsight")
    check(is_hindsight_file('webbrowsers/20260101_hindsight.jsonl'),
          "lower-case folder + *hindsight*.jsonl routes")
    check(is_hindsight_file('webbrowsers/Hindsight_output.xlsx') is False,
          "Hindsight .xlsx does NOT route (JSONL only)")
    check(is_hindsight_file('webbrowsers/User_chrome_downloads.csv') is False,
          "ordinary browser CSV is untouched (additive — existing routing intact)")
    check(is_hindsight_file('Hindsight_output.jsonl') is False,
          "bare filename with no folder does NOT route")
    check(is_hindsight_file('eventlogs/Hindsight_output.jsonl') is False,
          "hindsight jsonl outside webbrowsers/ does NOT route")

    print("\n== record mapping + consumer-contract payload keys ==")
    objs = [json.loads(ln) for ln in SYNTHETIC_JSONL.splitlines() if ln.strip()]
    mapped = [hindsight_record_to_fallback(o) for o in objs]

    # Rows 5 & 6 → skipped.
    check(mapped[4] is None, "unsupported 'local storage' type is skipped (None)")
    check(mapped[5] is None, "empty record is skipped (None)")

    # Row 1 — download with explicit referrer.
    fam1, p1 = mapped[0]
    check(fam1 == 'browser_downloads', "download row → browser_downloads family (got %r)" % fam1)
    check(p1.get('url') == 'https://swisstransfer.com/d/abc123/invoice.zip',
          "download url extracted (got %r)" % p1.get('url'))
    check(p1.get('referrer') == 'https://mail.example.org/inbox/msg42',
          "download referrer extracted from referrer field (got %r)" % p1.get('referrer'))
    check(p1.get('target_path') == 'C:\\Users\\victim\\Downloads\\invoice.zip',
          "download target_path extracted (got %r)" % p1.get('target_path'))
    check(p1.get('current_path') == p1.get('target_path'),
          "current_path mirrors target_path (consumer reads both)")
    check(p1.get('filename') == 'invoice.zip',
          "filename derived from target_path basename (got %r)" % p1.get('filename'))
    check(p1.get('end_time') == '2026-06-20T11:05:00Z',
          "end_time populated (consumer ORDER BY / date filter) (got %r)" % p1.get('end_time'))
    check(p1.get('start_time') == '2026-06-20T11:05:00Z',
          "start_time mirrors end_time (chat.py:187 / agent_tools.py read start_time) (got %r)" % p1.get('start_time'))
    check(p1.get('received_bytes') == '204800' and p1.get('total_bytes') == '204800',
          "received_bytes + total_bytes populated (got %r/%r)"
          % (p1.get('received_bytes'), p1.get('total_bytes')))

    # Row 2 — referrer recovered from interpretation text.
    fam2, p2 = mapped[1]
    check(fam2 == 'browser_downloads', "second download → browser_downloads")
    check(p2.get('referrer') == 'https://phish.example.net/landing',
          "referrer recovered from interpretation when no referrer field (got %r)" % p2.get('referrer'))
    check(p2.get('filename') == 'setup.exe', "filename derived for exe download")

    # Row 3 — visit → history.
    fam3, p3 = mapped[2]
    check(fam3 == 'browser_history', "url/visit row → browser_history family (got %r)" % fam3)
    check(p3.get('url') == 'https://example.org/login', "history url extracted")
    check(p3.get('title') == 'Example Login', "history title extracted")
    check(p3.get('last_visit_time') == '2026-06-20T10:50:00Z',
          "history last_visit_time extracted (got %r)" % p3.get('last_visit_time'))
    check(p3.get('visit_count') == '3', "history visit_count extracted (got %r)" % p3.get('visit_count'))

    # Row 4 — cookie → browser_misc with the load-bearing 'host' key.
    fam4, p4 = mapped[3]
    check(fam4 == 'browser_misc', "cookie row → browser_misc family (got %r)" % fam4)
    check(p4.get('host') == 'swisstransfer.com',
          "cookie host extracted (chat.py filters payload ? 'host') (got %r)" % p4.get('host'))
    check(p4.get('name') == 'session', "cookie name extracted")

    print("\n" + ("ALL TESTS PASSED" if not FAILS else "FAILURES: %d" % len(FAILS)))
    return 0 if not FAILS else 1


if __name__ == '__main__':
    sys.exit(main())
