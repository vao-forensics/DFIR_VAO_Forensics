#!/usr/bin/env python3
"""Build/refresh the OFFLINE hash-reputation databases used by analysis/hash_lookup.py.

Offline on purpose: an online hash lookup discloses to a third party which case is being
worked on. Owner's decision 2026-08-08 — offline first, online only as an explicit opt-in.

Sources (both reachable without any API key):
  * MalwareBazaar (abuse.ch) full CSV dump     -> KNOWN-BAD by SHA256 (table bad) AND by SHA1
    (table bad_sha1, with the malware family): Amcache records SHA1 only, so the SHA256-only
    text dump used until 18.10.2026 could never match an executed binary
  * CIRCL hashlookup bloom filter (DCSO format) -> KNOWN-GOOD (contains the whole NSRL)

NOTE ON POLARITY: NSRL/CIRCL is a known-GOOD whitelist, not a malware list. Its value is
that «NOT in the filter» is a hard signal (a bloom filter has no false negatives), i.e.
«this binary is not a known legitimate file» — which is exactly the lead we want.

Usage:  python3 hash_db_build.py [--dir /data/case_library/_hashdb] [--skip-download]
"""
import argparse
import os
import sqlite3
import sys
import time
import urllib.request
import zipfile

MB_URL = "https://bazaar.abuse.ch/export/csv/full/"
BLOOM_URL = "https://cra.circl.lu/hashlookup/hashlookup-full.bloom"
DEFAULT_DIR = "/data/case_library/_hashdb"


def log(*a):
    print(time.strftime("[%H:%M:%S]"), *a, flush=True)


def download(url, dest, timeout=900):
    log("downloading", url)
    req = urllib.request.Request(url, headers={"User-Agent": "dfir-bot/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as fh:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            fh.write(chunk)
    log("saved", dest, os.path.getsize(dest), "bytes")


def build_known_bad(work, skip_download=False):
    import csv
    import io
    zpath = os.path.join(work, "mb_full_csv.zip")
    if not skip_download or not os.path.exists(zpath):
        download(MB_URL, zpath)
    db = os.path.join(work, "known_bad.sqlite")
    tmp = db + ".building"
    if os.path.exists(tmp):
        os.remove(tmp)
    con = sqlite3.connect(tmp)
    con.execute("PRAGMA journal_mode=OFF")
    con.execute("PRAGMA synchronous=OFF")
    con.execute("CREATE TABLE bad(sha256 TEXT PRIMARY KEY) WITHOUT ROWID")
    con.execute("CREATE TABLE bad_sha1(sha1 TEXT PRIMARY KEY, sha256 TEXT, signature TEXT, "
                "file_name TEXT, first_seen TEXT) WITHOUT ROWID")
    n = n1 = 0
    b256, b1 = [], []

    def flush():
        con.executemany("INSERT OR IGNORE INTO bad VALUES(?)", b256)
        con.executemany("INSERT OR IGNORE INTO bad_sha1 VALUES(?,?,?,?,?)", b1)
        b256.clear(); b1.clear()

    with zipfile.ZipFile(zpath) as z:
        name = [m for m in z.namelist() if m.lower().endswith(".csv")][0]
        fh = io.TextIOWrapper(z.open(name), encoding="utf-8", errors="replace", newline="")
        # banner lines start with '#'; the header itself is '# "first_seen_utc","sha256_hash",...'
        rows = csv.reader((l for l in fh if not l.startswith("#")), skipinitialspace=True)
        for r in rows:
            if len(r) < 9:
                continue
            first, h256, _md5, h1, _rep, fname, _ft, _mime, sig = [x.strip() for x in r[:9]]
            if len(h256) == 64:
                b256.append((h256.lower(),)); n += 1
            if len(h1) == 40:
                b1.append((h1.lower(), h256.lower(), None if sig in ("", "n/a") else sig[:80],
                           fname[:120], first[:19])); n1 += 1
            if len(b256) >= 50000:
                flush()
    flush()
    con.commit()
    con.close()
    if n < 100000:
        # a truncated download must never replace a good database
        log("!! only", n, "rows parsed - keeping the old known_bad.sqlite"); os.remove(tmp); return 0
    os.replace(tmp, db)
    log("known_bad.sqlite built:", n, "sha256 /", n1, "sha1")
    return n


def fetch_bloom(work, skip_download=False):
    dest = os.path.join(work, "hashlookup-full.bloom")
    if skip_download and os.path.exists(dest):
        log("bloom already present:", os.path.getsize(dest), "bytes")
        return os.path.getsize(dest)
    download(BLOOM_URL, dest, timeout=3600)
    return os.path.getsize(dest)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=DEFAULT_DIR)
    ap.add_argument("--skip-download", action="store_true")
    ap.add_argument("--only", choices=["bad", "good"], default=None)
    a = ap.parse_args()
    os.makedirs(a.dir, exist_ok=True)
    if a.only in (None, "bad"):
        build_known_bad(a.dir, a.skip_download)
    if a.only in (None, "good"):
        fetch_bloom(a.dir, a.skip_download)
    log("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
