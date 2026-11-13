"""Offline hash-reputation lookup for the hashes the collector shipped in `hashes.csv`.

OFFLINE ON PURPOSE (owner's decision 2026-08-08): an online hash lookup discloses to a third
party which case is being worked on. Online enrichment stays a separate, explicit opt-in.

TWO DATABASES, TWO DIFFERENT QUESTIONS — do not conflate them in report wording:
  * known-BAD  : MalwareBazaar (abuse.ch) full SHA256 dump -> a hit is EVIDENCE.
  * known-GOOD : CIRCL hashlookup bloom filter (contains the whole NSRL) -> this is a
                 WHITELIST. It never proves a file is malicious. Its value is the negative:
                 a bloom filter has NO false negatives, so "NOT in the filter" is a hard
                 statement that the binary is not a known-legitimate file = worth a look.
                 A hit only means "probably stock" (bloom filters do have false positives),
                 so it may DE-PRIORITISE a file but must never CLEAR it.

MEASURED LIMITATION (2026-08-08): the served CIRCL filter is dated 2023-10-07. Of four stock
Windows binaries only calc.exe was recognised; notepad/cmd/explorer were not, because they
have been patched since. Therefore "not known-good" must NEVER be presented as suspicious on
its own. It is only ever a QUALIFIER on a file that some other rule already flagged - which
is exactly how it is used here, since only already-flagged files are hashed at all.

Databases live in `<CASE_LIB>/_hashdb/` and are built by analysis/hash_db_build.py.
"""
from __future__ import annotations

import csv
import os
import sqlite3

HASHDB_DIR = os.environ.get("DFIR_HASHDB_DIR", "/data/case_library/_hashdb")
KNOWN_BAD = os.path.join(HASHDB_DIR, "known_bad.sqlite")
BLOOM = os.path.join(HASHDB_DIR, "hashlookup-full.bloom")


# A bloom filter is only useful if its false-positive rate is small. If the reader
# misinterprets the filter parameters it still "works" - it just answers YES to almost
# everything, which would silently mark every binary as known-good and HIDE the real leads.
# So the filter must PROVE itself before it is trusted.
MAX_FP_RATE = 0.01
_SELF_TEST_PROBES = 2000


def bloom_self_test(bf, probes=_SELF_TEST_PROBES):
    """Probe with hashes that cannot be in any real dataset. Returns the observed FP rate."""
    import hashlib
    hits = 0
    for i in range(probes):
        h = hashlib.sha1(("dfir-selftest-%d" % i).encode()).hexdigest().upper()
        try:
            if bf.check(h.encode()):
                hits += 1
        except Exception:
            return 1.0
    return hits / float(probes)


def _bloom():
    """Load the CIRCL bloom filter, or None when absent, unreadable OR unreliable."""
    if not os.path.exists(BLOOM):
        return None
    try:
        from flor import BloomFilter
        bf = BloomFilter()
        with open(BLOOM, "rb") as fh:
            bf.read(fh)
    except Exception:
        return None
    rate = bloom_self_test(bf)
    if rate > MAX_FP_RATE:
        # Observed 0.66 with the `flor` reader on the CIRCL file (DCSO format): the reader
        # is not compatible, so every answer would be meaningless. Refuse to use it.
        return None
    return bf


def _known_bad_set(hashes):
    """Return the subset of sha256 values present in the known-bad DB."""
    if not hashes or not os.path.exists(KNOWN_BAD):
        return set()
    out = set()
    try:
        con = sqlite3.connect("file:%s?mode=ro" % KNOWN_BAD, uri=True)
        cur = con.cursor()
        vals = [h.lower() for h in hashes if h]
        for i in range(0, len(vals), 500):
            chunk = vals[i:i + 500]
            q = "SELECT sha256 FROM bad WHERE sha256 IN (%s)" % ",".join("?" * len(chunk))
            for (h,) in cur.execute(q, chunk):
                out.add(h)
        con.close()
    except sqlite3.Error:
        return set()
    return out


def known_bad_sha1(hashes):
    """{sha1: (family, mb_file_name, first_seen)} for the SHA1s found in MalwareBazaar.
    Empty dict when the database predates the SHA1 table (built before 18.10.2026)."""
    hs = sorted({str(h).strip().lower() for h in hashes if h and len(str(h).strip()) == 40})
    out = {}
    if not hs or not os.path.exists(KNOWN_BAD):
        return out
    try:
        con = sqlite3.connect("file:%s?mode=ro" % KNOWN_BAD, uri=True)
        for i in range(0, len(hs), 500):
            part = hs[i:i + 500]
            q = "SELECT sha1, signature, file_name, first_seen FROM bad_sha1 WHERE sha1 IN (%s)" % ",".join("?" * len(part))
            for h, sig, fn, fs in con.execute(q, part):
                out[h] = (sig, fn, fs)
        con.close()
    except sqlite3.Error:
        return {}
    return out


def db_status():
    """What is actually available, so the report can state its own limits honestly."""
    st = {"known_bad": False, "known_bad_count": 0, "known_good": False,
          "known_bad_mtime": None, "known_good_mtime": None}
    if os.path.exists(KNOWN_BAD):
        st["known_bad"] = True
        st["known_bad_mtime"] = int(os.path.getmtime(KNOWN_BAD))
        try:
            con = sqlite3.connect("file:%s?mode=ro" % KNOWN_BAD, uri=True)
            st["known_bad_count"] = con.execute("SELECT count(*) FROM bad").fetchone()[0]
            con.close()
        except sqlite3.Error:
            pass
    if os.path.exists(BLOOM):
        st["known_good"] = True
        st["known_good_mtime"] = int(os.path.getmtime(BLOOM))
    return st


def lookup_rows(rows):
    """Classify hash rows. `rows` = dicts with SHA256/SHA1/Path/FileName/Category.

    Returns {'bad': [...], 'unknown': [...], 'known_good': n, 'checked': n, 'status': {...}}
    """
    rows = [r for r in (rows or []) if (r.get("SHA256") or r.get("SHA1"))]
    res = {"bad": [], "unknown": [], "known_good": 0, "checked": len(rows),
           "status": db_status()}
    if not rows:
        return res

    bad = _known_bad_set([r.get("SHA256") for r in rows])
    bf = _bloom()
    # existence is not enough: a partially downloaded filter cannot be parsed, and the
    # report must not claim a known-good check happened when it did not.
    res["status"]["known_good_loaded"] = bf is not None

    for r in rows:
        sha256 = (r.get("SHA256") or "").lower()
        sha1 = (r.get("SHA1") or "").upper()
        item = {"path": r.get("Path"), "name": r.get("FileName"),
                "sha256": sha256, "sha1": sha1,
                "category": r.get("Category"), "size": r.get("SizeBytes")}
        if sha256 and sha256 in bad:
            item["verdict"] = "known_malware"
            res["bad"].append(item)
            continue
        if bf is not None and sha1:
            try:
                # CIRCL stores upper-case SHA-1 strings
                if bf.check(sha1.encode()):
                    res["known_good"] += 1
                    continue
            except Exception:
                pass
            item["verdict"] = "not_known_good"
            res["unknown"].append(item)
    return res


def lookup_csv(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        return lookup_rows(list(csv.DictReader(fh)))
