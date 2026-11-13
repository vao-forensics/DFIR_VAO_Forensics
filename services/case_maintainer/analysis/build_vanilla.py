#!/usr/bin/env python3
"""Build a compact index from VanillaWindowsReference (MIT) UniqueDirectoryAndNames.csv.

WHY THIS DATASET MATTERS
    The CIRCL/NSRL bloom answers only "is this HASH known-good", and the served filter is
    dated 2023 — measured: of notepad/cmd/calc/explorer on a patched Win10 22H2 it recognised
    only calc.exe. VanillaWindowsReference is PATH-AWARE and current (updated 2026-07),
    which enables two checks a hash whitelist cannot make:
      * a file sitting in a system directory that exists in NO vanilla Windows  -> added file
      * a Windows-native NAME appearing at a path where Windows never puts it   -> masquerade

STORAGE
    ~300 MB of text becomes a SQLite of 64-bit path fingerprints (blake2b-8 of the lowercased
    "dir\\name"). Membership only - we never need to read a path back - so 8 bytes per row
    instead of ~60. Collisions at 64 bits over ~10M rows are negligible.
"""
import csv
import hashlib
import os
import sqlite3
import sys

SRC = sys.argv[1] if len(sys.argv) > 1 else "/tmp/vwr_x/UniqueDirectoryAndNames.csv"
DB = sys.argv[2] if len(sys.argv) > 2 else "/data/case_library/_hashdb/vanilla_paths.sqlite"


def fp(s):
    return hashlib.blake2b(s.encode("utf-8", "replace"), digest_size=8).digest()


def main():
    tmp = DB + ".building"
    if os.path.exists(tmp):
        os.remove(tmp)
    con = sqlite3.connect(tmp)
    con.execute("PRAGMA journal_mode=OFF")
    con.execute("PRAGMA synchronous=OFF")
    # full "dir\name" pairs, and separately the set of directories that exist in vanilla
    con.execute("CREATE TABLE vpath(fp BLOB PRIMARY KEY) WITHOUT ROWID")
    con.execute("CREATE TABLE vdir(fp BLOB PRIMARY KEY) WITHOUT ROWID")
    con.execute("CREATE TABLE vname(fp BLOB PRIMARY KEY) WITHOUT ROWID")

    npath = ndir = nname = 0
    seen_dir, seen_name = set(), set()
    batch_p, batch_d, batch_n = [], [], []
    with open(SRC, encoding="utf-8", errors="replace", newline="") as fh:
        rd = csv.reader(fh)
        header = next(rd, None)
        for row in rd:
            if len(row) < 2:
                continue
            d, n = row[0].strip().lower(), row[1].strip().lower()
            if not n:
                continue
            batch_p.append((fp(d + "\\" + n),))
            npath += 1
            if d and d not in seen_dir:
                seen_dir.add(d)
                batch_d.append((fp(d),))
                ndir += 1
            if n not in seen_name:
                seen_name.add(n)
                batch_n.append((fp(n),))
                nname += 1
            if len(batch_p) >= 100000:
                con.executemany("INSERT OR IGNORE INTO vpath VALUES(?)", batch_p)
                con.executemany("INSERT OR IGNORE INTO vdir  VALUES(?)", batch_d)
                con.executemany("INSERT OR IGNORE INTO vname VALUES(?)", batch_n)
                batch_p, batch_d, batch_n = [], [], []
    con.executemany("INSERT OR IGNORE INTO vpath VALUES(?)", batch_p)
    con.executemany("INSERT OR IGNORE INTO vdir  VALUES(?)", batch_d)
    con.executemany("INSERT OR IGNORE INTO vname VALUES(?)", batch_n)
    con.commit()
    con.close()
    os.replace(tmp, DB)
    print("rows: paths=%d dirs=%d names=%d" % (npath, ndir, nname))
    print("db size: %.1f MB" % (os.path.getsize(DB) / 1048576.0))


if __name__ == "__main__":
    main()
